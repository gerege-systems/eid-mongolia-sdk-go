package pades

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gerege-systems/pdf"

	"github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/validate"
)

// Report — CA-ийн нийтийн шалгагчийн (/v3/validate/pdf) тайлантай ижил JSON хэлбэр.
type (
	Report          = validate.PDFReport
	SignatureReport = validate.SignatureReport
	CertInfo        = validate.CertInfo
	TimestampInfo   = validate.TimestampInfo
	LTVInfo         = validate.LTVInfo
	Indication      = validate.Indication
)

// Indication-ийн утгууд.
const (
	Valid         = validate.Valid
	Invalid       = validate.Invalid
	Indeterminate = validate.Indeterminate
)

// VerifyOptions — Verify-ийн тохиргоо.
type VerifyOptions struct {
	// Roots — итгэлийн тулгуур DER; хоосон бол Mongolian National Root CA.
	Roots [][]byte `json:"roots,omitempty"`
	// Intermediates — нэмэлт завсрын CA DER (шигтгэсэн 02–05-аас гадна).
	Intermediates [][]byte `json:"intermediates,omitempty"`
	// Issuers — eID-ийн олгогч гэж үзэх нэмэлт CA DER (шигтгэсэн 04/05-аас гадна; тест).
	Issuers [][]byte `json:"issuers,omitempty"`
	// Time — шалгах цаг (цагийн тэмдэггүй гарын үсэгт); тэг бол одоо.
	Time time.Time `json:"time,omitempty"`
}

// Verify — ValidatePDF-ийн сүлжээгүй хэлбэр (Offline: true): цуцлалтыг зөвхөн баримтын DSS-ийн OCSP/CRL-ээс.
//
// Deprecated: ValidatePDF (онлайн OCSP/CRL, ctx) ашиглана уу.
func Verify(doc []byte, o VerifyOptions) (*Report, error) {
	rep, err := ValidatePDF(context.Background(), doc, ValidateOptions{Roots: o.Roots, Intermediates: o.Intermediates,
		Issuers: o.Issuers, Time: o.Time, Offline: true})
	if ErrorCode(err) == CodePDFNoSignature {
		return &Report{Indication: Valid, Signatures: []SignatureReport{}}, nil // v0.6.0 хүртэлх зан
	}
	if ErrorCode(err) == CodePDFTooManySignatures {
		err.(*Error).Code = CodePDFInvalid // v0.6.0 хүртэлх зан
	}
	return rep, err
}

// docIDFromPage — баталгаажуулалтын хуудасны холбоос (`<pageVerifyURL><uuid>`)-оос docID; олдохгүй бол "".
func docIDFromPage(doc []byte) (id string) {
	defer func() {
		if recover() != nil {
			id = ""
		}
	}()
	r, err := pdf.NewReader(bytes.NewReader(doc), int64(len(doc)))
	if err != nil {
		return ""
	}
	for _, x := range r.Xref() {
		v := r.Resolve(x.Ptr(), x.Ptr())
		if v.Kind() != pdf.Dict || v.Key("Subtype").Name() != "Link" {
			continue
		}
		u := v.Key("A").Key("URI").RawString()
		if rest, ok := strings.CutPrefix(u, pageVerifyURL); ok && uuidRe.MatchString(rest) {
			return rest
		}
	}
	return ""
}

// stampMarkerRe — QR-тэй дардасны form stream-ийн эхний мөр (APPEARANCE_SPEC.md §5 алхам 6-ийн дүрэм): docId = 1-р бүлэг.
var stampMarkerRe = regexp.MustCompile(`^/EIDVerify <</URL \(https://ca\.eidmongolia\.mn/verify/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/([1-9][0-9]?)\)>> BDC\n`)

// stampMarkerMax — маркерын мөрийн дээд урт (байт; 99 + нөөц) — form stream-ээс уншина.
const stampMarkerMax = 128

// docIDFromStamps — Prepare-ийн docId дүрмийн 2.2-р алхам (APPEARANCE_SPEC.md §6.6): precheck-ийн шалгасан e-Seal гарын
// үсгүүдийн (seals — Sig толины объектын дугаар → байрлал) хамгийн ЭРТ зурсан, /EIDVerify тэмдэгтэй дардасны docId.
// Widget = сүүлийн revision-ий xref-ийн (объектын дугаарын дарааллаар, xref-ийн үетэй) толь, ӨӨРИЙН `/FT /Sig`, ӨӨРИЙН
// `/V` нь seals-ийн аль нэг толь руу ШУУД БУС лавлагаа. Гарын үсэг бүрт яг НЭГ widget — 2+ (зээлсэн /V) бол тэр гарын
// үсгийг бүхэлд нь алгасна. `/AP` → толь, `/N` → stream, `/Filter` алга эсвэл ШУУД null (шууд бус лавлагаа, [], нэр —
// алгасна); stream-ийн /Length байтын эхний ≤ 128 байт stampMarkerRe-ээр эхэлж, маркерын rev = тэр гарын үсгийн
// байрлал. Хамгийн бага ByteRange[2] + ByteRange[3] (тэнцвэл Sig толины объектын дугаар бага). Алга → "". Задлах алдаа
// (panic) → аль хэдийн олдсоныг ч хаяж алдаа (Prepare PDF_INVALID). Энэ нь docId сонгох санамж л — нотолгоо биш:
// зөв эсэхийг validator (Complete-ийн self-validation) батална.
func docIDFromStamps(doc []byte, seals map[uint32]int) (id string, err error) {
	defer func() {
		if r := recover(); r != nil {
			id, err = "", fmt.Errorf("PDF задлах: %v", r)
		}
	}()
	if len(seals) == 0 {
		return "", nil
	}
	r, err := pdf.NewReader(bytes.NewReader(doc), int64(len(doc)))
	if err != nil {
		return "", err
	}
	type stamp struct {
		widgets int
		docID   string
		end     int64
	}
	stamps := map[uint32]*stamp{}
	for _, x := range r.Xref() {
		v := r.Resolve(x.Ptr(), x.Ptr())
		if v.Kind() != pdf.Dict || v.Key("FT").Name() != "Sig" {
			continue
		}
		sig := v.Key("V")
		sp, xp := sig.GetPtr(), x.Ptr()
		// Шууд бус лавлагаа: шууд толь widget-ийн өөрийн ptr-тэй (extract.go-той ижил шалгалт).
		rev, isSeal := seals[sp.GetID()]
		if sig.Kind() != pdf.Dict || sp.GetID() == xp.GetID() || !isSeal {
			continue
		}
		s := stamps[sp.GetID()]
		if s == nil {
			s = &stamp{end: -1}
			stamps[sp.GetID()] = s
		}
		if s.widgets++; s.widgets > 1 {
			continue
		}
		if br := sig.Key("ByteRange"); br.Len() == 4 && br.Index(2).Kind() == pdf.Integer && br.Index(3).Kind() == pdf.Integer {
			s.end = br.Index(2).Int64() + br.Index(3).Int64() // precheck #8: 0 ≤ b, c ≤ len(doc)
		}
		ap := v.Key("AP")
		n := ap.Key("N")
		if ap.Kind() != pdf.Dict || n.Kind() != pdf.Stream {
			continue
		}
		// /Filter: алга эсвэл ШУУД null л (validator-ийн pdfDict ч шууд null-ийг «алга» гэж үзнэ); шууд бус лавлагааны
		// утга нь заасан объектын ptr-тэй (resolve), шууд утга нь stream-ийн өөрийн ptr-тэй.
		if f := n.Key("Filter"); !f.IsNull() || f.GetPtr() != n.GetPtr() {
			continue
		}
		head, _ := io.ReadAll(io.LimitReader(n.Reader(), stampMarkerMax))
		if sm := stampMarkerRe.FindSubmatch(head); sm != nil && string(sm[2]) == strconv.Itoa(rev) {
			s.docID = string(sm[1])
		}
	}
	best, bestObj := int64(math.MaxInt64), uint32(0)
	for obj, s := range stamps {
		if s.widgets != 1 || s.docID == "" || s.end < 0 {
			continue
		}
		if s.end < best || s.end == best && obj < bestObj {
			best, bestObj, id = s.end, obj, s.docID
		}
	}
	return id, nil
}
