package pades

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"regexp"
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

// docIDFromStamps — Prepare-ийн docId дүрмийн 2.2-р алхам (APPEARANCE_SPEC.md §6.6): precheck-ийн криптограф шалгасан
// гарын үсгүүдийн (verified — Sig толины объектын дугаар) хамгийн ЭРТ зурсан, /EIDVerify тэмдэгтэй дардасны docId.
// Widget = сүүлийн revision-ий xref-ийн (объектын дугаарын дарааллаар, xref-ийн үетэй) `/FT /Sig` толь, `/V` нь
// verified-ийн аль нэг толь руу ШУУД БУС лавлагаа. Гарын үсэг бүрт яг НЭГ widget байх ёстой — 2+ widget (зээлсэн /V)
// бол тэр гарын үсгийг бүхэлд нь алгасна. Widget-ийн `/AP` → толь, `/N` → stream, `/Filter` алга эсвэл null (бусад —
// хоосон массив ч — алгасна); stream-ийн /Length байтын эхний ≤ 128 байт stampMarkerRe-ээр эхэлнэ. Хамгийн бага
// ByteRange[2] + ByteRange[3] (тэнцвэл Sig толины объектын дугаар бага) нь сонгогдоно. Алга → "". Задлах явцад
// алдаа гарвал (panic) аль хэдийн олдсоныг ч хаяж алдаа буцаана — Prepare PDF_INVALID (fail closed).
func docIDFromStamps(doc []byte, verified map[uint32]bool) (id string, err error) {
	defer func() {
		if r := recover(); r != nil {
			id, err = "", fmt.Errorf("PDF задлах: %v", r)
		}
	}()
	if len(verified) == 0 {
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
		sp := sig.GetPtr()
		// Шууд бус лавлагаа: шууд толь widget-ийн өөрийн ptr-тэй (extract.go-той ижил шалгалт).
		if sig.Kind() != pdf.Dict || sp.GetID() == x.Ptr().GetID() || !verified[sp.GetID()] {
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
		if ap.Kind() != pdf.Dict || n.Kind() != pdf.Stream || !n.Key("Filter").IsNull() {
			continue
		}
		head, _ := io.ReadAll(io.LimitReader(n.Reader(), stampMarkerMax))
		if sm := stampMarkerRe.FindSubmatch(head); sm != nil {
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
