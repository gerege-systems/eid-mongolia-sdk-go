package pades

import (
	"bytes"
	"cmp"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/digitorus/pdf"
	"golang.org/x/text/unicode/norm"

	"github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/core"
	"github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/eidcrypto"
	"github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/validate"
)

// Хэмжээний хязгаар — CA-тай ижил (validate.MaxPAdESInputBytes / MaxPDFBytes).
const (
	// MaxInputBytes — Prepare-ийн оролтын дээд хэмжээ (10 MiB − 256 KiB): хуудас + R_sig + R_dss-ийн дараа гаралт
	// MaxOutputBytes-д багтана.
	MaxInputBytes = validate.MaxPAdESInputBytes
	// MaxOutputBytes — гарын үсэгтэй гаралтын дээд хэмжээ (10 MiB).
	MaxOutputBytes = validate.MaxPDFBytes
	// MaxSignatures — нэг баримтын гарын үсгийн дээд тоо (CA-ийн 16-тай ижил).
	MaxSignatures = 16
	// maxFileName — баталгаажуулалтын хуудсанд харуулах нэрийн дээд урт (тэмдэгт).
	maxFileName = 120
)

// Баталгаажуулалтын хуудасны тогтмол утгууд (CA-ийн brandName/brandDomain, main.go-ийн VerifyBase/TrustURL,
// tsaDisplayName()-ийн анхдагч).
const (
	pageBrand     = "eID Mongolia"
	pageProvider  = "ca.eidmongolia.mn"
	pageVerifyURL = "https://ca.eidmongolia.mn/verify/"
	pageTrustURL  = "https://eidmongolia.mn/trust"
	pageTSAName   = "eID Mongolia TSA (tsa.timeserver.mn)"
)

// PrepareOptions — Prepare-ийн тохиргоо. JSON (binding) түлхүүр нь lowerCamelCase.
type PrepareOptions struct {
	// SignerCert — иргэний SIGN гэрчилгээний DER (signingCertificateV2-д заавал).
	SignerCert []byte `json:"signerCert"`
	// Chain — олгогч гинж DER (04, 03, 02); хоосон бол шигтгэсэн eID гинжээс SignerCert-ийн олгогчоор бүтээнэ.
	Chain [][]byte `json:"chain,omitempty"`
	// SignerName — /Name; хоосон бол гэрчилгээний GIVENNAME SURNAME (CA-тай ижил).
	SignerName string `json:"signerName,omitempty"`
	// Reason — /Reason (≤ 127 UTF-16 нэгж, эс бөгөөс бичигдэхгүй).
	Reason string `json:"reason,omitempty"`
	// ClaimedRole — CA-ийн төлөөллийн хариуны claimedRole; signedAttrs-ийн signer-attributes-v2-д орно.
	ClaimedRole string `json:"claimedRole,omitempty"`
	// SigningTime — /M; тэг бол одоо. Үргэлж +08:00 бүсээр бичигдэнэ (агшин хэвээр).
	SigningTime time.Time `json:"signingTime,omitempty"`
	// DocID — баримтын UUID (verify хуудас/QR); хоосон бол эхний гарын үсэгт шинээр үүсгэнэ.
	DocID string `json:"docId,omitempty"`
	// VerifyPage — баталгаажуулалтын (QR) хуудас нэмэх эсэх. Зөвхөн гарын үсэггүй баримтад (эхний eID гарын үсэг)
	// нэмэгдэнэ — гарын үсэгтэй баримтад хуудас нэмбэл өмнөх гарын үсгийг эвдэнэ (CA-ийн дүрэм).
	VerifyPage bool `json:"verifyPage,omitempty"`
	// FileName — баримтын нэр: хуудсанд (VerifyPage үед заавал) ба CA-ийн бүртгэлд (Completed.FileName); NFC, ≤ 120.
	FileName string `json:"fileName,omitempty"`
	// Lang — хуудасны хэл: "mn" (анхдагч, хоосон бол) | "en" (PAGE_SPEC.md §3a).
	Lang string `json:"lang,omitempty"`
	// Appearance — харагдах гарын үсэг (APPEARANCE_SPEC.md); nil бол үл харагдах (анхдагч, өмнөхтэй байт-ижил).
	Appearance *Appearance `json:"appearance,omitempty"`
}

// Appearance — харагдах гарын үсгийн байршил (APPEARANCE_SPEC.md §1). Координат нь pt, тухайн хуудасны CropBox
// (байхгүй бол MediaBox)-ийн /Rotate-ийн ДАРААХ (дэлгэцэнд харагдах) зүүн доод булангаас; x баруун тийш, y дээш.
// Утга бүр 0.01 pt хүртэл тойрогдоно.
type Appearance struct {
	// Page — оролтын баримтын хуудас, 1-ээс; 0 (анхдагч) = оролтын сүүлийн хуудас (энэ Prepare-ийн нэмэх verify
	// хуудас тооцогдохгүй).
	Page   int     `json:"page,omitempty"`
	X      float64 `json:"x"`
	Y      float64 `json:"y"`
	Width  float64 `json:"width"`
	Height float64 `json:"height"`
	// Lang — "mn" | "en"; хоосон бол PrepareOptions.Lang (тэр нь хоосон бол mn).
	Lang string `json:"lang,omitempty"`
}

// Prepared — Prepare-ийн үр дүн.
type Prepared struct {
	DTBS   []byte // SHA-256(signedAttrs) — утас/токены зурах 32 байт
	Digest []byte // messageDigest = SHA-256(ByteRange)
	DocID  string
	State  []byte // тунгалаг, хадгалж болно (Complete-д буцааж өгнө)
}

// signingZone — /M ба хуудасны огнооны тогтмол бүс (Asia/Ulaanbaatar, DST-гүй).
var signingZone = time.FixedZone("+08", 8*3600)

var encryptKey = regexp.MustCompile(`/Encrypt\s+\d+\s+\d+\s+R`)

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Prepare — PDF-д гарын үсгийн revision (placeholder) бичиж, иргэний зурах DTBS-ийг буцаана. PDF сүлжээ рүү гарахгүй.
func Prepare(doc []byte, o PrepareOptions) (*Prepared, error) {
	if len(doc) > MaxInputBytes {
		return nil, newErr(CodePDFTooLarge, "PDF 9.75 MB-аас их байна", nil)
	}
	if !bytes.HasPrefix(doc, []byte("%PDF-")) {
		return nil, newErr(CodePDFInvalid, "PDF биш эсвэл эвдэрсэн", nil)
	}
	if err := validate.CheckStructure(doc); err != nil {
		return nil, newErr(CodePDFInvalid, "PDF-ийн бүтэц хэт гүн эсвэл төвөгтэй", err)
	}
	cert, err := x509.ParseCertificate(o.SignerCert)
	if err != nil {
		return nil, newErr(CodeSignerInvalid, "signerCert задарсангүй", err)
	}
	if _, err := core.SignatureAlgorithmFor(cert); err != nil {
		return nil, newErr(CodeSignerInvalid, "гэрчилгээний түлхүүрийн төрөл дэмжигдэхгүй", err)
	}
	chain, err := signerChain(cert, o.Chain)
	if err != nil {
		return nil, newErr(CodeSignerInvalid, "олгогч гинж", err)
	}
	if o.DocID != "" && !uuidRe.MatchString(o.DocID) {
		return nil, newErr(CodeRequestInvalid, "docId нь жижиг үсгийн UUID байх ёстой", nil)
	}
	if o.Lang != "" && o.Lang != "mn" && o.Lang != "en" {
		return nil, newErr(CodeRequestInvalid, "lang: mn | en", nil)
	}
	if err := checkAppearance(o); err != nil {
		return nil, err
	}
	now := o.SigningTime
	if now.IsZero() {
		now = time.Now()
	}
	// /M ба хуудасны огноо цагийн бүсийг хэвлэдэг — wrapper/төхөөрөмжийн time.Local-оос үл хамааран ижил агшин ижил
	// DTBS өгөхийн тулд үргэлж +08:00 (docs/PADES_CLIENT_SIDE.md §5; LoadLocation биш — WASM/мобайлд tzdata алга).
	now = now.In(signingZone)

	inSum := sha256.Sum256(doc)
	inHex := hex.EncodeToString(inSum[:])
	newDoc, revIndex, err := precheck(doc, append(eidcrypto.Issuers(), chain[0]))
	if err != nil {
		return nil, err
	}
	docID := o.DocID
	base, pageHex := doc, ""
	hasPage := newDoc && o.VerifyPage
	fileName, fileOK := cleanFileName(o.FileName)
	if !newDoc {
		// Эхний eID гарын үсгийн хуудаснаас (CA: бүртгэлээс; DOC_ID_MISMATCH).
		if fromPage := docIDFromPage(doc); fromPage != "" {
			if docID != "" && docID != fromPage {
				return nil, newErr(CodeRequestInvalid, "docId нь баримтын хуудсан дээрхтэй таарахгүй", nil)
			}
			docID = fromPage
		}
	}
	if newDoc && docID == "" {
		if docID, err = randUUID(); err != nil {
			return nil, err
		}
	}
	if hasPage {
		if !fileOK {
			return nil, newErr(CodeRequestInvalid, "fileName заавал, ≤ 120 тэмдэгт", nil)
		}
		base, err = core.AppendVerifyPage(doc, core.PageData{
			Brand: pageBrand, FileName: fileName, DocumentHash: inHex, FileSize: int64(len(doc)), DocID: docID,
			VerifyURL: pageVerifyURL + docID, TrustURL: pageTrustURL, CAName: cert.Issuer.CommonName, TSAName: pageTSAName,
			Provider: pageProvider, Lang: o.Lang,
		})
		if err != nil {
			return nil, newErr(CodePDFInvalid, "PDF задарсангүй (хуудас нэмж чадсангүй)", err)
		}
		ps := sha256.Sum256(base)
		pageHex = hex.EncodeToString(ps[:])
	}
	name := o.SignerName
	if strings.TrimSpace(name) == "" {
		name = core.SignerDisplayName(cert)
	}
	var prep *core.Prepared
	if o.Appearance == nil {
		prep, err = core.PrepareSignatureWithReason(base, now, name, o.Reason)
	} else {
		var vis core.Visible
		if vis, err = visibleSpec(doc, o, name, now, docID, revIndex); err != nil {
			return nil, err
		}
		prep, err = core.PrepareSignatureVisible(base, now, name, o.Reason, vis)
		if errors.Is(err, core.ErrAppearance) {
			return nil, newErr(CodeRequestInvalid, "appearance: "+strings.TrimPrefix(err.Error(), "pades: "), err)
		}
	}
	if err != nil {
		return nil, newErr(CodePDFInvalid, "PDF-д гарын үсгийн revision бичиж чадсангүй", err)
	}
	if len(prep.PDF)+(256<<10) > MaxOutputBytes {
		return nil, newErr(CodePDFTooLarge, "гарын үсэгтэй гаралт 10 MB-аас хэтэрнэ", nil)
	}
	attrs, err := core.SignedAttributesWithRole(prep.Digest, cert, o.ClaimedRole)
	if err != nil {
		return nil, newErr(CodeRequestInvalid, "claimedRole", err)
	}
	st := &prepState{DocID: docID, SignerCert: cert.Raw, SignedAttrs: attrs, ByteRange: prep.ByteRange, RevIndex: revIndex,
		InSHA256: inHex, HasPage: hasPage, PageSHA256: pageHex, ClaimedRole: o.ClaimedRole, FileName: fileName, PDF: prep.PDF, PreparedSHA256: sha256Hex(prep.PDF)}
	for _, c := range chain {
		st.Chain = append(st.Chain, c.Raw)
	}
	state, err := st.encode()
	if err != nil {
		return nil, err
	}
	return &Prepared{DTBS: core.DTBS(attrs), Digest: prep.Digest, DocID: docID, State: state}, nil
}

// checkAppearance — Appearance-ийн PDF-ээс үл хамаарах шалгалт (APPEARANCE_SPEC.md §1).
func checkAppearance(o PrepareOptions) error {
	a := o.Appearance
	if a == nil {
		return nil
	}
	bad := func(msg string) error { return newErr(CodeRequestInvalid, "appearance: "+msg, nil) }
	for _, v := range []float64{a.X, a.Y, a.Width, a.Height} {
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > 14400 {
			return bad("x, y, width, height нь 0…14400 pt")
		}
	}
	if a.Page < 0 {
		return bad("page ≥ 0")
	}
	if a.Lang != "" && a.Lang != "mn" && a.Lang != "en" {
		return bad("lang: mn | en")
	}
	if o.ClaimedRole != "" && !roleText(o.ClaimedRole) {
		return bad("claimedRole-д удирдах тэмдэгт")
	}
	return nil
}

// roleText — validator-ийн validClaimedRole-тэй ижил (харагдах дүрслэлийг validator claimedRole-оос дахин үүсгэнэ).
func roleText(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return false
		}
	}
	return utf8.ValidString(s)
}

// visibleSpec — Appearance → core.Visible: хуудас (0 → оролтын сүүлийн), h100, хэл, огноо, verify URL.
func visibleSpec(doc []byte, o PrepareOptions, name string, now time.Time, docID string, revIndex int) (core.Visible, error) {
	a := o.Appearance
	if docID == "" {
		return core.Visible{}, newErr(CodeRequestInvalid, "appearance: docId заавал (баримтад verify хуудас алга)", nil)
	}
	n, err := core.PageCount(doc)
	if err != nil {
		return core.Visible{}, newErr(CodePDFInvalid, "PDF задарсангүй", err)
	}
	page := a.Page
	if page == 0 {
		page = n
	}
	if page > n {
		return core.Visible{}, newErr(CodeRequestInvalid, fmt.Sprintf("appearance: page %d > хуудасны тоо %d", page, n), nil)
	}
	lang := cmp.Or(a.Lang, o.Lang, "mn")
	return core.Visible{
		Page: page, X: core.Round100(a.X), Y: core.Round100(a.Y), W: core.Round100(a.Width), H: core.Round100(a.Height),
		Name: strings.TrimSpace(name), Role: o.ClaimedRole, Lang: lang,
		Date: now.Format("2006-01-02 15:04") + " (+08)",
		URL:  pageVerifyURL + docID + "/" + strconv.Itoa(revIndex),
	}, nil
}

// encrypted — trailer-д /Encrypt (digitorus panic-ийг recover).
func encrypted(doc []byte) (enc bool) {
	defer func() {
		if recover() != nil {
			enc = false
		}
	}()
	r, err := pdf.NewReader(bytes.NewReader(doc), int64(len(doc)))
	if err != nil {
		// digitorus нь зарим шифрлэлтийг (AES-256) нээж чадахгүй — trailer/xref stream-ийн /Encrypt түлхүүрээр.
		return encryptKey.Match(doc)
	}
	return !r.Trailer().Key("Encrypt").IsNull()
}

// cleanFileName — CA-тай ижил: Cc/Cf/Zl/Zp хасаж NFC, trim; ≤ 120 тэмдэгт.
func cleanFileName(s string) (string, bool) {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) || r == utf8.RuneError {
			continue
		}
		b.WriteRune(r)
	}
	out := strings.TrimSpace(norm.NFC.String(b.String()))
	if out == "" || utf8.RuneCountInString(out) > maxFileName {
		return "", false
	}
	return out, true
}

func randUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("pades: uuid: %w", err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
