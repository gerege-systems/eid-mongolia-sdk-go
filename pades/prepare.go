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

	eid "github.com/gerege-systems/eid-mongolia-sdk-go"
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
	// VerifyPagePosition — where the verify page goes when it is added: VerifyPageLast ("last"; default, also when
	// empty) or VerifyPageFirst ("first" — it becomes page 1). Only takes effect when the page is added (VerifyPage on
	// an unsigned document). Appearance.Page, SuggestPlacement and Placement.Page always count the pages of the input
	// document as given, never the added page (PAGE_SPEC.md §8a, PLACEMENT_SPEC.md §1b).
	VerifyPagePosition string `json:"verifyPagePosition,omitempty"`
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
	// Page — оролтын баримтын хуудас, 1-ээс (тодорхой дугаар — юуг ч алгасахгүй); 0 (анхдагч) = оролтын eID verify
	// хуудас БИШ сүүлийн хуудас: энэ Prepare-ийн нэмэх ба өмнөх revision-уудын нэмсэн verify хуудсууд тооцогдохгүй
	// (PLACEMENT_SPEC.md §1a).
	Page   int     `json:"page,omitempty"`
	X      float64 `json:"x"`
	Y      float64 `json:"y"`
	Width  float64 `json:"width"`
	Height float64 `json:"height"`
	// Lang — "mn" | "en"; хоосон бол PrepareOptions.Lang (тэр нь хоосон бол mn).
	Lang string `json:"lang,omitempty"`
	// Exact — draw the stamp exactly at Page/X/Y/Width/Height (a position the signer chose): never moved off page
	// content. Placement.Status is then "requested", or "overlap" when content is under the rect ("unscanned" when the
	// page cannot be scanned). false (default) = the rect is only the preferred spot (PLACEMENT_SPEC.md §6, §6a).
	Exact bool `json:"exact,omitempty"`
	// SignatureImage — the signer's handwritten-signature image (CA: GET /v3/person/etsi/{etsi}/signature-image) drawn
	// inside the stamp (APPEARANCE_SPEC.md §6). nil = none (byte-identical to golden v9).
	SignatureImage *PDFImage `json:"signatureImage,omitempty"`
	// StampImage — the organization's stamp image (CA: representations[].stampImage); only with
	// PrepareOptions.ClaimedRole (onBehalfOf), REQUEST_INVALID otherwise. The round stamp overlaps the box top-right and
	// sticks out above it — Width/Height are the whole widget rect (APPEARANCE_SPEC.md §6.3).
	StampImage *PDFImage `json:"stampImage,omitempty"`
}

// PDFImage — a "PDF image" as the CA serves it (APPEARANCE_SPEC.md §6.1): one ink colour + an 8-bit alpha channel.
// The SDK writes Alpha into the PDF verbatim (/SMask, /FlateDecode) — nothing is compressed at runtime.
type PDFImage struct {
	Width  int    `json:"width"`  // px, 1…1600
	Height int    `json:"height"` // px, 1…1600
	Color  [3]int `json:"color"`  // [r, g, b], 0…255
	// Alpha — zlib stream (RFC 1950, no preset dictionary, nothing after the Adler-32) inflating to exactly
	// Width·Height bytes, rows top-down, no PNG filter bytes; ≤ 300 KiB. JSON: base64.
	Alpha []byte `json:"alpha"`
	// SHA256 — lowercase hex SHA-256 of the PNG the CA stores; not written into the PDF, carried to the registration
	// (Completed.Images → POST /v3/pdf/signatures `images`).
	SHA256 string `json:"sha256"`
}

// Default stamp sizes (pt) when Appearance.Width and Height are both 0 (APPEARANCE_SPEC.md §6.3): without images, with a
// signature image, and with a stamp image (with or without a signature image; the height includes the stamp's overflow).
const (
	DefaultStampWidth, DefaultStampHeight                   = 220, 64
	DefaultSignatureStampWidth, DefaultSignatureStampHeight = 220, 110
	DefaultOrgStampWidth, DefaultOrgStampHeight             = 240, 147.5
)

// appearanceSize — Width/Height, or the default for the images when both are 0.
func appearanceSize(a *Appearance) (w, h float64) {
	if a.Width != 0 || a.Height != 0 {
		return a.Width, a.Height
	}
	switch {
	case a.StampImage != nil:
		return DefaultOrgStampWidth, DefaultOrgStampHeight
	case a.SignatureImage != nil:
		return DefaultSignatureStampWidth, DefaultSignatureStampHeight
	}
	return DefaultStampWidth, DefaultStampHeight
}

var sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (im *PDFImage) core() *core.PDFImage {
	if im == nil {
		return nil
	}
	return &core.PDFImage{W: im.Width, H: im.Height, Color: im.Color, Alpha: im.Alpha}
}

// PrepareOptions.VerifyPagePosition values.
const (
	VerifyPageLast  = "last"
	VerifyPageFirst = "first"
)

// Prepared — Prepare-ийн үр дүн.
type Prepared struct {
	DTBS   []byte // SHA-256(signedAttrs) — утас/токены зурах 32 байт
	Digest []byte // messageDigest = SHA-256(ByteRange)
	DocID  string
	State  []byte // тунгалаг, хадгалж болно (Complete-д буцааж өгнө)
	// Placement — where the visible stamp was drawn; nil without Appearance (PLACEMENT_SPEC.md).
	Placement *Placement
}

// Placement — the visible stamp's final rect (Appearance coordinates, pt) and how it was chosen. The stamp avoids
// existing page content (PLACEMENT_SPEC.md): Status "requested" = drawn at Appearance.X/Y; "moved" = that spot was
// occupied and the stamp moved to free space; "overlap" = no free spot (Exact: content under the rect), drawn at the
// requested spot over content; "unscanned" = the page could not be scanned within the limits, drawn at the requested
// spot. With Appearance.Exact the status is never "moved".
type Placement struct {
	Page   int     `json:"page"`
	X      float64 `json:"x"`
	Y      float64 `json:"y"`
	Width  float64 `json:"width"`
	Height float64 `json:"height"`
	Status string  `json:"status"`
}

// signingZone — /M ба хуудасны огнооны тогтмол бүс (Asia/Ulaanbaatar, DST-гүй).
var signingZone = time.FixedZone("+08", 8*3600)

// encryptKey — trailer / xref stream-ийн /Encrypt: лавлагаа (`N G R`) эсвэл шууд толь (`<<`); /EncryptMetadata биш.
var encryptKey = regexp.MustCompile(`/Encrypt(?:\s+\d+\s+\d+\s+R|\s*<<)`)

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
	if o.VerifyPagePosition != "" && o.VerifyPagePosition != VerifyPageLast && o.VerifyPagePosition != VerifyPageFirst {
		return nil, newErr(CodeRequestInvalid, "verifyPagePosition: last | first", nil)
	}
	if err := checkAppearance(o); err != nil {
		return nil, err
	}
	if a := o.Appearance; a != nil && a.StampImage != nil && o.ClaimedRole == "" {
		return nil, newErr(CodeRequestInvalid, "appearance: stampImage зөвхөн claimedRole (onBehalfOf)-той", nil)
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
		base, err = core.InsertVerifyPage(doc, core.PageData{
			Brand: pageBrand, FileName: fileName, DocumentHash: inHex, FileSize: int64(len(doc)), DocID: docID,
			VerifyURL: pageVerifyURL + docID, TrustURL: pageTrustURL, CAName: cert.Issuer.CommonName, TSAName: pageTSAName,
			Provider: pageProvider, Lang: o.Lang,
		}, o.VerifyPagePosition == VerifyPageFirst)
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
	var vis core.Visible
	if o.Appearance == nil {
		prep, err = core.PrepareSignatureWithReason(base, now, name, o.Reason)
	} else {
		if vis, err = visibleSpec(doc, o, name, now, docID, revIndex); err != nil {
			return nil, err
		}
		// vis.Page counts the input's pages; a verify page added in front shifts them by one in base (§1b).
		onBase := vis
		if hasPage && o.VerifyPagePosition == VerifyPageFirst {
			onBase.Page++
		}
		prep, err = core.PrepareSignatureVisible(base, now, name, o.Reason, onBase)
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
	if a := o.Appearance; a != nil {
		if a.SignatureImage != nil {
			st.Images = append(st.Images, eid.PDFSignatureImage{Kind: eid.PDFImageSignature, SHA256: a.SignatureImage.SHA256})
		}
		if a.StampImage != nil {
			st.Images = append(st.Images, eid.PDFSignatureImage{Kind: eid.PDFImageStamp, SHA256: a.StampImage.SHA256})
		}
	}
	for _, c := range chain {
		st.Chain = append(st.Chain, c.Raw)
	}
	state, err := st.encode()
	if err != nil {
		return nil, err
	}
	out := &Prepared{DTBS: core.DTBS(attrs), Digest: prep.Digest, DocID: docID, State: state}
	if pl := prep.Placement; pl != nil && o.Appearance != nil {
		out.Placement = &Placement{Page: vis.Page, X: float64(pl.X) / 100, Y: float64(pl.Y) / 100,
			Width: float64(vis.W) / 100, Height: float64(vis.H) / 100, Status: string(pl.Status)}
	}
	return out, nil
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
	for _, x := range []struct {
		name string
		im   *PDFImage
	}{{"signatureImage", a.SignatureImage}, {"stampImage", a.StampImage}} {
		if x.im == nil {
			continue
		}
		if !sha256Re.MatchString(x.im.SHA256) {
			return bad(x.name + ".sha256: жижиг hex SHA-256")
		}
		if err := core.CheckPDFImage(x.im.core()); err != nil {
			return bad(x.name + ": " + strings.TrimPrefix(err.Error(), "pades: харагдах гарын үсэг: зураг: "))
		}
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

// visibleSpec — Appearance → core.Visible: хуудас (0 → verify биш сүүлийн), h100, хэл, огноо, verify URL.
func visibleSpec(doc []byte, o PrepareOptions, name string, now time.Time, docID string, revIndex int) (core.Visible, error) {
	a := o.Appearance
	if docID == "" {
		return core.Visible{}, newErr(CodeRequestInvalid, "appearance: docId заавал (баримтад verify хуудас алга)", nil)
	}
	// page 0 / байхгүй = eID verify хуудас БИШ сүүлийн хуудас (PLACEMENT_SPEC §1a); тодорхой дугаар хэвээр.
	last, n, err := core.DefaultStampPage(doc, pageVerifyURL+docID)
	if err != nil {
		return core.Visible{}, newErr(CodePDFInvalid, "PDF задарсангүй", err)
	}
	page := a.Page
	if page == 0 {
		page = last
	}
	if page > n {
		return core.Visible{}, newErr(CodeRequestInvalid, fmt.Sprintf("appearance: page %d > хуудасны тоо %d", page, n), nil)
	}
	lang := cmp.Or(a.Lang, o.Lang, "mn")
	w, h := appearanceSize(a)
	return core.Visible{
		Page: page, X: core.Round100(a.X), Y: core.Round100(a.Y), W: core.Round100(w), H: core.Round100(h),
		Sig: a.SignatureImage.core(), Stamp: a.StampImage.core(),
		Name: strings.TrimSpace(name), Role: o.ClaimedRole, Lang: lang,
		Date:  now.Format("2006-01-02 15:04") + " (+08)",
		URL:   pageVerifyURL + docID + "/" + strconv.Itoa(revIndex),
		Avoid: true, Exact: a.Exact,
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
