package pades

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"regexp"
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
	// FileName — хуудсанд харуулах баримтын нэр (VerifyPage үед заавал; NFC, ≤ 120 тэмдэгт).
	FileName string `json:"fileName,omitempty"`
	// Lang — хуудасны хэл (mn|en). Одоогоор CA-ийн хуудастай байт-ижил байхын тулд зөвхөн англи бичвэр.
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
		fileName, ok := cleanFileName(o.FileName)
		if !ok {
			return nil, newErr(CodeRequestInvalid, "fileName заавал, ≤ 120 тэмдэгт", nil)
		}
		base, err = core.AppendVerifyPage(doc, core.PageData{
			Brand: pageBrand, FileName: fileName, DocumentHash: inHex, FileSize: int64(len(doc)), DocID: docID,
			VerifyURL: pageVerifyURL + docID, TrustURL: pageTrustURL, CAName: cert.Issuer.CommonName, TSAName: pageTSAName,
			Provider: pageProvider,
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
	prep, err := core.PrepareSignatureWithReason(base, now, name, o.Reason)
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
		InSHA256: inHex, HasPage: hasPage, PageSHA256: pageHex, ClaimedRole: o.ClaimedRole, PDF: prep.PDF, PreparedSHA256: sha256Hex(prep.PDF)}
	for _, c := range chain {
		st.Chain = append(st.Chain, c.Raw)
	}
	state, err := st.encode()
	if err != nil {
		return nil, err
	}
	return &Prepared{DTBS: core.DTBS(attrs), Digest: prep.Digest, DocID: docID, State: state}, nil
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
