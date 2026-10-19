package validate

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Задлах үе шат (hostile оролт). digitorus/pdf нь дайсагнасан PDF-д зориулагдаагүй: гүн
// давхарлалт → stack overflow (recover барихгүй, процесс унана), /Extends гогцоо → мөнхийн
// давталт, /Size → гигабайтын хуваарилалт. Тиймээс Extract-ийг prod-д ЗӨВХӨН тусдаа,
// хугацаа/санах ойн хязгаартай дэд процесс дотор ажиллуулна (worker.go). Энэ үе шат итгэлийн
// шийдвэр ГАРГАХГҮЙ — зөвхөн баримтаас баримт (байт, гэрчилгээ, криптограф таарсан эсэх)-ыг
// гаргаж, эцэг процесс (Evaluate) дүгнэнэ.

// MaxPDFBytes — PDF-ийн дээд хэмжээ (nginx client_max_body_size 12m-ээс бага).
const MaxPDFBytes = 10 << 20

// MaxPAdESInputBytes — PAdES prepare-ийн оролтын дээд хэмжээ (10 MiB − 256 KiB = 10 223 616): хуудас + R_sig +
// R_dss-ийн өсөлтийн дараа гаралт MaxPDFBytes-д багтаж, нийтийн шалгагч ба дараагийн prepare хүлээн авна
// (docs/PADES_SIGNING.md §3.5). /.well-known/eid pdfSigning.maxInputBytes, prepare, хуудасны хязгаар нэг эх.
const MaxPAdESInputBytes = MaxPDFBytes - 256<<10

// maxSignatures — нэг баримт дахь гарын үсгийн дээд тоо (хуваалцсан /Contents-тэй олон dict-ээр
// ажлыг үржүүлэхээс хамгаална).
const maxSignatures = 16

// encryptRef — trailer / xref stream-ийн /Encrypt лавлагаа (pades.encrypted-тэй ижил).
var encryptRef = regexp.MustCompile(`/Encrypt\s+\d+\s+\d+\s+R`)

var (
	ErrNoSignature   = errors.New("баримтад цахим гарын үсэг алга")
	ErrNotPDF        = errors.New("PDF файл задарсангүй")
	ErrEncrypted     = errors.New("шифрлэгдсэн PDF-ийг шалгах боломжгүй — нууцлалыг арилгаад дахин оролдоно уу")
	ErrNotCert       = errors.New("X.509 гэрчилгээ задарсангүй")
	ErrTooMany       = errors.New("баримтад хэт олон гарын үсэг байна")
	ErrUnprocessable = errors.New("баримтыг задалж чадсангүй")
)

// RawSignature — нэг гарын үсгээс задалсан баримт (worker → эцэг процесс, JSON).
type RawSignature struct {
	SignerName  string     `json:"signer_name"`
	Reason      string     `json:"reason"`
	Location    string     `json:"location"`
	ClaimedTime *time.Time `json:"claimed_time,omitempty"`
	// Malformed — бүтэц эвдэрсэн (ByteRange, Contents, PKCS#7). Бусад талбар хоосон байж болно.
	Malformed bool `json:"malformed"`
	// Integrity — PKCS#7 гарын үсэг ByteRange-ийн байтуудтай таарсан.
	Integrity   bool `json:"integrity"`
	WeakDigest  bool `json:"weak_digest"`
	CoversWhole bool `json:"covers_whole"`
	// CoversWhole == false үед: гарын үсгийн мужийн ДАРАА нэмэгдсэн revision-уудын ангилал
	// (revisions.go). LaterSignaturesOnly — ялгаа бүр гарын үсэг/LTV-ийн зөвшөөрөгдсөн жагсаалтад багтсан.
	LaterSignaturesOnly bool `json:"later_signatures_only"`
	LaterSignatures     int  `json:"later_signatures"`
	LaterVisible        bool `json:"later_visible"`
	// Visible — энэ гарын үсгийн талбар/widget (/V → энэ толь) хоосон биш /Rect эсвэл /AP-тэй (хуудсан дээр харагдана).
	Visible bool `json:"visible"`
	// SignedEnd — ByteRange[2]+ByteRange[3]: гарын үсгийн revision-ийн төгсгөл (задарсан үед). Эцэг процесс
	// doc[:SignedEnd]-ийн sha256-г ӨӨРӨӨ тооцно (ValidatePDF) — worker hash өгөхгүй.
	SignedEnd int64   `json:"signed_end,omitempty"`
	objNum    int     // гарын үсгийн толийн объектын дугаар
	byteRange []int64 // задарсан (Malformed биш) үед
	// Leaf — гарын үсэг зурсан гэрчилгээ; Certs — PKCS#7-д суулгасан бусад гэрчилгээ (DER).
	Leaf      []byte        `json:"leaf,omitempty"`
	Certs     [][]byte      `json:"certs,omitempty"`
	Timestamp *RawTimestamp `json:"timestamp,omitempty"`
	// SubFilter — Sig толийн /SubFilter (adbe.pkcs7.detached | ETSI.CAdES.detached | …).
	SubFilter string `json:"sub_filter,omitempty"`
	// SigningCertV2 — signedAttrs-ийн signingCertificateV2: "" (байхгүй), "match" (certHash = SHA-256(leaf),
	// issuerSerial байвал leaf-тэй таарсан), "mismatch" (задарсан ч таарахгүй / задарсангүй).
	SigningCertV2 string `json:"signing_cert_v2,omitempty"`
	// SigningTimeAttr — signedAttrs-д signingTime байгаа (PAdES baseline-д хориотой).
	SigningTimeAttr bool `json:"signing_time_attr,omitempty"`
	// ClaimedRoles — signedAttrs-ийн signer-attributes-v2 claimedAttributes-ийн тэмдэгт мөр утгууд (гарын үсэг
	// зурагчийн мэдүүлсэн үүрэг; байгууллагын нэрийн өмнөөс гарын үсэгт «<албан тушаал>, <нэр> (NTRMN-…)»).
	ClaimedRoles []string `json:"claimed_roles,omitempty"`
	// CMSSHA256 — /Contents-ийн CMS DER-ийн (тэг дүүргэлтгүй, ASN.1 уртаар) sha256 (жижиг hex); MessageDigest —
	// signedAttrs-ийн messageDigest (hex). SDK: CA-ийн бүртгэл (POST /pdf/signatures, docs/PADES_CLIENT_SIDE.md §4.3,
	// §10) ба өмнөх гарын үсгийн priorCmsSha256-д.
	CMSSHA256     string `json:"cms_sha256,omitempty"`
	MessageDigest string `json:"message_digest,omitempty"`
	// DSS — баримтын (эцсийн Catalog-ийн) /DSS-ийн LTV өгөгдөл; гарын үсэг бүрд ижил заагч (баримтын түвшин).
	DSS *RawDSS `json:"dss,omitempty"`
}

// RawDSS — /DSS-ийн /Certs /OCSPs /CRLs stream-уудын тайлсан байт (итгэлийн шийдвэргүй — эцэг процесс).
type RawDSS struct {
	Certs [][]byte `json:"certs,omitempty"`
	OCSPs [][]byte `json:"ocsps,omitempty"`
	CRLs  [][]byte `json:"crls,omitempty"`
}

// RawTimestamp — RFC 3161 токен. Matches — messageImprint нь гарын үсгийн утгын hash-тай таарсан
// БӨГӨӨД токены гарын үсэг TSA-ийн гэрчилгээгээр батлагдсан.
type RawTimestamp struct {
	Time       time.Time `json:"time"`
	Serial     string    `json:"serial"`
	Matches    bool      `json:"matches"`
	WeakDigest bool      `json:"weak_digest"`
	TSACert    []byte    `json:"tsa_cert,omitempty"`
	Certs      [][]byte  `json:"certs,omitempty"`
}

// Extract — PDF-ийн бүх /Type /Sig гарын үсгийг задална. ЗӨВХӨН worker дотор дууд (дээрхийг үз).
func Extract(doc []byte) ([]RawSignature, error) { return extractWith(doc, profileOwnSigner) }

// extractWith — Extract-ийн бие. p нь revision-ийн ангилагчийн горим: prod-д ҮРГЭЛЖ profileOwnSigner
// (Extract); profileBroad-ийг зөвхөн тест дуудна.
func extractWith(doc []byte, p profile) (sigs []RawSignature, err error) {
	defer func() {
		if r := recover(); r != nil {
			sigs, err = nil, ErrNotPDF
		}
		if CorpusHook != nil && err != nil {
			CorpusHook(doc, p == profileBroad, nil, nil, "", err)
		}
	}()
	// digitorus-ийн рекурс хязгааргүй — гүн давхарласан баримт stack overflow (recover барихгүй) өгнө.
	if err := CheckStructure(doc); err != nil {
		return nil, err
	}
	rdr, err := pdf.NewReader(bytes.NewReader(doc), int64(len(doc)))
	if err != nil {
		// digitorus нь AES-256 / хэрэглэгчийн нууц үгтэй баримтыг нээхгүй — trailer/xref stream-ийн /Encrypt түлхүүрээр.
		if encryptRef.Match(doc) {
			return nil, ErrEncrypted
		}
		return nil, ErrNotPDF
	}
	// /Encrypt: digitorus RC4-д /Contents-ийг (спекээр шифрлэгддэггүй) тайлж эвддэг, AES-128-д panic хийдэг тул
	// шифрлэгдсэн баримтыг ямар ч хувилбарт шалгахгүй (CA, TS SDK-тэй ижил). Keys — /Encrypt толийг resolve хийхгүй
	// (AES-д O/U string-ийг тайлах гэж panic хийнэ).
	if slices.Contains(rdr.Trailer().Keys(), "Encrypt") {
		return nil, ErrEncrypted
	}
	visible := map[uint32]bool{} // Sig толийн дугаар → widget харагдах
	docID := ""
	for _, x := range rdr.Xref() {
		obj := rdr.Resolve(x.Ptr(), x.Ptr())
		if obj.Kind() != pdf.Dict {
			continue
		}
		if obj.Key("FT").Name() == "Sig" && obj.Key("V").Kind() == pdf.Dict {
			vp, xp := obj.Key("V").GetPtr(), x.Ptr()
			if vp.GetID() != xp.GetID() {
				visible[vp.GetID()] = visible[vp.GetID()] || widgetVisible(obj)
			}
		}
		if u := obj.Key("A").Key("URI").RawString(); docID == "" && obj.Key("Subtype").Name() == "Link" {
			if rest, ok := strings.CutPrefix(u, apVerifyPrefix); ok && uuidRe.MatchString(rest) {
				docID = rest // verify хуудасны холбоос (PRECHECKS.md: эхнийх)
			}
		}
		if obj.Key("Contents").IsNull() || obj.Key("ByteRange").IsNull() {
			continue
		}
		// DocTimeStamp (PAdES-LTA) нь өөр бүтэцтэй (TSTInfo-г гарын үсэг гэж шалгавал худлаа
		// «хүчингүй» гарна) — одоохондоо алгасна.
		if t := obj.Key("Type").Name(); t != "" && t != "Sig" {
			continue
		}
		if len(sigs) == maxSignatures {
			return nil, ErrTooMany
		}
		s := extractSignature(doc, obj)
		ptr := x.Ptr()
		s.objNum = int(ptr.GetID())
		sigs = append(sigs, s)
	}
	if len(sigs) == 0 {
		return nil, ErrNoSignature
	}
	for i := range sigs {
		sigs[i].Visible = visible[uint32(sigs[i].objNum)] // #nosec G115 -- xref-ийн дугаар
	}
	if dss := extractDSS(rdr.Trailer().Key("Root").Key("DSS")); dss != nil {
		for i := range sigs {
			sigs[i].DSS = dss
		}
	}
	// Задарч, доорх шалгалтад орсон гарын үсгүүд: revision-ийн ангилагч «дараагийн гарын үсэг» гэж зөвхөн
	// эдгээрийг л тооцно (алгассан DocTimeStamp, бүтэц эвдэрсэн толь тооцогдохгүй).
	known := map[int][]int64{}
	metas := map[int]sigMeta{}
	for _, s := range sigs {
		if !s.Malformed {
			known[s.objNum] = s.byteRange
			metas[s.objNum] = sigMeta{revIndex: 1, roleOK: len(s.ClaimedRoles) <= 1}
		}
	}
	for num, m := range metas {
		for _, s := range sigs {
			if !s.Malformed && s.SignedEnd < known[num][2]+known[num][3] {
				m.revIndex++
			}
			if s.objNum == num && len(s.ClaimedRoles) == 1 {
				m.role = s.ClaimedRoles[0]
			}
		}
		metas[num] = m
	}
	var revs *revisions
	for i := range sigs {
		if s := &sigs[i]; !s.Malformed && !s.CoversWhole {
			if revs == nil {
				revs = newRevisions(doc, known, p)
				revs.sigs, revs.docID = metas, docID
			}
			later := revs.later(s.SignedEnd)
			s.LaterSignaturesOnly, s.LaterSignatures, s.LaterVisible = later.SignaturesOnly, later.Signatures, later.Visible
		}
	}
	if CorpusHook != nil {
		m := make(map[int]SigMeta, len(metas))
		for k, v := range metas {
			m[k] = SigMeta{RevIndex: v.revIndex, Role: v.role, RoleOK: v.roleOK}
		}
		CorpusHook(doc, p == profileBroad, sigs, m, docID, nil)
	}
	return sigs, nil
}

// CorpusHook — ЗӨВХӨН тест: extractWith-ийн оролт/гаралтыг differential corpus-д (TS SDK-ийн validatePdf-ийн порт
// Go-той ижил дүгнэлт гаргаж байгааг тулгах) бичнэ. Prod-д nil.
var CorpusHook func(doc []byte, broad bool, sigs []RawSignature, metas map[int]SigMeta, docID string, err error)

// SigMeta — CorpusHook-д: гарын үсгийн харагдах дүрслэлийн өгөгдөл (sigMeta-ийн экспортолсон хуулбар).
type SigMeta struct {
	RevIndex int    `json:"revIndex"`
	Role     string `json:"role"`
	RoleOK   bool   `json:"roleOK"`
}

// ObjNum / ByteRange — CorpusHook-д: экспортлогдоогүй талбарууд.
func (s RawSignature) ObjNum() int        { return s.objNum }
func (s RawSignature) ByteRange() []int64 { return s.byteRange }

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// widgetVisible — гарын үсгийн widget хуудсан дээр харагдах эсэх: /AP-тэй эсвэл /Rect-ийн өргөн, өндөр хоёулаа 0 биш.
func widgetVisible(w pdf.Value) bool {
	if !w.Key("AP").IsNull() {
		return true
	}
	r := w.Key("Rect")
	if r.Kind() != pdf.Array || r.Len() != 4 {
		return false
	}
	return r.Index(0).Float64() != r.Index(2).Float64() && r.Index(1).Float64() != r.Index(3).Float64()
}

func extractSignature(doc []byte, obj pdf.Value) RawSignature {
	s := RawSignature{
		SignerName: obj.Key("Name").Text(),
		Reason:     obj.Key("Reason").Text(),
		Location:   obj.Key("Location").Text(),
	}
	if m := obj.Key("M"); !m.IsNull() {
		if t, err := parsePDFDate(m.Text()); err == nil {
			s.ClaimedTime = &t
		}
	}
	contents := []byte(obj.Key("Contents").RawString())
	br := byteRange(obj.Key("ByteRange"))
	signed, whole, ok := signedBytes(doc, br, contents)
	if !ok {
		s.Malformed = true
		return s
	}
	s.CoversWhole, s.SignedEnd, s.byteRange = whole, br[2]+br[3], br
	s.SubFilter = obj.Key("SubFilter").Name()

	p7, err := pkcs7.Parse(contents)
	if err != nil || len(p7.Signers) != 1 {
		s.Malformed = true
		return s
	}
	leaf := p7.GetOnlySigner()
	if leaf == nil {
		s.Malformed = true
		return s
	}
	s.Leaf = leaf.Raw
	if der, ok := cmsDER(contents); ok {
		sum := sha256.Sum256(der)
		s.CMSSHA256 = hex.EncodeToString(sum[:])
	}
	attrs := make([]rawAttr, 0, len(p7.Signers[0].AuthenticatedAttributes))
	for _, a := range p7.Signers[0].AuthenticatedAttributes {
		attrs = append(attrs, rawAttr{Type: a.Type, Value: a.Value})
	}
	s.SigningCertV2, s.SigningTimeAttr = signedAttrChecks(attrs, leaf)
	s.ClaimedRoles = claimedRoles(attrs)
	for _, a := range attrs {
		var md []byte
		if a.Type.Equal(oidAttrMessageDigest) {
			if _, err := asn1.Unmarshal(a.Value.Bytes, &md); err == nil {
				s.MessageDigest = hex.EncodeToString(md)
			}
		}
	}
	for _, c := range p7.Certificates {
		if !c.Equal(leaf) {
			s.Certs = append(s.Certs, c.Raw)
		}
	}
	s.WeakDigest = !strongDigestOID(p7.Signers[0].DigestAlgorithm.Algorithm)
	p7.Content = signed
	s.Integrity = p7.Verify() == nil
	s.Timestamp = extractTimestamp(p7)
	return s
}

var oidAttrMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}

// cmsDER — /Contents-ийн эхний ASN.1 элемент (placeholder-ийн тэг дүүргэлтгүй CMS).
func cmsDER(contents []byte) ([]byte, bool) {
	in := cryptobyte.String(contents)
	var el cryptobyte.String
	if !in.ReadASN1Element(&el, cbasn1.SEQUENCE) {
		return nil, false
	}
	return el, true
}

var oidTimeStampToken = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}

func extractTimestamp(p7 *pkcs7.PKCS7) *RawTimestamp {
	si := p7.Signers[0]
	for _, attr := range si.UnauthenticatedAttributes {
		if !attr.Type.Equal(oidTimeStampToken) {
			continue
		}
		out := &RawTimestamp{}
		// timestamp.Parse нь токены PKCS#7 гарын үсгийг (гэрчилгээ суулгасан үед) шалгана.
		ts, err := timestamp.Parse(attr.Value.Bytes)
		if err != nil {
			return out
		}
		out.Time = ts.Time.UTC()
		out.Serial = hexSerial(ts.SerialNumber)
		tsp, err := pkcs7.Parse(attr.Value.Bytes)
		if err != nil || len(tsp.Signers) != 1 {
			return out
		}
		tsa := tsp.GetOnlySigner()
		if tsa == nil {
			return out
		}
		out.TSACert = tsa.Raw
		for _, c := range tsp.Certificates {
			if !c.Equal(tsa) {
				out.Certs = append(out.Certs, c.Raw)
			}
		}
		out.WeakDigest = !strongDigestOID(tsp.Signers[0].DigestAlgorithm.Algorithm) || !strongHash(ts.HashAlgorithm)
		if !ts.HashAlgorithm.Available() {
			return out
		}
		h := ts.HashAlgorithm.New()
		h.Write(si.EncryptedDigest)
		out.Matches = bytes.Equal(h.Sum(nil), ts.HashedMessage)
		return out
	}
	return nil
}

var strongDigests = []asn1.ObjectIdentifier{
	{2, 16, 840, 1, 101, 3, 4, 2, 1}, // SHA-256
	{2, 16, 840, 1, 101, 3, 4, 2, 2}, // SHA-384
	{2, 16, 840, 1, 101, 3, 4, 2, 3}, // SHA-512
}

func strongDigestOID(o asn1.ObjectIdentifier) bool {
	for _, s := range strongDigests {
		if o.Equal(s) {
			return true
		}
	}
	return false
}

func strongHash(h crypto.Hash) bool {
	return h == crypto.SHA256 || h == crypto.SHA384 || h == crypto.SHA512
}

// signedBytes — ByteRange [0 a b c]-ийн хамарсан байтууд. Хоёр мужийн хоорондох зай нь ЗӨВХӨН энэ
// dict-ийн /Contents-ийн <hex> байх ёстой (өөр объект эсвэл харагдах текстийг гарын үсгийн гадна
// нуухаас хамгаална). whole — мужууд файлыг төгсгөл хүртэл хамарсан эсэх.
func signedBytes(doc []byte, br []int64, contents []byte) (signed []byte, whole, ok bool) {
	if len(br) != 4 {
		return nil, false, false
	}
	n := int64(len(doc))
	a0, l0, a1, l1 := br[0], br[1], br[2], br[3]
	if a0 != 0 || l0 <= 0 || l1 < 0 || a1 <= l0 || a1 > n || l1 > n-a1 {
		return nil, false, false
	}
	gap := doc[l0:a1]
	if len(gap) < 2 || gap[0] != '<' || gap[len(gap)-1] != '>' {
		return nil, false, false
	}
	raw, err := hex.DecodeString(string(gap[1 : len(gap)-1]))
	if err != nil || !bytes.Equal(raw, contents) {
		return nil, false, false
	}
	out := make([]byte, 0, l0+l1)
	out = append(out, doc[:l0]...)
	out = append(out, doc[a1:a1+l1]...)
	return out, a1+l1 == n, true
}

func byteRange(v pdf.Value) []int64 {
	if v.Kind() != pdf.Array || v.Len() != 4 {
		return nil
	}
	out := make([]int64, 0, 4)
	for i := 0; i < 4; i++ {
		if v.Index(i).Kind() != pdf.Integer {
			return nil
		}
		out = append(out, v.Index(i).Int64())
	}
	return out
}

// parsePDFDate — PDF огноо "D:YYYYMMDDHHmmSS+HH'mm'".
func parsePDFDate(s string) (time.Time, error) {
	s = strings.TrimPrefix(s, "D:")
	s = strings.ReplaceAll(s, "'", "")
	for _, layout := range []string{"20060102150405-0700", "20060102150405Z0700", "20060102150405Z", "20060102150405"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("pdf date %q", s)
}

func parseCerts(ders [][]byte) []*x509.Certificate {
	out := make([]*x509.Certificate, 0, len(ders))
	for _, d := range ders {
		if c, err := x509.ParseCertificate(d); err == nil {
			out = append(out, c)
		}
	}
	return out
}

var (
	oidSigningCertV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
	oidSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
)

// essCertIDv2 — RFC 5035 ESSCertIDv2 (hashAlgorithm анхдагч SHA-256).
type essCertIDv2 struct {
	HashAlgorithm pkix.AlgorithmIdentifier `asn1:"optional"`
	CertHash      []byte
	IssuerSerial  struct {
		Issuer asn1.RawValue
		Serial *big.Int
	} `asn1:"optional"`
}

// signedAttrChecks — signingCertificateV2 нь leaf-тэй таарах эсэх, signingTime байгаа эсэх.
// rawAttr — pkcs7-ийн экспортлогдоогүй attribute-ийн хуулбар.
type rawAttr struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue
}

func signedAttrChecks(attrs []rawAttr, leaf *x509.Certificate) (certV2 string, signingTime bool) {
	for _, a := range attrs {
		switch {
		case a.Type.Equal(oidSigningTime):
			signingTime = true
		case a.Type.Equal(oidSigningCertV2):
			if certV2 != "" {
				certV2 = "mismatch" // давхар
				continue
			}
			certV2 = "mismatch"
			var sc struct{ Certs []essCertIDv2 }
			if rest, err := asn1.Unmarshal(a.Value.Bytes, &sc); err != nil || len(rest) != 0 || len(sc.Certs) == 0 {
				continue
			}
			id := sc.Certs[0]
			h := crypto.SHA256
			if len(id.HashAlgorithm.Algorithm) > 0 {
				switch {
				case id.HashAlgorithm.Algorithm.Equal(strongDigests[0]):
				case id.HashAlgorithm.Algorithm.Equal(strongDigests[1]):
					h = crypto.SHA384
				case id.HashAlgorithm.Algorithm.Equal(strongDigests[2]):
					h = crypto.SHA512
				default:
					continue
				}
			}
			sum := h.New()
			sum.Write(leaf.Raw)
			if !bytes.Equal(sum.Sum(nil), id.CertHash) {
				continue
			}
			if id.IssuerSerial.Serial != nil && id.IssuerSerial.Serial.Cmp(leaf.SerialNumber) != 0 {
				continue
			}
			certV2 = "match"
		}
	}
	return certV2, signingTime
}

// Мэдүүлсэн үүргийн задлалтын хязгаар (дайсагнасан оролт): утгын тоо ба тэмдэгтийн урт.
const (
	maxClaimedRoles     = 4
	maxClaimedRoleRunes = 900
)

var (
	oidSignerAttrV2 = asn1.ObjectIdentifier{0, 4, 0, 19122, 1, 1}
	oidAtRole       = asn1.ObjectIdentifier{2, 5, 4, 72}
)

// claimedRoles — signer-attributes-v2 (ETSI EN 319 122-1): SEQUENCE { claimedAttributes [0] EXPLICIT SEQUENCE OF
// Attribute, … }. id-at-role төрлийн UTF8String/PrintableString утгуудыг (EU DSS-ийн бичдэг хэлбэр) буцаана; задрахгүй,
// хэт урт, удирдах тэмдэгттэй утгыг алгасна (мэдээллийн талбар — гарын үсгийн дүгнэлтэд нөлөөлөхгүй).
func claimedRoles(attrs []rawAttr) []string {
	var out []string
	for _, a := range attrs {
		if !a.Type.Equal(oidSignerAttrV2) {
			continue
		}
		in := cryptobyte.String(a.Value.Bytes)
		var seq, claimed, list cryptobyte.String
		if !in.ReadASN1(&seq, cbasn1.SEQUENCE) {
			continue
		}
		if !seq.PeekASN1Tag(cbasn1.Tag(0).ContextSpecific().Constructed()) {
			continue
		}
		if !seq.ReadASN1(&claimed, cbasn1.Tag(0).ContextSpecific().Constructed()) || !claimed.ReadASN1(&list, cbasn1.SEQUENCE) {
			continue
		}
		for !list.Empty() && len(out) < maxClaimedRoles {
			var at, values cryptobyte.String
			var typ asn1.ObjectIdentifier
			if !list.ReadASN1(&at, cbasn1.SEQUENCE) || !at.ReadASN1ObjectIdentifier(&typ) || !at.ReadASN1(&values, cbasn1.SET) {
				break
			}
			if !typ.Equal(oidAtRole) {
				continue
			}
			for !values.Empty() && len(out) < maxClaimedRoles {
				var v cryptobyte.String
				var tag cbasn1.Tag
				if !values.ReadAnyASN1(&v, &tag) {
					break
				}
				if tag != cbasn1.UTF8String && tag != cbasn1.PrintableString {
					continue
				}
				if r := string(v); validClaimedRole(r) {
					out = append(out, r)
				}
			}
		}
	}
	return out
}

func validClaimedRole(s string) bool {
	if s == "" || !utf8.ValidString(s) || utf8.RuneCountInString(s) > maxClaimedRoleRunes {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return false
		}
	}
	return true
}

// DSS-ийн задлалтын хязгаар.
const (
	maxDSSItems  = 64
	maxDSSStream = 1 << 20
)

// extractDSS — /DSS-ийн stream-уудыг тайлж уншина. Задрахгүй / хязгаар хэтэрсэн мөрийг алгасна (LTV-д
// «дутуу» болно — fail-closed). DSS байхгүй бол nil.
func extractDSS(dss pdf.Value) *RawDSS {
	if dss.Kind() != pdf.Dict {
		return nil
	}
	read := func(key string) [][]byte {
		arr := dss.Key(key)
		var out [][]byte
		for i := 0; i < arr.Len() && i < maxDSSItems; i++ {
			e := arr.Index(i)
			if e.Kind() != pdf.Stream {
				continue
			}
			b, err := io.ReadAll(io.LimitReader(e.Reader(), maxDSSStream+1))
			if err != nil || len(b) > maxDSSStream {
				continue
			}
			out = append(out, b)
		}
		return out
	}
	return &RawDSS{Certs: read("Certs"), OCSPs: read("OCSPs"), CRLs: read("CRLs")}
}
