// Package validate — нийтийн гарын үсэг/гэрчилгээ шалгагч (eidmongolia.mn/verify-ийн backend).
//
// Хоёр үе шат: (1) Extract — дайсагнасан PDF-ийг задална (prod-д тусгаарлагдсан дэд процесс,
// worker.go); (2) Evaluate — итгэлийн шийдвэр: гинжийг ЗӨВХӨН шигтгэсэн үндэсний Root CA (01)-ээс
// тогтоож, түлхүүрийн хэрэглээ, хугацаа, цагийн тэмдэг, цуцлалтыг (OCSP-той ижил эх сурвалж, Store)
// шалгана. digitorus/pdfsign/verify-г ашиглахгүй — тэр нь системийн root-оор итгэл тогтоож,
// ByteRange-ийн хамрахыг шалгадаггүй.
package validate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	eidcrypto "github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/eidcrypto"
	"math/big"
	"slices"
	"strings"
	"time"
)

//go:embed national-root-ca.pem
var nationalRootPEM []byte

// NationalRoots — Mongolian National Root CA (pki/chain/01). Итгэлийн цорын ганц тулгуур.
func NationalRoots() (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(nationalRootPEM) {
		return nil, errors.New("validate: national root CA задарсангүй")
	}
	return pool, nil
}

// NationalRootCerts — үндэсний Root CA-ийн гэрчилгээ(нүүд) (PAdES DSS: 02-ийн CRL-ийг шалгах олгогч).
func NationalRootCerts() ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := nationalRootPEM
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("validate: national root CA задарсангүй")
	}
	return out, nil
}

// Indication — ETSI EN 319 102-1-ийн дээд түвшний дүгнэлттэй ижил гурван утга.
type Indication string

const (
	Valid         Indication = "valid"
	Invalid       Indication = "invalid"
	Indeterminate Indication = "indeterminate"
)

// Problem кодууд — клиент эдгээрийг хэрэглэгчийн хэлээр орчуулна.
const (
	ProblemIntegrity         = "integrity_failed"       // гарын үсэг зурсны дараа агуулга өөрчлөгдсөн / гарын үсэг таарахгүй
	ProblemMalformed         = "malformed_signature"    // гарын үсгийн бүтэц эвдэрсэн
	ProblemWeakAlgorithm     = "weak_algorithm"         // SHA-1/MD5 зэрэг хуучирсан hash
	ProblemUntrusted         = "untrusted_chain"        // үндэсний Root CA хүртэл гинж хүрэхгүй
	ProblemKeyUsage          = "wrong_key_usage"        // гэрчилгээ гарын үсэг зурахад зориулагдаагүй (нэвтрэлт, TLS…)
	ProblemRevoked           = "revoked"                // гэрчилгээ цуцлагдсан (гарын үсэг зурахаас өмнө)
	ProblemRevokedAfter      = "revoked_after_signing"  // гарын үсэг зурсны ДАРАА цуцлагдсан (гарын үсэг хүчинтэй хэвээр)
	ProblemRevocationUnknown = "revocation_unavailable" // цуцлалтын төлөв тогтоогдсонгүй
	ProblemExpired           = "expired"                // гэрчилгээний хугацаа дууссан
	ProblemNotYetValid       = "not_yet_valid"          // гэрчилгээ хараахан хүчин төгөлдөр болоогүй
	ProblemModifiedAfter     = "modified_after_signing" // гарын үсгийн дараа баримтад нэмэлт өөрчлөлт орсон
	ProblemTimestampInvalid  = "timestamp_invalid"      // цагийн тэмдэг таарахгүй / итгэмжлэгдээгүй
)

// Revocation — нэг гэрчилгээний цуцлалтын төлөв.
type Revocation struct {
	Status    string     `json:"status"` // good | revoked | unknown
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// CertStatus — Store-оос уншсан төлөв (OCSP responder-тэй ижил эх сурвалж).
type CertStatus struct {
	Issued    bool
	Revoked   bool
	RevokedAt time.Time
}

// StatusSource — манай issuing CA-аас гарсан гэрчилгээний цуцлалтыг өгнө. cert — шалгах гэрчилгээ, issuer — гинжийн
// (гарын үсгээр баталгаажсан) олгогч: нотолгоо (OCSP CertID, CRL issuer/гарын үсэг) энэ хосынх байх ёстой. at — шалгах
// цаг (цагийн тэмдгийн цаг эсвэл одоо): «good» нотолгоо at-д шинэлэг байх ёстой (FreshAt).
type StatusSource interface {
	CertStatus(cert, issuer *x509.Certificate, at time.Time) (CertStatus, error)
}

// Validator — шалгагч. Roots нь үндэсний Root CA; Intermediates нь манай завсрын CA-ууд
// (PDF-д гинж дутуу суулгасан ч гинж бүтээгдэнэ); Issuers — цуцлалтыг Status-аас асуух CA-ууд.
// Extract nil бол задлалтыг процесс дотроо хийнэ — ЗӨВХӨН тестэд (prod-д IsolatedExtractor).
type Validator struct {
	Roots         *x509.CertPool
	Intermediates []*x509.Certificate
	Issuers       []*x509.Certificate
	Status        StatusSource
	Extract       func(ctx context.Context, doc []byte) ([]RawSignature, error)
	Now           func() time.Time
}

// CertInfo — гэрчилгээний нийтэд харуулж болох хураангуй.
type CertInfo struct {
	CommonName  string     `json:"common_name"`
	Subject     string     `json:"subject"`
	Issuer      string     `json:"issuer"`
	Serial      string     `json:"serial"` // HEX (OCSP/CRL-ийн конвенц)
	NotBefore   time.Time  `json:"not_before"`
	NotAfter    time.Time  `json:"not_after"`
	Usage       string     `json:"usage"`         // sign | auth | seal | document_signer | timestamp | other
	IssuedByEID bool       `json:"issued_by_eid"` // манай issuing CA (04/05)-аас гарсан
	Revocation  Revocation `json:"revocation"`
}

// CertReport — /v3/validate/certificate-ийн хариу.
type CertReport struct {
	Indication   Indication `json:"indication"`
	Problems     []string   `json:"problems"`
	ChainTrusted bool       `json:"chain_trusted"`
	Chain        []string   `json:"chain"` // leaf → root, CN-ээр
	Certificate  CertInfo   `json:"certificate"`
}

// TimestampInfo — RFC 3161 цагийн тэмдэг.
type TimestampInfo struct {
	Time    time.Time `json:"time"`
	Serial  string    `json:"serial"`
	TSA     string    `json:"tsa"`
	Trusted bool      `json:"trusted"`
}

// SignerNameSource-ийн утгууд — signer_name хаанаас гарсныг клиентэд хэлнэ.
const (
	SignerNamePlatformAttested = "platform_attested"
	SignerNameCertificate      = "certificate"
	SignerNameUnverified       = "unverified"
)

// SignatureReport — PDF доторх нэг гарын үсэг. ClaimedName/Reason/Location нь PDF-д БИЧИГДСЭН,
// баталгаагүй утга. SignerName нь итгэж харуулж болох нэр, SignerNameSource нь түүний эх сурвалж:
//   - platform_attested — гарын үсэг бүрэн бүтэн, гинж итгэмжлэгдсэн, манай issuing CA-аас гарсан
//     doc-signer зурсан (хуучин stamp, 2026-10-13 хүртэл): SignerName = PDF-ийн /Name (платформ иргэний гэрчилгээнээс бичсэн);
//   - certificate — SignerName = гэрчилгээний subject-ийн нэр (GIVENNAME + SURNAME, эсвэл CN);
//   - unverified — гэрчилгээ задраагүй: SignerName хоосон.
//
// ClaimedName нь /Name-ийн түүхий текст (үргэлж) — клиент зөвхөн SignerName-ээс зөрсөн үед, хоёрдогч
// тайлбар болгон харуулж болно.
type SignatureReport struct {
	Indication          Indication     `json:"indication"`
	Problems            []string       `json:"problems"`
	SignerName          string         `json:"signer_name"`
	ClaimedName         string         `json:"claimed_name,omitempty"`
	SignerNameSource    string         `json:"signer_name_source"`
	Reason              string         `json:"reason,omitempty"`
	Location            string         `json:"location,omitempty"`
	ClaimedTime         *time.Time     `json:"claimed_time,omitempty"` // гарын үсэг зурагчийн мэдүүлсэн (баталгаагүй) цаг
	SigningTime         *time.Time     `json:"signing_time,omitempty"` // итгэмжлэгдсэн цагийн тэмдгийн цаг
	Timestamp           *TimestampInfo `json:"timestamp,omitempty"`
	CoversWholeDocument bool           `json:"covers_whole_document"`
	// Доорх гурав нь CoversWholeDocument == false үед л утгатай (үгүй бол false/0/false).
	// ExtendedBySignaturesOnly — энэ гарын үсгийн дараах revision бүр зөвхөн гарын үсэг/LTV-ийн
	// зөвшөөрөгдсөн өөрчлөлт (revisions.go) агуулсан; false бол modified_after_signing тавигдана.
	ExtendedBySignaturesOnly bool `json:"extended_by_signatures_only"`
	// LaterSignatures — энэ гарын үсгийн мужийн дараа нэмэгдсэн гарын үсэг / баримтын цагийн тэмдгийн тоо.
	LaterSignatures int `json:"later_signatures"`
	// VisibleLaterSignature — дараагийн аль нэг гарын үсгийн widget хоосон биш /Rect эсвэл /AP-тэй
	// (хуудсан дээр харагдах дүрслэл нэмэгдсэн). Prod-ийн горимд (profileOwnSigner) зөвхөн PAdES бичигчийн яг
	// хэлбэрийн харагдах гарын үсэг (pades/APPEARANCE_SPEC.md §5) зөвшөөрөгдөнө; бусад нь modified_after_signing.
	VisibleLaterSignature bool `json:"visible_later_signature"`
	// Visible — ЭНЭ гарын үсгийн widget хуудсан дээр харагдана (/AP эсвэл хоосон биш /Rect; APPEARANCE_SPEC.md).
	// Мэдээллийн талбар — indication-д нөлөөлөхгүй.
	Visible      bool      `json:"visible"`
	ChainTrusted bool      `json:"chain_trusted"`
	Chain        []string  `json:"chain"`
	Certificate  *CertInfo `json:"certificate,omitempty"`
	// CivilID — гарын үсэг зурагчийн гэрчилгээний subject SERIALNUMBER "PNOMN-<civil_id>"-ийн civil_id (иргэний
	// гэрчилгээ биш бол хоосон). Зөвхөн ОРУУЛСАН ФАЙЛ дахь гэрчилгээнээс гарна — файлтай хүн SERIALNUMBER-ийг
	// (certificate.subject-д ч мөн) аль хэдийн эзэмшдэг тул маскгүй. Холбоосоор (файлгүй) нээх /v3/verify/* нь
	// маскласан хэвээр (httpapi/verify_page.go civilIDVisibleTail). DB-ээс хэзээ ч нэмэхгүй.
	CivilID string `json:"civil_id,omitempty"`
	// RevisionSHA256 — энэ гарын үсгийн revision-ий байт (doc[:ByteRange[2]+ByteRange[3]])-ын sha256 (жижиг hex).
	// Платформын stamp бүрийн гаралттай тэнцүү тул дуудагч pdf_stamps-аас session олно. JSON-д гаргахгүй.
	RevisionSHA256 string `json:"-"`
	// SessionID — дуудагч (handlers_validate.go) pdf_signatures / pdf_stamps-аас олсон үед л: платформын eID session.
	// Энэ багц DB мэдэхгүй.
	SessionID string `json:"session_id,omitempty"`
	// DocID — дуудагч pdf_signatures-аас олсон үед: баримтын ID (нэгдсэн /verify/{docID}).
	DocID string `json:"doc_id,omitempty"`
	// KeyMedium — зурагчийн түлхүүрийн байршил: "token" (USB токен) | "phone" (eID апп) | "unknown" (CA !377). CA нь
	// бүртгэлээс тавина; SDK (pades.ValidatePDF) зөвхөн гэрчилгээнээс — validatepdf.go keyMedium.
	KeyMedium string `json:"key_medium"`
	// ClaimedRoles — CMS-ийн signer-attributes-v2 (0.4.0.19122.1.1) claimedAttributes / id-at-role: гарын үсэг
	// зурагчийн мэдүүлсэн үүрэг (гарын үсгээр хамгаалагдсан, гэхдээ өөрөө баталгаа биш). eID-ийн байгууллагын нэрийн
	// өмнөөс гарын үсэгт «<албан тушаал>, <байгууллага> (NTRMN-…)».
	ClaimedRoles []string `json:"claimed_roles,omitempty"`
	// OnBehalfOf* — дуудагч (handlers_validate.go) pdf_signatures-аас олсон бол: eID гарын үсэг зурах үед (prepare ба
	// finalize) төлөөллийг бүртгэлээр шалгасан байгууллага. CMS-ийн мэдүүлгээс бус, CA-ийн бүртгэлээс.
	OnBehalfOfOrg         string `json:"on_behalf_of_org,omitempty"`
	OnBehalfOfOrgRegister string `json:"on_behalf_of_org_register,omitempty"`
	// SignatureLevel — ETSI.CAdES.detached гарын үсгийн PAdES baseline түвшин: PAdES-BASELINE-B | -T (итгэмжлэгдсэн
	// цагийн тэмдэгтэй) | -LT (+ LTV бүрэн). Бусад SubFilter-д хоосон.
	SignatureLevel string `json:"signature_level,omitempty"`
	// LTV — гинжийн (root-оос бусад) ба TSA гинжийн гэрчилгээ бүрд баримтын DSS-д тохирох OCSP/CRL байгаа эсэх
	// (мэдээллийн; indication-ийг өөрчлөхгүй — §8.3). Гэрчилгээ задраагүй бол nil.
	LTV *LTVInfo `json:"ltv,omitempty"`
	// CertificateLevel — гарын үсэг зурагчийн гэрчилгээний түвшин (eid.CertificateLevelOf, гарын үсгийн протокол):
	// qcStatements-д QcCompliance → QUALIFIED (+ QcSSCD → QSCD), бусад → ADVANCED (USB токен). Гинж итгэмжлэгдээгүй
	// эсвэл qcStatements гэмтсэн бол хоосон. SDK бөглөнө (pades.ValidatePDF); CA-д нэмэх санал.
	CertificateLevel string `json:"certificate_level,omitempty"`
}

// LTVInfo — урт хугацааны баталгаажуулалтын өгөгдлийн бүрэн байдал. Missing — DSS-д хүчинтэй цуцлалтын
// мэдээлэл олдоогүй гэрчилгээний CN.
type LTVInfo struct {
	Complete bool     `json:"complete"`
	Missing  []string `json:"missing"`
}

// PDFReport — /v3/validate/pdf-ийн хариу.
type PDFReport struct {
	Indication Indication        `json:"indication"`
	Signatures []SignatureReport `json:"signatures"`
	// StampLookup — "unavailable": дуудагч pdf_stamps-ийг уншиж чадаагүй (session_id-гүй нь «бүртгэлд олдсонгүй»
	// гэсэн үг БИШ). Хайлт амжилттай эсвэл хийгдээгүй бол хоосон.
	StampLookup string `json:"stamp_lookup,omitempty"`
}

func (v *Validator) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// ParseCertificate — PEM (CERTIFICATE) эсвэл base64/түүхий DER-ийг задална.
func ParseCertificate(in []byte) (*x509.Certificate, error) {
	// Түүхий DER-ийг ЭХЛЭЭД, огт хөндөлгүй үзнэ: TrimSpace нь гарын үсгийн сүүлийн байт 0x20/0x0a г.м. байвал
	// DER-ийг тайрч «гэрчилгээ биш» болгодог байв (CI-д санамсаргүй унадаг тест, 2026-09-28).
	if c, err := x509.ParseCertificate(in); err == nil {
		return c, nil
	}
	in = bytes.TrimSpace(in)
	if blk, _ := pem.Decode(in); blk != nil {
		if blk.Type != "CERTIFICATE" {
			return nil, ErrNotCert
		}
		in = blk.Bytes
	} else if der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(in)), "")); err == nil {
		in = der
	}
	c, err := x509.ParseCertificate(in)
	if err != nil {
		return nil, ErrNotCert
	}
	return c, nil
}

// ValidateCertificate — гэрчилгээг одоогийн цагаар шалгана: гинж, хугацаа, цуцлалт.
func (v *Validator) ValidateCertificate(cert *x509.Certificate) CertReport {
	now := v.now()
	rep := CertReport{Problems: []string{}}
	chain, trusted := v.verifyChain(cert, nil, now)
	rep.ChainTrusted = trusted
	rep.Chain = chainNames(cert, chain)
	info := v.certInfo(cert, chain, now)
	rep.Certificate = info
	if !trusted {
		rep.Problems = append(rep.Problems, ProblemUntrusted)
	}
	rep.Problems = append(rep.Problems, validityProblems(cert, now)...)
	switch info.Revocation.Status {
	case "revoked":
		rep.Problems = append(rep.Problems, ProblemRevoked)
	case "unknown":
		if trusted {
			rep.Problems = append(rep.Problems, ProblemRevocationUnknown)
		}
	}
	rep.Indication = indication(rep.Problems)
	return rep
}

func validityProblems(c *x509.Certificate, at time.Time) []string {
	switch {
	case at.After(c.NotAfter):
		return []string{ProblemExpired}
	case at.Before(c.NotBefore):
		return []string{ProblemNotYetValid}
	}
	return nil
}

// indication — problem-уудаас дүгнэлт. Итгэлийг эвддэг бол invalid, зөвхөн тогтоож чадаагүй
// (цуцлалт, цаг, дараа нь өөрчлөгдсөн) бол indeterminate.
func indication(problems []string) Indication {
	out := Valid
	for _, p := range problems {
		switch p {
		case ProblemIntegrity, ProblemMalformed, ProblemWeakAlgorithm, ProblemUntrusted, ProblemKeyUsage,
			ProblemRevoked, ProblemExpired, ProblemNotYetValid:
			return Invalid
		case ProblemRevokedAfter:
		default:
			out = Indeterminate
		}
	}
	return out
}

// ValidatePDF — PDF доторх бүх гарын үсгийг шалгана.
func (v *Validator) ValidatePDF(ctx context.Context, doc []byte) (*PDFReport, error) {
	extract := v.Extract
	if extract == nil {
		extract = func(_ context.Context, d []byte) ([]RawSignature, error) { return Extract(d) }
	}
	raws, err := extract(ctx, doc)
	if err != nil {
		return nil, err
	}
	rep := &PDFReport{Signatures: make([]SignatureReport, 0, len(raws))}
	for _, r := range raws {
		s := v.evaluateSignature(r)
		s.RevisionSHA256 = revisionSHA256(doc, r)
		rep.Signatures = append(rep.Signatures, s)
	}
	rep.Indication = Valid
	for _, s := range rep.Signatures {
		if s.Indication == Invalid {
			rep.Indication = Invalid
			break
		}
		if s.Indication == Indeterminate {
			rep.Indication = Indeterminate
		}
	}
	return rep, nil
}

// certCivilID — иргэний гэрчилгээний SERIALNUMBER (PNOMN-<civil_id>, docs/IDENTIFIERS.md)-ээс civil_id; бусад ("").
func certCivilID(c *x509.Certificate) string {
	if id, ok := strings.CutPrefix(c.Subject.SerialNumber, "PNOMN-"); ok {
		return id
	}
	return ""
}

// revisionSHA256 — doc[:SignedEnd]-ийн sha256. Worker-ийн өгсөн тоог зөвхөн мужаар шалгаад, hash-ыг эцэг процесс
// бодит байтаас тооцно (worker эвдэрсэн байсан ч өөр файлын hash гаргаж чадахгүй). Задраагүй бол "".
func revisionSHA256(doc []byte, r RawSignature) string {
	if r.Malformed || r.SignedEnd <= 0 || r.SignedEnd > int64(len(doc)) {
		return ""
	}
	sum := sha256.Sum256(doc[:r.SignedEnd])
	return hex.EncodeToString(sum[:])
}

func (v *Validator) evaluateSignature(r RawSignature) SignatureReport {
	// signer_name: PDF-ийн /Name-ийг хэн ч бичиж чадна (иргэн өөрийн SIGN гэрчилгээгээр жинхэнэ гарын үсэг
	// угсраад өөр хүний нэр бичиж болно) тул түүхий текст зөвхөн claimed_name-д очно. signer_name нь
	// гэрчилгээнээс, эсвэл — зөвхөн манай doc-signer зурсан нь батлагдсан үед — /Name-ээс гарна (доор).
	s := SignatureReport{
		Problems:            []string{},
		ClaimedName:         r.SignerName,
		SignerNameSource:    SignerNameUnverified,
		Reason:              r.Reason,
		ClaimedRoles:        r.ClaimedRoles,
		Location:            r.Location,
		ClaimedTime:         r.ClaimedTime,
		CoversWholeDocument: r.CoversWhole,
		Visible:             r.Visible,
		Chain:               []string{},
	}
	// Worker-ийн хариуг дахин хатуу болгоно: бүтэн хамарсан эсвэл зөвшөөрөгдөөгүй үед бүгд тэг.
	if !r.CoversWhole && r.LaterSignaturesOnly {
		s.ExtendedBySignaturesOnly, s.LaterSignatures, s.VisibleLaterSignature = true, r.LaterSignatures, r.LaterVisible
	}
	fail := func(p string) SignatureReport {
		s.Problems = append(s.Problems, p)
		s.Indication = Invalid
		return s
	}
	if r.Malformed {
		return fail(ProblemMalformed)
	}
	leaf, err := x509.ParseCertificate(r.Leaf)
	if err != nil {
		return fail(ProblemMalformed)
	}
	s.SignerName, s.SignerNameSource = eidcrypto.SubjectDisplayName(leaf), SignerNameCertificate
	s.CivilID = certCivilID(leaf)
	if !r.Integrity {
		return fail(ProblemIntegrity)
	}
	if r.WeakDigest {
		return fail(ProblemWeakAlgorithm)
	}
	// PAdES (ETSI.CAdES.detached): signingCertificateV2 заавал, leaf-тэй таарна (§8.1).
	cades := r.SubFilter == subFilterCAdES
	if cades && r.SigningCertV2 != "match" {
		return fail(ProblemMalformed)
	}

	// Цаг: итгэмжлэгдсэн цагийн тэмдэг байвал түүгээр, эс бөгөөс одоогийн цагаар шалгана
	// (мэдүүлсэн /M цаг баталгаагүй тул итгэлийн шийдвэрт ашиглахгүй).
	at := v.now()
	var tsChain []*x509.Certificate
	if r.Timestamp != nil {
		ts, chain, ok := v.evaluateTimestamp(*r.Timestamp)
		tsChain = chain
		s.Timestamp = ts
		if ok {
			t := ts.Time
			s.SigningTime = &t
			at = t
		} else {
			s.Problems = append(s.Problems, ProblemTimestampInvalid)
		}
	}

	chain, trusted := v.verifyChain(leaf, parseCerts(r.Certs), at)
	s.ChainTrusted = trusted
	s.Chain = chainNames(leaf, chain)
	info := v.certInfo(leaf, chain, at)
	s.Certificate = &info
	if !trusted {
		s.Problems = append(s.Problems, ProblemUntrusted)
	}
	if !signingUsage(info.Usage) {
		s.Problems = append(s.Problems, ProblemKeyUsage)
	}
	s.Problems = append(s.Problems, validityProblems(leaf, at)...)
	switch info.Revocation.Status {
	case "revoked":
		// Итгэмжлэгдсэн цагийн тэмдгээс ХОЙШ цуцлагдсан бол гарын үсэг хүчинтэй хэвээр.
		if s.SigningTime != nil && info.Revocation.RevokedAt != nil && info.Revocation.RevokedAt.After(*s.SigningTime) {
			s.Problems = append(s.Problems, ProblemRevokedAfter)
		} else {
			s.Problems = append(s.Problems, ProblemRevoked)
		}
	case "unknown":
		// Манай бус (жишээ нь 02-оос гарсан өөр провайдерын) гэрчилгээний цуцлалтыг бид мэдэхгүй —
		// «хүчинтэй» гэж хэлэхгүй.
		if trusted {
			s.Problems = append(s.Problems, ProblemRevocationUnknown)
		}
	}
	// Манай doc-signer (платформын түлхүүр) зурсан нь батлагдсан үед л /Name нь платформын баталгаа: энэ
	// түлхүүрээр зөвхөн платформ зурдаг байсан бөгөөд /Name-ийг иргэний гэрчилгээнээс бичдэг (устсан stamp). Энд
	// хүрсэн бол гарын үсэг бүрэн бүтэн, hash сул биш. Гинж итгэмжлэгдээгүй, манай issuing CA-аас гараагүй,
	// эсвэл цуцлагдсан (түлхүүр алдагдсан байж болох — revoked_after_signing биш) бол гэрчилгээний нэр хэвээр.
	if trusted && info.IssuedByEID && info.Usage == "document_signer" && !slices.Contains(s.Problems, ProblemRevoked) {
		s.SignerName, s.SignerNameSource = r.SignerName, SignerNamePlatformAttested
	}
	// Манай PAdES хэлбэрт signingTime attr хориотой (цаг /M ба timestamp-д); гадны гарын үсэгт шаардахгүй.
	if cades && r.SigningTimeAttr && info.IssuedByEID {
		s.Problems = append(s.Problems, ProblemMalformed)
	}
	// Дараа нь зөвхөн гарын үсэг (PAdES incremental revision) / LTV өгөгдөл нэмэгдсэн бол өөрчлөлт биш.
	if !r.CoversWhole && !r.LaterSignaturesOnly {
		s.Problems = append(s.Problems, ProblemModifiedAfter)
	}
	if trusted {
		s.LTV = ltvCoverage(r.DSS, at, v.now(), chain, tsChain)
	}
	if cades {
		switch {
		case s.SigningTime != nil && s.LTV != nil && s.LTV.Complete:
			s.SignatureLevel = "PAdES-BASELINE-LT"
		case s.SigningTime != nil:
			s.SignatureLevel = "PAdES-BASELINE-T"
		default:
			s.SignatureLevel = "PAdES-BASELINE-B"
		}
	}
	s.Indication = indication(s.Problems)
	return s
}

// signingUsage — баримтад гарын үсэг зурахад зориулагдсан профайл (ca_profile.go): иргэний SIGN,
// байгууллагын тамга, баримтын doc-signer. Нэвтрэлт (PIN1), TLS, OCSP, TSA-ийн гэрчилгээгээр
// зурсан гарын үсгийг хүлээн авахгүй.
func signingUsage(u string) bool {
	return u == "sign" || u == "seal" || u == "document_signer"
}

// evaluateTimestamp — токен гарын үсгийн утгатай таарч, TSA-ийн гэрчилгээ timeStamping EKU-тэй,
// үндэсний Root CA хүртэл токены цагт (хугацааны fallback-гүй) хүчинтэй байх ёстой.
func (v *Validator) evaluateTimestamp(r RawTimestamp) (*TimestampInfo, []*x509.Certificate, bool) {
	info := &TimestampInfo{Time: r.Time, Serial: r.Serial}
	tsa, err := x509.ParseCertificate(r.TSACert)
	if err != nil {
		return info, nil, false
	}
	info.TSA = tsa.Subject.CommonName
	if !r.Matches || r.WeakDigest || r.Time.IsZero() || !eidcrypto.IsTSASigningCert(tsa) {
		return info, nil, false
	}
	var chain []*x509.Certificate
	chain, info.Trusted = v.verifyAt(tsa, parseCerts(r.Certs), r.Time, x509.ExtKeyUsageTimeStamping)
	return info, chain, info.Trusted
}

func (v *Validator) pool(extra []*x509.Certificate) *x509.CertPool {
	inter := x509.NewCertPool()
	for _, c := range extra {
		inter.AddCert(c)
	}
	for _, c := range v.Intermediates {
		inter.AddCert(c)
	}
	return inter
}

// verifyAt — leaf-ийг үндэсний Root CA хүртэл яг at цагт шалгана (бүх гишүүний хугацааг оруулна).
func (v *Validator) verifyAt(leaf *x509.Certificate, extra []*x509.Certificate, at time.Time, eku x509.ExtKeyUsage) ([]*x509.Certificate, bool) {
	if v.Roots == nil {
		return nil, false
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: v.Roots, Intermediates: v.pool(extra), CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{eku}})
	if err != nil || len(chains) == 0 {
		return nil, false
	}
	return chains[0], true
}

// verifyChain — гарын үсэг/гэрчилгээний гинж. at цагт бүтэхгүй бол leaf-ийн хүчинтэй хугацааны дунд
// үед дахин бүтээнэ: гинж өөрөө зөв боловч leaf-ийн хугацаа таарахгүйг (expired/not_yet_valid —
// дуудагч тусад нь тавина) «итгэмжлэгдээгүй»-ээс ялгах. Root/EKU/нэрийн алдаа цагаас хамаардаггүй
// тул fallback итгэлгүй гинжийг итгэмжлэгдсэн болгохгүй. Дунд үед завсрын CA-ийн хугацаа ч шалгагдана.
func (v *Validator) verifyChain(leaf *x509.Certificate, extra []*x509.Certificate, at time.Time) ([]*x509.Certificate, bool) {
	if chain, ok := v.verifyAt(leaf, extra, at, x509.ExtKeyUsageAny); ok {
		return chain, true
	}
	if at.After(leaf.NotAfter) || at.Before(leaf.NotBefore) {
		return v.verifyAt(leaf, extra, leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore)/2), x509.ExtKeyUsageAny)
	}
	return nil, false
}

func (v *Validator) certInfo(c *x509.Certificate, chain []*x509.Certificate, at time.Time) CertInfo {
	info := CertInfo{
		CommonName: c.Subject.CommonName,
		Subject:    nameString(c.Subject),
		Issuer:     nameString(c.Issuer),
		Serial:     hexSerial(c.SerialNumber),
		NotBefore:  c.NotBefore.UTC(),
		NotAfter:   c.NotAfter.UTC(),
		Usage:      usageOf(c),
		Revocation: Revocation{Status: "unknown"},
	}
	if len(chain) < 2 || !v.isIssuer(chain[1]) {
		return info
	}
	info.IssuedByEID = true
	if v.Status == nil {
		return info
	}
	st, err := v.Status.CertStatus(c, chain[1], at)
	switch {
	case err != nil, !st.Issued:
		// DB алдаа эсвэл бүртгэлгүй serial — «good» гэж таамаглахгүй (OCSP-тэй адил fail-closed).
	case st.Revoked:
		t := st.RevokedAt.UTC()
		info.Revocation = Revocation{Status: "revoked", RevokedAt: &t}
	default:
		info.Revocation = Revocation{Status: "good"}
	}
	return info
}

// isIssuer — гинжийн олгогч манай 04/05 мөн эсэх: subject DN + public key (SPKI) байт-ижил. Бүтэн cert-ийн
// байтаар биш — 04/05-ийг ижил түлхүүр/subject-тэй дахин олгодог (AIA засвар, certificatePolicies) тул PDF-д
// суусан өмнөх хувь (өөр serial) ч ижил CA; гинж аль хэдийн гарын үсгээр баталгаажсан.
func (v *Validator) isIssuer(c *x509.Certificate) bool {
	for _, is := range v.Issuers {
		if bytes.Equal(c.RawSubject, is.RawSubject) && bytes.Equal(c.RawSubjectPublicKeyInfo, is.RawSubjectPublicKeyInfo) {
			return true
		}
	}
	return false
}

var oidEKUDocumentSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 36}

// usageOf — ca_profile.go-ийн профайлуудыг KU/EKU-аар ялгана.
func usageOf(c *x509.Certificate) string {
	for _, e := range c.ExtKeyUsage {
		switch e {
		case x509.ExtKeyUsageTimeStamping:
			return "timestamp"
		case x509.ExtKeyUsageOCSPSigning:
			return "other"
		}
	}
	if c.IsCA {
		return "other"
	}
	for _, e := range c.UnknownExtKeyUsage {
		if e.Equal(oidEKUDocumentSigning) {
			return "document_signer"
		}
	}
	cc := c.KeyUsage&x509.KeyUsageContentCommitment != 0
	ds := c.KeyUsage&x509.KeyUsageDigitalSignature != 0
	switch {
	case cc && !ds && len(c.ExtKeyUsage) == 0:
		return "seal"
	case cc:
		return "sign"
	case ds:
		for _, e := range c.ExtKeyUsage {
			if e == x509.ExtKeyUsageClientAuth {
				return "auth"
			}
		}
	}
	return "other"
}

func chainNames(leaf *x509.Certificate, chain []*x509.Certificate) []string {
	if len(chain) == 0 {
		return []string{leaf.Subject.CommonName}
	}
	out := make([]string, 0, len(chain))
	for _, c := range chain {
		out = append(out, c.Subject.CommonName)
	}
	return out
}

func hexSerial(n *big.Int) string {
	if n == nil {
		return ""
	}
	return strings.ToUpper(n.Text(16))
}
