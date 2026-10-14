package eid

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Validator — RP-API-аас ирсэн session хариуг КРИПТОГРАФААР баталгаажуулна. SDK-ийн гол аюулгүйн давхарга:
// endResult == OK гэдэгт ДАНГААР нь итгэхгүй (RP-API эвдэрсэн/proxy хийгдсэн бол хуурамч OK ирж болзошгүй):
//
//  1. state == COMPLETE && endResult == OK
//  2. иргэний гэрчилгээг trust anchor (Mongolian National Root CA) хүртэл гинжээр баталгаажуулна — crypto/x509
//     Verify (RFC 5280: basicConstraints/pathLen, keyCertSign, name constraints, EKU давхарга, critical extension)
//  3. гэрчилгээ (ба гинжийн CA-ууд) хүчинтэй хугацаанд, шаардсан certLevel хангана
//  4. гарын үсгийг иргэний public key-ээр шалгана: auth → ACSP_V2 payload, sign → RP-ийн digest
//
// Аль нэг алхам бүтэлгүйтвэл *ValidationError (endResult ≠ OK бол *SessionFailedError) — хариунд ИТГЭХГҮЙ.
// Validator нь goroutine-safe.
type Validator struct {
	anchors        []*x509.Certificate
	intermediates  []*x509.Certificate
	requiredLevel  CertificateLevel
	skew           time.Duration
	allowUntrusted bool
	revocation     RevocationChecker
	revocationMode RevocationMode
	allowedIssuers map[string]bool
	checkKeyUsage  bool
	schemeName     string
	now            func() time.Time
}

// RevocationStatus — цуцлалтын төлөв.
type RevocationStatus string

const (
	RevocationGood    RevocationStatus = "good"
	RevocationRevoked RevocationStatus = "revoked"
	RevocationUnknown RevocationStatus = "unknown"
	// RevocationUnchecked — CheckRevocationStatus: checker "unknown" хариулсан ч soft-fail горимд зөвшөөрөгдсөн.
	RevocationUnchecked RevocationStatus = "unchecked"
	// RevocationSkipped — CheckRevocationStatus: RevocationChecker тохируулаагүй (асуугаагүй).
	RevocationSkipped RevocationStatus = "skipped"
)

// RevocationMode — "unknown" төлөвийн шийдвэр.
type RevocationMode string

const (
	// RevocationHardFail — "unknown"-г татгалзана (анхдагч).
	RevocationHardFail RevocationMode = "hard-fail"
	// RevocationSoftFail — "unknown"-г зөвшөөрнө.
	RevocationSoftFail RevocationMode = "soft-fail"
)

// RevocationChecker — иргэний гэрчилгээ цуцлагдсан эсэхийг шалгах hook (OCSP / CRL). RP нь гэрчилгээний AIA (OCSP)
// / CDP (CRL)-ээр хэрэгжүүлж, хариуны гарын үсэг, issuer, serial, хугацааг баталгаажуулна. issuer нь trust pool-оос
// олдсон шууд issuer (олдоогүй бол nil). Сүлжээний алдааг RevocationGood гэж үзэхгүй — error эсвэл RevocationUnknown.
type RevocationChecker func(ctx context.Context, cert, issuer *x509.Certificate) (RevocationStatus, error)

// TrustConfig — итгэлийн тохиргоо.
type TrustConfig struct {
	// TrustAnchorsPEM — trust anchor (Root CA) PEM-үүд (ж: NationalRootCAPEM). Production-д ЗААВАЛ — хоосон бол
	// ValidateAuth/ValidateSign алдаа буцаана (AllowUntrusted-аар л алгасна, зөвхөн dev/тест).
	TrustAnchorsPEM []string
	// IntermediatesPEM — завсрын CA PEM-үүд (leaf ↔ root хооронд). Нэг мөрөнд олон гэрчилгээ байж болно.
	IntermediatesPEM []string
	// RequiredLevel — шаардах certLevel ("" = QUALIFIED). Шаардсанаас дээш түвшнийг хүлээн авна (QSCD ⊇ QUALIFIED).
	RequiredLevel CertificateLevel
	// ClockSkew — гэрчилгээний хугацааг шалгахад зөвшөөрөх цагийн зөрүү (анхдагч 0).
	ClockSkew time.Duration
	// AllowUntrusted — trust anchor өгөөгүй ч баталгаажуулалт үргэлжлүүлнэ (гинж шалгахгүй). ЗӨВХӨН dev/тест.
	AllowUntrusted bool
	// Revocation — цуцлалт шалгагч. nil бол CheckRevocation no-op (QUALIFIED non-repudiation-д RP-ийн үүрэг).
	Revocation RevocationChecker
	// RevocationMode — "" = RevocationHardFail.
	RevocationMode RevocationMode
	// AllowedIssuerSKIs — иргэний гэрчилгээг шууд гаргасан CA-ийн Subject Key Identifier (hex, ":" зөвшөөрнө) жагсаалт.
	// Хоосон бол trust anchor хүртэл гинжлэгдсэн дурын CA зөвшөөрөгдөнө (хуучин зан). Ижил root-ийн доорх өөр CA
	// (ж: байгууллагын Issuing CA) иргэний гэрчилгээ гаргахаас хамгаалахад: []string{CitizenIssuingCASKI}.
	AllowedIssuerSKIs []string
	// CheckKeyUsage — true бол гэрчилгээний зориулалтыг CA-ийн профайлаар шалгана: auth → KeyUsage digitalSignature +
	// ExtKeyUsage clientAuth (P-CITIZEN-AUTH); sign → KeyUsage contentCommitment / nonRepudiation (P-CITIZEN-SIGN).
	// false (анхдагч) — шалгахгүй (хуучин зан).
	CheckKeyUsage bool
	// SchemeName — ACSP_V2 payload-ийн scheme нэр (CA-ийн capabilities.acsp_scheme_name); "" = "smart-id".
	SchemeName string
}

// CitizenIssuingCASKI — eID Mongolia Issuing CA (04)-ийн Subject Key Identifier: иргэний утасны болон USB токены
// AUTH/SIGN гэрчилгээг гаргадаг цорын ганц CA. TrustConfig.AllowedIssuerSKIs-д.
const CitizenIssuingCASKI = "b8a37f2c64ad677912db7d9e34f246358a2fb909"

// VerifiedIdentity — баталгаажсан иргэн (auth).
type VerifiedIdentity struct {
	DocumentNumber string
	// Certificate — иргэний X.509 гэрчилгээ.
	Certificate *x509.Certificate
	// Subject — задалсан subject (нэр, ETSI дугаар); SubjectDN — түүхий DN.
	Subject          Subject
	SubjectDN        string
	CertificateLevel string
}

// VerifiedSignature — баталгаажсан гарын үсэг (sign).
type VerifiedSignature struct {
	DocumentNumber     string
	SignatureValueB64  string
	SignatureAlgorithm string
	Certificate        *x509.Certificate
	Subject            Subject
	SubjectDN          string
	CertificateLevel   string
}

// ValidateAuthOptions — ValidateAuth-ийн нэмэлт шалгалт (device-link relay хаалт).
type ValidateAuthOptions struct {
	// ExpectedFlowType — RP-ийн ХАРУУЛСАН холбоосын төрөл (эсвэл push). Өгвөл гарын үсэг зурагдсан flowType ЯГ
	// ИЖИЛ байх ёстой: QR хуудас → FlowQR; гар утасны браузер дахь товч → FlowWeb2App; RP-ийн апп дахь товч →
	// FlowApp2App; push → FlowNotification. Web2App/App2App үед UserChallengeVerifier ЗААВАЛ.
	//
	// Нэг хуудсанд QR ба товч хоёуланг харуулсан бол: callback-аар (verifier-тэй) ирсэн үр дүнг Web2App/App2App-аар,
	// poll-оор ирснийг QR-аар шалга.
	ExpectedFlowType FlowType
	// UserChallengeVerifier — callback URL-ийн userChallengeVerifier параметр (ижил төхөөрөмжийн урсгалд апп RP руу
	// буцаахдаа нэмдэг). Өгвөл BASE64URL(SHA-256(verifier)) нь гарын үсэг зурагдсан userChallenge-тэй таарна.
	UserChallengeVerifier string
}

// ValidateSignOptions — ValidateSign-ийн нэмэлт шалгалт.
type ValidateSignOptions struct {
	// ExpectedFlowType — RP-ийн эхлүүлсэн урсгал (device-link: FlowQR / FlowWeb2App / FlowApp2App; push →
	// FlowNotification). Өгвөл хариуны flowType ЯГ ИЖИЛ байх ёстой — ValidateAuthOptions.ExpectedFlowType-тэй ижил.
	// RAW_DIGEST_SIGNATURE-д flowType гарын үсэгт ОРДОГГҮЙ (зөвхөн digest зурагдана) — энэ нь RP-API хариуны
	// тулгалт, криптограф баталгаа биш.
	ExpectedFlowType FlowType
	// ExpectedAlgorithm — хүсэлтэд илгээсэн signatureAlgorithm (SignContext.SignatureAlgorithm). Өгвөл хариуны RSA
	// алгоритм ЯГ ИЖИЛ байх ёстой: sha256WithRSAEncryption хүссэн session-д rsassa-pss (эсвэл эсрэгээр) хариу →
	// *ValidationError. CA-ийн хуучин threshold-ECDSA credential хүссэн алгоритмаас үл хамааран «ecdsa-with-SHA256»
	// буцаадаг (түлхүүрийн төрөл гэрчилгээнд бэхлэгдсэн) — үүнийг зөвхөн EC P-256 гэрчилгээ + SHA-256 үед
	// зөвшөөрнө. "" = хуучин зан (RSA алгоритмыг тулгахгүй).
	ExpectedAlgorithm SignatureAlgorithm
	// ExpectedCertificate — урьдчилж мэдсэн гэрчилгээ (certificate-choice: Signer.Certificate). Өгвөл хариуны
	// гэрчилгээ байт-ижил байх ёстой — өөр төхөөрөмж/гэрчилгээгээр зурсан бол (олон утастай иргэн) *ValidationError.
	ExpectedCertificate *x509.Certificate
}

// NewValidator — PEM-үүдийг задалж Validator үүсгэнэ.
func NewValidator(t TrustConfig) (*Validator, error) {
	anchors, err := parseCerts(t.TrustAnchorsPEM)
	if err != nil {
		return nil, fmt.Errorf("eid: TrustAnchorsPEM: %w", err)
	}
	inter, err := parseCerts(t.IntermediatesPEM)
	if err != nil {
		return nil, fmt.Errorf("eid: IntermediatesPEM: %w", err)
	}
	var issuers map[string]bool
	for _, s := range t.AllowedIssuerSKIs {
		ski := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), ":", ""))
		if b, err := hex.DecodeString(ski); err != nil || len(b) == 0 {
			return nil, fmt.Errorf("eid: AllowedIssuerSKIs: %q hex key identifier биш", s)
		}
		if issuers == nil {
			issuers = map[string]bool{}
		}
		issuers[ski] = true
	}
	return &Validator{
		anchors:        anchors,
		intermediates:  inter,
		requiredLevel:  orDefault(t.RequiredLevel, LevelQualified),
		skew:           t.ClockSkew,
		allowUntrusted: t.AllowUntrusted,
		revocation:     t.Revocation,
		revocationMode: orDefault(t.RevocationMode, RevocationHardFail),
		allowedIssuers: issuers,
		checkKeyUsage:  t.CheckKeyUsage,
		schemeName:     t.SchemeName,
		now:            time.Now,
	}, nil
}

func parseCerts(pems []string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for _, s := range pems {
		rest := []byte(s)
		n := 0
		for {
			var b *pem.Block
			b, rest = pem.Decode(rest)
			if b == nil {
				break
			}
			if b.Type != "CERTIFICATE" {
				continue
			}
			c, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				return nil, err
			}
			out = append(out, c)
			n++
		}
		if n == 0 {
			return nil, errors.New("PEM CERTIFICATE блок алга")
		}
	}
	return out, nil
}

var userChallengeRE = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// ValidateAuth — auth session-ийн хариуг бүрэн шалгаж баталгаажсан иргэнийг буцаана. acsp = session эхлүүлэхэд
// SDK-ийн буцаасан (RP хадгалсан) контекст. Цуцлалтыг дараа нь CheckRevocation-оор шалгана.
func (v *Validator) ValidateAuth(r *SessionResult, acsp *ACSPContext, o ValidateAuthOptions) (*VerifiedIdentity, error) {
	if acsp == nil {
		return nil, invalid("ACSP контекст алга")
	}
	leaf, err := v.precheck(r, "ACSP_V2")
	if err != nil {
		return nil, err
	}
	if sr, err := base64.StdEncoding.DecodeString(r.ServerRandom); err != nil || len(sr) < 18 {
		return nil, invalid("serverRandom алга/богино")
	}
	if !userChallengeRE.MatchString(r.UserChallenge) {
		return nil, invalid("userChallenge буруу хэлбэртэй")
	}
	flow := FlowType(r.FlowType)
	if flow == "" || !slices.Contains(acsp.FlowTypes, flow) {
		return nil, invalid("flowType %s нь санал болгосон урсгалд байхгүй", r.FlowType)
	}
	if o.ExpectedFlowType != "" && flow != o.ExpectedFlowType {
		return nil, invalid("flowType %s ≠ эхлүүлсэн урсгал %s (relay байж болзошгүй)", flow, o.ExpectedFlowType)
	}
	sameDevice := o.ExpectedFlowType == FlowWeb2App || o.ExpectedFlowType == FlowApp2App
	if sameDevice && o.UserChallengeVerifier == "" {
		return nil, invalid("%s урсгалд callback-ийн userChallengeVerifier заавал", o.ExpectedFlowType)
	}
	if o.UserChallengeVerifier != "" && UserChallengeOf(o.UserChallengeVerifier) != r.UserChallenge {
		return nil, invalid("userChallengeVerifier нь гарын үсэг зурагдсан userChallenge-тэй таарсангүй")
	}
	if r.InteractionTypeUsed == "" {
		return nil, invalid("interactionTypeUsed алга")
	}
	alg, hash, err := algorithmOf(r, leaf.PublicKey, string(acsp.SignatureAlgorithm), string(acsp.HashAlgorithm))
	if err != nil {
		return nil, err
	}
	cb, err := SignedCallbackURL(r.InitialCallbackURL, acsp.InitialCallbackURL, r.FlowType)
	if err != nil {
		return nil, err
	}
	payload := BuildACSPV2Payload(ACSPV2Params{
		SchemeName:          v.schemeName,
		ServerRandom:        r.ServerRandom,
		RPChallenge:         acsp.RPChallenge,
		UserChallenge:       r.UserChallenge,
		RelyingPartyName:    acsp.RelyingPartyName,
		BrokeredRpName:      acsp.BrokeredRpName,
		Interactions:        acsp.Interactions,
		InteractionTypeUsed: r.InteractionTypeUsed,
		InitialCallbackURL:  cb,
		FlowType:            r.FlowType,
	})
	if !VerifyPayloadSignature(payload, r.SignatureValueB64, leaf.PublicKey, alg, hash) {
		return nil, invalid("auth гарын үсэг ACSP_V2 payload-той таарсангүй (хуурамч хариу байж болзошгүй)")
	}
	return &VerifiedIdentity{
		DocumentNumber:   r.DocumentNumber,
		Certificate:      leaf,
		Subject:          ParseSubject(leaf),
		SubjectDN:        leaf.Subject.String(),
		CertificateLevel: r.CertificateLevel,
	}, nil
}

// ValidateSign — sign session-ийн хариуг бүрэн шалгаж баталгаажсан гарын үсгийг буцаана. digestB64 = хүсэлтэд
// илгээсэн digest; hash = түүнийг үүсгэсэн hash ("" = SHA-256). opts — сонголттой, дээд тал нь нэг
// (ValidateSignOptions); өгөөгүй бол flowType шалгахгүй.
func (v *Validator) ValidateSign(r *SessionResult, digestB64 string, hash HashAlgorithm, opts ...ValidateSignOptions) (*VerifiedSignature, error) {
	if len(opts) > 1 {
		return nil, invalid("ValidateSign: ValidateSignOptions дээд тал нь нэг")
	}
	leaf, err := v.precheck(r, "RAW_DIGEST_SIGNATURE")
	if err != nil {
		return nil, err
	}
	var o ValidateSignOptions
	if len(opts) == 1 {
		o = opts[0]
	}
	if o.ExpectedFlowType != "" && FlowType(r.FlowType) != o.ExpectedFlowType {
		return nil, invalid("flowType %s ≠ эхлүүлсэн урсгал %s (relay байж болзошгүй)", r.FlowType, o.ExpectedFlowType)
	}
	if o.ExpectedCertificate != nil && !bytes.Equal(leaf.Raw, o.ExpectedCertificate.Raw) {
		return nil, invalid("гэрчилгээ certificate-choice-оор сонгосонтой таарахгүй (serial %s ≠ %s)",
			certSerial(leaf), certSerial(o.ExpectedCertificate))
	}
	want := string(orDefault(hash, SHA256))
	digest, err := base64.StdEncoding.DecodeString(digestB64)
	if err != nil {
		return nil, invalid("digest base64 буруу")
	}
	alg, h, err := algorithmOf(r, leaf.PublicKey, string(o.ExpectedAlgorithm), want)
	if err != nil {
		return nil, err
	}
	ch, err := cryptoHash(h)
	if err != nil {
		return nil, err
	}
	if len(digest) != ch.Size() {
		return nil, invalid("digest урт hashAlgorithm-тай таарахгүй")
	}
	if !VerifyPrehashedSignature(digest, r.SignatureValueB64, leaf.PublicKey, alg, h) {
		return nil, invalid("гарын үсэг өгсөн digest-тэй таарсангүй")
	}
	return &VerifiedSignature{
		DocumentNumber:     r.DocumentNumber,
		SignatureValueB64:  r.SignatureValueB64,
		SignatureAlgorithm: r.SignatureAlgorithm,
		Certificate:        leaf,
		Subject:            ParseSubject(leaf),
		SubjectDN:          leaf.Subject.String(),
		CertificateLevel:   r.CertificateLevel,
	}, nil
}

// CheckRevocation — тохируулсан RevocationChecker-ээр гэрчилгээний төлвийг шалгана. Checker алга бол no-op (nil).
// RevocationRevoked, мөн hard-fail горимд RevocationUnknown → *ValidationError; checker-ийн алдаа → алдаа (итгэхгүй).
// ValidateAuth/ValidateSign-ийн дараа дуудна. Төлвийг мэдэх шаардлагатай бол CheckRevocationStatus.
func (v *Validator) CheckRevocation(ctx context.Context, cert *x509.Certificate) error {
	_, err := v.CheckRevocationStatus(ctx, cert)
	return err
}

// CheckRevocationStatus — CheckRevocation + юу шийдсэнийг буцаана (лог/аудитад):
//
//	RevocationGood, nil      — issuer хүчинтэй гэж хариулсан
//	RevocationUnchecked, nil — "unknown", soft-fail горимд зөвшөөрөв
//	RevocationSkipped, nil   — RevocationChecker тохируулаагүй
//	RevocationRevoked, *ValidationError — цуцлагдсан
//	RevocationUnknown, *ValidationError — "unknown", hard-fail
//	"", error                — checker-ийн алдаа (итгэхгүй)
func (v *Validator) CheckRevocationStatus(ctx context.Context, cert *x509.Certificate) (RevocationStatus, error) {
	return v.CheckRevocationWith(ctx, cert, v.revocation, v.revocationMode)
}

// CheckRevocationWith — CheckRevocationStatus-тэй ижил, гэхдээ Trust-ийн биш өгсөн checker ба горимоор (issuer-ийг
// Validator-ийн trust pool-оос олно). checker nil бол RevocationSkipped; mode "" = RevocationHardFail.
func (v *Validator) CheckRevocationWith(ctx context.Context, cert *x509.Certificate, checker RevocationChecker, mode RevocationMode) (RevocationStatus, error) {
	if checker == nil {
		return RevocationSkipped, nil
	}
	status, err := checker(ctx, cert, v.findIssuer(cert))
	if err != nil {
		return "", fmt.Errorf("eid: revocation шалгалт: %w", err)
	}
	switch status {
	case RevocationGood:
		return RevocationGood, nil
	case RevocationRevoked:
		return RevocationRevoked, invalid("гэрчилгээ цуцлагдсан (revoked)")
	}
	if mode == RevocationSoftFail {
		return RevocationUnchecked, nil
	}
	return RevocationUnknown, invalid("гэрчилгээний revocation төлөв тогтоогдсонгүй (hard-fail)")
}

// algorithmOf — хариуны signatureAlgorithm + hash-ийг RP-ийн хүссэнтэй ба гэрчилгээний түлхүүрийн төрөлтэй
// тулгана (downgrade / alg confusion хаалт).
//
// ECDSA: CA-ийн ECDSA credential зөвхөн SHA-256 digest зурна (SHA-384/512 session-д SplitKey RSA л) — тиймээс
// зөвхөн «ecdsa-with-SHA256», EC P-256 түлхүүр, хүссэн hash SHA-256 (TS SDK 0.9.0-тэй ижил). RSA нэрс нь заавал RSA
// түлхүүртэй, hash нь хүссэнтэй ЯГ таарна.
func algorithmOf(r *SessionResult, pub crypto.PublicKey, wantAlg, wantHash string) (alg, hash string, err error) {
	alg = r.SignatureAlgorithm
	_, isRSA := pub.(*rsa.PublicKey)
	_, isEC := pub.(*ecdsa.PublicKey)
	switch {
	case alg == string(AlgRSASSAPSS):
		if !isRSA {
			return "", "", invalid("rsassa-pss нь RSA бус гэрчилгээтэй")
		}
		p := r.SignatureAlgorithmParameters
		if p != nil {
			hash = p.HashAlgorithm
		}
		ch, herr := cryptoHash(hash)
		if herr != nil {
			return "", "", herr
		}
		if p.MaskGenAlgorithm != nil && p.MaskGenAlgorithm.Parameters != nil &&
			p.MaskGenAlgorithm.Parameters.HashAlgorithm != "" && p.MaskGenAlgorithm.Parameters.HashAlgorithm != hash {
			return "", "", invalid("MGF1 hash нь hashAlgorithm-аас өөр")
		}
		if p.SaltLength != nil && *p.SaltLength != ch.Size() {
			return "", "", invalid("saltLength ≠ hLen")
		}
	case alg == string(AlgSHA256WithRSA) || alg == string(AlgSHA384WithRSA) || alg == string(AlgSHA512WithRSA):
		if !isRSA {
			return "", "", invalid("%s нь RSA бус гэрчилгээтэй", alg)
		}
		hash = "SHA-" + alg[3:6]
	case alg == string(AlgECDSAWithSHA256):
		if !isEC || !isP256(pub) {
			return "", "", invalid("%s нь EC P-256 бус гэрчилгээтэй", alg)
		}
		hash = string(SHA256)
		if wantHash != hash {
			// CA ECDSA credential-аар SHA-256-аас өөр hash зурдаггүй — ийм хариу серверээс гарахгүй.
			return "", "", invalid("ecdsa-with-SHA256 хариу %s хүссэн session-д боломжгүй (ECDSA credential зөвхөн SHA-256)", wantHash)
		}
	default:
		return "", "", invalid("дэмжигдээгүй signatureAlgorithm: %s", alg)
	}
	if wantAlg != "" && alg != wantAlg && alg != string(AlgECDSAWithSHA256) {
		return "", "", invalid("signatureAlgorithm %s ≠ хүссэн %s", alg, wantAlg)
	}
	if hash != wantHash {
		return "", "", invalid("hashAlgorithm %s ≠ хүссэн %s", hash, wantHash)
	}
	return alg, hash, nil
}

func isP256(pub crypto.PublicKey) bool {
	k, ok := pub.(*ecdsa.PublicKey)
	return ok && k.Curve == elliptic.P256()
}

// precheck — state/endResult, гэрчилгээ, гинж, хугацаа, certLevel — нийтлэг шалгалт.
func (v *Validator) precheck(r *SessionResult, protocol string) (*x509.Certificate, error) {
	if err := sessionDone(r); err != nil {
		return nil, err
	}
	if r.SignatureProtocol != "" && r.SignatureProtocol != protocol {
		return nil, invalid("signatureProtocol %s ≠ %s", r.SignatureProtocol, protocol)
	}
	if r.CertificateDERB64 == "" {
		return nil, invalid("хариунд гэрчилгээ алга")
	}
	if r.SignatureValueB64 == "" {
		return nil, invalid("хариунд гарын үсэг алга")
	}
	return v.leafOf(r, protocol)
}

// sessionDone — COMPLETE + OK; амжилтгүй endResult → *SessionFailedError.
func sessionDone(r *SessionResult) error {
	if r == nil {
		return invalid("хариу алга")
	}
	if r.State != StateComplete {
		return invalid("session дуусаагүй (state=%s)", r.State)
	}
	if r.EndResult != EndResultOK {
		er := r.EndResult
		if er == "" {
			er = "UNKNOWN"
		}
		return &SessionFailedError{EndResult: er}
	}
	return nil
}

// leafOf — хариуны гэрчилгээ: documentNumber, задлалт, хугацаа, certLevel, зориулалт (protocol), гинж, issuer.
func (v *Validator) leafOf(r *SessionResult, protocol string) (*x509.Certificate, error) {
	if r.CertificateDERB64 == "" {
		return nil, invalid("хариунд гэрчилгээ алга")
	}
	if r.DocumentNumber == "" {
		return nil, invalid("хариунд documentNumber алга")
	}
	der, err := base64.StdEncoding.DecodeString(r.CertificateDERB64)
	if err != nil {
		return nil, invalid("гэрчилгээ base64 буруу")
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, invalid("гэрчилгээ задарсангүй: %v", err)
	}
	now := v.now()
	if err := v.checkValidity(leaf, now); err != nil {
		return nil, err
	}
	if err := v.checkLevel(r.CertificateLevel); err != nil {
		return nil, err
	}
	if err := v.checkPurpose(leaf, protocol); err != nil {
		return nil, err
	}
	// Trust anchor ЗААВАЛ — хоосон бол fail-closed (AllowUntrusted-аар л алгасна).
	if len(v.anchors) == 0 {
		if !v.allowUntrusted {
			return nil, invalid("trust anchor тохируулаагүй — итгэлцэл шалгах боломжгүй (production-д TrustAnchorsPEM өг, эсвэл AllowUntrusted)")
		}
		return leaf, nil
	}
	usage := x509.ExtKeyUsageClientAuth
	if protocol != "ACSP_V2" {
		usage = x509.ExtKeyUsageEmailProtection
	}
	if err := v.verifyChain(leaf, now, usage); err != nil {
		return nil, err
	}
	if err := v.checkIssuer(leaf); err != nil {
		return nil, err
	}
	return leaf, nil
}

// checkValidity — алдааны текстэд subject (иргэний нэр/PNOMN) биш serial (hex) орно.
func (v *Validator) checkValidity(c *x509.Certificate, now time.Time) error {
	if now.Add(v.skew).Before(c.NotBefore) {
		return invalid("гэрчилгээ хүчинтэй болоогүй байна (serial %s)", certSerial(c))
	}
	if now.Add(-v.skew).After(c.NotAfter) {
		return invalid("гэрчилгээний хугацаа дууссан (serial %s)", certSerial(c))
	}
	return nil
}

func certSerial(c *x509.Certificate) string {
	if c.SerialNumber == nil {
		return "?"
	}
	return c.SerialNumber.Text(16)
}

// checkPurpose — CheckKeyUsage үед гэрчилгээний зориулалт протоколд тохирох эсэх (CA crypto/ca_profile.go):
// ACSP_V2 (auth) → KU digitalSignature + EKU clientAuth (эсвэл any); RAW_DIGEST_SIGNATURE (sign) → KU contentCommitment.
func (v *Validator) checkPurpose(leaf *x509.Certificate, protocol string) error {
	if !v.checkKeyUsage {
		return nil
	}
	if protocol == "ACSP_V2" {
		if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			return invalid("нэвтрэлтийн гэрчилгээнд KeyUsage digitalSignature алга")
		}
		if !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth) && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny) {
			return invalid("нэвтрэлтийн гэрчилгээнд ExtKeyUsage clientAuth алга (гарын үсгийн гэрчилгээ байж болзошгүй)")
		}
		return nil
	}
	if leaf.KeyUsage&x509.KeyUsageContentCommitment == 0 {
		return invalid("гарын үсгийн гэрчилгээнд KeyUsage nonRepudiation (contentCommitment) алга")
	}
	return nil
}

// checkIssuer — AllowedIssuerSKIs тохируулсан бол leaf-ийн шууд issuer-ийн SKI (issuer-т алга бол leaf-ийн AKI)
// жагсаалтад байх ёстой.
func (v *Validator) checkIssuer(leaf *x509.Certificate) error {
	if len(v.allowedIssuers) == 0 {
		return nil
	}
	ski := leaf.AuthorityKeyId
	if is := v.findIssuer(leaf); is != nil && len(is.SubjectKeyId) > 0 {
		ski = is.SubjectKeyId
	}
	if len(ski) == 0 || !v.allowedIssuers[hex.EncodeToString(ski)] {
		return invalid("гэрчилгээг гаргасан CA зөвшөөрөгдсөн иргэний issuer биш (AllowedIssuerSKIs)")
	}
	return nil
}

var levelRank = map[string]int{"ADVANCED": 1, "QUALIFIED": 2, "QSCD": 3}

func (v *Validator) checkLevel(level string) error {
	need, ok := levelRank[string(v.requiredLevel)]
	if !ok {
		need = 2
	}
	if levelRank[level] < need {
		return invalid("гэрчилгээний түвшин хүрэлцэхгүй: %s < %s", level, v.requiredLevel)
	}
	return nil
}

// verifyChain — crypto/x509-ийн RFC 5280 замын шалгалт (x509.Certificate.Verify): гинжийг trust anchor хүртэл
// угсарч, CA бүрийн basicConstraints (CA:TRUE, pathLenConstraint), keyUsage keyCertSign, name constraints, EKU-ийн
// давхарга (завсрын CA-д EKU байвал leaf-ийн зориулалтыг агуулах), хүчинтэй хугацаа, гарын үсэг, үл таних critical
// extension-ийг шалгана. usage — auth → clientAuth, sign → emailProtection (CA ca_profile.go: P-CITIZEN-AUTH =
// clientAuth+emailProtection, P-CITIZEN-SIGN = emailProtection; EKU-гүй leaf-ийг Go "any" гэж үзнэ).
// certificatePolicies-ийг шалгахгүй (Go 1.22-д VerifyOptions.CertificatePolicies байхгүй) — CA-ийн гинжинд
// policyConstraints / inhibitAnyPolicy алга.
func (v *Validator) verifyChain(leaf *x509.Certificate, now time.Time, usage x509.ExtKeyUsage) error {
	roots := x509.NewCertPool()
	for _, a := range v.anchors {
		roots.AddCert(a)
	}
	inter := x509.NewCertPool()
	for _, c := range v.intermediates {
		inter.AddCert(c)
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   chainTime(leaf, now),
		KeyUsages:     []x509.ExtKeyUsage{usage},
	})
	if err != nil {
		return chainError(err)
	}
	return nil
}

// chainTime — гинжийг шалгах мөч: now, ГЭХДЭЭ leaf-ийн хүчинтэй хугацаанд хавчина. leaf-ийн хугацааг checkValidity
// ClockSkew-тэй аль хэдийн шалгасан тул энэ нь зөвхөн skew-ийн хүрээнд (≤ ClockSkew) шилжинэ.
func chainTime(leaf *x509.Certificate, now time.Time) time.Time {
	if now.Before(leaf.NotBefore) {
		return leaf.NotBefore
	}
	if now.After(leaf.NotAfter) {
		return leaf.NotAfter
	}
	return now
}

// chainError — x509.Verify-ийн алдааг ValidationError болгоно. Алдааны текстэд гэрчилгээний subject (иргэний
// нэр/PNOMN) орохгүй — зөвхөн шалтгааны ангилал.
func chainError(err error) error {
	var ci x509.CertificateInvalidError
	if errors.As(err, &ci) {
		reason := map[x509.InvalidReason]string{
			x509.NotAuthorizedToSign:           "завсрын гэрчилгээ CA биш эсвэл keyCertSign эрхгүй",
			x509.Expired:                       "гинжийн гэрчилгээний хугацаа дууссан эсвэл хүчинтэй болоогүй",
			x509.CANotAuthorizedForThisName:    "CA-ийн name constraints зөрчсөн",
			x509.TooManyIntermediates:          "pathLenConstraint зөрчсөн (завсрын CA хэт олон)",
			x509.IncompatibleUsage:             "гэрчилгээний ExtKeyUsage энэ үйлдэлд тохирохгүй (гинжийн EKU)",
			x509.NameMismatch:                  "issuer/subject нэр таарахгүй",
			x509.UnconstrainedName:             "name constraints-ийн шалгаж чадахгүй нэр",
			x509.TooManyConstraints:            "name constraints хэт олон",
			x509.CANotAuthorizedForExtKeyUsage: "CA-ийн ExtKeyUsage энэ зориулалтыг зөвшөөрөхгүй",
		}[ci.Reason]
		if reason == "" {
			reason = "гинжийн гэрчилгээ хүчингүй"
		}
		return invalid("гэрчилгээний гинж хүчингүй: %s", reason)
	}
	var uce x509.UnhandledCriticalExtension
	if errors.As(err, &uce) {
		return invalid("гэрчилгээний гинж хүчингүй: үл таних critical extension")
	}
	return invalid("гэрчилгээний итгэлцлийн гинж trust anchor (Root CA) хүрсэнгүй")
}

func issuedBy(child, parent *x509.Certificate) bool {
	if !parent.IsCA || !bytes.Equal(child.RawIssuer, parent.RawSubject) {
		return false
	}
	if len(child.AuthorityKeyId) > 0 && len(parent.SubjectKeyId) > 0 && !bytes.Equal(child.AuthorityKeyId, parent.SubjectKeyId) {
		return false
	}
	return child.CheckSignatureFrom(parent) == nil
}

// findIssuer — leaf-ийн шууд issuer (revocation шалгагчид).
func (v *Validator) findIssuer(leaf *x509.Certificate) *x509.Certificate {
	for _, c := range append(slices.Clone(v.intermediates), v.anchors...) {
		if issuedBy(leaf, c) {
			return c
		}
	}
	return nil
}

// SignedCallbackURL — ACSP_V2 payload-ийн initialCallbackUrl. CA урсгалаар шийднэ (Smart-ID: QR/Notification → "",
// Web2App/App2App → RP-ийн callback). Хариуны утгыг (signature.initialCallbackUrl) зөвхөн "" эсвэл RP-ийн илгээсэн
// callback-тай байт-ижил бол хэрэглэнэ; Web2App/App2App-д заавал RP-ийн callback. Талбар алга (хуучин CA) → RP-ийн
// callback.
func SignedCallbackURL(fromResponse *string, rpCallback, flowType string) (string, error) {
	if fromResponse == nil {
		return rpCallback, nil
	}
	got := *fromResponse
	if got != "" && got != rpCallback {
		return "", invalid("signature.initialCallbackUrl нь хоосон ч биш, илгээсэн callback ч биш (хуурамч хариу байж болзошгүй)")
	}
	if (flowType == string(FlowWeb2App) || flowType == string(FlowApp2App)) && got != rpCallback {
		return "", invalid("%s урсгалд signature.initialCallbackUrl нь илгээсэн callback байх ёстой", flowType)
	}
	return got, nil
}

// UserChallengeOf — Smart-ID: userChallenge = BASE64URL(SHA-256(UTF-8(userChallengeVerifier))), padding-гүй.
func UserChallengeOf(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// VerifyPayloadSignature — payload (auth) дээрх гарын үсэг: HASH_hash(payload)-ийг VerifyPrehashedSignature-аар.
func VerifyPayloadSignature(payload []byte, sigB64 string, pub crypto.PublicKey, alg, hash string) bool {
	ch, err := cryptoHash(hash)
	if err != nil {
		return false
	}
	d := ch.New()
	d.Write(payload)
	return VerifyPrehashedSignature(d.Sum(nil), sigB64, pub, alg, hash)
}

// VerifyPrehashedSignature — бэлэн digest дээрх гарын үсэг. rsassa-pss (salt = hLen), shaNNNWithRSAEncryption
// (PKCS#1 v1.5), ecdsa-with-SHA256 (P-256, SHA-256, ASN.1 DER). Алгоритм ба түлхүүрийн төрөл таарахгүй бол false.
func VerifyPrehashedSignature(digest []byte, sigB64 string, pub crypto.PublicKey, alg, hash string) bool {
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || len(sig) == 0 {
		return false
	}
	ch, err := cryptoHash(hash)
	if err != nil || len(digest) != ch.Size() {
		return false
	}
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if alg == string(AlgRSASSAPSS) {
			return rsa.VerifyPSS(k, ch, digest, sig, &rsa.PSSOptions{SaltLength: ch.Size(), Hash: ch}) == nil
		}
		if strings.HasPrefix(alg, "sha") && strings.HasSuffix(alg, "WithRSAEncryption") {
			return rsa.VerifyPKCS1v15(k, ch, digest, sig) == nil
		}
	case *ecdsa.PublicKey:
		if alg == string(AlgECDSAWithSHA256) && ch == crypto.SHA256 && k.Curve == elliptic.P256() {
			return ecdsa.VerifyASN1(k, digest, sig)
		}
	}
	return false
}
