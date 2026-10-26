package eid

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// «Миний QR» (CA гэрээ myqr-2026-10-26): иргэн eID апп дээрээ «EIDMN-QR1:<token>» QR (120 с, нэг удаагийн) харуулна →
// RP QR.Start-аар POST /authentication/qr → иргэн утсан дээрээ PIN2-оор (QUALIFIED SIGN түлхүүр) зөвшөөрнө →
// QR.Result нь иргэний ӨӨРИЙН PS256 JWS-ийг (x5c = [SIGN гэрчилгээ, issuing CA]) гинж + цуцлалт + гарын үсэг + claim-аар
// шалгаж «Миний мэдээлэл»-ийн бүх талбарыг (payload-ийн дарааллаар) ба нүүрний зургийг буцаана. CA өгөгдлийн хуулбар
// хадгалахгүй — presentation-ийг нэг л удаа уншина (дахин уншвал 410 QR_PRESENTATION_GONE). RP-д зөвхөн QR_PRESENT эрх.

const (
	// QRPrefix — иргэний аппын QR-ийн агуулгын угтвар: "EIDMN-QR1:<token>".
	QRPrefix = "EIDMN-QR1:"
	// QRJWSType — presentation JWS-ийн header typ.
	QRJWSType = "eidmn-myqr+jwt"
	// DefaultQRIssuer — presentation JWS-ийн iss.
	DefaultQRIssuer = "https://ca.eidmongolia.mn"
	// QRMaxAge — exp − iat-ийн дээд утга (CA: exp = iat + 300).
	QRMaxAge = 300 * time.Second
	// QRClockSkew — iat / exp / гэрчилгээний хугацааг шалгахад зөвшөөрөх цагийн зөрүү.
	QRClockSkew = 60 * time.Second

	qrMaxJWS        = 512 << 10
	qrMaxFields     = 128
	qrMaxKeyRunes   = 64
	qrMaxValueBytes = 2048
	qrMaxPhotoBytes = 150 << 10
	qrSaltLength    = 32
)

// «Миний QR»-ийн алдааны кодууд — *QRError.Code (CA гэрээ §6.2; TS / .NET SDK-д ижил). CA-ийн бусад код (403
// PERMISSION_DENIED / RP_REQUIRED, 409 NO_SIGNING_CERTIFICATE, 400 REQUEST_INVALID, 429 RATE_LIMITED) хэвээр
// *ForbiddenError / *APIError-оор ирнэ.
const (
	// CodeQRFormatInvalid — сканнердсан мөр "EIDMN-QR1:<43 тэмдэгт base64url>" биш. Клиент талын.
	CodeQRFormatInvalid = "QR_FORMAT_INVALID"
	// CodeQRTokenInvalid — 404: токен танигдахгүй / хугацаа дууссан (120 с) / ашиглагдсан → иргэнээс шинэ QR гаргуул.
	CodeQRTokenInvalid = "QR_TOKEN_INVALID"
	// CodeQRPending — QR.Result-ийн хүлээх хугацаа (WaitOptions) дууссан ч иргэн хараахан хариулаагүй (CA-ийн session
	// идэвхтэй) — дахин Result / Check дуудаж болно. CA-ийн жинхэнэ хугацаа дуусалт = *SessionFailedError{TIMEOUT}.
	CodeQRPending = "QR_PENDING"
	// CodeQRPresentationGone — 410: presentation аль хэдийн нэг удаа уншигдсан эсвэл хугацаа нь дууссан → шинэ QR.
	CodeQRPresentationGone = "QR_PRESENTATION_GONE"
	// Доорх кодууд — VerifyQRPresentation-ийн шалгалт (§6.1); аль нь ч гарвал хариунд ИТГЭХГҮЙ.
	CodeQRJWSMalformed      = "QR_JWS_MALFORMED"
	CodeQRHeaderInvalid     = "QR_HEADER_INVALID"
	CodeQRChainInvalid      = "QR_CHAIN_INVALID"
	CodeQRCertRevoked       = "QR_CERT_REVOKED"
	CodeQRRevocationUnknown = "QR_REVOCATION_UNKNOWN"
	CodeQRSignatureInvalid  = "QR_SIGNATURE_INVALID"
	CodeQRClaimsInvalid     = "QR_CLAIMS_INVALID"
	CodeQRAudienceMismatch  = "QR_AUDIENCE_MISMATCH"
	CodeQRSessionMismatch   = "QR_SESSION_MISMATCH"
	CodeQRNonceMismatch     = "QR_NONCE_MISMATCH"
	CodeQRNotYetValid       = "QR_NOT_YET_VALID"
	CodeQRExpired           = "QR_EXPIRED"
	CodeQRDataInvalid       = "QR_DATA_INVALID"
)

// errors.Is-ийн sentinel-ууд: *QRError (ба QR_TOKEN_INVALID-д *APIError) Code-оор тулгана.
var (
	ErrQRFormatInvalid     = errors.New("eid: " + CodeQRFormatInvalid)
	ErrQRTokenInvalid      = errors.New("eid: " + CodeQRTokenInvalid)
	ErrQRPending           = errors.New("eid: " + CodeQRPending)
	ErrQRPresentationGone  = errors.New("eid: " + CodeQRPresentationGone)
	ErrQRJWSMalformed      = errors.New("eid: " + CodeQRJWSMalformed)
	ErrQRHeaderInvalid     = errors.New("eid: " + CodeQRHeaderInvalid)
	ErrQRChainInvalid      = errors.New("eid: " + CodeQRChainInvalid)
	ErrQRCertRevoked       = errors.New("eid: " + CodeQRCertRevoked)
	ErrQRRevocationUnknown = errors.New("eid: " + CodeQRRevocationUnknown)
	ErrQRSignatureInvalid  = errors.New("eid: " + CodeQRSignatureInvalid)
	ErrQRClaimsInvalid     = errors.New("eid: " + CodeQRClaimsInvalid)
	ErrQRAudienceMismatch  = errors.New("eid: " + CodeQRAudienceMismatch)
	ErrQRSessionMismatch   = errors.New("eid: " + CodeQRSessionMismatch)
	ErrQRNonceMismatch     = errors.New("eid: " + CodeQRNonceMismatch)
	ErrQRNotYetValid       = errors.New("eid: " + CodeQRNotYetValid)
	ErrQRExpired           = errors.New("eid: " + CodeQRExpired)
	ErrQRDataInvalid       = errors.New("eid: " + CodeQRDataInvalid)
)

var qrSentinels = map[string]error{
	CodeQRFormatInvalid:     ErrQRFormatInvalid,
	CodeQRTokenInvalid:      ErrQRTokenInvalid,
	CodeQRPending:           ErrQRPending,
	CodeQRPresentationGone:  ErrQRPresentationGone,
	CodeQRJWSMalformed:      ErrQRJWSMalformed,
	CodeQRHeaderInvalid:     ErrQRHeaderInvalid,
	CodeQRChainInvalid:      ErrQRChainInvalid,
	CodeQRCertRevoked:       ErrQRCertRevoked,
	CodeQRRevocationUnknown: ErrQRRevocationUnknown,
	CodeQRSignatureInvalid:  ErrQRSignatureInvalid,
	CodeQRClaimsInvalid:     ErrQRClaimsInvalid,
	CodeQRAudienceMismatch:  ErrQRAudienceMismatch,
	CodeQRSessionMismatch:   ErrQRSessionMismatch,
	CodeQRNonceMismatch:     ErrQRNonceMismatch,
	CodeQRNotYetValid:       ErrQRNotYetValid,
	CodeQRExpired:           ErrQRExpired,
	CodeQRDataInvalid:       ErrQRDataInvalid,
}

// QRError — «Миний QR»-ийн алдаа (Code — дээрх CodeQR*). CA-ийн 404 QR_TOKEN_INVALID / 410-ийг ч энэ төрлөөр буцаана
// (Cause = анхны *APIError, errors.As-аар авна).
type QRError struct {
	Code   string
	Reason string
	Cause  error
}

func (e *QRError) Error() string { return "eid: " + e.Code + ": " + e.Reason }

func (e *QRError) Unwrap() error { return e.Cause }

func (e *QRError) Is(target error) bool { return qrSentinels[e.Code] == target }

func qrErr(code, format string, a ...any) *QRError {
	return &QRError{Code: code, Reason: fmt.Sprintf(format, a...)}
}

var qrTokenRe = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// ParseQR — сканнердсан QR-ийн агуулгаас токеныг гаргана: ASCII хоосон зай хасаад "EIDMN-QR1:" + 43 тэмдэгт
// base64url. Бусад бүх хэлбэр (угтваргүй токен ч) → *QRError{CodeQRFormatInvalid}.
func ParseQR(scanned string) (string, error) {
	s, ok := strings.CutPrefix(strings.Trim(scanned, " \t\n\v\f\r"), QRPrefix)
	if !ok || !qrTokenRe.MatchString(s) {
		return "", qrErr(CodeQRFormatInvalid, "eID «Миний QR» биш")
	}
	return s, nil
}

// QRConfig — Config.QR. Тэг утга = prod CA.
type QRConfig struct {
	// Issuer — хүлээгдэх iss; "" = DefaultQRIssuer (тест орчинд л).
	Issuer string
}

// QRStartRequest — QR.Start-ийн оролт.
type QRStartRequest struct {
	// QR — сканнердсан агуулга ("EIDMN-QR1:<token>").
	QR string
	// Nonce — RP-ийн nonce (16–128 тэмдэгт, хэвлэгдэх ASCII 0x21–0x7E; ж: захиалгын дугаар); JWS-д яг буцаж ирнэ.
	// "" бол base64url(16 санамсаргүй байт) — 22 тэмдэгт.
	Nonce string
	// RelyingPartyName — дэд системийн шошго (ж: «Касс 3», лог); "" = Credentials.RPName. Иргэнд харагдах нэр нь CA-ийн
	// бүртгэлийнх (JWS-ийн rp_name).
	RelyingPartyName string
}

// QRSession — QR.Start-ийн хариу. JSON-оор хадгалж (stateless RP) QR.Result / Check / Verify-д дамжуулна.
type QRSession struct {
	SessionID string `json:"sessionID"`
	Nonce     string `json:"nonce"`
}

// QRData — JWS payload-ийн data: иргэний аппын «Миний мэдээлэл» (хэвээр, нэр солиогүй).
type QRData struct {
	Source string            `json:"source"`
	Fields map[string]string `json:"fields"`
	Photo  string            `json:"photo,omitempty"`
}

// QRClaims — шалгагдсан JWS payload.
type QRClaims struct {
	Iss       string `json:"iss"`
	Sub       string `json:"sub"`
	Aud       string `json:"aud"`
	RPName    string `json:"rp_name"`
	Sid       string `json:"sid"`
	Nonce     string `json:"nonce"`
	Iat       int64  `json:"iat"`
	Exp       int64  `json:"exp"`
	Statement string `json:"statement"`
	Data      QRData `json:"data"`
}

// QRSigner — гарын үсэг зурсан иргэн (x5c[0]-ээс; нэрс латин, гэрчилгээнийх).
type QRSigner struct {
	Certificate                          *x509.Certificate
	ETSI, GivenName, Surname, CommonName string
}

// QRPresentation — шалгагдсан «Миний QR» presentation.
type QRPresentation struct {
	// JWS — түүхий compact JWS (маргаан / аудитад хадгалж болно — иргэний гарын үсэгтэй нотолгоо).
	JWS    string
	Claims QRClaims
	// Data — data.fields (түлхүүр нь эх сурвалжийнх, хэвээр); Keys — payload-ийн дараалал (Go map дарааллыг алддаг).
	Data map[string]string
	Keys []string
	// Source — data.source (dan, passport, citizenid, gsign, guardian, unknown …).
	Source string
	// Photo — нүүрний зураг (JPEG байт); байхгүй бол nil.
	Photo    []byte
	Signer   QRSigner
	SignedAt time.Time
	// SHA256 — hex(SHA-256(signing input)) жижиг үсгээр = CA-ийн аудитын qrsha (маргааныг тулгахад).
	SHA256 string
}

// QRExpect — VerifyQRPresentation-ийн хүлээлт.
type QRExpect struct {
	RPUUID    string // aud (том/жижиг үсэг ялгахгүй)
	SessionID string // QRSession.SessionID
	Nonce     string // QRSession.Nonce (яг)
	Issuer    string // "" = DefaultQRIssuer
	Now       time.Time
}

// QRCheck — QR.Check-ийн хариу: Complete == false бол иргэн хараахан хариулаагүй (Presentation nil).
type QRCheck struct {
	Complete     bool
	Presentation *QRPresentation
}

// QRService — «Миний QR»: ParseQR → Start → Result / Check. Goroutine-safe.
type QRService struct {
	h      *httpDoer
	creds  Credentials
	issuer string
	trust  TrustConfig

	ocspOnce sync.Once
	ocsp     RevocationChecker
}

// Parse — ParseQR.
func (s *QRService) Parse(scanned string) (string, error) { return ParseQR(scanned) }

type qrStartBody struct {
	QR               string `json:"qr"`
	RelyingPartyUUID string `json:"relyingPartyUUID"`
	RelyingPartyName string `json:"relyingPartyName"`
	Nonce            string `json:"nonce"`
}

// Start — POST /authentication/qr: QR-ийн токеныг (нэг удаагийн) CA-д өгч иргэний утас руу PIN2 хүсэлт илгээнэ. VC
// байхгүй (иргэний утсанд зөвхөн нэг өгүүлбэр харагдана). Алдаа: *QRError — FORMAT_INVALID (сүлжээгүй), CA-ийн 404
// QR_TOKEN_INVALID (Cause = *APIError); 403 *ForbiddenError (PERMISSION_DENIED — QR_PRESENT эрх алга, RP_REQUIRED);
// 409 *APIError NO_SIGNING_CERTIFICATE; 400 REQUEST_INVALID (nonce буруу); 429 RATE_LIMITED.
func (s *QRService) Start(ctx context.Context, req QRStartRequest) (*QRSession, error) {
	token, err := ParseQR(req.QR)
	if err != nil {
		return nil, err
	}
	nonce := req.Nonce
	if nonce == "" {
		if nonce, err = qrNonce(); err != nil {
			return nil, err
		}
	}
	body := qrStartBody{
		QR:               QRPrefix + token,
		RelyingPartyUUID: s.creds.RPUUID,
		RelyingPartyName: orDefault(req.RelyingPartyName, s.creds.RPName),
		Nonce:            nonce,
	}
	var r sessionStartResponse
	if err := s.h.postJSON(ctx, routeAuthQR.expand(), body, &r); err != nil {
		return nil, qrServerErr(err)
	}
	if r.SessionID == "" {
		return nil, fmt.Errorf("eid: POST %s: sessionID алга", routeAuthQR.path)
	}
	return &QRSession{SessionID: r.SessionID, Nonce: nonce}, nil
}

// qrNonce — base64url(16 CSPRNG байт), 22 тэмдэгт.
func qrNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("eid: nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// qrServerErr — CA-ийн QR кодуудыг *QRError болгоно (Cause = анхны *APIError, errors.As-аар авна): 410 →
// QR_PRESENTATION_GONE (биеийн кодоос үл хамааран), QR_TOKEN_INVALID. Бусад алдаа хэвээр.
func qrServerErr(err error) error {
	var ae *APIError
	if !errors.As(err, &ae) {
		return err
	}
	switch {
	case ae.Status == http.StatusGone:
		return &QRError{Code: CodeQRPresentationGone, Reason: "presentation аль хэдийн уншигдсан эсвэл хугацаа дууссан — шинэ QR уншуулна уу", Cause: err}
	case ae.Code == CodeQRTokenInvalid:
		return &QRError{Code: ae.Code, Reason: fmt.Sprintf("CA %d", ae.Status), Cause: err}
	}
	return err
}

// Result — session дуустал GET /session/{id}-ийг long-poll хийж (opts nil бол discovery-ийн session TTL-ээр),
// presentation-ийг VerifyQRPresentation-аар шалгана (Config.Trust; Revocation nil бол NewOCSPChecker, hard-fail). Иргэн
// татгалзсан / CA-ийн TIMEOUT → *SessionFailedError; хүлээх хугацаа дууссан ч session идэвхтэй → ErrQRPending;
// 410 → ErrQRPresentationGone (presentation нэг л удаа уншигдана); шалгалт унавал *QRError (§6.2) — ИТГЭХГҮЙ.
func (s *QRService) Result(ctx context.Context, sess *QRSession, opts *WaitOptions) (*QRPresentation, error) {
	if sess == nil || sess.SessionID == "" {
		return nil, errors.New("eid: QR.Result: QRSession шаардлагатай")
	}
	r, err := (&SessionService{h: s.h}).WaitForResult(ctx, sess.SessionID, opts)
	if err != nil {
		return nil, qrServerErr(err)
	}
	if r.State != StateComplete {
		return nil, qrErr(CodeQRPending, "иргэн хараахан хариулаагүй")
	}
	return s.finish(ctx, r, sess)
}

// Check — нэг удаагийн шалгалт (polling UI): GET /session/{id} (serverPoll хүртэл; ≤ 0 бол 1 с). Иргэн хараахан
// хариулаагүй бол QRCheck{Complete: false}; бусад нь Result-тэй ижил.
func (s *QRService) Check(ctx context.Context, sess *QRSession, serverPoll time.Duration) (*QRCheck, error) {
	if sess == nil || sess.SessionID == "" {
		return nil, errors.New("eid: QR.Check: QRSession шаардлагатай")
	}
	if serverPoll <= 0 {
		serverPoll = time.Second
	}
	r, err := (&SessionService{h: s.h}).Poll(ctx, sess.SessionID, serverPoll)
	if err != nil {
		return nil, qrServerErr(err)
	}
	if r.State != StateComplete {
		return &QRCheck{}, nil
	}
	res, err := s.finish(ctx, r, sess)
	if err != nil {
		return nil, err
	}
	return &QRCheck{Complete: true, Presentation: res}, nil
}

func (s *QRService) finish(ctx context.Context, r *SessionResult, sess *QRSession) (*QRPresentation, error) {
	if r.EndResult != EndResultOK {
		er := r.EndResult
		if er == "" {
			er = "UNKNOWN"
		}
		return nil, &SessionFailedError{EndResult: er}
	}
	if r.Presentation == nil || r.Presentation.JWS == "" {
		return nil, qrErr(CodeQRJWSMalformed, "хариунд presentation алга")
	}
	return s.Verify(ctx, r.Presentation.JWS, sess)
}

// Verify — хадгалсан presentation JWS-ийг QRSession-тэй тулгаж шалгана (Config.Trust, Config.QR.Issuer).
func (s *QRService) Verify(ctx context.Context, jws string, sess *QRSession) (*QRPresentation, error) {
	if sess == nil {
		return nil, errors.New("eid: QR.Verify: QRSession шаардлагатай")
	}
	t := s.trust
	if t.Revocation == nil {
		s.ocspOnce.Do(func() { s.ocsp = NewOCSPChecker(OCSPOptions{}) })
		t.Revocation = s.ocsp
	}
	return VerifyQRPresentation(ctx, jws, QRExpect{RPUUID: s.creds.RPUUID, SessionID: sess.SessionID, Nonce: sess.Nonce, Issuer: s.issuer}, t)
}

// VerifyQRPresentation — «Миний QR» presentation-ийг (иргэний PS256 JWS) CA гэрээний §6.1-ийн дарааллаар шалгана;
// эхний алдаагаар *QRError{Code} буцна. Итгэл (trust):
//
//   - TrustAnchorsPEM хоосон бол SDK-д суусан NationalRootCAPEM (AllowUntrusted энд үйлчлэхгүй — гинж үргэлж);
//     IntermediatesPEM nil бол CitizenIntermediatesPEM; x5c[1] нь зөвхөн завсрын нэр дэвшигч, anchor биш;
//   - AllowedIssuerSKIs хоосон бол CitizenIssuingCASKI (AllowAnyIssuer-аар унтарна); RequiredLevel "" = QUALIFIED;
//     leaf-ийн KeyUsage contentCommitment (SkipKeyUsageCheck-ээр л алгасна); RSA ≥ 2048; цаг ± 60 с;
//   - Revocation nil бол NewOCSPChecker (сүлжээ); RevocationMode "" = hard-fail (unknown / алдаа → QR_REVOCATION_UNKNOWN).
//
// TrustConfig-ийн PEM / SKI буруу бол энгийн error (тохиргооны алдаа). Сүлжээ зөвхөн OCSP-д.
func VerifyQRPresentation(ctx context.Context, jws string, exp QRExpect, trust TrustConfig) (*QRPresentation, error) {
	if len(trust.TrustAnchorsPEM) == 0 {
		trust.TrustAnchorsPEM = []string{NationalRootCAPEM}
	}
	if trust.Revocation == nil {
		trust.Revocation = NewOCSPChecker(OCSPOptions{})
	}
	v, err := NewValidator(trust)
	if err != nil {
		return nil, err
	}
	return verifyQR(ctx, jws, exp, v)
}

var b64urlSegRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func verifyQR(ctx context.Context, jws string, exp QRExpect, v *Validator) (*QRPresentation, error) {
	// 1. Хэлбэр.
	if len(jws) == 0 || len(jws) > qrMaxJWS {
		return nil, qrErr(CodeQRJWSMalformed, "JWS хоосон эсвэл %d байтаас урт", qrMaxJWS)
	}
	seg := strings.Split(jws, ".")
	if len(seg) != 3 {
		return nil, qrErr(CodeQRJWSMalformed, "compact JWS (3 хэсэг) биш")
	}
	for _, s := range seg {
		if !b64urlSegRe.MatchString(s) {
			return nil, qrErr(CodeQRJWSMalformed, "JWS-ийн хэсэг base64url биш")
		}
	}
	// 2–3. Header + x5c.
	leaf, inter, err := parseQRHeader(seg[0])
	if err != nil {
		return nil, err
	}
	now := exp.Now
	if now.IsZero() {
		now = time.Now()
	}
	// 4. Гинж.
	issuer, err := v.qrChain(leaf, inter, now)
	if err != nil {
		return nil, err
	}
	// 5. Цуцлалт.
	if err := v.qrRevocation(ctx, leaf, issuer); err != nil {
		return nil, err
	}
	// 6. Гарын үсэг: RSASSA-PSS SHA-256, MGF1-SHA-256, salt 32 — ирсэн ASCII байт дээр (дахин сериалчлахгүй).
	input := seg[0] + "." + seg[1]
	digest := sha256.Sum256([]byte(input))
	sig, err := base64.RawURLEncoding.Strict().DecodeString(seg[2])
	if err != nil {
		return nil, qrErr(CodeQRSignatureInvalid, "гарын үсэг base64url буруу")
	}
	pub := leaf.PublicKey.(*rsa.PublicKey) // qrChain RSA гэдгийг шалгасан
	if rsa.VerifyPSS(pub, crypto.SHA256, digest[:], sig, &rsa.PSSOptions{SaltLength: qrSaltLength, Hash: crypto.SHA256}) != nil {
		return nil, qrErr(CodeQRSignatureInvalid, "PS256 гарын үсэг таарсангүй")
	}
	// 7–12. Payload.
	pb, err := base64.RawURLEncoding.Strict().DecodeString(seg[1])
	if err != nil || !utf8.Valid(pb) {
		return nil, qrErr(CodeQRJWSMalformed, "payload base64url / UTF-8 буруу")
	}
	c, keys, photo, err := parseQRPayload(pb, leaf, exp, now)
	if err != nil {
		return nil, err
	}
	// 13.
	subj := ParseSubject(leaf)
	return &QRPresentation{
		JWS:      jws,
		Claims:   *c,
		Data:     maps.Clone(c.Data.Fields),
		Keys:     keys,
		Source:   c.Data.Source,
		Photo:    photo,
		Signer:   QRSigner{Certificate: leaf, ETSI: c.Sub, GivenName: subj.GivenName, Surname: subj.Surname, CommonName: subj.CommonName},
		SignedAt: time.Unix(c.Iat, 0),
		SHA256:   hex.EncodeToString(digest[:]),
	}, nil
}

// parseQRHeader — §6.1 алхам 2–3: яг {alg: PS256, typ: eidmn-myqr+jwt, x5c: [2 мөр]}; x5c стандарт base64 DER.
func parseQRHeader(seg string) (leaf, inter *x509.Certificate, err error) {
	bad := func(format string, a ...any) error { return qrErr(CodeQRHeaderInvalid, format, a...) }
	hb, err := base64.RawURLEncoding.Strict().DecodeString(seg)
	if err != nil || !utf8.Valid(hb) {
		return nil, nil, bad("header base64url / UTF-8 буруу")
	}
	members, err := jsonObject(hb)
	if err != nil {
		return nil, nil, bad("header JSON объект биш")
	}
	if len(members) != 3 {
		return nil, nil, bad("header нь яг alg, typ, x5c байх ёстой")
	}
	m := memberMap(members)
	if alg, ok := jsonString(m["alg"]); !ok || alg != "PS256" {
		return nil, nil, bad("alg PS256 биш")
	}
	if typ, ok := jsonString(m["typ"]); !ok || typ != QRJWSType {
		return nil, nil, bad("typ %s биш", QRJWSType)
	}
	raw, ok := m["x5c"]
	var arr []json.RawMessage
	if !ok || len(raw) == 0 || raw[0] != '[' || json.Unmarshal(raw, &arr) != nil || len(arr) != 2 {
		return nil, nil, bad("x5c нь яг 2 гэрчилгээтэй массив биш")
	}
	certs := make([]*x509.Certificate, 2)
	for i, r := range arr {
		s, ok := jsonString(r)
		if !ok || s == "" {
			return nil, nil, bad("x5c[%d] хоосон эсвэл мөр биш", i)
		}
		der, err := strictStdBase64(s)
		if err != nil {
			return nil, nil, bad("x5c[%d] стандарт base64 биш", i)
		}
		if certs[i], err = x509.ParseCertificate(der); err != nil {
			return nil, nil, bad("x5c[%d] X.509 биш", i)
		}
	}
	return certs[0], certs[1], nil
}

// qrChain — §6.1 алхам 4: leaf CA биш, RSA ≥ 2048, хугацаа ± QRClockSkew, KU contentCommitment, түвшин (QcStatements),
// гинж leaf → (x5c[1] ∪ intermediates) → anchors, шууд issuer-ийн SKI allowlist-д. Шууд issuer-ийг буцаана.
func (v *Validator) qrChain(leaf, extra *x509.Certificate, now time.Time) (*x509.Certificate, error) {
	bad := func(format string, a ...any) error { return qrErr(CodeQRChainInvalid, format, a...) }
	if leaf.IsCA {
		return nil, bad("x5c[0] нь CA гэрчилгээ")
	}
	if pub, ok := leaf.PublicKey.(*rsa.PublicKey); !ok || pub.N.BitLen() < 2048 {
		return nil, bad("гэрчилгээний түлхүүр RSA ≥ 2048 биш")
	}
	if now.Add(QRClockSkew).Before(leaf.NotBefore) || now.Add(-QRClockSkew).After(leaf.NotAfter) {
		return nil, bad("гэрчилгээ хүчинтэй хугацаанд биш (serial %s)", certSerial(leaf))
	}
	if v.checkKeyUsage && leaf.KeyUsage&x509.KeyUsageContentCommitment == 0 {
		return nil, bad("гарын үсгийн гэрчилгээнд KeyUsage contentCommitment алга")
	}
	level, err := CertificateLevelOf(leaf, "RAW_DIGEST_SIGNATURE")
	if err != nil {
		return nil, bad("qcStatements буруу")
	}
	if err := v.checkLevel(string(level)); err != nil {
		return nil, bad("гэрчилгээний түвшин %s хүрэлцэхгүй", level)
	}
	if len(v.anchors) == 0 {
		return nil, bad("trust anchor алга")
	}
	roots := x509.NewCertPool()
	for _, a := range v.anchors {
		roots.AddCert(a)
	}
	pool := x509.NewCertPool()
	pool.AddCert(extra)
	for _, c := range v.intermediates {
		pool.AddCert(c)
	}
	// EKU-г гэрээ шаарддаггүй (§6.1) — TS / .NET-тэй ижил үр дүнгийн тулд Any.
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: pool, CurrentTime: chainTime(leaf, now),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return nil, &QRError{Code: CodeQRChainInvalid, Reason: chainError(err).(*ValidationError).Reason, Cause: err}
	}
	for _, ch := range chains {
		if len(ch) < 2 {
			continue
		}
		is := ch[1]
		if len(v.allowedIssuers) == 0 {
			return is, nil
		}
		ski := is.SubjectKeyId
		if len(ski) == 0 {
			ski = leaf.AuthorityKeyId
		}
		if len(ski) > 0 && v.allowedIssuers[hex.EncodeToString(ski)] {
			return is, nil
		}
	}
	return nil, bad("гэрчилгээг гаргасан CA зөвшөөрөгдсөн иргэний issuer биш (AllowedIssuerSKIs)")
}

// qrRevocation — §6.1 алхам 5: revoked → QR_CERT_REVOKED; unknown / алдаа → hard-fail бол QR_REVOCATION_UNKNOWN,
// soft-fail бол зөвшөөрнө.
func (v *Validator) qrRevocation(ctx context.Context, leaf, issuer *x509.Certificate) error {
	var (
		status RevocationStatus
		err    error
	)
	if v.revocation != nil {
		status, err = v.revocation(ctx, leaf, issuer)
	}
	switch {
	case status == RevocationRevoked:
		return qrErr(CodeQRCertRevoked, "гэрчилгээ цуцлагдсан (serial %s)", certSerial(leaf))
	case err == nil && status == RevocationGood:
		return nil
	case v.revocationMode == RevocationSoftFail:
		return nil
	}
	return &QRError{Code: CodeQRRevocationUnknown, Reason: "гэрчилгээний цуцлалтын төлөв тогтоогдсонгүй (hard-fail)", Cause: err}
}

const (
	qrStatementPrefix = "Та "
	qrStatementSuffix = "-д «Миний мэдээлэл» хэсгийн бүх мэдээллийг хуваалцах гэж байна"
)

var qrSourceRe = regexp.MustCompile(`^[a-z0-9_-]{1,32}$`)

// parseQRPayload — §6.1 алхам 7–12.
func parseQRPayload(pb []byte, leaf *x509.Certificate, exp QRExpect, now time.Time) (*QRClaims, []string, []byte, error) {
	members, err := jsonObject(pb)
	if err != nil {
		return nil, nil, nil, qrErr(CodeQRJWSMalformed, "payload JSON объект биш")
	}
	m := memberMap(members)
	claims := func(format string, a ...any) error { return qrErr(CodeQRClaimsInvalid, format, a...) }
	var c QRClaims
	strs := []struct {
		name string
		dst  *string
	}{{"iss", &c.Iss}, {"sub", &c.Sub}, {"aud", &c.Aud}, {"rp_name", &c.RPName}, {"sid", &c.Sid}, {"nonce", &c.Nonce}, {"statement", &c.Statement}}
	for _, f := range strs {
		s, ok := jsonString(m[f.name])
		if !ok {
			return nil, nil, nil, claims("%s мөр биш", f.name)
		}
		*f.dst = s
	}
	var ok1, ok2 bool
	c.Iat, ok1 = jsonInt(m["iat"])
	c.Exp, ok2 = jsonInt(m["exp"])
	if !ok1 || !ok2 {
		return nil, nil, nil, claims("iat / exp бүхэл тоо биш")
	}
	if c.Iss != orDefault(exp.Issuer, DefaultQRIssuer) {
		return nil, nil, nil, claims("iss таарсангүй")
	}
	if c.Sub == "" || c.Sub != leaf.Subject.SerialNumber {
		return nil, nil, nil, claims("sub гэрчилгээний serialNumber-тэй таарсангүй")
	}
	if c.Statement != qrStatementPrefix+c.RPName+qrStatementSuffix {
		return nil, nil, nil, claims("statement rp_name-тэй таарсангүй")
	}
	if exp.RPUUID == "" || !strings.EqualFold(c.Aud, exp.RPUUID) {
		return nil, nil, nil, qrErr(CodeQRAudienceMismatch, "aud (RP UUID) таарсангүй")
	}
	if exp.SessionID == "" || c.Sid != exp.SessionID {
		return nil, nil, nil, qrErr(CodeQRSessionMismatch, "sid таарсангүй")
	}
	if exp.Nonce == "" || c.Nonce != exp.Nonce {
		return nil, nil, nil, qrErr(CodeQRNonceMismatch, "nonce таарсангүй")
	}
	if d := c.Exp - c.Iat; d <= 0 || d > int64(QRMaxAge/time.Second) {
		return nil, nil, nil, claims("exp − iat нь (0, 300] биш")
	}
	if time.Unix(c.Iat, 0).After(now.Add(QRClockSkew)) {
		return nil, nil, nil, qrErr(CodeQRNotYetValid, "iat ирээдүйд")
	}
	if !now.Before(time.Unix(c.Exp, 0).Add(QRClockSkew)) {
		return nil, nil, nil, qrErr(CodeQRExpired, "presentation-ийн хугацаа дууссан")
	}
	keys, photo, err := parseQRData(m["data"], &c.Data)
	if err != nil {
		return nil, nil, nil, err
	}
	return &c, keys, photo, nil
}

// parseQRData — §6.1 алхам 12 (§1.3-ийн хязгаар). Алдааны текстэд түлхүүр / утга орохгүй.
func parseQRData(raw json.RawMessage, d *QRData) ([]string, []byte, error) {
	bad := func(format string, a ...any) error { return qrErr(CodeQRDataInvalid, format, a...) }
	members, err := jsonObject(raw)
	if err != nil {
		return nil, nil, bad("data объект биш")
	}
	m := memberMap(members)
	for _, mb := range members {
		if mb.Key != "source" && mb.Key != "fields" && mb.Key != "photo" {
			return nil, nil, bad("data-д илүү гишүүн")
		}
	}
	src, ok := jsonString(m["source"])
	if !ok || !qrSourceRe.MatchString(src) {
		return nil, nil, bad("source буруу")
	}
	fields, err := jsonObject(m["fields"])
	if err != nil {
		return nil, nil, bad("fields объект биш")
	}
	if len(fields) > qrMaxFields {
		return nil, nil, bad("fields > %d", qrMaxFields)
	}
	d.Source, d.Fields = src, make(map[string]string, len(fields))
	keys := make([]string, 0, len(fields))
	for i, f := range fields {
		if n := utf8.RuneCountInString(f.Key); n == 0 || n > qrMaxKeyRunes || !utf8.ValidString(f.Key) {
			return nil, nil, bad("fields[%d]: түлхүүр 1–%d тэмдэгт биш", i, qrMaxKeyRunes)
		}
		for _, r := range f.Key {
			if r <= 0x1F || (r >= 0x7F && r <= 0x9F) {
				return nil, nil, bad("fields[%d]: түлхүүрт удирдах тэмдэгт", i)
			}
		}
		val, ok := jsonString(f.Val)
		if !ok {
			return nil, nil, bad("fields[%d]: утга мөр биш", i)
		}
		if len(val) > qrMaxValueBytes || strings.IndexByte(val, 0) >= 0 {
			return nil, nil, bad("fields[%d]: утга > %d байт эсвэл U+0000", i, qrMaxValueBytes)
		}
		d.Fields[f.Key] = val
		keys = append(keys, f.Key)
	}
	var photo []byte
	if raw, present := m["photo"]; present {
		s, ok := jsonString(raw)
		if !ok {
			return nil, nil, bad("photo мөр биш")
		}
		if photo, err = strictStdBase64(s); err != nil {
			return nil, nil, bad("photo стандарт base64 биш")
		}
		if len(photo) > qrMaxPhotoBytes {
			return nil, nil, bad("photo > %d байт", qrMaxPhotoBytes)
		}
		if !bytes.HasPrefix(photo, []byte{0xFF, 0xD8, 0xFF}) {
			return nil, nil, bad("photo JPEG биш")
		}
		d.Photo = s
	}
	if len(fields) == 0 && photo == nil {
		return nil, nil, bad("fields хоосон, photo ч алга")
	}
	return keys, photo, nil
}

// strictStdBase64 — RFC 4648 §4, padding-тай, мөр таслалгүй (Go-ийн decoder CR/LF-ийг алгасдаг тул тусад нь хаана).
func strictStdBase64(s string) ([]byte, error) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, errors.New("base64-д мөр таслал")
	}
	return base64.StdEncoding.Strict().DecodeString(s)
}

// jsonMember — JSON объектын нэг гишүүн (дарааллаа хадгална).
type jsonMember struct {
	Key string
	Val json.RawMessage
}

// jsonObject — нэг JSON объектыг гишүүдийн дарааллаар задална; давхардсан түлхүүр, илүү өгөгдөл → алдаа.
func jsonObject(raw []byte) ([]jsonMember, error) {
	if len(raw) == 0 {
		return nil, errors.New("хоосон")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("JSON объект биш")
	}
	var out []jsonMember
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		k, ok := tok.(string)
		if !ok || seen[k] {
			return nil, errors.New("түлхүүр буруу / давхардсан")
		}
		seen[k] = true
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		out = append(out, jsonMember{Key: k, Val: v})
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("JSON-ийн дараа илүү өгөгдөл")
	}
	return out, nil
}

func memberMap(ms []jsonMember) map[string]json.RawMessage {
	m := make(map[string]json.RawMessage, len(ms))
	for _, x := range ms {
		m[x.Key] = x.Val
	}
	return m
}

// jsonString — raw нь JSON мөр бол утга (null / тоо → false).
func jsonString(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

// jsonInt — raw нь бутархай / зэрэггүй JSON бүхэл тоо бол утга.
func jsonInt(raw json.RawMessage) (int64, bool) {
	n, err := strconv.ParseInt(string(raw), 10, 64)
	return n, err == nil
}
