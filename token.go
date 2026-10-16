package eid

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"
)

// TokenService — иргэний USB токен (PKCS#11, EC P-256):
//
//   - гэрчилгээ олголт (CA docs/TOKEN_CERT.md, RP-д TOKEN_ISSUE + SIGN эрх): IssueCertificate → иргэн утсаараа PIN2-оор
//     батална → Session.Poll (TokenCertificate.Status = ISSUED) → CertificateResult → VerifyTokenCertificates;
//   - токеноор нэвтрэлт (docs/TOKEN_AUTH.md, AUTH эрх): AuthChallenge → токен TokenAuthDigest-ийг CKM_ECDSA-аар зурна
//     (түүхий r||s) → AuthVerify.
//
// Алдаа: {"error","code"} — *APIError.Code (ж: TOKEN_LIMIT_REACHED → TokenLimitOf, TOKEN_IN_USE, TOKEN_SCOPE_CHANGE,
// CHALLENGE_EXPIRED, CERT_INVALID);
// түр алдаа (RATE_LIMITED, STATE_UNAVAILABLE, ISSUANCE_PENDING) — APIError.Retryable + RetryAfter.
type TokenService struct {
	h     *httpDoer
	creds Credentials
	v     *Validator // AuthVerify-ийн гэрчилгээний шалгалт (Config.Trust)
}

// TokenCertInput — POST /token/certificate-ийн оролт.
type TokenCertInput struct {
	// SignerEtsi — иргэн (PNOMN-…), батлах push түүний утсанд очно.
	SignerEtsi string
	// CSRAuth, CSRSign — PKCS#10 DER (EC P-256, ecdsa-with-SHA256, өөр өөр түлхүүр, ≤ 4 KiB).
	CSRAuth, CSRSign []byte
	// TokenSerial — токены serial ([A-Za-z0-9-]{1,64}).
	TokenSerial string
	// TokenLabel — заавал биш (≤ 64); "" бол илгээхгүй.
	TokenLabel string
	// OnBehalfOf — байгууллагын токен (NTRMN-…); "" = хувийн токен.
	OnBehalfOf string
}

// TokenCertStart — олголтын эхлэлийн хариу: утсанд очсон SIGN session.
type TokenCertStart struct {
	SessionID string
	// VC — иргэнд ХАРУУЛАХ баталгаажуулах код (ПИН биш).
	VC string
	// CSRAuthSHA256, CSRSignSHA256 — hex(SHA-256(CSR DER)); SDK илгээсэн CSR-тэй тулгасан.
	CSRAuthSHA256 string
	CSRSignSHA256 string
	ExpiresAt     string
}

// TokenCertItem — олгосон нэг гэрчилгээ.
type TokenCertItem struct {
	// Certificate — base64 DER.
	Certificate    string `json:"certificate"`
	CertificatePEM string `json:"certificatePem"`
	SerialHex      string `json:"serialHex"`
	NotBefore      string `json:"notBefore"`
	NotAfter       string `json:"notAfter"`
}

// TokenOrganization — токенд холбогдсон байгууллага.
type TokenOrganization struct {
	Etsi string `json:"etsi"`
	Name string `json:"name"`
}

// TokenCertResult — GET /token/certificate/{sessionID} (зөвхөн үүсгэсэн RP, 24 цаг идэмпотент).
type TokenCertResult struct {
	Status string         `json:"status"`
	Auth   *TokenCertItem `json:"auth"`
	Sign   *TokenCertItem `json:"sign"`
	// Chain — base64 DER: 04, 03, 02 (root-гүй).
	Chain    []string `json:"chain"`
	ChainPEM string   `json:"chainPem"`
	// Organization — хувийн токенд nil.
	Organization     *TokenOrganization `json:"organization"`
	KeyMedium        string             `json:"keyMedium"`
	CertificateLevel string             `json:"certificateLevel"`
	Raw              json.RawMessage    `json:"-"`
}

// TokenAuthChallenge — POST /token/auth/challenge хариу. Токен TokenAuthDigest(RPUUID, Challenge)-ийг зурна.
type TokenAuthChallenge struct {
	ChallengeID string `json:"challengeId"`
	// Challenge — base64 (32 байт).
	Challenge string `json:"challenge"`
	// RPUUID — CA-ийн холбосон RP (жижиг үсэг) — hash-д ЯГ ЭНЭ мөр орно.
	RPUUID    string    `json:"rpUUID"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// TokenIdentity — CA-ийн баталгаажуулсан иргэн. GivenName/Surname — KYC бүртгэлээс (кирилл).
type TokenIdentity struct {
	Etsi      string `json:"etsi"`
	GivenName string `json:"givenName"`
	Surname   string `json:"surname"`
}

// TokenAuthResult — POST /token/auth/verify хариу (endResult OK, identity нь гэрчилгээний subject — SDK тулгасан).
type TokenAuthResult struct {
	Identity  TokenIdentity
	SerialHex string
	NotAfter  time.Time
	// Organization — токен байгууллагад холбогдсон бол; эс бөгөөс nil.
	Organization *TokenOrganization
	Raw          json.RawMessage
}

type tokenCertRequest struct {
	RelyingPartyUUID string            `json:"relyingPartyUUID"`
	RelyingPartyName string            `json:"relyingPartyName"`
	Signer           map[string]string `json:"signer"`
	CSRAuth          string            `json:"csrAuth"`
	CSRSign          string            `json:"csrSign"`
	TokenSerial      string            `json:"tokenSerial"`
	TokenLabel       string            `json:"tokenLabel,omitempty"`
	OnBehalfOf       string            `json:"onBehalfOf"`
	Flow             string            `json:"flow"`
}

// IssueCertificate — POST /token/certificate: токены AUTH + SIGN гэрчилгээ олголт эхлүүлнэ (иргэн утсаараа батална).
// CA-ийн буцаасан CSR hash-ууд илгээсэнтэй таарахгүй бол *ValidationError.
//
// Сунгалт: ижил TokenSerial дээр энэ иргэний ACTIVE бүртгэл байвал олголт = сунгалт, scope-ийг хадгална — байгууллагын
// токен зөвхөн тэр байгууллагаар (OnBehalfOf ижил), хувийн токен зөвхөн хувиараа. Өөр scope бол 409
// CodeTokenScopeChange (override үгүй); scope солих = иргэн eID апп-аас токеноо цуцлаад шинээр олгуулна. Бусад 409:
// CodeTokenLimitReached (TokenLimitOf), CodeTokenInUse, CodeAccountDeletePending.
func (t *TokenService) IssueCertificate(ctx context.Context, in TokenCertInput) (*TokenCertStart, error) {
	if strings.TrimSpace(in.SignerEtsi) == "" || len(in.CSRAuth) == 0 || len(in.CSRSign) == 0 || strings.TrimSpace(in.TokenSerial) == "" {
		return nil, errors.New("eid: token: SignerEtsi, CSRAuth, CSRSign, TokenSerial шаардлагатай")
	}
	// CA DisallowUnknownFields — яг эдгээр талбар.
	req := tokenCertRequest{
		RelyingPartyUUID: t.creds.RPUUID,
		RelyingPartyName: t.creds.RPName,
		Signer:           map[string]string{"etsi": strings.TrimSpace(in.SignerEtsi)},
		CSRAuth:          base64.StdEncoding.EncodeToString(in.CSRAuth),
		CSRSign:          base64.StdEncoding.EncodeToString(in.CSRSign),
		TokenSerial:      strings.TrimSpace(in.TokenSerial),
		TokenLabel:       in.TokenLabel,
		OnBehalfOf:       strings.TrimSpace(in.OnBehalfOf),
		Flow:             "notification",
	}
	var r struct {
		SessionID     string  `json:"sessionID"`
		VC            vcValue `json:"vc"`
		CSRAuthSHA256 string  `json:"csrAuthSha256"`
		CSRSignSHA256 string  `json:"csrSignSha256"`
		ExpiresAt     string  `json:"expiresAt"`
	}
	if err := t.h.postJSON(ctx, routeTokenCertificate.expand(), req, &r); err != nil {
		return nil, err
	}
	if !hexSHA256Equal(r.CSRAuthSHA256, in.CSRAuth) || !hexSHA256Equal(r.CSRSignSHA256, in.CSRSign) {
		return nil, invalid("token: CA-ийн csrAuthSha256/csrSignSha256 илгээсэн CSR-тэй таарсангүй")
	}
	return &TokenCertStart{
		SessionID: r.SessionID, VC: string(r.VC),
		CSRAuthSHA256: strings.ToLower(r.CSRAuthSHA256), CSRSignSHA256: strings.ToLower(r.CSRSignSHA256), ExpiresAt: r.ExpiresAt,
	}, nil
}

// tokenResultTimeout — CA олголт дуусаагүй бол ≤ 15с хүлээдэг.
const tokenResultTimeout = 30 * time.Second

// CertificateResult — GET /token/certificate/{sessionID}: олгосон AUTH + SIGN гэрчилгээ + гинж. Токенд бичихээс өмнө
// VerifyTokenCertificates-аар CSR-ийн түлхүүртэй тулга. Эхлэл ба батлалтын хооронд нөхцөл өөрчлөгдсөн бол 409
// (CodeTokenLimitReached / CodeTokenInUse / CodeTokenScopeChange / CodeAccountDeletePending) — гэрчилгээ гараагүй.
func (t *TokenService) CertificateResult(ctx context.Context, sessionID string) (*TokenCertResult, error) {
	var r TokenCertResult
	path := routeTokenCertificateResult.expand(sessionID)
	if err := t.h.getJSON(ctx, path, tokenResultTimeout, &r.Raw); err != nil {
		return nil, err
	}
	if len(r.Raw) > 0 {
		if err := decodeJSON(r.Raw, path, &r); err != nil {
			return nil, err
		}
	}
	return &r, nil
}

// VerifyTokenCertificates — олгосон AUTH/SIGN гэрчилгээ бүр задарч, илгээсэн CSR-ийн public key-тэй (SPKI) ЯГ таарахыг
// шалгана. Таарахгүй бол *ValidationError — гэрчилгээг токенд бүү бич.
func VerifyTokenCertificates(r *TokenCertResult, csrAuth, csrSign []byte) error {
	if r == nil || r.Auth == nil || r.Sign == nil {
		return invalid("token: auth/sign гэрчилгээ алга")
	}
	for _, p := range []struct {
		name string
		item *TokenCertItem
		csr  []byte
	}{{"auth", r.Auth, csrAuth}, {"sign", r.Sign, csrSign}} {
		csr, err := x509.ParseCertificateRequest(p.csr)
		if err != nil {
			return fmt.Errorf("eid: token: %s CSR задарсангүй: %w", p.name, err)
		}
		der, err := base64.StdEncoding.DecodeString(p.item.Certificate)
		if err != nil {
			return invalid("token: %s гэрчилгээ base64 буруу", p.name)
		}
		crt, err := x509.ParseCertificate(der)
		if err != nil {
			return invalid("token: %s гэрчилгээ задарсангүй", p.name)
		}
		if !bytes.Equal(crt.RawSubjectPublicKeyInfo, csr.RawSubjectPublicKeyInfo) {
			return invalid("token: %s гэрчилгээний түлхүүр CSR-ийнхтэй таарсангүй", p.name)
		}
	}
	return nil
}

// AuthChallenge — POST /token/auth/challenge: энэ RP-д холбогдсон нэг удаагийн challenge (2 мин).
func (t *TokenService) AuthChallenge(ctx context.Context) (*TokenAuthChallenge, error) {
	var r TokenAuthChallenge
	body := map[string]string{"relyingPartyUUID": t.creds.RPUUID, "relyingPartyName": t.creds.RPName}
	if err := t.h.postJSON(ctx, routeTokenAuthChallenge.expand(), body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// AuthVerify — POST /token/auth/verify: токены AUTH гэрчилгээ (DER) + challenge дээрх түүхий r||s (64 байт).
//
// v0.6.0-аас SDK CA-ийн OK-д дангаар итгэхгүй (бусад auth-тай ижил): CA руу илгээхээс өмнө ch.RPUUID == энэ RP,
// гарын үсэг TokenAuthDigest(ch.RPUUID, ch.Challenge) дээр гэрчилгээний түлхүүрээр (EC P-256) таарах, гэрчилгээ
// Config.Trust-аар (хугацаа, зориулалт auth, гинж, issuer allowlist) хүчинтэйг шалгана (эс бөгөөс *ValidationError,
// CA руу явахгүй); дараа нь CA-ийн endResult == OK ба identity.etsi == гэрчилгээний SERIALNUMBER. Цуцлалтыг CA шалгана;
// RP нэмж Validator.CheckRevocation дуудаж болно. ch — AuthChallenge-ийн хариу (RP хадгалсан, эсвэл клиентээс буцаж
// ирсэн — CA ChallengeID-ээр тулгана). Challenge нэг удаагийн — алдааны дараа шинээр авна.
func (t *TokenService) AuthVerify(ctx context.Context, ch *TokenAuthChallenge, certDER, signature []byte) (*TokenAuthResult, error) {
	crt, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("eid: token auth: гэрчилгээ задарсангүй: %w", err)
	}
	if ch == nil || ch.ChallengeID == "" || len(signature) == 0 {
		return nil, errors.New("eid: token auth: challenge (ChallengeID, Challenge, RPUUID) ба signature шаардлагатай")
	}
	if !strings.EqualFold(ch.RPUUID, t.creds.RPUUID) {
		return nil, invalid("token auth: challenge өөр RP-д холбогдсон (rpUUID)")
	}
	digest, err := TokenAuthDigest(ch.RPUUID, ch.Challenge)
	if err != nil {
		return nil, &ValidationError{Reason: "token auth: challenge/rpUUID хэлбэр буруу", Cause: err}
	}
	if !verifyTokenSignature(crt, digest, signature) {
		return nil, invalid("token auth: гарын үсэг challenge-тэй таарсангүй (EC P-256 r||s)")
	}
	if t.v == nil {
		return nil, errors.New("eid: token auth: Validator алга (NewClient-ээр үүсгэнэ үү)")
	}
	if err := t.v.verifyTokenAuthCertificate(crt); err != nil {
		return nil, err
	}
	body := map[string]string{
		"challengeId": ch.ChallengeID,
		"certificate": base64.StdEncoding.EncodeToString(certDER),
		"signature":   base64.StdEncoding.EncodeToString(signature),
	}
	var raw json.RawMessage
	path := routeTokenAuthVerify.expand()
	if err := t.h.postJSON(ctx, path, body, &raw); err != nil {
		return nil, err
	}
	var r struct {
		Result struct {
			EndResult string `json:"endResult"`
		} `json:"result"`
		Identity TokenIdentity `json:"identity"`
		Cert     struct {
			SerialHex string    `json:"serialHex"`
			NotAfter  time.Time `json:"notAfter"`
		} `json:"cert"`
		Organization *TokenOrganization `json:"organization"`
	}
	if err := decodeJSON(raw, path, &r); err != nil {
		return nil, err
	}
	if r.Result.EndResult != EndResultOK {
		return nil, invalid("token auth: endResult OK биш")
	}
	if r.Identity.Etsi == "" || r.Identity.Etsi != crt.Subject.SerialNumber {
		return nil, invalid("token auth: identity.etsi нь гэрчилгээний SERIALNUMBER биш")
	}
	org := r.Organization
	if org != nil && org.Etsi == "" {
		org = nil
	}
	return &TokenAuthResult{Identity: r.Identity, SerialHex: r.Cert.SerialHex, NotAfter: r.Cert.NotAfter, Organization: org, Raw: raw}, nil
}

// verifyTokenSignature — токены түүхий r||s (P-256, 64 байт) нь digest дээр гэрчилгээний түлхүүрээр таарах эсэх.
func verifyTokenSignature(crt *x509.Certificate, digest, sig []byte) bool {
	pub, ok := crt.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() || len(sig) != 64 {
		return false
	}
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	return ecdsa.Verify(pub, digest, r, s)
}

var rpUUIDRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// TokenAuthDigest — токены зурах 32 байт: SHA-256("eID-TOKEN-AUTH" || rpUUID || challenge) (docs/TOKEN_AUTH.md).
// rpUUID — challenge хариуны RPUUID (жижиг үсэг, 36), challengeB64 — challenge (32 байт base64). Токен үүнийг
// CKM_ECDSA-аар (урьдчилан hash-лэсэн) зурж, түүхий r||s (64 байт)-ийг AuthVerify-д өгнө.
func TokenAuthDigest(rpUUID, challengeB64 string) ([]byte, error) {
	if !rpUUIDRe.MatchString(rpUUID) {
		return nil, errors.New("eid: token auth: rpUUID жижиг үсгийн 36 тэмдэгт UUID биш")
	}
	ch, err := base64.StdEncoding.DecodeString(challengeB64)
	if err != nil || len(ch) != 32 {
		return nil, errors.New("eid: token auth: challenge 32 байт base64 биш")
	}
	h := sha256.New()
	h.Write([]byte("eID-TOKEN-AUTH"))
	h.Write([]byte(rpUUID))
	h.Write(ch)
	return h.Sum(nil), nil
}

// Токены хязгаарын төрөл (TokenLimit.Kind).
const (
	TokenKindPersonal     = "PERSONAL"
	TokenKindOrganization = "ORGANIZATION"
)

// Токены олголтын 409 кодууд (*APIError.Code; session-ий TokenCertificate.ErrorCode-д ч ирнэ).
const (
	// CodeTokenLimitReached — иргэний токены хязгаар хүрсэн (TokenLimitOf-оор дэлгэрэнгүй).
	CodeTokenLimitReached = "TOKEN_LIMIT_REACHED"
	// CodeTokenInUse — TokenSerial өөр иргэнд хүчинтэй гэрчилгээтэй бүртгэлтэй.
	CodeTokenInUse = "TOKEN_IN_USE"
	// CodeTokenScopeChange — сунгалт scope-ийг солих гэсэн (хувийн ↔ байгууллага, эсвэл өөр OnBehalfOf). Override үгүй:
	// иргэн eID апп-аас токеноо цуцалж (/v3/mobile/tokens/{tokenSerial}/revoke) байж шинэ scope-оор олгуулна.
	CodeTokenScopeChange = "TOKEN_SCOPE_CHANGE"
	// CodeAccountDeletePending — иргэн «Бүртгэл устгах» хүсэлт (PENDING) өгсөн: токен олгохгүй (CA !377).
	CodeAccountDeletePending = "ACCOUNT_DELETE_PENDING"
)

// TokenCertInfo — discovery (/.well-known/eid)-ийн tokenCertificate блок.
type TokenCertInfo struct {
	Enabled bool `json:"enabled"`
	// Issue — POST олголтын бүтэн URL; Result — GET үр дүнгийн URL template ({sessionID}).
	Issue  string `json:"issue"`
	Result string `json:"result"`
	// Permission — шаардлагатай RP эрх (TOKEN_ISSUE).
	Permission       string `json:"permission"`
	CertificateLevel string `json:"certificateLevel"`
	KeyAlgorithm     string `json:"keyAlgorithm"`
	// OnBehalfOf — "optional": хоосон = хувийн токен.
	OnBehalfOf string `json:"onBehalfOf"`
	// ScopeLockedOnRenewal — true: сунгалт (ижил TokenSerial дээр ACTIVE бүртгэлтэй) scope-ийг хадгална; өөр scope бол
	// 409 CodeTokenScopeChange. Хуучин CA-д талбар алга → false.
	ScopeLockedOnRenewal bool            `json:"scopeLockedOnRenewal"`
	Raw                  json.RawMessage `json:"-"`
}

// CertificateInfo — discovery-ийн tokenCertificate блок. Блок байхгүй (хуучин CA) бол Enabled false.
func (t *TokenService) CertificateInfo(ctx context.Context) (*TokenCertInfo, error) {
	var d struct {
		TokenCertificate json.RawMessage `json:"tokenCertificate"`
	}
	if err := t.h.getJSON(ctx, discoveryPath, 0, &d); err != nil {
		return nil, err
	}
	var out TokenCertInfo
	if len(d.TokenCertificate) > 0 && string(d.TokenCertificate) != "null" {
		if err := decodeJSON(d.TokenCertificate, discoveryPath, &out); err != nil {
			return nil, err
		}
		out.Raw = d.TokenCertificate
	}
	return &out, nil
}

// TokenLimit — 409 TOKEN_LIMIT_REACHED-ийн дэлгэрэнгүй: иргэн Kind төрлийн Limit хүчинтэй токентой (Limit 0 = тухайн
// төрлийн олголт хаалттай). Organization — зөвхөн ORGANIZATION-д (NTRMN-…).
type TokenLimit struct {
	Kind         string
	Limit        int
	Organization string
}

// TokenLimitOf — err нь 409 TOKEN_LIMIT_REACHED бол түүний {kind, limit, organization}. Гэрээнээс гадуур хэлбэр бол
// (nil, false) — татгалзал хүчинтэй хэвээр, дэлгэрэнгүйгүй.
func TokenLimitOf(err error) (*TokenLimit, bool) {
	var api *APIError
	if !errors.As(err, &api) || api.Code != CodeTokenLimitReached {
		return nil, false
	}
	var b struct {
		Kind         string  `json:"kind"`
		Limit        *int    `json:"limit"`
		Organization *string `json:"organization"`
	}
	if json.Unmarshal([]byte(api.Body), &b) != nil || b.Limit == nil || *b.Limit < 0 {
		return nil, false
	}
	out := &TokenLimit{Kind: b.Kind, Limit: *b.Limit}
	switch b.Kind {
	case TokenKindPersonal:
	case TokenKindOrganization:
		if b.Organization == nil || !strings.HasPrefix(*b.Organization, "NTRMN-") {
			return nil, false
		}
		out.Organization = *b.Organization
	default:
		return nil, false
	}
	return out, true
}

// hexSHA256Equal — hexDigest нь data-ийн SHA-256 эсэх (том/жижиг үсэг хамаагүй).
func hexSHA256Equal(hexDigest string, data []byte) bool {
	want, err := hex.DecodeString(strings.TrimSpace(hexDigest))
	if err != nil || len(want) != sha256.Size {
		return false
	}
	got := sha256.Sum256(data)
	return subtle.ConstantTimeCompare(got[:], want) == 1
}
