// Package oidc — «eID-ээр нэвтрэх»: OpenID Connect (Authorization Code + PKCE S256) RP тал. Зөвхөн backend
// (client_secret).
//
// Нэвтрэх хуудсыг (QR / push / утасны хөтчөөс шууд апп) eID сервер өөрөө харуулна; RP зөвхөн:
//
//  1. CreateAuthorization → State/Nonce/CodeVerifier-ийг httpOnly cookie / server session-д хадгалаад URL руу 302;
//  2. HandleCallback(query, хадгалсан) → state тулгаж, code-ийг id_token болгон сольж, ES256-аар шалгана.
//
// Гэрээ: https://developer.eidmongolia.mn/#oidc (issuer https://login.eidmongolia.mn).
package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	eid "github.com/gerege-systems/eid-mongolia-sdk-go"
)

// Issuer — eID-ийн OIDC issuer (төгсгөлд "/" байхгүй).
const Issuer = "https://login.eidmongolia.mn"

// SDK-ийн OIDC-д хүлээдэг утгууд — гэрээний тест (contract_test.go, `go test -tags contract`) discovery-тэй тулгана.
const (
	defaultScope            = "openid"
	pkceMethod              = "S256"
	idTokenAlg              = "ES256"
	tokenEndpointAuthMethod = "client_secret_basic" // Authorization: Basic (RFC 6749 §2.3.1)
)

// acr утгууд — иргэний гэрчилгээний бодит түвшин.
const (
	ACRQualified = "urn:eidmongolia:loa:qualified"
	ACRAdvanced  = "urn:eidmongolia:loa:advanced"
)

const (
	clockSkew      = 60 // секунд
	cacheTTL       = time.Hour
	defaultTimeout = 10 * time.Second
	maxBody        = 1 << 20
)

// ErrorCode — OIDC алдааны код: authorize redirect (RFC 6749 §4.1.2.1), token endpoint (§5.2)-ийн стандарт
// кодууд ба SDK-ийн өөрийн шалгалтын кодууд.
type ErrorCode string

const (
	// ErrAccessDenied — иргэн татгалзсан, нэвтрэлтийн хугацаа дууссан, эсвэл гэрчилгээний шалгалт унасан → «дахин оролд».
	ErrAccessDenied            ErrorCode = "access_denied"
	ErrLoginRequired           ErrorCode = "login_required"
	ErrInvalidRequest          ErrorCode = "invalid_request"
	ErrInvalidScope            ErrorCode = "invalid_scope"
	ErrUnauthorizedClient      ErrorCode = "unauthorized_client"
	ErrUnsupportedResponseType ErrorCode = "unsupported_response_type"
	ErrRequestNotSupported     ErrorCode = "request_not_supported"
	ErrTemporarilyUnavailable  ErrorCode = "temporarily_unavailable"
	ErrServerError             ErrorCode = "server_error"
	ErrInvalidClient           ErrorCode = "invalid_client"
	ErrInvalidGrant            ErrorCode = "invalid_grant"
	ErrUnsupportedGrantType    ErrorCode = "unsupported_grant_type"
	// ErrStateMismatch — callback-ийн state хадгалсантай таарсангүй (CSRF / өөр tab / cookie дууссан) → дахин эхлүүл.
	ErrStateMismatch ErrorCode = "state_mismatch"
	// ErrInvalidCallback — code алга / хэт урт, эсвэл iss параметр өөр.
	ErrInvalidCallback ErrorCode = "invalid_callback"
	// ErrInvalidIDToken — id_token-ий гарын үсэг / iss / aud / exp / iat / nonce шалгалт унасан (ИТГЭХГҮЙ).
	ErrInvalidIDToken ErrorCode = "invalid_id_token"
	// ErrDiscoveryFailed — discovery/JWKS буруу эсвэл issuer таарахгүй.
	ErrDiscoveryFailed ErrorCode = "discovery_failed"
)

var knownCodes = map[string]bool{
	"access_denied": true, "login_required": true, "invalid_request": true, "invalid_scope": true,
	"unauthorized_client": true, "unsupported_response_type": true, "request_not_supported": true,
	"temporarily_unavailable": true, "server_error": true, "invalid_client": true, "invalid_grant": true,
	"unsupported_grant_type": true,
}

func knownOrServerError(s string) ErrorCode {
	if knownCodes[s] {
		return ErrorCode(s)
	}
	return ErrServerError
}

// Error — OIDC урсгалын алдаа; Code-оор салгана. Description нь серверийн error_description — логт л, хэрэглэгчид
// шууд харуулахгүй.
type Error struct {
	Code        ErrorCode
	Message     string
	Description string
}

func (e *Error) Error() string { return "eid/oidc: " + e.Message }

func badToken(why string) error {
	return &Error{Code: ErrInvalidIDToken, Message: "id_token: " + why}
}

// Config — Client-ийн тохиргоо.
type Config struct {
	// ClientID — RP UUID (relyingPartyUUID).
	ClientID string
	// ClientSecret — RP API secret (rp_sk_…), зөвхөн backend-д.
	ClientSecret string
	// RedirectURI — бүртгэлтэй redirect URI (https), тэмдэгт бүрээрээ таарах ёстой.
	RedirectURI string
	// Issuer — "" = Issuer.
	Issuer string
	// Scope — "" = "openid". Иргэний ETSI дугаар хэрэгтэй бол "openid pnomn" (RP-д PNOMN эрх).
	Scope string
	// Timeout — HTTP дуудлага бүрийн хугацаа (0 = 10s).
	Timeout time.Duration
	// HTTPClient — nil = шинэ http.Client. Redirect дагахгүй (SDK CheckRedirect-ийг дарна). mTLS-тэй RP:
	// RP-API-д хэрэглэдэг client cert-тэй Transport (README §6).
	HTTPClient *http.Client
	// UseMTLSEndpointAliases — RFC 8705 §5: true бол code солих хүсэлт discovery-ийн
	// mtls_endpoint_aliases["token_endpoint"] руу явна (require_mtls-тэй RP; HTTPClient-д client cert заавал).
	// Discovery-д alias байхгүй бол TokenEndpoint руу буцна; alias https биш бол ErrDiscoveryFailed. Анхдагч false.
	UseMTLSEndpointAliases bool
}

// Discovery — /.well-known/openid-configuration-ийн хэрэгтэй талбарууд.
type Discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	// MTLSEndpointAliases — RFC 8705 §5 (ж: "token_endpoint" → https://rp.eidmongolia.mn/oauth2/token).
	MTLSEndpointAliases map[string]string `json:"mtls_endpoint_aliases,omitempty"`
}

// AuthorizationOptions — CreateAuthorization-ийн нэмэлт тохиргоо.
type AuthorizationOptions struct {
	// Scope — энэ хүсэлтэд scope-ыг дарна.
	Scope string
	// Display — "touch" (анхдагч: утасны хөтчөөс шууд eID апп) эсвэл "page" (үргэлж нэвтрэх хуудас, ж: таблет киоск).
	Display string
}

// Authorization — RP-ийн хадгалах гүйлгээ: httpOnly cookie / server session-д (браузерийн JS-д биш).
type Authorization struct {
	// URL — хөтчийг энэ рүү 302.
	URL          string
	State        string
	Nonce        string
	CodeVerifier string
}

// CallbackChecks — CreateAuthorization-аас хадгалсан утгууд.
type CallbackChecks struct {
	State        string `json:"state"`
	Nonce        string `json:"nonce"`
	CodeVerifier string `json:"codeVerifier"`
}

// Audience — aud claim (мөр эсвэл массив).
type Audience []string

// UnmarshalJSON — "aud": "x" эсвэл ["x","y"].
func (a *Audience) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*a = Audience{s}
		return nil
	}
	var l []string
	if err := json.Unmarshal(b, &l); err != nil {
		return err
	}
	*a = l
	return nil
}

// Claims — id_token-ий claim-ууд.
type Claims struct {
	Iss string   `json:"iss"`
	Aud Audience `json:"aud"`
	Azp string   `json:"azp,omitempty"`
	// Sub — pairwise: RP тус бүрд өөр, иргэнд тогтмол. Хэрэглэгчийг ҮҮГЭЭР таньна (нэр/имэйлээр биш).
	Sub   string `json:"sub"`
	Exp   int64  `json:"exp"`
	Iat   int64  `json:"iat"`
	Nonce string `json:"nonce"`
	// AuthTime — иргэн баталгаажуулсан мөч (Unix сек).
	AuthTime int64 `json:"auth_time"`
	// Acr — ACRQualified эсвэл ACRAdvanced.
	Acr string `json:"acr"`
	// GivenName, FamilyName — гэрчилгээний GIVENNAME / SURNAME, латин (ICAO, том үсэг); FamilyName = эцэг/эхийн нэр.
	GivenName  string `json:"given_name"`
	FamilyName string `json:"family_name"`
	// GivenNameMN, FamilyNameMN — кирилл (бүртгэлд байхгүй бол "").
	GivenNameMN  string `json:"given_name_mn,omitempty"`
	FamilyNameMN string `json:"family_name_mn,omitempty"`
	// PNOMN — PNOMN-<иргэний дугаар>; зөвхөн pnomn scope + PNOMN эрхтэй үед.
	PNOMN string `json:"pnomn,omitempty"`
}

// CallbackResult — HandleCallback-ийн амжилттай үр дүн.
type CallbackResult struct {
	Claims  *Claims
	IDToken string
}

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// Client — eID OIDC RP client. Goroutine-safe.
type Client struct {
	cfg    Config
	issuer string
	scope  string
	hc     *http.Client
	now    func() time.Time

	mu      sync.Mutex
	disc    *Discovery
	discAt  time.Time
	keys    []jwk
	keysAt  time.Time
	hasKeys bool
}

// NewClient — тохиргоог шалгаж Client үүсгэнэ.
func NewClient(cfg Config) (*Client, error) {
	if cfg.ClientID == "" {
		return nil, errors.New("eid/oidc: ClientID хоосон")
	}
	if cfg.ClientSecret == "" {
		return nil, errors.New("eid/oidc: ClientSecret хоосон")
	}
	if !strings.HasPrefix(cfg.RedirectURI, "https://") {
		return nil, errors.New("eid/oidc: RedirectURI https:// байх ёстой")
	}
	iss := cfg.Issuer
	if iss == "" {
		iss = Issuer
	}
	scope := cfg.Scope
	if scope == "" {
		scope = defaultScope
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	hc := &http.Client{}
	if cfg.HTTPClient != nil {
		c := *cfg.HTTPClient
		hc = &c
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{cfg: cfg, issuer: strings.TrimRight(iss, "/"), scope: scope, hc: hc, now: time.Now}, nil
}

// Issuer — тохируулсан issuer.
func (c *Client) Issuer() string { return c.issuer }

// Discover — discovery document (1 цаг cache, алдааг cache-лэхгүй). issuer нь тохиргоотой ЯГ таарах ёстой
// (OIDC Discovery §4.3), endpoint-ууд https.
func (c *Client) Discover(ctx context.Context) (*Discovery, error) {
	c.mu.Lock()
	if c.disc != nil && c.now().Sub(c.discAt) < cacheTTL {
		d := c.disc
		c.mu.Unlock()
		return d, nil
	}
	c.mu.Unlock()
	var d Discovery
	if err := c.getJSON(ctx, c.issuer+"/.well-known/openid-configuration", &d); err != nil {
		return nil, err
	}
	if d.Issuer != c.issuer {
		return nil, &Error{Code: ErrDiscoveryFailed, Message: "discovery-ийн issuer таарахгүй (хүлээсэн " + c.issuer + ")"}
	}
	for k, v := range map[string]string{"authorization_endpoint": d.AuthorizationEndpoint, "token_endpoint": d.TokenEndpoint, "jwks_uri": d.JWKSURI} {
		if !strings.HasPrefix(v, "https://") {
			return nil, &Error{Code: ErrDiscoveryFailed, Message: "discovery: " + k + " буруу"}
		}
	}
	c.mu.Lock()
	c.disc, c.discAt = &d, c.now()
	c.mu.Unlock()
	return &d, nil
}

// CreateAuthorization — authorize URL + санамсаргүй State / Nonce / PKCE CodeVerifier. RP эдгээрийг хөтчийн
// session-тэй холбож хадгалаад хөтчийг URL руу 302 хийнэ. o = nil бол анхдагч.
func (c *Client) CreateAuthorization(ctx context.Context, o *AuthorizationOptions) (*Authorization, error) {
	if o == nil {
		o = &AuthorizationOptions{}
	}
	d, err := c.Discover(ctx)
	if err != nil {
		return nil, err
	}
	state, nonce, verifier := randomB64URL(), randomB64URL(), randomB64URL() // 43 тэмдэгт
	u, err := url.Parse(d.AuthorizationEndpoint)
	if err != nil {
		return nil, &Error{Code: ErrDiscoveryFailed, Message: "authorization_endpoint буруу URL"}
	}
	scope := o.Scope
	if scope == "" {
		scope = c.scope
	}
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {c.cfg.ClientID},
		"redirect_uri":          {c.cfg.RedirectURI},
		"scope":                 {scope},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {PKCEChallenge(verifier)},
		"code_challenge_method": {pkceMethod},
	}
	if o.Display != "" {
		q.Set("display", o.Display)
	}
	u.RawQuery = q.Encode()
	return &Authorization{URL: u.String(), State: state, Nonce: nonce, CodeVerifier: verifier}, nil
}

// HandleCallback — redirect_uri руу ирсэн callback-ийг шийднэ (query = r.URL.Query()): state тулгах (constant-time;
// таарахгүй бол code-ийг огт солихгүй) → iss (RFC 9207, байвал) → error бол *Error → code солих → id_token шалгах.
// Амжилтгүй бүх тохиолдолд *Error эсвэл *eid.NetworkError.
func (c *Client) HandleCallback(ctx context.Context, query url.Values, checks CallbackChecks) (*CallbackResult, error) {
	state := query.Get("state")
	if checks.State == "" || subtle.ConstantTimeCompare([]byte(state), []byte(checks.State)) != 1 {
		return nil, &Error{Code: ErrStateMismatch, Message: "state таарсангүй — нэвтрэлтийг дахин эхлүүлнэ үү"}
	}
	if query.Has("iss") && query.Get("iss") != c.issuer {
		return nil, &Error{Code: ErrInvalidCallback, Message: "callback-ийн iss таарахгүй"}
	}
	if e := query.Get("error"); e != "" {
		code := knownOrServerError(e)
		return nil, &Error{Code: code, Message: "eID нэвтрэлт амжилтгүй: " + string(code), Description: query.Get("error_description")}
	}
	code := query.Get("code")
	if code == "" || len(code) > 512 {
		return nil, &Error{Code: ErrInvalidCallback, Message: "callback-д code алга"}
	}
	idToken, err := c.exchangeCode(ctx, code, checks.CodeVerifier)
	if err != nil {
		return nil, err
	}
	claims, err := c.VerifyIDToken(ctx, idToken, checks.Nonce)
	if err != nil {
		return nil, err
	}
	return &CallbackResult{Claims: claims, IDToken: idToken}, nil
}

// exchangeCode — POST token_endpoint (client_secret_basic, RFC 6749 §2.3.1) → id_token.
func (c *Client) exchangeCode(ctx context.Context, code, verifier string) (string, error) {
	d, err := c.Discover(ctx)
	if err != nil {
		return "", err
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {c.cfg.RedirectURI},
		"code_verifier": {verifier},
	}
	endpoint, err := c.tokenEndpoint(d)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("eid/oidc: token request: %w", err)
	}
	basic := url.QueryEscape(c.cfg.ClientID) + ":" + url.QueryEscape(c.cfg.ClientSecret)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(basic)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	res, err := c.hc.Do(req)
	if err != nil {
		return "", netErr(endpoint, err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxBody))
	if err != nil {
		return "", netErr(endpoint, err)
	}
	var j struct {
		IDToken          any `json:"id_token"`
		Error            any `json:"error"`
		ErrorDescription any `json:"error_description"`
	}
	_ = json.Unmarshal(raw, &j) // JSON биш (proxy) — доор статусаар
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		e, _ := j.Error.(string)
		desc, _ := j.ErrorDescription.(string)
		code := knownOrServerError(e)
		return "", &Error{Code: code, Message: fmt.Sprintf("token %d: %s", res.StatusCode, code), Description: desc}
	}
	tok, _ := j.IDToken.(string)
	if tok == "" {
		return "", &Error{Code: ErrServerError, Message: "token хариунд id_token алга"}
	}
	return tok, nil
}

// tokenEndpoint — UseMTLSEndpointAliases + alias байвал alias (RFC 8705 §5), эс бөгөөс TokenEndpoint.
func (c *Client) tokenEndpoint(d *Discovery) (string, error) {
	if !c.cfg.UseMTLSEndpointAliases {
		return d.TokenEndpoint, nil
	}
	alias, ok := d.MTLSEndpointAliases["token_endpoint"]
	if !ok {
		return d.TokenEndpoint, nil
	}
	if !strings.HasPrefix(alias, "https://") {
		return "", &Error{Code: ErrDiscoveryFailed, Message: "discovery: mtls_endpoint_aliases.token_endpoint буруу"}
	}
	return alias, nil
}

// VerifyIDToken — id_token шалгана: JWKS (kid, 1 цаг cache; танихгүй kid → нэг удаа дахин татна) ES256 гарын үсэг,
// iss, aud (= ClientID; олон aud бол azp), exp / iat (±60 сек), nonce (constant-time), sub. Амжилтгүй бол
// *Error{Code: ErrInvalidIDToken}.
func (c *Client) VerifyIDToken(ctx context.Context, idToken, nonce string) (*Claims, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, badToken("хэлбэр буруу")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	hb, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	pb, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	if err1 != nil || err2 != nil || json.Unmarshal(hb, &header) != nil {
		return nil, badToken("хэлбэр буруу")
	}
	var present map[string]json.RawMessage
	if json.Unmarshal(pb, &present) != nil || present == nil {
		return nil, badToken("хэлбэр буруу")
	}
	if header.Alg != idTokenAlg {
		return nil, badToken("alg ES256 биш")
	}
	if header.Kid == "" {
		return nil, badToken("kid алга")
	}
	key, err := c.key(ctx, header.Kid)
	if err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return nil, badToken("гарын үсэг таарсангүй")
	}
	// JWS ES256 = r||s (64 байт, RFC 7518 §3.4).
	h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(key, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return nil, badToken("гарын үсэг таарсангүй")
	}

	var cl Claims
	if err := json.Unmarshal(pb, &cl); err != nil {
		return nil, badToken("claims задарсангүй")
	}
	for _, k := range []string{"exp", "iat", "nonce", "sub"} {
		if _, ok := present[k]; !ok {
			return nil, badToken(k + " алга")
		}
	}
	now := c.now().Unix()
	if cl.Iss != c.issuer {
		return nil, badToken("iss таарахгүй")
	}
	if !contains(cl.Aud, c.cfg.ClientID) {
		return nil, badToken("aud таарахгүй")
	}
	if len(cl.Aud) > 1 && cl.Azp != c.cfg.ClientID {
		return nil, badToken("azp таарахгүй")
	}
	if now > cl.Exp+clockSkew {
		return nil, badToken("хугацаа дууссан")
	}
	if cl.Iat > now+clockSkew {
		return nil, badToken("iat ирээдүйд")
	}
	if nonce == "" || subtle.ConstantTimeCompare([]byte(cl.Nonce), []byte(nonce)) != 1 {
		return nil, badToken("nonce таарахгүй")
	}
	if cl.Sub == "" {
		return nil, badToken("sub алга")
	}
	return &cl, nil
}

// key — kid-тэй P-256 түлхүүр. Cache-д алга бол JWKS-ийг нэг удаа дахин татна.
func (c *Client) key(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	for _, force := range []bool{false, true} {
		keys, err := c.jwks(ctx, force)
		if err != nil {
			return nil, err
		}
		for _, k := range keys {
			if k.Kid == kid && k.Kty == "EC" && k.Crv == "P-256" && (k.Use == "" || k.Use == "sig") && (k.Alg == "" || k.Alg == "ES256") {
				pub, err := p256Key(k.X, k.Y)
				if err != nil {
					return nil, badToken("JWKS түлхүүр буруу")
				}
				return pub, nil
			}
		}
	}
	return nil, badToken("танихгүй kid " + kid)
}

func (c *Client) jwks(ctx context.Context, force bool) ([]jwk, error) {
	c.mu.Lock()
	if !force && c.hasKeys && c.now().Sub(c.keysAt) < cacheTTL {
		k := c.keys
		c.mu.Unlock()
		return k, nil
	}
	c.mu.Unlock()
	d, err := c.Discover(ctx)
	if err != nil {
		return nil, err
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := c.getJSON(ctx, d.JWKSURI, &set); err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.keys, c.keysAt, c.hasKeys = set.Keys, c.now(), true
	c.mu.Unlock()
	return set.Keys, nil
}

// p256SPKIPrefix — id-ecPublicKey + prime256v1 SubjectPublicKeyInfo-ийн угтвар (uncompressed point-оос өмнө).
var p256SPKIPrefix = []byte{
	0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
	0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
}

// p256Key — JWK x/y → *ecdsa.PublicKey (x509 parser нь цэг муруй дээр байгааг шалгана).
func p256Key(xB64, yB64 string) (*ecdsa.PublicKey, error) {
	x, err1 := base64.RawURLEncoding.DecodeString(xB64)
	y, err2 := base64.RawURLEncoding.DecodeString(yB64)
	if err1 != nil || err2 != nil || len(x) != 32 || len(y) != 32 {
		return nil, errors.New("x/y урт буруу")
	}
	der := append(append(append([]byte{}, p256SPKIPrefix...), x...), y...)
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("EC биш")
	}
	return pub, nil
}

func (c *Client) getJSON(ctx context.Context, u string, out any) error {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return &Error{Code: ErrDiscoveryFailed, Message: "буруу URL: " + u}
	}
	req.Header.Set("Accept", "application/json")
	res, err := c.hc.Do(req)
	if err != nil {
		return netErr(u, err)
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return &Error{Code: ErrDiscoveryFailed, Message: fmt.Sprintf("%d: %s", res.StatusCode, u)}
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxBody))
	if err != nil {
		return netErr(u, err)
	}
	if json.Unmarshal(raw, out) != nil {
		return &Error{Code: ErrDiscoveryFailed, Message: "JSON биш: " + u}
	}
	return nil
}

// PKCEChallenge — S256: BASE64URL(SHA-256(ASCII(code_verifier))) (RFC 7636 §4.2).
func PKCEChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func randomB64URL() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("eid/oidc: crypto/rand: " + err.Error()) // crypto/rand алдаа = системийн эвдрэл
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func netErr(op string, err error) error {
	var ne net.Error
	timeout := errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())
	return &eid.NetworkError{Op: op, Timeout: timeout, Err: err}
}

func contains(l []string, s string) bool {
	for _, v := range l {
		if v == s {
			return true
		}
	}
	return false
}
