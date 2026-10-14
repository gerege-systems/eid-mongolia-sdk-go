package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	eid "github.com/gerege-systems/eid-mongolia-sdk-go"
)

const (
	clientID = "6f1c2a3b-0000-4000-8000-000000000001"
	secret   = "rp_sk_a+b/c:d é"
	redirect = "https://rp.example.mn/eid/callback"
)

type key struct {
	kid  string
	priv *ecdsa.PrivateKey
}

func newKey(kid string) key {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return key{kid, k}
}

func (k key) jwk() map[string]string {
	b := k.priv.PublicKey.X.FillBytes(make([]byte, 32))
	c := k.priv.PublicKey.Y.FillBytes(make([]byte, 32))
	return map[string]string{"kty": "EC", "crv": "P-256", "kid": k.kid, "use": "sig", "alg": "ES256",
		"x": base64.RawURLEncoding.EncodeToString(b), "y": base64.RawURLEncoding.EncodeToString(c)}
}

func b64u(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

func jwt(k key, claims map[string]any, kid string) string {
	if kid == "" {
		kid = k.kid
	}
	in := b64u(map[string]string{"alg": "ES256", "typ": "JWT", "kid": kid}) + "." + b64u(claims)
	h := sha256.Sum256([]byte(in))
	r, s, _ := ecdsa.Sign(rand.Reader, k.priv, h[:])
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

type mock struct {
	srv       *httptest.Server
	mu        sync.Mutex
	keys      []map[string]string
	issuer    string // discovery-д буцаах issuer ("" = srv.URL)
	jwksN     int
	discN     int
	tokenReqs []*http.Request
	tokenBody []string
	token     func() (int, string)
	aliases   map[string]string // mtls_endpoint_aliases (nil = discovery-д алга)
}

func newMock(t *testing.T) *mock {
	m := &mock{}
	m.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		base := m.srv.URL
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			m.discN++
			iss := m.issuer
			if iss == "" {
				iss = base
			}
			doc := map[string]any{"issuer": iss, "authorization_endpoint": base + "/oauth2/authorize",
				"token_endpoint": base + "/oauth2/token", "jwks_uri": base + "/oauth2/jwks"}
			if m.aliases != nil {
				al := map[string]string{}
				for k, v := range m.aliases {
					al[k] = strings.ReplaceAll(v, "{base}", base)
				}
				doc["mtls_endpoint_aliases"] = al
			}
			_ = json.NewEncoder(w).Encode(doc)
		case "/oauth2/jwks":
			m.jwksN++
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": m.keys})
		case "/oauth2/token", "/mtls/oauth2/token":
			b, _ := io.ReadAll(r.Body)
			m.tokenReqs = append(m.tokenReqs, r)
			m.tokenBody = append(m.tokenBody, string(b))
			st, body := 500, "{}"
			if m.token != nil {
				st, body = m.token()
			}
			w.WriteHeader(st)
			_, _ = io.WriteString(w, body)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mock) client(t *testing.T) *Client {
	c, err := NewClient(Config{ClientID: clientID, ClientSecret: secret, RedirectURI: redirect, Issuer: m.srv.URL, HTTPClient: m.srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (m *mock) claims(over map[string]any) map[string]any {
	now := time.Now().Unix()
	c := map[string]any{"iss": m.srv.URL, "aud": clientID, "sub": "pairwise-sub-1", "exp": now + 300, "iat": now, "nonce": "n-123",
		"auth_time": now - 5, "acr": ACRQualified, "given_name": "BAT", "family_name": "DORJ", "given_name_mn": "Бат", "family_name_mn": "Дорж"}
	for k, v := range over {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return c
}

func wantCode(t *testing.T, err error, code ErrorCode) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) || e.Code != code {
		t.Fatalf("%s хүлээв, авсан %v", code, err)
	}
}

func TestPKCE_RFC7636Vector(t *testing.T) {
	if got := PKCEChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"); got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatal(got)
	}
}

func TestCreateAuthorization(t *testing.T) {
	m := newMock(t)
	c, _ := NewClient(Config{ClientID: clientID, ClientSecret: secret, RedirectURI: redirect, Issuer: m.srv.URL + "/", Scope: "openid pnomn", HTTPClient: m.srv.Client()})
	ctx := context.Background()
	a, err := c.CreateAuthorization(ctx, &AuthorizationOptions{Display: "page"})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(a.URL)
	q := u.Query()
	if u.Scheme+"://"+u.Host+u.Path != m.srv.URL+"/oauth2/authorize" || q.Get("response_type") != "code" || q.Get("client_id") != clientID ||
		q.Get("redirect_uri") != redirect || q.Get("scope") != "openid pnomn" || q.Get("display") != "page" || q.Get("state") != a.State ||
		q.Get("nonce") != a.Nonce || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") != PKCEChallenge(a.CodeVerifier) ||
		len(a.CodeVerifier) != 43 {
		t.Fatal(a.URL)
	}
	b, _ := c.CreateAuthorization(ctx, nil)
	if a.State == b.State || a.Nonce == b.Nonce || a.CodeVerifier == b.CodeVerifier {
		t.Fatal("санамсаргүй биш")
	}
	if bu, _ := url.Parse(b.URL); bu.Query().Has("display") || bu.Query().Get("scope") != "openid pnomn" {
		t.Fatal(b.URL)
	}
	if m.discN != 1 {
		t.Fatalf("discovery cache: %d", m.discN)
	}
}

func TestDiscover_IssuerMismatch(t *testing.T) {
	m := newMock(t)
	m.issuer = "https://evil.example"
	_, err := m.client(t).Discover(context.Background())
	wantCode(t, err, ErrDiscoveryFailed)
	m.issuer = ""
	if _, err := m.client(t).Discover(context.Background()); err != nil { // алдааг cache-лээгүй
		t.Fatal(err)
	}
}

func TestHandleCallback_FullFlow(t *testing.T) {
	m := newMock(t)
	k := newKey("k1")
	m.keys = []map[string]string{k.jwk()}
	m.token = func() (int, string) {
		b, _ := json.Marshal(map[string]any{"id_token": jwt(k, m.claims(nil), ""), "token_type": "Bearer", "expires_in": 300})
		return 200, string(b)
	}
	q, _ := url.ParseQuery("code=abc&state=s-1")
	r, err := m.client(t).HandleCallback(context.Background(), q, CallbackChecks{State: "s-1", Nonce: "n-123", CodeVerifier: strings.Repeat("v", 43)})
	if err != nil {
		t.Fatal(err)
	}
	if r.Claims.Sub != "pairwise-sub-1" || r.Claims.GivenNameMN != "Бат" || r.Claims.PNOMN != "" || r.Claims.Acr != ACRQualified || r.IDToken == "" {
		t.Fatalf("%+v", r.Claims)
	}
	req := m.tokenReqs[0]
	raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(req.Header.Get("Authorization"), "Basic "))
	// RFC 6749 §2.3.1 — form-urlencode хийгээд base64 (':' '+' '/' зай UTF-8 кодлогдоно)
	if string(raw) != clientID+":rp_sk_a%2Bb%2Fc%3Ad+%C3%A9" || req.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Fatalf("basic %q", raw)
	}
	body, _ := url.ParseQuery(m.tokenBody[0])
	if body.Get("grant_type") != "authorization_code" || body.Get("code") != "abc" || body.Get("redirect_uri") != redirect ||
		body.Get("code_verifier") != strings.Repeat("v", 43) {
		t.Fatal(m.tokenBody[0])
	}
}

func TestHandleCallback_Errors(t *testing.T) {
	m := newMock(t)
	c := m.client(t)
	ctx := context.Background()
	checks := CallbackChecks{State: "s-1", Nonce: "n", CodeVerifier: "v"}
	cb := func(raw string, ch CallbackChecks) error {
		q, _ := url.ParseQuery(raw)
		_, err := c.HandleCallback(ctx, q, ch)
		return err
	}
	wantCode(t, cb("code=abc&state=s-2", checks), ErrStateMismatch)
	wantCode(t, cb("code=abc", checks), ErrStateMismatch)
	wantCode(t, cb("error=access_denied&state=x", checks), ErrStateMismatch) // error-той ч state буруу бол
	wantCode(t, cb("code=abc&state=", CallbackChecks{}), ErrStateMismatch)
	err := cb("error=access_denied&error_description=expired&state=s-1", checks)
	var e *Error
	if !errors.As(err, &e) || e.Code != ErrAccessDenied || e.Description != "expired" {
		t.Fatal(err)
	}
	wantCode(t, cb("error=login_required&state=s-1", checks), ErrLoginRequired)
	wantCode(t, cb("error=weird&state=s-1", checks), ErrServerError)
	wantCode(t, cb("state=s-1", checks), ErrInvalidCallback)
	wantCode(t, cb("code="+strings.Repeat("a", 513)+"&state=s-1", checks), ErrInvalidCallback)
	wantCode(t, cb("code=a&state=s-1&iss="+url.QueryEscape("https://evil.example"), checks), ErrInvalidCallback)
	if len(m.tokenReqs) != 0 {
		t.Fatal("token дуудагдсан")
	}
	m.token = func() (int, string) { return 400, `{"error":"invalid_grant","error_description":"code used"}` }
	wantCode(t, cb("code=a&state=s-1", checks), ErrInvalidGrant)
	m.token = func() (int, string) { return 502, `<html>bad gateway</html>` }
	wantCode(t, cb("code=a&state=s-1", checks), ErrServerError)
	m.token = func() (int, string) { return 200, `{"token_type":"Bearer"}` }
	wantCode(t, cb("code=a&state=s-1", checks), ErrServerError)
}

func TestNetworkError(t *testing.T) {
	c, _ := NewClient(Config{ClientID: "c", ClientSecret: "s", RedirectURI: redirect, Issuer: "https://127.0.0.1:1"})
	var ne *eid.NetworkError
	if _, err := c.Discover(context.Background()); !errors.As(err, &ne) {
		t.Fatal(err)
	}
}

func TestVerifyIDToken(t *testing.T) {
	m := newMock(t)
	k := newKey("k1")
	m.keys = []map[string]string{k.jwk()}
	c := m.client(t)
	ctx := context.Background()
	if cl, err := c.VerifyIDToken(ctx, jwt(k, m.claims(nil), ""), "n-123"); err != nil || cl.Acr != ACRQualified || cl.AuthTime == 0 {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	bad := func(over map[string]any, nonce string) {
		t.Helper()
		_, err := c.VerifyIDToken(ctx, jwt(k, m.claims(over), ""), nonce)
		wantCode(t, err, ErrInvalidIDToken)
	}
	bad(map[string]any{"aud": "other-client"}, "n-123")
	bad(map[string]any{"aud": []string{clientID, "other"}}, "n-123") // олон aud, azp алга
	bad(map[string]any{"aud": []string{clientID, "other"}, "azp": "other"}, "n-123")
	bad(map[string]any{"exp": now - 61}, "n-123")
	bad(map[string]any{"iat": now + 120}, "n-123")
	bad(nil, "n-other")
	bad(nil, "")
	bad(map[string]any{"iss": m.srv.URL + "/"}, "n-123")
	bad(map[string]any{"sub": ""}, "n-123")
	bad(map[string]any{"exp": nil}, "n-123")
	bad(map[string]any{"nonce": nil}, "n-123")
	bad(map[string]any{"exp": "soon"}, "n-123")
	// clock skew дотор — зөвшөөрнө
	for _, over := range []map[string]any{{"exp": now - 30}, {"aud": []string{clientID, "other"}, "azp": clientID}} {
		if _, err := c.VerifyIDToken(ctx, jwt(k, m.claims(over), ""), "n-123"); err != nil {
			t.Fatal(err)
		}
	}
}

func TestVerifyIDToken_KeyRotation(t *testing.T) {
	m := newMock(t)
	k1, k2 := newKey("k1"), newKey("k2")
	m.keys = []map[string]string{k1.jwk()}
	c := m.client(t)
	ctx := context.Background()
	if _, err := c.VerifyIDToken(ctx, jwt(k1, m.claims(nil), ""), "n-123"); err != nil || m.jwksN != 1 {
		t.Fatal(err, m.jwksN)
	}
	m.mu.Lock()
	m.keys = []map[string]string{k1.jwk(), k2.jwk()} // түлхүүр солигдов
	m.mu.Unlock()
	if _, err := c.VerifyIDToken(ctx, jwt(k2, m.claims(nil), ""), "n-123"); err != nil || m.jwksN != 2 {
		t.Fatal(err, m.jwksN)
	}
	if _, err := c.VerifyIDToken(ctx, jwt(k2, m.claims(nil), ""), "n-123"); err != nil || m.jwksN != 2 {
		t.Fatal(err, m.jwksN) // cache
	}
	_, err := c.VerifyIDToken(ctx, jwt(k1, m.claims(nil), "k-none"), "n-123")
	wantCode(t, err, ErrInvalidIDToken)
	if m.jwksN != 3 {
		t.Fatal(m.jwksN) // огт байхгүй kid → нэг refetch
	}
}

func TestVerifyIDToken_ForgedTokens(t *testing.T) {
	m := newMock(t)
	k := newKey("k1")
	other := newKey("k1") // ижил kid, өөр түлхүүр
	m.keys = []map[string]string{k.jwk()}
	c := m.client(t)
	ctx := context.Background()
	v := func(tok string) {
		t.Helper()
		_, err := c.VerifyIDToken(ctx, tok, "n-123")
		wantCode(t, err, ErrInvalidIDToken)
	}
	v(jwt(other, m.claims(nil), ""))
	parts := strings.Split(jwt(k, m.claims(nil), ""), ".")
	v(parts[0] + "." + b64u(m.claims(map[string]any{"sub": "attacker"})) + "." + parts[2])
	v(b64u(map[string]string{"alg": "none", "kid": "k1"}) + "." + b64u(m.claims(nil)) + ".")
	v(b64u(map[string]string{"alg": "HS256", "kid": "k1"}) + "." + b64u(m.claims(nil)) + "." + parts[2])
	v(b64u(map[string]string{"alg": "ES256"}) + "." + parts[1] + "." + parts[2]) // kid алга
	v("not-a-jwt")
	v(parts[0] + "." + parts[1] + "." + parts[2][:20])
	// JWKS-д муруй дээр биш цэг
	bk := k.jwk()
	bk["y"] = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	m.mu.Lock()
	m.keys = []map[string]string{bk}
	m.mu.Unlock()
	c2 := m.client(t)
	_, err := c2.VerifyIDToken(ctx, jwt(k, m.claims(nil), ""), "n-123")
	wantCode(t, err, ErrInvalidIDToken)
}

func TestNewClient_Config(t *testing.T) {
	if _, err := NewClient(Config{ClientSecret: "s", RedirectURI: redirect}); err == nil {
		t.Fatal("clientId хоосон")
	}
	if _, err := NewClient(Config{ClientID: "c", ClientSecret: "s", RedirectURI: "http://x/cb"}); err == nil {
		t.Fatal("http redirect")
	}
	c, _ := NewClient(Config{ClientID: "c", ClientSecret: "s", RedirectURI: redirect})
	if c.Issuer() != Issuer {
		t.Fatal(c.Issuer())
	}
}

func TestMTLSEndpointAliases(t *testing.T) {
	k := newKey("k1")
	run := func(t *testing.T, flag bool, aliases map[string]string) (*mock, error) {
		m := newMock(t)
		m.keys = []map[string]string{k.jwk()}
		m.aliases = aliases
		m.token = func() (int, string) {
			b, _ := json.Marshal(map[string]any{"id_token": jwt(k, m.claims(nil), ""), "token_type": "Bearer", "expires_in": 300})
			return 200, string(b)
		}
		c, err := NewClient(Config{ClientID: clientID, ClientSecret: secret, RedirectURI: redirect, Issuer: m.srv.URL,
			HTTPClient: m.srv.Client(), UseMTLSEndpointAliases: flag})
		if err != nil {
			t.Fatal(err)
		}
		q, _ := url.ParseQuery("code=abc&state=s-1")
		_, err = c.HandleCallback(context.Background(), q, CallbackChecks{State: "s-1", Nonce: "n-123", CodeVerifier: strings.Repeat("v", 43)})
		return m, err
	}
	paths := func(m *mock) []string {
		var p []string
		for _, r := range m.tokenReqs {
			p = append(p, r.URL.Path)
		}
		return p
	}
	alias := map[string]string{"token_endpoint": "{base}/mtls/oauth2/token"}

	t.Run("flag on → alias", func(t *testing.T) {
		m, err := run(t, true, alias)
		if err != nil || strings.Join(paths(m), ",") != "/mtls/oauth2/token" {
			t.Fatal(err, paths(m))
		}
	})
	t.Run("flag off → token_endpoint", func(t *testing.T) {
		m, err := run(t, false, alias)
		if err != nil || strings.Join(paths(m), ",") != "/oauth2/token" {
			t.Fatal(err, paths(m))
		}
	})
	t.Run("alias алга → token_endpoint", func(t *testing.T) {
		m, err := run(t, true, nil)
		if err != nil || strings.Join(paths(m), ",") != "/oauth2/token" {
			t.Fatal(err, paths(m))
		}
	})
	t.Run("http alias → discovery_failed", func(t *testing.T) {
		m, err := run(t, true, map[string]string{"token_endpoint": "http://rp.example/oauth2/token"})
		wantCode(t, err, ErrDiscoveryFailed)
		if len(m.tokenReqs) != 0 {
			t.Fatal("token хүсэлт явсан")
		}
	})
}
