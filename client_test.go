package eid

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

var creds = Credentials{RPUUID: "rp-uuid", RPName: "Гэрээний систем", APISecret: "rp_sk_secret123"}

type rec struct {
	mu   sync.Mutex
	reqs []*http.Request
	body [][]byte
}

func (r *rec) last() (*http.Request, []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reqs[len(r.reqs)-1], r.body[len(r.body)-1]
}

// server — fn нь хариуг бичнэ; хүсэлт бүрийг бичиж авна.
func server(t *testing.T, fn http.HandlerFunc) (*Client, *rec) {
	t.Helper()
	rc := &rec{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		rc.mu.Lock()
		rc.reqs = append(rc.reqs, r)
		rc.body = append(rc.body, b)
		rc.mu.Unlock()
		r.Body = io.NopCloser(strings.NewReader(string(b)))
		fn(w, r)
	}))
	t.Cleanup(srv.Close)
	c, err := NewClient(Config{BaseURL: srv.URL, Credentials: creds, Trust: TrustConfig{AllowUntrusted: true}})
	if err != nil {
		t.Fatal(err)
	}
	return c, rc
}

func jsonReply(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

func TestResolveBaseURL(t *testing.T) {
	for in, want := range map[string]string{
		"":                             "https://rp.eidmongolia.mn",
		"https://rp.eidmongolia.mn/":   "https://rp.eidmongolia.mn",
		"https://rp.eidmongolia.mn/v3": "https://rp.eidmongolia.mn/v3",
		"http://localhost:8080/v3":     "http://localhost:8080/v3",
		"http://127.0.0.1:8080":        "http://127.0.0.1:8080",
		"http://[::1]:8080":            "http://[::1]:8080",
	} {
		if got, err := ResolveBaseURL(in); err != nil || got != want {
			t.Errorf("%q → %q, %v", in, got, err)
		}
	}
	if _, err := ResolveBaseURL("https://ca.eidmongolia.mn"); err == nil || !strings.Contains(err.Error(), "rp.eidmongolia.mn") {
		t.Fatal(err)
	}
	for _, in := range []string{"http://rp.eidmongolia.mn", "http://10.0.0.5:8080", "http://localhost.example.com"} {
		if _, err := ResolveBaseURL(in); err == nil || !strings.Contains(err.Error(), "https") {
			t.Errorf("%s: http зөвшөөрөгдөв (%v)", in, err)
		}
	}
	if _, err := ResolveBaseURL("not a url"); err == nil {
		t.Fatal("буруу URL зөвшөөрөгдөв")
	}
	if _, err := NewClient(Config{}); err == nil {
		t.Fatal("secret-гүй client")
	}
}

func TestHTTPErrors(t *testing.T) {
	ctx := context.Background()
	c, _ := server(t, jsonReply(401, "boom"))
	var ae *AuthenticationError
	if _, err := c.Session.Poll(ctx, "x", time.Second); !errors.As(err, &ae) {
		t.Fatal(err)
	}
	c, _ = server(t, jsonReply(403, `{"error":"төлөөлөх эрхгүй","code":"REPRESENTATION_DENIED"}`))
	var fe *ForbiddenError
	if _, err := c.Sign.DigestByEtsi(ctx, "PNOMN-1", SHA256Base64(nil), nil, nil); !errors.As(err, &fe) ||
		fe.Code != CodeRepresentationDenied || !strings.Contains(fe.Error(), "REPRESENTATION_DENIED") {
		t.Fatal(err)
	}
	c, _ = server(t, jsonReply(403, "<html>nginx</html>"))
	if _, err := c.Session.Poll(ctx, "x", time.Second); !errors.As(err, &fe) || fe.Code != "" || !strings.Contains(fe.Error(), "allowlist") {
		t.Fatal(err)
	}
	c, _ = server(t, jsonReply(404, `{"error":"байгууллага олдсонгүй","code":"ORG_NOT_FOUND"}`))
	var api *APIError
	if _, err := c.Organization.GetRepresentations(ctx, "PNOMN-1"); !errors.As(err, &api) || api.Status != 404 || api.Code != CodeOrgNotFound {
		t.Fatal(err)
	}
	c, _ = server(t, func(w http.ResponseWriter, r *http.Request) { time.Sleep(300 * time.Millisecond) })
	tctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	var ne *NetworkError
	if _, err := c.Session.Poll(tctx, "x", time.Second); !errors.As(err, &ne) || !ne.Timeout || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if len(OnBehalfErrorCodes) != 7 {
		t.Fatal(len(OnBehalfErrorCodes))
	}
}

func TestAuth_RequestBodyAndParse(t *testing.T) {
	ctx := context.Background()
	c, rc := server(t, jsonReply(200, `{"sessionID":"s1","vc":{"type":"alphaNumeric5","value":"90177"}}`))
	s, err := c.Auth.NotificationByEtsi(ctx, "PNOMN-12345678", []Interaction{{Type: "displayTextAndPIN", DisplayText60: "Нэвтрэх"}},
		&AuthOptions{CallbackURL: " https://rp.test/cb ", OnBehalfOf: " NTRMN-6235972 "})
	if err != nil {
		t.Fatal(err)
	}
	req, body := rc.last()
	if req.URL.Path != "/authentication/notification/etsi/PNOMN-12345678" || req.Header.Get("Authorization") != "Bearer rp_sk_secret123" ||
		req.Header.Get("Content-Type") != "application/json" {
		t.Fatal(req.URL.Path, req.Header)
	}
	var b map[string]any
	_ = json.Unmarshal(body, &b)
	spp := b["signatureProtocolParameters"].(map[string]any)
	if b["relyingPartyUUID"] != "rp-uuid" || b["relyingPartyName"] != "Гэрээний систем" || b["certificateLevel"] != "QUALIFIED" ||
		b["signatureProtocol"] != "ACSP_V2" || b["initialCallbackUrl"] != "https://rp.test/cb" || b["onBehalfOf"] != "NTRMN-6235972" ||
		spp["rpChallenge"] != s.RPChallenge || spp["signatureAlgorithm"] != "rsassa-pss" ||
		spp["signatureAlgorithmParameters"].(map[string]any)["hashAlgorithm"] != "SHA-512" || b["interactions"] != s.ACSP.Interactions {
		t.Fatalf("body %s", body)
	}
	if s.SessionID != "s1" || s.VC != "90177" || s.ACSP.InitialCallbackURL != "https://rp.test/cb" ||
		len(s.ACSP.FlowTypes) != 3 || s.ACSP.FlowTypes[0] != FlowNotification {
		t.Fatalf("%+v %+v", s, s.ACSP)
	}

	c, rc = server(t, jsonReply(200, `{"sessionID":"s2","sessionToken":"t","sessionSecret":"c2VjcmV0","deviceLinkBase":"https://ca.eidmongolia.mn/dl","vc":"04821"}`))
	d, err := c.Auth.DeviceLinkAnonymous(ctx, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	req, body = rc.last()
	if req.URL.Path != "/authentication/device-link/anonymous" || strings.Contains(string(body), "onBehalfOf") || strings.Contains(string(body), "initialCallbackUrl") {
		t.Fatalf("%s %s", req.URL.Path, body)
	}
	if d.VC != "04821" || d.SessionToken != "t" || d.DeviceLinkBase != "https://ca.eidmongolia.mn/dl" || time.Since(d.ReceivedAt) > 5*time.Second ||
		len(d.ACSP.FlowTypes) != 1 || d.ACSP.FlowTypes[0] != FlowQR {
		t.Fatalf("%+v", d)
	}
}

func TestSign_Body(t *testing.T) {
	c, rc := server(t, jsonReply(200, `{"sessionID":"s1","vc":{"type":"alphaNumeric5","value":"90177"}}`))
	s, err := c.Sign.TextByEtsi(context.Background(), "PNOMN-1", "x", nil, &SignOptions{OnBehalfOf: "NTRMN-6235972"})
	if err != nil || s.VC != "90177" || s.ACSP != nil || s.RPChallenge != "" {
		t.Fatal(err, s)
	}
	req, body := rc.last()
	var b struct {
		SignatureProtocol           string
		OnBehalfOf                  string
		SignatureProtocolParameters struct {
			Digest                       string
			SignatureAlgorithm           string
			SignatureAlgorithmParameters struct{ HashAlgorithm string }
		}
	}
	_ = json.Unmarshal(body, &b)
	if req.URL.Path != "/signature/notification/etsi/PNOMN-1" || b.SignatureProtocol != "RAW_DIGEST_SIGNATURE" || b.OnBehalfOf != "NTRMN-6235972" ||
		b.SignatureProtocolParameters.Digest != SHA256Base64([]byte("x")) || b.SignatureProtocolParameters.SignatureAlgorithmParameters.HashAlgorithm != "SHA-256" {
		t.Fatalf("%s", body)
	}
}

func TestParseSessionResult(t *testing.T) {
	r, err := ParseSessionResult([]byte(`{
		"state":"COMPLETE","result":{"endResult":"OK","documentNumber":"AB1234567"},"signatureProtocol":"ACSP_V2",
		"signature":{"value":"c2ln","serverRandom":"+wVP2U/SMKVkVrggDjNTXFV/","userChallenge":"TLSjYRH2oYw8tW2bq0it0IUb7WIFkCLgF8NTc7-4Zq4",
			"flowType":"Notification","signatureAlgorithm":"rsassa-pss",
			"signatureAlgorithmParameters":{"hashAlgorithm":"SHA-512","maskGenAlgorithm":{"algorithm":"id-mgf1","parameters":{"hashAlgorithm":"SHA-512"}},"saltLength":64,"trailerField":"0xbc"}},
		"cert":{"value":"Y2VydA==","certificateLevel":"QUALIFIED"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if r.State != "COMPLETE" || r.SignatureProtocol != "ACSP_V2" || r.ServerRandom != "+wVP2U/SMKVkVrggDjNTXFV/" || r.FlowType != "Notification" ||
		r.SignatureAlgorithmParameters.HashAlgorithm != "SHA-512" || *r.SignatureAlgorithmParameters.SaltLength != 64 || r.EndResult != "OK" ||
		r.DocumentNumber != "AB1234567" || r.SignatureValueB64 != "c2ln" || r.CertificateDERB64 != "Y2VydA==" || r.CertificateLevel != "QUALIFIED" ||
		r.OnBehalfOf != nil || r.InitialCallbackURL != nil {
		t.Fatalf("%+v", r)
	}
	r, _ = ParseSessionResult([]byte(`{"state":"COMPLETE","signature":{"initialCallbackUrl":""},
		"onBehalfOf":{"orgEtsi":"NTRMN-6235972","orgName":"Герэге Системс ХХК"}}`))
	if r.InitialCallbackURL == nil || *r.InitialCallbackURL != "" || r.OnBehalfOf.OrgEtsi != "NTRMN-6235972" || r.OnBehalfOf.RightType != "" {
		t.Fatalf("%+v", r)
	}
	r, _ = ParseSessionResult([]byte(`{"state":"COMPLETE","result":{"endResult":"OK"},
		"onBehalfOf":{"orgEtsi":"NTRMN-6235972","orgName":"Гэрэгэ Системс ХХК","role":"ceo","rightType":"ADMIN"}}`))
	if r.OnBehalfOf.RightType != "ADMIN" {
		t.Fatalf("%+v", r.OnBehalfOf)
	}
	if r, _ = ParseSessionResult([]byte(`{"state":"RUNNING"}`)); r.OnBehalfOf != nil {
		t.Fatal(r)
	}
}

func TestSession_PollAndWait(t *testing.T) {
	var n int
	var mu sync.Mutex
	c, rc := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/eid" { // WaitOptions.ExpiresAt алга → discovery sessionTtl
			_, _ = io.WriteString(w, `{"sessionTtl":{"auth":300,"sign":600}}`)
			return
		}
		mu.Lock()
		n++
		k := n
		mu.Unlock()
		if k < 3 {
			_, _ = io.WriteString(w, `{"state":"RUNNING"}`)
			return
		}
		_, _ = io.WriteString(w, `{"state":"COMPLETE","result":{"endResult":"OK"}}`)
	})
	r, err := c.Session.WaitForResult(context.Background(), "abc/def", &WaitOptions{ServerPoll: 2 * time.Second})
	if err != nil || r.State != StateComplete || n != 3 {
		t.Fatal(err, r, n)
	}
	req, _ := rc.last()
	if req.URL.EscapedPath() != "/session/abc%2Fdef" || req.URL.Query().Get("timeoutMs") != "2000" {
		t.Fatal(req.URL.String())
	}
	// MaxWait дуусвал сүүлчийн RUNNING-г алдаагүй буцаана
	c, _ = server(t, jsonReply(200, `{"state":"RUNNING"}`))
	r, err = c.Session.WaitForResult(context.Background(), "x", &WaitOptions{MaxWait: 10 * time.Millisecond})
	if err != nil || r.State != StateRunning {
		t.Fatal(err, r)
	}
}

// WaitForResult-ийн анхдагч хугацаа session-ий амьдрах хугацааг дагана (CA: auth 300 с, sign 600 с), 150 с-т таслахгүй.
func TestWaitDeadline(t *testing.T) {
	near := func(got time.Time, want time.Duration) bool {
		d := time.Until(got)
		return d > want-5*time.Second && d <= want
	}
	c, rc := server(t, jsonReply(200, `{"sessionTtl":{"auth":300,"sign":600}}`))
	if d := c.Session.waitDeadline(context.Background(), &WaitOptions{}); !near(d, 600*time.Second+WaitGrace) {
		t.Fatal("discovery max(auth, sign) + grace", time.Until(d))
	}
	if req, _ := rc.last(); req.URL.Path != "/.well-known/eid" {
		t.Fatal(req.URL.Path)
	}
	exp := time.Now().Add(280 * time.Second)
	if d := c.Session.waitDeadline(context.Background(), &WaitOptions{ExpiresAt: exp}); !d.Equal(exp.Add(WaitGrace)) {
		t.Fatal("ExpiresAt + grace", d)
	}
	if d := c.Session.waitDeadline(context.Background(), &WaitOptions{ExpiresAt: time.Now().Add(-time.Hour)}); !near(d, time.Second) {
		t.Fatal("өнгөрсөн ExpiresAt → нэг poll", time.Until(d))
	}
	if d := c.Session.waitDeadline(context.Background(), &WaitOptions{MaxWait: 42 * time.Second, ExpiresAt: exp}); !near(d, 42*time.Second) {
		t.Fatal("MaxWait давуу", time.Until(d))
	}
	// Хуучин CA (sessionTtl алга) эсвэл discovery унасан → DefaultMaxWait (600 с).
	for _, h := range []http.HandlerFunc{jsonReply(200, `{"version":"v3"}`), jsonReply(503, `{}`)} {
		c, _ := server(t, h)
		if d := c.Session.waitDeadline(context.Background(), &WaitOptions{}); !near(d, DefaultMaxWait) {
			t.Fatal("fallback", time.Until(d))
		}
	}
}

func TestOrganization(t *testing.T) {
	c, rc := server(t, jsonReply(200, `{"personEtsi":"PNOMN-12345678","representations":[{"orgEtsi":"NTRMN-6235972","orgRegister":"6235972",
		"orgName":"Гэрэгэ Системс ХХК","role":"ceo","rightType":"ADMIN","source":"REGISTRY","validFrom":"2026-10-01T00:00:00Z"}]}`))
	r, err := c.Organization.GetRepresentations(context.Background(), "PNOMN-12345678")
	if err != nil || len(r.Representations) != 1 || r.Representations[0].RightType != "ADMIN" {
		t.Fatal(err, r)
	}
	if req, _ := rc.last(); req.URL.Path != "/organization/representations/etsi/PNOMN-12345678" || req.Method != http.MethodGet {
		t.Fatal(req.URL.Path)
	}
}
