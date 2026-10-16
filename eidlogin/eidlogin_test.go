package eidlogin

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	eid "github.com/gerege-systems/eid-mongolia-sdk-go"
)

// fakeEID — RP-API-г дуурайна: session эхлүүлэх хүсэлтийг хадгалж, COMPLETE үед БОДИТ ACSP_V2 гарын үсэг (тестийн
// түлхүүрээр) буцаана — Validator (AllowUntrusted) гарын үсэг, flowType, verifier-ийг жинхэнээр шалгана.
type fakeEID struct {
	mu       sync.Mutex
	key      *rsa.PrivateKey
	certDER  []byte
	req      map[string]any // сүүлийн start хүсэлт
	path     string
	end      string // "" = RUNNING
	flow     string // гарын үсэгт зурах flowType
	verifier string
	tamper   bool
	// refuse — notification start-ын хариу: "" = бодит session; "json400" = eID-ийн татгалзал (JSON 4xx);
	// "proxy400" = JSON бус 4xx (proxy); "500" — eID 5xx; "401" — RP-ийн нууц буруу.
	refuse      string
	polledOther bool
}

const sid = "0b5e6a4c-1d2e-4f3a-8b9c-0d1e2f3a4b5c"

func newFake(t *testing.T) *fakeEID {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		// v0.6.0: зориулалт анхдагчаар (KU DS + EKU clientAuth), түвшин гэрчилгээнээс (AUTH KU keyEncipherment → QUALIFIED).
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection},
		Subject: pkix.Name{Country: []string{"MN"}, CommonName: "DORJ,BAT", SerialNumber: "PNOMN-111949212017",
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier{2, 5, 4, 42}, Value: "BAT"},
				{Type: asn1.ObjectIdentifier{2, 5, 4, 4}, Value: "DORJ"},
			}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeEID{key: k, certDER: der}
}

func (f *fakeEID) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.URL.Path == "/authentication/device-link/anonymous":
		f.path = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&f.req)
		_ = json.NewEncoder(w).Encode(map[string]any{"sessionID": sid, "sessionToken": "tok_ABC-123",
			"sessionSecret": base64.StdEncoding.EncodeToString(make([]byte, 32)), "deviceLinkBase": "https://ca.eidmongolia.mn/dl", "vc": "12345"})
	case strings.HasPrefix(r.URL.Path, "/authentication/notification/etsi/") && f.refuse != "":
		f.path = r.URL.EscapedPath()
		switch f.refuse {
		case "json400":
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"хэрэглэгч олдсонгүй"}`)
		case "proxy400":
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, "<html>400 The SSL certificate error</html>")
		case "401":
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"unauthorized"}`)
		default:
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `{"error":"дотоод алдаа"}`)
		}
	case r.URL.Path != "/session/"+sid && strings.HasPrefix(r.URL.Path, "/session/"):
		f.polledOther = true
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"error":"session олдсонгүй"}`)
	case strings.HasPrefix(r.URL.Path, "/authentication/notification/etsi/"):
		f.path = r.URL.EscapedPath()
		_ = json.NewDecoder(r.Body).Decode(&f.req)
		_ = json.NewEncoder(w).Encode(map[string]any{"sessionID": sid, "vc": map[string]string{"type": "alphaNumeric4", "value": "54321"}})
	case r.URL.Path == "/session/"+sid:
		if f.end == "" {
			_ = json.NewEncoder(w).Encode(map[string]any{"state": "RUNNING"})
			return
		}
		if f.end != "OK" {
			_ = json.NewEncoder(w).Encode(map[string]any{"state": "COMPLETE", "result": map[string]string{"endResult": f.end}})
			return
		}
		_ = json.NewEncoder(w).Encode(f.signed())
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"error":"not found"}`)
	}
}

func (f *fakeEID) signed() map[string]any {
	params := f.req["signatureProtocolParameters"].(map[string]any)
	cb := ""
	if f.flow == "Web2App" {
		cb, _ = f.req["initialCallbackUrl"].(string)
	}
	sr := base64.StdEncoding.EncodeToString([]byte("server-random-0123456789"))
	uc := eid.UserChallengeOf(f.verifier)
	payload := eid.BuildACSPV2Payload(eid.ACSPV2Params{
		ServerRandom: sr, RPChallenge: params["rpChallenge"].(string), UserChallenge: uc,
		RelyingPartyName: f.req["relyingPartyName"].(string), Interactions: f.req["interactions"].(string),
		InteractionTypeUsed: "displayTextAndPIN", InitialCallbackURL: cb, FlowType: f.flow,
	})
	if f.tamper {
		payload = append(payload, 'x')
	}
	d := sha512.Sum512(payload)
	sig, err := rsa.SignPSS(rand.Reader, f.key, crypto.SHA512, d[:], &rsa.PSSOptions{SaltLength: 64})
	if err != nil {
		panic(err)
	}
	return map[string]any{
		"state":  "COMPLETE",
		"result": map[string]string{"endResult": "OK", "documentNumber": "doc-1"},
		"signature": map[string]any{"value": base64.StdEncoding.EncodeToString(sig), "signatureAlgorithm": "rsassa-pss",
			"serverRandom": sr, "userChallenge": uc, "flowType": f.flow, "initialCallbackUrl": cb,
			"signatureAlgorithmParameters": map[string]string{"hashAlgorithm": "SHA-512"}},
		"signatureProtocol":   "ACSP_V2",
		"cert":                map[string]string{"value": base64.StdEncoding.EncodeToString(f.certDER), "certificateLevel": "QUALIFIED"},
		"interactionTypeUsed": "displayTextAndPIN",
		"person":              map[string]string{"civilId": "111949212017", "firstName": "Бат", "lastName": "Дорж"},
	}
}

func (f *fakeEID) set(end, flow, verifier string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.end, f.flow, f.verifier = end, flow, verifier
}

type event struct {
	kind EventKind
	sid  string
	meta map[string]any
}

type env struct {
	h      *Handler
	fake   *fakeEID
	ids    []*Identity
	keys   []string
	server *httptest.Server
	// sleeps — PushFloor / decoy poll-ын хүлээлт (хуурмаг цаг: бодитоор унтахгүй).
	sleeps []time.Duration
	events []event
}

func setup(t *testing.T, mod func(*Config)) *env {
	t.Helper()
	e := &env{fake: newFake(t)}
	e.server = httptest.NewServer(e.fake)
	t.Cleanup(e.server.Close)
	c, err := eid.NewClient(eid.Config{BaseURL: e.server.URL, Credentials: eid.Credentials{RPUUID: "rp-1", RPName: "Демо банк", APISecret: "rp_sk_test"},
		Trust: eid.TrustConfig{AllowUntrusted: true}})
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		Client: c, CallbackURL: "https://bank.example.mn/auth/eid/callback", FailureRedirect: "/login",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		OnSuccess: func(w http.ResponseWriter, _ *http.Request, id *Identity) (*Success, error) {
			e.ids = append(e.ids, id)
			http.SetCookie(w, &http.Cookie{Name: "app_session", Value: "s1", Path: "/", HttpOnly: true})
			return &Success{Redirect: "/dashboard", Data: map[string]string{"user": id.ETSI}}, nil
		},
	}
	if mod != nil {
		mod(&cfg)
	}
	userEvent := cfg.OnEvent
	cfg.OnEvent = func(ctx context.Context, k EventKind, s string, m map[string]any) {
		e.events = append(e.events, event{k, s, m})
		if userEvent != nil {
			userEvent(ctx, k, s, m)
		}
	}
	if e.h, err = New(cfg); err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	e.h.now = func() time.Time { return t0 }
	e.h.sleep = func(_ context.Context, d time.Duration) { e.sleeps = append(e.sleeps, d) }
	return e
}

func (e *env) kinds() []EventKind {
	var out []EventKind
	for _, ev := range e.events {
		out = append(out, ev.kind)
	}
	return out
}

type resp struct {
	code   int
	body   map[string]any
	header http.Header
}

func (e *env) do(t *testing.T, method, target, body string, hdr map[string]string) resp {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, target, rd)
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	out := resp{code: w.Code, header: w.Header()}
	_ = json.Unmarshal(w.Body.Bytes(), &out.body)
	return out
}

func loginCookie(t *testing.T, h http.Header) string {
	t.Helper()
	for _, c := range h.Values("Set-Cookie") {
		if strings.HasPrefix(c, "eid_login=") && !strings.HasPrefix(c, "eid_login=;") {
			for _, attr := range []string{"HttpOnly", "Secure", "SameSite=Lax"} {
				if !strings.Contains(c, attr) {
					t.Fatalf("cookie-д %s алга: %s", attr, c)
				}
			}
			return strings.SplitN(c, ";", 2)[0]
		}
	}
	t.Fatalf("eid_login cookie алга: %v", h.Values("Set-Cookie"))
	return ""
}

func TestQRFlow(t *testing.T) {
	e := setup(t, nil)
	s := e.do(t, "POST", "/auth/eid/start", `{"mode":"qr"}`, nil)
	if s.code != 200 || s.body["mode"] != "qr" || s.body["vc"] != "12345" {
		t.Fatalf("start: %d %v", s.code, s.body)
	}
	if q, _ := s.body["qr"].(string); !strings.HasPrefix(q, "https://ca.eidmongolia.mn/dl?deviceLinkType=QR&elapsedSeconds=") {
		t.Fatalf("qr: %v", s.body["qr"])
	}
	if _, ok := e.fake.req["initialCallbackUrl"]; ok {
		t.Fatal("QR session-д callback илгээх ёсгүй")
	}
	cookie := loginCookie(t, s.header)
	p := e.do(t, "GET", "/auth/eid/status", "", map[string]string{"Cookie": cookie})
	if p.body["state"] != "PENDING" || !strings.Contains(p.body["qr"].(string), "deviceLinkType=QR") {
		t.Fatalf("pending: %v", p.body)
	}
	e.fake.set("OK", "QR", "")
	ok := e.do(t, "GET", "/auth/eid/status", "", map[string]string{"Cookie": cookie})
	if ok.body["state"] != "OK" || ok.body["redirect"] != "/dashboard" || ok.body["data"].(map[string]any)["user"] != "PNOMN-111949212017" {
		t.Fatalf("ok: %v", ok.body)
	}
	if len(e.ids) != 1 || e.ids[0].CivilID != "111949212017" || e.ids[0].FlowType != eid.FlowQR || e.ids[0].GivenName != "BAT" ||
		e.ids[0].Person == nil || e.ids[0].Person.FirstName != "Бат" ||
		e.ids[0].SessionID != sid || e.ids[0].DocumentNumber == "" || e.ids[0].Certificate == nil {
		t.Fatalf("identity: %+v", e.ids)
	}
	if sc := strings.Join(ok.header.Values("Set-Cookie"), "\n"); !strings.Contains(sc, "app_session=s1") || !strings.Contains(sc, "eid_login=;") {
		t.Fatalf("Set-Cookie: %s", sc)
	}
	again := e.do(t, "GET", "/auth/eid/status", "", map[string]string{"Cookie": cookie})
	if again.body["state"] != "EXPIRED" || len(e.ids) != 1 {
		t.Fatalf("нэг удаа л: %v", again.body)
	}
}

func TestStatusBinding(t *testing.T) {
	e := setup(t, nil)
	s := e.do(t, "POST", "/auth/eid/start", `{"mode":"qr"}`, nil)
	cookie := loginCookie(t, s.header)
	for _, c := range []string{"", "eid_login=" + sid + "." + strings.Repeat("A", 43), cookie[:len(cookie)-1] + "x"} {
		r := e.do(t, "GET", "/auth/eid/status", "", map[string]string{"Cookie": c})
		if r.body["state"] != "EXPIRED" {
			t.Fatalf("%q: %v", c, r.body)
		}
	}
}

func TestPushFlowAndRateLimit(t *testing.T) {
	e := setup(t, nil)
	if r := e.do(t, "POST", "/auth/eid/start", `{"mode":"push","idCode":"abc"}`, nil); r.code != 400 {
		t.Fatalf("invalid id: %d", r.code)
	}
	s := e.do(t, "POST", "/auth/eid/start", `{"mode":"push","idCode":"уб 12345678"}`, nil)
	if s.code != 200 || s.body["vc"] != "54321" || s.body["qr"] != nil {
		t.Fatalf("push start: %d %v", s.code, s.body)
	}
	if want := "/authentication/notification/etsi/" + url.PathEscape("УБ12345678"); e.fake.path != want {
		t.Fatalf("path %s ≠ %s", e.fake.path, want)
	}
	e.fake.set("OK", "Notification", "")
	ok := e.do(t, "GET", "/auth/eid/status", "", map[string]string{"Cookie": loginCookie(t, s.header)})
	if ok.body["state"] != "OK" || e.ids[0].FlowType != eid.FlowNotification {
		t.Fatalf("push ok: %v", ok.body)
	}
	e.do(t, "POST", "/auth/eid/start", `{"mode":"push","idCode":"УБ12345678"}`, nil)
	e.do(t, "POST", "/auth/eid/start", `{"mode":"push","idCode":"УБ12345678"}`, nil)
	if r := e.do(t, "POST", "/auth/eid/start", `{"mode":"push","idCode":"УБ12345678"}`, nil); r.code != 429 || r.header.Get("Retry-After") != "60" {
		t.Fatalf("rate limit: %d", r.code)
	}
}

func TestRateLimitHookIP(t *testing.T) {
	var keys []string
	e := setup(t, func(c *Config) {
		c.RateLimit = func(_ context.Context, k string) bool { keys = append(keys, k); return !strings.HasPrefix(k, "start:") }
		c.ClientIP = func(*http.Request) string { return "203.0.113.5" }
	})
	if r := e.do(t, "POST", "/auth/eid/start", `{"mode":"qr"}`, nil); r.code != 429 {
		t.Fatalf("%d", r.code)
	}
	if len(keys) != 1 || keys[0] != "start:203.0.113.5" {
		t.Fatalf("keys %v", keys)
	}
}

func pushCodes(t *testing.T, e *env, n int) []int {
	t.Helper()
	var out []int
	for range n {
		out = append(out, e.do(t, "POST", "/auth/eid/start", `{"mode":"push","idCode":"УБ12345678"}`, nil).code)
	}
	return out
}

func TestRateLimitsMergeKeepsDefaultPush(t *testing.T) {
	var keys []string
	e := setup(t, func(c *Config) {
		c.RateLimits = map[string]RateRule{"start": {Func: func(_ context.Context, k string) bool { keys = append(keys, k); return true }}}
		c.ClientIP = func(*http.Request) string { return "203.0.113.5" }
	})
	if got := pushCodes(t, e, 4); !slices.Equal(got, []int{200, 200, 200, 429}) {
		t.Fatalf("push %v", got)
	}
	if len(keys) != 4 || keys[0] != "start:203.0.113.5" {
		t.Fatalf("keys %v", keys)
	}
}

func TestRateLimitFuncAddsToDefault(t *testing.T) {
	var keys []string
	e := setup(t, func(c *Config) {
		c.RateLimit = func(_ context.Context, k string) bool { keys = append(keys, k); return true }
	})
	if got := pushCodes(t, e, 4); !slices.Equal(got, []int{200, 200, 200, 429}) {
		t.Fatalf("push %v", got)
	}
	if len(keys) != 3 {
		t.Fatalf("анхдагч татгалзсан үед RateLimit дуудагдахгүй: %v", keys)
	}
}

func TestRateLimitsOverridePush(t *testing.T) {
	for name, tc := range map[string]struct {
		rule RateRule
		want []int
	}{
		"window": {RateRule{Max: 1, Window: time.Minute}, []int{200, 429}},
		"off":    {RateRule{}, []int{200, 200, 200, 200, 200}},
		"func":   {RateRule{Func: func(context.Context, string) bool { return true }}, []int{200, 200, 200, 200, 200}},
	} {
		e := setup(t, func(c *Config) { c.RateLimits = map[string]RateRule{"push": tc.rule} })
		if got := pushCodes(t, e, len(tc.want)); !slices.Equal(got, tc.want) {
			t.Errorf("%s: %v ≠ %v", name, got, tc.want)
		}
	}
	lim := DefaultRateLimit()
	lim["start"] = RateRule{Max: 2, Window: time.Minute}
	e := setup(t, func(c *Config) {
		c.RateLimits = lim
		c.ClientIP = func(*http.Request) string { return "198.51.100.9" }
	})
	var got []int
	for range 3 {
		got = append(got, e.do(t, "POST", "/auth/eid/start", `{"mode":"qr"}`, nil).code)
	}
	if !slices.Equal(got, []int{200, 200, 429}) {
		t.Fatalf("start %v", got)
	}
}

func TestDefaultRateLimitAndValidation(t *testing.T) {
	d := DefaultRateLimit()
	if len(d) != 2 || d["push"].Max != 3 || d["push"].Window != time.Minute || d["start"].Max != 20 || d["start"].Window != time.Minute {
		t.Fatalf("%+v", d)
	}
	d["push"] = RateRule{}
	if DefaultRateLimit()["push"].Max != 3 {
		t.Fatal("DefaultRateLimit шинэ map буцаах ёстой")
	}
	for _, rl := range []map[string]RateRule{{"pin": {}}, {"push": {Max: 1}}} {
		if _, err := buildLimits(rl); err == nil {
			t.Errorf("%v: алдаа хүлээсэн", rl)
		}
	}
}

func TestForwardedClientIP(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:5555"
	r.Header.Add("X-Forwarded-For", "198.51.100.7, 10.0.0.3")
	r.Header.Add("X-Forwarded-For", "10.0.0.2")
	r.Header.Set("X-Real-IP", "10.0.0.9")
	for hops, want := range map[int]string{1: "10.0.0.2", 2: "10.0.0.3", 3: "198.51.100.7", 4: ""} {
		if got := ForwardedClientIP(hops)(r); got != want {
			t.Errorf("hops=%d: %q, хүлээсэн %q", hops, got, want)
		}
	}
	r.Header.Del("X-Forwarded-For")
	if got := ForwardedClientIP(1)(r); got != "10.0.0.9" {
		t.Errorf("X-Real-IP: %q", got)
	}
	if got := RemoteAddrIP(r); got != "10.0.0.1" {
		t.Errorf("RemoteAddrIP: %q", got)
	}
	defer func() {
		if recover() == nil {
			t.Error("hops=0 panic хийх ёстой")
		}
	}()
	ForwardedClientIP(0)
}

func TestForwardedClientIPRateLimit(t *testing.T) {
	var keys []string
	e := setup(t, func(c *Config) {
		c.RateLimit = func(_ context.Context, k string) bool { keys = append(keys, k); return true }
		c.ClientIP = ForwardedClientIP(1)
	})
	if r := e.do(t, "POST", "/auth/eid/start", `{"mode":"qr"}`, map[string]string{"X-Forwarded-For": "1.2.3.4, 198.51.100.7"}); r.code != 200 {
		t.Fatalf("%d", r.code)
	}
	if len(keys) != 1 || keys[0] != "start:198.51.100.7" {
		t.Fatalf("keys %v", keys)
	}
}

func TestCSRF(t *testing.T) {
	e := setup(t, nil)
	if r := e.do(t, "POST", "/auth/eid/start", `{"mode":"qr"}`, map[string]string{"Sec-Fetch-Site": "cross-site"}); r.code != 403 {
		t.Fatalf("cross-site: %d", r.code)
	}
	if r := e.do(t, "POST", "/auth/eid/start", `mode=qr`, map[string]string{"Content-Type": "application/x-www-form-urlencoded"}); r.code != 415 {
		t.Fatalf("form: %d", r.code)
	}
	if r := e.do(t, "GET", "/auth/eid/start?mode=qr", "", nil); r.code != 405 {
		t.Fatalf("GET qr: %d", r.code)
	}
}

func TestFailed(t *testing.T) {
	e := setup(t, nil)
	s := e.do(t, "POST", "/auth/eid/start", `{"mode":"qr"}`, nil)
	e.fake.set("USER_REFUSED", "", "")
	r := e.do(t, "GET", "/auth/eid/status", "", map[string]string{"Cookie": loginCookie(t, s.header)})
	if r.body["state"] != "FAILED" || r.body["error"] != "USER_REFUSED" {
		t.Fatalf("%v", r.body)
	}

	e = setup(t, nil)
	s = e.do(t, "POST", "/auth/eid/start", `{"mode":"qr"}`, nil)
	e.fake.tamper = true
	e.fake.set("OK", "QR", "")
	r = e.do(t, "GET", "/auth/eid/status", "", map[string]string{"Cookie": loginCookie(t, s.header)})
	if r.body["state"] != "FAILED" || r.body["error"] != "VALIDATION" || len(e.ids) != 0 {
		t.Fatalf("tampered: %v", r.body)
	}

	// QR-ээр эхэлсэн session-ийг Web2App-аар баталгаажуулсан (relay) → flowType таарахгүй.
	e = setup(t, nil)
	s = e.do(t, "POST", "/auth/eid/start", `{"mode":"qr"}`, nil)
	e.fake.set("OK", "Notification", "")
	r = e.do(t, "GET", "/auth/eid/status", "", map[string]string{"Cookie": loginCookie(t, s.header)})
	if r.body["error"] != "VALIDATION" || len(e.ids) != 0 {
		t.Fatalf("flow mismatch: %v", r.body)
	}
}

const iphoneChrome = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 CriOS/120.0 Mobile/15E148 Safari/604.1"

func TestWeb2AppFlow(t *testing.T) {
	e := setup(t, nil)
	s := e.do(t, "GET", "/auth/eid/start?mode=web2app&lang=en", "", map[string]string{"User-Agent": iphoneChrome})
	loc := s.header.Get("Location")
	if s.code != 302 || !strings.HasPrefix(loc, "https://ca.eidmongolia.mn/dl?deviceLinkType=Web2App&sessionToken=tok_ABC-123&sessionType=auth&version=1.0&lang=eng&authCode=") {
		t.Fatalf("start: %d %s", s.code, loc)
	}
	if cb := e.fake.req["initialCallbackUrl"]; cb != "https://bank.example.mn/auth/eid/callback?retScheme=googlechromes" {
		t.Fatalf("callback %v", cb)
	}
	cookie := loginCookie(t, s.header)
	const v = "dGVzdC12ZXJpZmllci0zMi1ieXRlcy14eHh4eHh4eHg"
	e.fake.set("OK", "Web2App", v)
	if r := e.do(t, "GET", "/auth/eid/status", "", map[string]string{"Cookie": cookie}); r.body["state"] != "WAIT_CALLBACK" || len(e.ids) != 0 {
		t.Fatalf("poll Web2App-ийг дуусгахгүй: %v", r.body)
	}
	cb := "/auth/eid/callback?retScheme=googlechromes&sessionId=" + sid + "&userChallengeVerifier=" + v
	// Өөр хөтөч (cookie-гүй) — verifier зөв ч хүлээн авахгүй (login CSRF).
	if r := e.do(t, "GET", cb, "", nil); r.code != 303 || r.header.Get("Location") != "/login?eid_error=expired" || len(e.ids) != 0 {
		t.Fatalf("unbound: %d %s", r.code, r.header.Get("Location"))
	}
	// Буруу verifier → VALIDATION.
	bad := strings.Replace(cb, v, "wrong-verifier", 1)
	if r := e.do(t, "GET", bad, "", map[string]string{"Cookie": cookie}); r.header.Get("Location") != "/login?eid_error=VALIDATION" || len(e.ids) != 0 {
		t.Fatalf("bad verifier: %s", r.header.Get("Location"))
	}

	e = setup(t, nil)
	s = e.do(t, "GET", "/auth/eid/start?mode=web2app", "", map[string]string{"User-Agent": iphoneChrome})
	cookie = loginCookie(t, s.header)
	e.fake.set("OK", "Web2App", v)
	r := e.do(t, "GET", cb, "", map[string]string{"Cookie": cookie})
	if r.code != 303 || r.header.Get("Location") != "/dashboard" || len(e.ids) != 1 || e.ids[0].FlowType != eid.FlowWeb2App {
		t.Fatalf("callback ok: %d %s %+v", r.code, r.header.Get("Location"), e.ids)
	}
}

func TestCallbackUnbound(t *testing.T) {
	e := setup(t, nil)
	s := e.do(t, "GET", "/auth/eid/start?mode=web2app", "", map[string]string{"User-Agent": iphoneChrome})
	cookie := loginCookie(t, s.header)
	e.fake.set("OK", "Web2App", "v")
	for _, target := range []string{
		"/auth/eid/callback?sessionId=" + sid,
		"/auth/eid/callback?sessionId=11111111-1111-4111-8111-111111111111&userChallengeVerifier=v",
	} {
		if r := e.do(t, "GET", target, "", map[string]string{"Cookie": cookie}); r.header.Get("Location") != "/login?eid_error=unbound" {
			t.Fatalf("%s: %s", target, r.header.Get("Location"))
		}
	}
	if len(e.ids) != 0 {
		t.Fatal("onSuccess дуудагдах ёсгүй")
	}
}

func TestConfig(t *testing.T) {
	c, _ := eid.NewClient(eid.Config{Credentials: eid.Credentials{APISecret: "x", RPName: "RP"}})
	ok := func(w http.ResponseWriter, r *http.Request, id *Identity) (*Success, error) { return nil, nil }
	for _, cb := range []string{"https://bank.mn/eid/cb", "http://bank.mn/auth/eid/callback"} {
		if _, err := New(Config{Client: c, OnSuccess: ok, CallbackURL: cb}); err == nil {
			t.Fatalf("%s хүлээн авах ёсгүй", cb)
		}
	}
	if _, err := New(Config{Client: c}); err == nil {
		t.Fatal("OnSuccess заавал")
	}
	e := setup(t, func(c *Config) { c.CallbackURL = "" })
	if r := e.do(t, "GET", "/auth/eid/start?mode=web2app", "", nil); r.code != 400 {
		t.Fatalf("web2app тохируулаагүй: %d", r.code)
	}
	if r := e.do(t, "GET", "/auth/eid/other", "", nil); r.code != 404 {
		t.Fatalf("404: %d", r.code)
	}
	if got := e.h.interactions[0].DisplayText60; got != "Демо банк-д нэвтрэх" {
		t.Fatalf("display text %q", got)
	}
}

func TestWithReturnHint(t *testing.T) {
	cb := "https://bank.example.mn/auth/eid/callback"
	cases := map[string]string{
		iphoneChrome: cb + "?retScheme=googlechromes",
		"Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/120.0 Mobile Safari/537.36 SamsungBrowser/24.0": cb + "?retPkg=com.sec.android.app.sbrowser",
		"Mozilla/5.0 (Macintosh) Safari/605": cb,
	}
	for ua, want := range cases {
		if got := WithReturnHint(cb, ua); got != want {
			t.Fatalf("%s: %s ≠ %s", ua, got, want)
		}
	}
}

// v0.6.0: start анхдагчаар нэг IP-ээс 60 секундэд 20; RateRule{} — хязгааргүй.
func TestDefaultStartLimit(t *testing.T) {
	ip := "192.0.2.1"
	e := setup(t, func(c *Config) { c.ClientIP = func(*http.Request) string { return ip } })
	for i := 0; i < 20; i++ {
		if r := e.do(t, "POST", "/auth/eid/start", `{"mode":"qr"}`, nil); r.code != 200 {
			t.Fatalf("#%d: %d", i, r.code)
		}
	}
	if r := e.do(t, "POST", "/auth/eid/start", `{"mode":"qr"}`, nil); r.code != 429 {
		t.Fatalf("21: %d", r.code)
	}
	ip = "192.0.2.2"
	if r := e.do(t, "POST", "/auth/eid/start", `{"mode":"qr"}`, nil); r.code != 200 {
		t.Fatalf("өөр IP: %d", r.code)
	}
	off := setup(t, func(c *Config) {
		c.ClientIP = func(*http.Request) string { return "192.0.2.1" }
		c.RateLimits = map[string]RateRule{"start": {}}
	})
	for i := 0; i < 25; i++ {
		if r := off.do(t, "POST", "/auth/eid/start", `{"mode":"qr"}`, nil); r.code != 200 {
			t.Fatalf("off #%d: %d", i, r.code)
		}
	}
}

// Дүүрсэн хязгаарлагч: олон түлхүүрээр дүүргэж тухайн түлхүүрийн хязгаарыг тойрох боломжгүй; шинэ түлхүүр fail-closed;
// цонх өнгөрсөн түлхүүр цэвэрлэгдэнэ.
func TestWindowLimiterFullFailsClosed(t *testing.T) {
	ctx := context.Background()
	lim := windowLimiter(1, 50*time.Millisecond, 3)
	if !lim(ctx, "push:victim") || lim(ctx, "push:victim") {
		t.Fatal("victim 1/цонх")
	}
	if !lim(ctx, "a") || !lim(ctx, "b") {
		t.Fatal("a, b")
	}
	if lim(ctx, "c") {
		t.Fatal("дүүрсэн — шинэ түлхүүр татгалзагдах ёстой")
	}
	if lim(ctx, "push:victim") {
		t.Fatal("victim-ийн тоолуур арилсан (v0.5.x: бүгдийг цэвэрлэдэг байв)")
	}
	time.Sleep(60 * time.Millisecond)
	if !lim(ctx, "c") {
		t.Fatal("цонх өнгөрсөн түлхүүрүүд цэвэрлэгдэх ёстой")
	}
}

// Санах ойн сан: дээд хэмжээнд хүрвэл хугацаа дууссаныг цэвэрлэнэ, үгүй бол ErrStoreFull (эхэлсэнийг устгахгүй);
// start → 503 busy.
func TestMemoryStoreCap(t *testing.T) {
	ctx := context.Background()
	s := newMemoryStore(2)
	if err := s.Set(ctx, &Tx{SessionID: "a"}, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := s.Set(ctx, &Tx{SessionID: "b"}, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	if err := s.Set(ctx, &Tx{SessionID: "c"}, time.Minute); err != nil {
		t.Fatal("хугацаа дууссан b цэвэрлэгдэх ёстой:", err)
	}
	if err := s.Set(ctx, &Tx{SessionID: "d"}, time.Minute); !errors.Is(err, ErrStoreFull) {
		t.Fatal(err)
	}
	if err := s.Set(ctx, &Tx{SessionID: "a"}, time.Minute); err != nil {
		t.Fatal("байгаа түлхүүрийг шинэчлэх:", err)
	}
	if tx, _ := s.Get(ctx, "a"); tx == nil {
		t.Fatal("a устсан")
	}
	full := setup(t, func(c *Config) { c.Store = fullStore{} })
	r := full.do(t, "POST", "/auth/eid/start", `{"mode":"qr"}`, nil)
	if r.code != 503 || r.body["error"] != "busy" {
		t.Fatalf("%d %v", r.code, r.body)
	}
	if MemoryStoreMax != 10_000 || NewMemoryStore().(*memoryStore).max != MemoryStoreMax {
		t.Fatal("MemoryStoreMax")
	}
}

type fullStore struct{}

func (fullStore) Get(context.Context, string) (*Tx, error)      { return nil, nil }
func (fullStore) Set(context.Context, *Tx, time.Duration) error { return ErrStoreFull }
func (fullStore) Delete(context.Context, string) (bool, error)  { return false, nil }
