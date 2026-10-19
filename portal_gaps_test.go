package eid

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Порталыг (eid-mongolia-mn) SDK руу шилжүүлэхэд илэрсэн дутагдлууд (0.1.2).

func TestSessionPersonRawToken(t *testing.T) {
	raw := `{"state":"COMPLETE","result":{"endResult":"OK","documentNumber":"d1"},
		"person":{"firstName":"Бат","lastName":"Дорж","familyName":"Боржигон","firstNameEn":"BAT","lastNameEn":"DORJ",
			"civilId":"12345678","regNo":"УБ99112233","birthDate":"1999-11-22","gender":"M","geID":42},
		"tokenCertificate":{"status":"ISSUED","authSerialHex":"3F9A","signSerialHex":"7C01"},"futureField":1}`
	r, err := ParseSessionResult([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	want := Person{FirstName: "Бат", LastName: "Дорж", FamilyName: "Боржигон", FirstNameEn: "BAT", LastNameEn: "DORJ",
		CivilID: "12345678", RegNo: "УБ99112233", BirthDate: "1999-11-22", Gender: "M", GeID: 42}
	if r.Person == nil || *r.Person != want {
		t.Fatalf("%+v", r.Person)
	}
	if r.TokenCertificate == nil || r.TokenCertificate.Status != TokenCertIssued || r.TokenCertificate.SignSerialHex != "7C01" {
		t.Fatalf("%+v", r.TokenCertificate)
	}
	var m map[string]any
	if json.Unmarshal(r.Raw, &m) != nil || m["futureField"] != float64(1) {
		t.Fatalf("raw %s", r.Raw)
	}
	if !PersonMatchesCertificate(r.Person, Subject{SerialNumber: "PNOMN-12345678"}) ||
		PersonMatchesCertificate(r.Person, Subject{SerialNumber: "PNOMN-87654321"}) ||
		PersonMatchesCertificate(&Person{}, Subject{SerialNumber: "PNOMN-"}) || PersonMatchesCertificate(nil, Subject{}) {
		t.Fatal("PersonMatchesCertificate")
	}
	r, _ = ParseSessionResult([]byte(`{"state":"RUNNING","person":{},"tokenCertificate":{}}`))
	if r.Person != nil || r.TokenCertificate != nil {
		t.Fatalf("%+v", r)
	}

	// Poll — Raw бөглөгдөнө
	c, _ := server(t, jsonReply(200, raw))
	pr, err := c.Session.Poll(context.Background(), "s1", time.Second)
	if err != nil || pr.Person == nil || pr.Person.GeID != 42 || len(pr.Raw) == 0 {
		t.Fatal(err, pr)
	}
}

func TestRetryAfterAndHeaders(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	for in, want := range map[string]time.Duration{
		"5": 5 * time.Second, " 60 ": time.Minute, "": 0, "-1": 0, "0": 0, "abc": 0, "999999999": 0,
		now.Add(30 * time.Second).Format(http.TimeFormat): 30 * time.Second,
		now.Add(-time.Minute).Format(http.TimeFormat):     0,
	} {
		if got := parseRetryAfter(in, now); got != want {
			t.Errorf("%q → %v, want %v", in, got, want)
		}
	}

	ctx := context.Background()
	reply := func(status int, retry, body string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			if retry != "" {
				w.Header().Set("Retry-After", retry)
			}
			w.Header().Set("X-Request-Id", "req-1")
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
		}
	}
	reg := PDFSignatureRegistration{DocID: "d", RevIndex: 1, Medium: PDFMediumPhone, SessionID: "s1", CMS: []byte{0},
		FileName: "a.pdf", InSHA256: "in", PageSHA256: "pg", SigRevSHA256: "sr", OutSHA256: "out"}
	for _, tc := range []struct {
		status int
		retry  string
		code   string
	}{
		{429, "5", CodeRateLimited},
		{503, "5", CodeIssuancePending},
		{503, "5", CodeStateUnavailable},
	} {
		c, _ := server(t, reply(tc.status, tc.retry, `{"error":"түр","code":"`+tc.code+`"}`))
		_, err := c.PDF.RegisterSignature(ctx, reg)
		var api *APIError
		if !errors.As(err, &api) || api.Status != tc.status || api.Code != tc.code || !api.Retryable() ||
			api.RetryAfter != parseRetryAfter(tc.retry, time.Now()) || api.RetryAfter == 0 || api.Header.Get("X-Request-Id") != "req-1" {
			t.Fatalf("%+v: %v", tc, err)
		}
	}
	c, _ := server(t, reply(409, "", `{"error":"x","code":"DOC_ID_CONFLICT"}`))
	var api *APIError
	if _, err := c.PDF.RegisterSignature(ctx, reg); !errors.As(err, &api) || api.Retryable() {
		t.Fatal(err)
	}
	// proxy-ийн 503 + Retry-After — кодгүй ч давтаж болно
	c, _ = server(t, reply(503, "10", "<html>bad gateway</html>"))
	if _, err := c.PDF.RegisterSignature(ctx, reg); !errors.As(err, &api) || !api.Retryable() || api.Code != "" {
		t.Fatal(err)
	}
	c, _ = server(t, reply(403, "7", `{"error":"x","code":"REPRESENTATION_REVOKED"}`))
	var fe *ForbiddenError
	if _, err := c.PDF.RegisterSignature(ctx, reg); !errors.As(err, &fe) || fe.RetryAfter != 7*time.Second || fe.Header.Get("X-Request-Id") != "req-1" {
		t.Fatal(err)
	}
}

func TestPDFTimeoutConfigurable(t *testing.T) {
	c, err := NewClient(Config{Credentials: creds, Trust: TrustConfig{AllowUntrusted: true}})
	if err != nil || c.PDF.timeout != DefaultPDFTimeout || DefaultPDFTimeout != 80*time.Second {
		t.Fatal(err, c.PDF.timeout)
	}
	srv, _ := server(t, func(http.ResponseWriter, *http.Request) { time.Sleep(300 * time.Millisecond) })
	base := srv.PDF.h.base
	c, err = NewClient(Config{BaseURL: base, Credentials: creds, PDFTimeout: 50 * time.Millisecond, Trust: TrustConfig{AllowUntrusted: true}})
	if err != nil {
		t.Fatal(err)
	}
	var ne *NetworkError
	reg := PDFSignatureRegistration{DocID: "d", RevIndex: 2, Medium: PDFMediumToken, CMS: []byte{0}}
	if _, err := c.PDF.RegisterSignature(context.Background(), reg); !errors.As(err, &ne) || !ne.Timeout {
		t.Fatal(err)
	}
}

func TestSignFileName(t *testing.T) {
	c, rc := server(t, jsonReply(200, `{"sessionID":"s1","vc":{"type":"alphaNumeric5","value":"12345"}}`))
	if _, err := c.Sign.DigestByEtsi(context.Background(), "PNOMN-1", SHA256Base64([]byte("x")), nil, &SignOptions{FileName: " Гэрээ.pdf "}); err != nil {
		t.Fatal(err)
	}
	_, body := rc.last()
	var m map[string]any
	_ = json.Unmarshal(body, &m)
	if m["fileName"] != "Гэрээ.pdf" {
		t.Fatalf("%s", body)
	}
	if _, err := c.Sign.DigestByEtsi(context.Background(), "PNOMN-1", SHA256Base64([]byte("x")), nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, body = rc.last(); strings.Contains(string(body), "fileName") {
		t.Fatalf("fileName хоосон ч явав: %s", body)
	}
}

func TestPersonService(t *testing.T) {
	ctx := context.Background()
	c, rc := server(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/certificates/"):
			_, _ = io.WriteString(w, `{"personEtsi":"PNOMN-1","counts":{"valid":1,"total":1},"certificates":[{"documentNumber":"d",
				"type":"AUTH","keyMedium":"TOKEN","serialNumber":"ab","certificateLevel":"ADVANCED","status":"VALID",
				"notBefore":"2026-10-12T16:36:35+08:00","notAfter":"2027-10-12T16:36:35+08:00","issuerDn":"CN=x",
				"organization":{"etsi":"NTRMN-6235972","name":"Гэрэгэ"}}]}`)
		case strings.HasPrefix(r.URL.Path, "/devices/"):
			_, _ = io.WriteString(w, `{"personEtsi":"PNOMN-1","devices":[{"documentNumber":"d","platform":"APNS",
				"enrolledAt":"2026-10-01T00:00:00Z","active":true}],"activeCount":1,"total":1}`)
		case strings.HasPrefix(r.URL.Path, "/rp/activity/"):
			_, _ = io.WriteString(w, `{"personEtsi":"PNOMN-1","counts":{"authentication":2,"signature":1},"sessions":[{"id":"9",
				"kind":"AUTH","flow":"AUTHENTICATION","outcome":"OK","timestamp":"2026-10-01T00:00:00Z"}],"total":3,"limit":5,"offset":10}`)
		case strings.HasPrefix(r.URL.Path, "/person/summary/"):
			_, _ = io.WriteString(w, `{"personEtsi":"PNOMN-1","firstName":"Бат","lastName":"Дорж","certificates":{"valid":2},
				"activity":{"authentication":42},"devicesActive":1,"devicesTotal":2,"representationCount":1}`)
		case strings.HasPrefix(r.URL.Path, "/person/children/"):
			_, _ = io.WriteString(w, `{"children":[{"etsi":"PNOMN-2","regNo":"УБ","name":"Дорж Сүх","registered":false}]}`)
		}
	})
	certs, err := c.Person.Certificates(ctx, "PNOMN-1")
	if err != nil || certs.Counts.Valid != 1 || certs.Certificates[0].Organization.Etsi != "NTRMN-6235972" ||
		certs.Certificates[0].NotAfter.Year() != 2027 || len(certs.Raw) == 0 {
		t.Fatal(err, certs)
	}
	if req, _ := rc.last(); req.URL.Path != "/certificates/etsi/PNOMN-1" || req.Method != http.MethodGet {
		t.Fatal(req.URL.Path)
	}
	dev, err := c.Person.Devices(ctx, "PNOMN-1")
	if err != nil || dev.ActiveCount != 1 || dev.Devices[0].Platform != "APNS" {
		t.Fatal(err, dev)
	}
	act, err := c.Person.Activity(ctx, "PNOMN-1", &ActivityQuery{Flow: "AUTHENTICATION", Limit: 5, Offset: 10})
	if err != nil || act.Counts.Authentication != 2 || act.Sessions[0].Kind != "AUTH" || act.Offset != 10 {
		t.Fatal(err, act)
	}
	if req, _ := rc.last(); req.URL.Path != "/rp/activity/etsi/PNOMN-1" || req.URL.RawQuery != "flow=AUTHENTICATION&limit=5&offset=10" {
		t.Fatal(req.URL.String())
	}
	if _, err := c.Person.Activity(ctx, "PNOMN-1", nil); err != nil {
		t.Fatal(err)
	}
	if req, _ := rc.last(); req.URL.RawQuery != "" {
		t.Fatal(req.URL.RawQuery)
	}
	sum, err := c.Person.Summary(ctx, "PNOMN-1")
	if err != nil || sum.LastName != "Дорж" || sum.Activity.Authentication != 42 || sum.RepresentationCount != 1 {
		t.Fatal(err, sum)
	}
	if req, _ := rc.last(); req.URL.Path != "/person/summary/etsi/PNOMN-1" {
		t.Fatal(req.URL.Path)
	}
	ch, err := c.Person.Children(ctx, "PNOMN-1")
	if err != nil || len(ch.Children) != 1 || ch.Children[0].Name != "Дорж Сүх" {
		t.Fatal(err, ch)
	}
	if req, _ := rc.last(); req.URL.Path != "/person/children/etsi/PNOMN-1" {
		t.Fatal(req.URL.Path)
	}
	c, _ = server(t, jsonReply(403, `{"error":"RP-д PKI_READ эрх алга"}`))
	var fe *ForbiddenError
	if _, err := c.Person.Summary(ctx, "PNOMN-1"); !errors.As(err, &fe) {
		t.Fatal(err)
	}
}

// tokenKeys — EC P-256 CSR + тэр түлхүүрт олгосон гэрчилгээ (testPKI inter-ээс).
func tokenKeys(t *testing.T, serial string) (csr []byte, cert *testCA) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored"}}, k)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := leafTmpl()
	tmpl.Subject.SerialNumber = serial
	return csr, mkCert(t, tmpl, testPKI(t).inter, &k.PublicKey, k)
}

func TestTokenCertificate(t *testing.T) {
	ctx := context.Background()
	csrA, certA := tokenKeys(t, "PNOMN-12345678")
	csrS, certS := tokenKeys(t, "PNOMN-12345678")
	hx := func(b []byte) string { h := sha256.Sum256(b); return strings.ToUpper(hex.EncodeToString(h[:])) }
	c, rc := server(t, jsonReply(200, `{"sessionID":"ts1","vc":{"type":"alphaNumeric5","value":"04817"},
		"csrAuthSha256":"`+hx(csrA)+`","csrSignSha256":"`+hx(csrS)+`","expiresAt":"2026-10-12T16:41:34+08:00"}`))
	s, err := c.Token.IssueCertificate(ctx, TokenCertInput{SignerEtsi: "PNOMN-12345678", CSRAuth: csrA, CSRSign: csrS, TokenSerial: "EP2003-0042A1"})
	if err != nil || s.SessionID != "ts1" || s.VC != "04817" || s.CSRAuthSHA256 != strings.ToLower(hx(csrA)) {
		t.Fatal(err, s)
	}
	req, body := rc.last()
	var got map[string]any
	_ = json.Unmarshal(body, &got)
	want := map[string]any{"relyingPartyUUID": "rp-uuid", "relyingPartyName": "Гэрээний систем",
		"signer": map[string]any{"etsi": "PNOMN-12345678"}, "csrAuth": base64.StdEncoding.EncodeToString(csrA),
		"csrSign": base64.StdEncoding.EncodeToString(csrS), "tokenSerial": "EP2003-0042A1", "onBehalfOf": "", "flow": "notification"}
	if req.URL.Path != "/token/certificate" || req.Method != http.MethodPost || !reflect.DeepEqual(got, want) {
		t.Fatalf("%s %s", req.URL.Path, body)
	}
	// CA өөр CSR-ийн hash буцаавал итгэхгүй
	c, _ = server(t, jsonReply(200, `{"sessionID":"ts1","csrAuthSha256":"`+hx(csrS)+`","csrSignSha256":"`+hx(csrS)+`"}`))
	_, err = c.Token.IssueCertificate(ctx, TokenCertInput{SignerEtsi: "PNOMN-1", CSRAuth: csrA, CSRSign: csrS, TokenSerial: "x", TokenLabel: "L", OnBehalfOf: "NTRMN-1"})
	wantInvalid(t, err, "csrAuthSha256")
	if _, err := c.Token.IssueCertificate(ctx, TokenCertInput{}); err == nil {
		t.Fatal("хоосон оролт")
	}

	b64 := base64.StdEncoding.EncodeToString
	result := `{"status":"ISSUED","auth":{"certificate":"` + b64(certA.cert.Raw) + `","serialHex":"A"},
		"sign":{"certificate":"` + b64(certS.cert.Raw) + `","serialHex":"S"},"chain":["x"],"organization":null,
		"keyMedium":"TOKEN","certificateLevel":"ADVANCED"}`
	c, rc = server(t, jsonReply(200, result))
	r, err := c.Token.CertificateResult(ctx, "ts1")
	if err != nil || r.Status != TokenCertIssued || r.Organization != nil || r.KeyMedium != "TOKEN" || len(r.Raw) == 0 {
		t.Fatal(err, r)
	}
	if req, _ := rc.last(); req.URL.Path != "/token/certificate/ts1" || req.Method != http.MethodGet {
		t.Fatal(req.URL.Path)
	}
	if err := VerifyTokenCertificates(r, csrA, csrS); err != nil {
		t.Fatal(err)
	}
	wantInvalid(t, VerifyTokenCertificates(r, csrS, csrA), "түлхүүр")
	wantInvalid(t, VerifyTokenCertificates(&TokenCertResult{}, csrA, csrS), "алга")

	c, _ = server(t, jsonReply(409, `{"error":"хязгаар","code":"TOKEN_LIMIT_REACHED","kind":"ORGANIZATION","limit":1,"organization":"NTRMN-6235972"}`))
	_, err = c.Token.IssueCertificate(ctx, TokenCertInput{SignerEtsi: "PNOMN-1", CSRAuth: csrA, CSRSign: csrS, TokenSerial: "x"})
	if l, ok := TokenLimitOf(err); !ok || l.Kind != TokenKindOrganization || l.Limit != 1 || l.Organization != "NTRMN-6235972" {
		t.Fatal(err, l)
	}
	for _, body := range []string{
		`{"code":"TOKEN_LIMIT_REACHED","kind":"PERSONAL"}`,
		`{"code":"TOKEN_LIMIT_REACHED","kind":"ORGANIZATION","limit":1}`,
		`{"code":"TOKEN_LIMIT_REACHED","kind":"X","limit":1}`,
		`{"code":"TOKEN_IN_USE","kind":"PERSONAL","limit":1}`,
	} {
		if _, ok := TokenLimitOf(&APIError{Status: 409, Code: errorCode(body), Body: body}); ok {
			t.Fatal(body)
		}
	}
	if l, ok := TokenLimitOf(&APIError{Status: 409, Code: CodeTokenLimitReached, Body: `{"kind":"PERSONAL","limit":0}`}); !ok || l.Limit != 0 {
		t.Fatal(l)
	}

	c, _ = server(t, jsonReply(409, `{"error":"Токены төрлийг солихын тулд …","code":"TOKEN_SCOPE_CHANGE"}`))
	_, err = c.Token.IssueCertificate(ctx, TokenCertInput{SignerEtsi: "PNOMN-1", CSRAuth: csrA, CSRSign: csrS, TokenSerial: "x", OnBehalfOf: "NTRMN-1"})
	var api *APIError
	if !errors.As(err, &api) || api.Status != 409 || api.Code != CodeTokenScopeChange || api.Retryable() {
		t.Fatal(err)
	}
	if _, ok := TokenLimitOf(err); ok {
		t.Fatal("scope change ≠ limit")
	}
}

func TestTokenCertificateInfo(t *testing.T) {
	c, rc := server(t, jsonReply(200, `{"version":"v3","tokenCertificate":{"certificateLevel":"ADVANCED","enabled":true,
		"issue":"https://rp.eidmongolia.mn/token/certificate","keyAlgorithm":"EC P-256 (ecdsa-with-SHA256)","onBehalfOf":"optional",
		"permission":"TOKEN_ISSUE","result":"https://rp.eidmongolia.mn/token/certificate/{sessionID}","scopeLockedOnRenewal":true,"appTransaction":"optional","personalAutoSupersede":true}}`))
	i, err := c.Token.CertificateInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := rc.last(); r.URL.Path != "/.well-known/eid" || !i.Enabled || !i.ScopeLockedOnRenewal || i.Permission != "TOKEN_ISSUE" || i.OnBehalfOf != "optional" || i.AppTransaction != "optional" || !i.PersonalAutoSupersede || len(i.Raw) == 0 {
		t.Fatalf("%+v", i)
	}
	old, _ := server(t, jsonReply(200, `{"version":"v3"}`))
	i, err = old.Token.CertificateInfo(context.Background())
	if err != nil || i.Enabled || i.ScopeLockedOnRenewal || i.AppTransaction != "" {
		t.Fatalf("%+v %v", i, err)
	}
}

// TestTokenCertificateAppTransaction — appTransaction (CA !390): өгсөн бол илгээнэ, > 16 KiB бол илгээхгүй,
// 400 APP_ATTESTATION_INVALID → *APIError.Code.
func TestTokenCertificateAppTransaction(t *testing.T) {
	ctx := context.Background()
	csrA, _ := tokenKeys(t, "PNOMN-12345678")
	csrS, _ := tokenKeys(t, "PNOMN-12345678")
	hx := func(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
	in := TokenCertInput{SignerEtsi: "PNOMN-12345678", CSRAuth: csrA, CSRSign: csrS, TokenSerial: "EP2003-0042A1",
		AppTransaction: "eyJhbGciOiJFUzI1NiJ9.e30.sig"}
	c, rc := server(t, jsonReply(200, `{"sessionID":"ts1","vc":{"type":"alphaNumeric5","value":"04817"},
		"csrAuthSha256":"`+hx(csrA)+`","csrSignSha256":"`+hx(csrS)+`"}`))
	if s, err := c.Token.IssueCertificate(ctx, in); err != nil || s.Supersedes != nil {
		t.Fatal(err, s)
	}
	_, body := rc.last()
	var got map[string]any
	_ = json.Unmarshal(body, &got)
	if got["appTransaction"] != in.AppTransaction {
		t.Fatalf("%s", body)
	}

	// supersedes (CA !392): хувийн хязгаар хүрсэн үед
	c2, _ := server(t, jsonReply(200, `{"sessionID":"ts2","csrAuthSha256":"`+hx(csrA)+`","csrSignSha256":"`+hx(csrS)+`",
		"supersedes":[{"tokenSerial":"EP2003-0001"}]}`))
	if s, err := c2.Token.IssueCertificate(ctx, in); err != nil || len(s.Supersedes) != 1 || s.Supersedes[0].TokenSerial != "EP2003-0001" {
		t.Fatal(err, s)
	}

	in.AppTransaction = strings.Repeat("a", MaxAppTransactionBytes)
	if _, err := c.Token.IssueCertificate(ctx, in); err != nil {
		t.Fatal("16 KiB яг зөвшөөрөгдөнө:", err)
	}
	n := len(rc.reqs)
	in.AppTransaction += "a"
	if _, err := c.Token.IssueCertificate(ctx, in); !errors.Is(err, ErrAppTransactionTooLarge) {
		t.Fatal(err)
	}
	if len(rc.reqs) != n {
		t.Fatal("хэт том appTransaction CA руу илгээгдсэн")
	}

	c, _ = server(t, jsonReply(400, `{"error":"апп баталгаа хүчингүй","code":"APP_ATTESTATION_INVALID"}`))
	in.AppTransaction = "x.y.z"
	_, err := c.Token.IssueCertificate(ctx, in)
	var api *APIError
	if !errors.As(err, &api) || api.Status != 400 || api.Code != CodeAppAttestationInvalid || api.Retryable() {
		t.Fatal(err)
	}
}

func errorCode(body string) string { _, c := errorBody([]byte(body)); return c }

func TestTokenAuth(t *testing.T) {
	ctx := context.Background()
	// docs/TOKEN_AUTH.md тест вектор
	d, err := TokenAuthDigest("2d87bd3a-1303-41bf-81bd-37d6b92fb7bc", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")
	if err != nil || hex.EncodeToString(d) != "a88f9803b82f9e0701752360184f18f2035bc2447372283e3fa009fe2cfeeef5" {
		t.Fatal(err, hex.EncodeToString(d))
	}
	for _, bad := range [][2]string{
		{"2D87BD3A-1303-41BF-81BD-37D6B92FB7BC", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="},
		{"2d87bd3a-1303-41bf-81bd-37d6b92fb7bc", "AAEC"},
	} {
		if _, err := TokenAuthDigest(bad[0], bad[1]); err == nil {
			t.Fatal(bad)
		}
	}

	c, rc := server(t, jsonReply(200, `{"challengeId":"c1","challenge":"q3J0","rpUUID":"2d87bd3a-1303-41bf-81bd-37d6b92fb7bc","expiresAt":"2026-10-12T08:42:10Z"}`))
	ch, err := c.Token.AuthChallenge(ctx)
	if err != nil || ch.ChallengeID != "c1" || ch.ExpiresAt.IsZero() {
		t.Fatal(err, ch)
	}
	req, body := rc.last()
	if req.URL.Path != "/token/auth/challenge" || string(body) != `{"relyingPartyName":"Гэрээний систем","relyingPartyUUID":"rp-uuid"}` {
		t.Fatalf("%s %s", req.URL.Path, body)
	}

	// v0.6.0: SDK CA руу илгээхээс өмнө гарын үсэг (r||s, TokenAuthDigest), rpUUID, гэрчилгээг (гинж/зориулалт/issuer) шалгана.
	const rp = "2d87bd3a-1303-41bf-81bd-37d6b92fb7bc"
	chal := &TokenAuthChallenge{ChallengeID: "c1", Challenge: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", RPUUID: rp}
	_, cert := tokenKeys(t, "PNOMN-55667788")
	sigOf := func(k crypto.Signer, ch *TokenAuthChallenge) []byte {
		dg, err := TokenAuthDigest(ch.RPUUID, ch.Challenge)
		if err != nil {
			t.Fatal(err)
		}
		r, s, err := ecdsa.Sign(rand.Reader, k.(*ecdsa.PrivateKey), dg)
		if err != nil {
			t.Fatal(err)
		}
		return append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	}
	sig := sigOf(cert.key, chal)
	p := testPKI(t)
	okTrust := TrustConfig{TrustAnchorsPEM: []string{p.root.pem}, IntermediatesPEM: []string{p.inter.pem}, AllowAnyIssuer: true}
	tsrv := func(fn http.HandlerFunc, trust TrustConfig) (*Client, *rec) {
		t.Helper()
		rc := &rec{}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			rc.mu.Lock()
			rc.reqs, rc.body = append(rc.reqs, r), append(rc.body, b)
			rc.mu.Unlock()
			fn(w, r)
		}))
		t.Cleanup(srv.Close)
		cl, err := NewClient(Config{BaseURL: srv.URL, Credentials: Credentials{RPUUID: rp, RPName: "x", APISecret: "s"}, Trust: trust})
		if err != nil {
			t.Fatal(err)
		}
		return cl, rc
	}
	ok := `{"result":{"endResult":"OK"},"identity":{"etsi":"PNOMN-55667788","givenName":"Бат","surname":"Болд"},
		"cert":{"serialHex":"4f1c","notAfter":"2027-10-12T08:40:00Z"},"organization":{"etsi":"NTRMN-1","name":"X"}}`
	c, rc = tsrv(jsonReply(200, ok), okTrust)
	res, err := c.Token.AuthVerify(ctx, chal, cert.cert.Raw, sig)
	if err != nil || res.Identity.Surname != "Болд" || res.SerialHex != "4f1c" || res.Organization.Etsi != "NTRMN-1" || res.NotAfter.Year() != 2027 {
		t.Fatal(err, res)
	}
	_, body = rc.last()
	var got map[string]string
	_ = json.Unmarshal(body, &got)
	if len(got) != 3 || got["challengeId"] != "c1" || got["certificate"] != base64.StdEncoding.EncodeToString(cert.cert.Raw) {
		t.Fatalf("%s", body)
	}
	for _, reply := range []string{
		strings.Replace(ok, "PNOMN-55667788", "PNOMN-99999999", 1), // өөр иргэн
		strings.Replace(ok, `"OK"`, `"DENIED"`, 1),
	} {
		c, _ = tsrv(jsonReply(200, reply), okTrust)
		_, err = c.Token.AuthVerify(ctx, chal, cert.cert.Raw, sig)
		wantInvalid(t, err, "token auth")
		if strings.Contains(err.Error(), "PNOMN-") {
			t.Fatal("PII:", err)
		}
	}
	// CA OK гэсэн ч SDK-ийн шалгалт унавал CA руу ЯВАХГҮЙ.
	other := *chal
	other.Challenge = "AQECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	otherRP := *chal
	otherRP.RPUUID = "00000000-0000-4000-8000-000000000000"
	// Токены SIGN гэрчилгээ (P-CITIZEN-SIGN-TOKEN: KU contentCommitment, EKU-гүй) нэвтрэлтэд.
	sk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signTmpl := leafTmpl()
	signTmpl.Subject.SerialNumber = "PNOMN-55667788"
	signTmpl.KeyUsage, signTmpl.ExtKeyUsage = x509.KeyUsageDigitalSignature|x509.KeyUsageContentCommitment, nil
	signCert := mkCert(t, signTmpl, p.inter, &sk.PublicKey, sk)
	for _, tc := range []struct {
		name  string
		ch    *TokenAuthChallenge
		cert  []byte
		sig   []byte
		trust TrustConfig
		want  string
	}{
		{"тэг гарын үсэг", chal, cert.cert.Raw, make([]byte, 64), okTrust, "гарын үсэг"},
		{"өөр challenge", &other, cert.cert.Raw, sig, okTrust, "гарын үсэг"},
		{"өөр RP", &otherRP, cert.cert.Raw, sigOf(cert.key, &otherRP), okTrust, "rpUUID"},
		{"анхдагч issuer", chal, cert.cert.Raw, sig, TrustConfig{TrustAnchorsPEM: []string{p.root.pem}, IntermediatesPEM: []string{p.inter.pem}}, "AllowedIssuerSKIs"},
		{"anchor алга", chal, cert.cert.Raw, sig, TrustConfig{}, "trust anchor"},
		{"гарын үсгийн гэрчилгээ", chal, signCert.cert.Raw, sigOf(signCert.key, chal), okTrust, "clientAuth"},
	} {
		cl, rcl := tsrv(jsonReply(200, ok), tc.trust)
		_, err := cl.Token.AuthVerify(ctx, tc.ch, tc.cert, tc.sig)
		wantInvalid(t, err, tc.want)
		if len(rcl.reqs) != 0 {
			t.Fatalf("%s: CA руу явсан", tc.name)
		}
	}
	if _, err := c.Token.AuthVerify(ctx, chal, []byte("junk"), sig); err == nil {
		t.Fatal("буруу гэрчилгээ")
	}
	if _, err := c.Token.AuthVerify(ctx, nil, cert.cert.Raw, sig); err == nil {
		t.Fatal("challenge алга")
	}
	c, _ = tsrv(jsonReply(410, `{"error":"x","code":"CHALLENGE_EXPIRED"}`), okTrust)
	var api *APIError
	if _, err := c.Token.AuthVerify(ctx, chal, cert.cert.Raw, sig); !errors.As(err, &api) || api.Code != "CHALLENGE_EXPIRED" {
		t.Fatal(err)
	}
}

func TestAuthenticationErrorBody(t *testing.T) {
	// CA-ийн rpAuth: {"error":"RP API secret буруу"} (code-гүй)
	c, _ := server(t, jsonReply(401, `{"error":"RP API secret буруу"}`))
	var ae *AuthenticationError
	if _, err := c.Session.Poll(context.Background(), "x", time.Second); !errors.As(err, &ae) || ae.Message != "RP API secret буруу" || ae.Code != "" {
		t.Fatal(err)
	}
	c, _ = server(t, jsonReply(401, `{"error":"API secret буруу","code":"RP_AUTH_FAILED"}`))
	if _, err := c.Session.Poll(context.Background(), "x", time.Second); !errors.As(err, &ae) ||
		ae.Code != "RP_AUTH_FAILED" || ae.Message != "API secret буруу" || !strings.Contains(ae.Body, "RP_AUTH_FAILED") ||
		!strings.Contains(ae.Error(), "RP_AUTH_FAILED") {
		t.Fatal(err)
	}
	c, _ = server(t, jsonReply(401, "<html>401 Authorization Required</html>"))
	if _, err := c.Session.Poll(context.Background(), "x", time.Second); !errors.As(err, &ae) || ae.Code != "" || ae.Message != "" ||
		!strings.Contains(ae.Body, "html") {
		t.Fatal(err)
	}
}

// ── validator ──

func purposeLeaf(t *testing.T, ku x509.KeyUsage, eku []x509.ExtKeyUsage) *testCA {
	t.Helper()
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := leafTmpl()
	tmpl.KeyUsage, tmpl.ExtKeyUsage = ku, eku
	return mkCert(t, tmpl, testPKI(t).inter, &k.PublicKey, k)
}

func validatorWith(t *testing.T, mod func(*TrustConfig)) *Validator {
	t.Helper()
	p := testPKI(t)
	tc := TrustConfig{TrustAnchorsPEM: []string{p.root.pem}, IntermediatesPEM: []string{p.inter.pem}, AllowAnyIssuer: true}
	mod(&tc)
	v, err := NewValidator(tc)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestValidatorIssuerAllowlist(t *testing.T) {
	p := testPKI(t)
	r, acsp := signedAuth(t, "QR", authOpts{})
	ski := strings.ToUpper(hexColon(p.inter.cert.SubjectKeyId)) // ":"-тэй, том үсэг
	if _, err := validatorWith(t, func(c *TrustConfig) { c.AllowedIssuerSKIs = []string{ski} }).ValidateAuth(r, acsp, ValidateAuthOptions{}); err != nil {
		t.Fatal(err)
	}
	_, err := validatorWith(t, func(c *TrustConfig) { c.AllowedIssuerSKIs = []string{CitizenIssuingCASKI} }).ValidateAuth(r, acsp, ValidateAuthOptions{})
	wantInvalid(t, err, "AllowedIssuerSKIs")
	if _, err := NewValidator(TrustConfig{AllowedIssuerSKIs: []string{"zz"}}); err == nil {
		t.Fatal("буруу SKI")
	}
	// CitizenIssuingCASKI нь testdata-ийн бодит 04-тэй таарна
	b, err := os.ReadFile("testdata/eid-mongolia-issuing-ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	pem, _ := parseCerts([]string{string(b)})
	if hex.EncodeToString(pem[0].SubjectKeyId) != CitizenIssuingCASKI {
		t.Fatal(hex.EncodeToString(pem[0].SubjectKeyId))
	}
}

func TestValidatorKeyUsage(t *testing.T) {
	strict := validatorWith(t, func(*TrustConfig) {}) // v0.6.0-аас зориулалт анхдагчаар
	auth := purposeLeaf(t, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection})
	sign := purposeLeaf(t, x509.KeyUsageDigitalSignature|x509.KeyUsageContentCommitment, []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection})

	r, acsp := signedAuth(t, "QR", authOpts{leaf: auth})
	if _, err := strict.ValidateAuth(r, acsp, ValidateAuthOptions{}); err != nil {
		t.Fatal(err)
	}
	r, acsp = signedAuth(t, "QR", authOpts{leaf: sign})
	_, err := strict.ValidateAuth(r, acsp, ValidateAuthOptions{})
	wantInvalid(t, err, "clientAuth")
	// SkipKeyUsageCheck ч EKU-г гинжийн шалгалт (x509.Verify, auth → clientAuth) үргэлж шалгана (0.1.3-аас).
	_, err = validatorWith(t, func(c *TrustConfig) { c.SkipKeyUsageCheck = true }).ValidateAuth(r, acsp, ValidateAuthOptions{})
	wantInvalid(t, err, "гинж")

	digest := sha256.Sum256([]byte("doc"))
	mkSign := func(leaf *testCA) *SessionResult {
		return &SessionResult{State: StateComplete, EndResult: EndResultOK, DocumentNumber: "d", SignatureProtocol: "RAW_DIGEST_SIGNATURE",
			SignatureAlgorithm: "rsassa-pss", SignatureAlgorithmParameters: &SignatureAlgorithmParameters{HashAlgorithm: "SHA-256"},
			SignatureValueB64: signDigest(t, leaf.key, "rsassa-pss", crypto.SHA256, digest[:]), CertificateLevel: "QUALIFIED",
			CertificateDERB64: base64.StdEncoding.EncodeToString(leaf.cert.Raw)}
	}
	d64 := base64.StdEncoding.EncodeToString(digest[:])
	if _, err := strict.ValidateSign(mkSign(sign), d64, SHA256); err != nil {
		t.Fatal(err)
	}
	_, err = strict.ValidateSign(mkSign(auth), d64, SHA256)
	wantInvalid(t, err, "nonRepudiation")
}

func TestValidatorSchemeName(t *testing.T) {
	r, acsp := signedAuth(t, "QR", authOpts{}) // "smart-id"-ээр зурсан
	_, err := validatorWith(t, func(c *TrustConfig) { c.SchemeName = "eid-mongolia" }).ValidateAuth(r, acsp, ValidateAuthOptions{})
	wantInvalid(t, err, "ACSP_V2")
	if _, err := validatorWith(t, func(c *TrustConfig) { c.SchemeName = "smart-id" }).ValidateAuth(r, acsp, ValidateAuthOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestCheckRevocationStatus(t *testing.T) {
	leaf := testPKI(t).rsaLeaf.cert
	ctx := context.Background()
	mk := func(st RevocationStatus, err error, mode RevocationMode) *Validator {
		return validatorWith(t, func(c *TrustConfig) {
			c.RevocationMode = mode
			c.Revocation = func(context.Context, *x509.Certificate, *x509.Certificate) (RevocationStatus, error) { return st, err }
		})
	}
	for _, tc := range []struct {
		v       *Validator
		want    RevocationStatus
		invalid bool
	}{
		{trusted(t), RevocationSkipped, false},
		{mk(RevocationGood, nil, ""), RevocationGood, false},
		{mk(RevocationUnknown, nil, RevocationSoftFail), RevocationUnchecked, false},
		{mk(RevocationRevoked, nil, RevocationSoftFail), RevocationRevoked, true},
		{mk(RevocationUnknown, nil, ""), RevocationUnknown, true},
	} {
		st, err := tc.v.CheckRevocationStatus(ctx, leaf)
		var ve *ValidationError
		if st != tc.want || errors.As(err, &ve) != tc.invalid || (!tc.invalid && err != nil) {
			t.Fatalf("%v: %s %v", tc.want, st, err)
		}
	}
	boom := errors.New("ocsp down")
	if st, err := mk(RevocationGood, boom, RevocationSoftFail).CheckRevocationStatus(ctx, leaf); st != "" || !errors.Is(err, boom) {
		t.Fatal(st, err)
	}
}

// ── PII: алдааны текстэд PNOMN / РД / кирилл нэр орохгүй ──

func noPII(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("алдаа хүлээв")
	}
	msg := err.Error()
	for _, pii := range []string{"PNOMN-", "12345678", "Бат", "Дорж"} {
		if strings.Contains(msg, pii) {
			t.Fatalf("%q алдаанд: %q", pii, msg)
		}
	}
}

func TestErrorsWithoutPII(t *testing.T) {
	ctx := context.Background()
	// сүлжээ: зам + *url.Error-ийн бүтэн URL
	c, err := NewClient(Config{BaseURL: "http://127.0.0.1:1", Credentials: creds, Trust: TrustConfig{AllowUntrusted: true}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Auth.NotificationByEtsi(ctx, "PNOMN-12345678", nil, nil)
	noPII(t, err)
	var ne *NetworkError
	if !errors.As(err, &ne) || ne.Op != "POST /authentication/notification/etsi/…" || strings.Contains(ne.Err.Error(), "PNOMN") {
		t.Fatalf("%+v", ne)
	}
	_, err = c.Person.Activity(ctx, "PNOMN-12345678", &ActivityQuery{Limit: 5})
	noPII(t, err)
	_, err = c.Sign.DigestByDocument(ctx, "doc-12345678", SHA256Base64(nil), nil, nil)
	noPII(t, err)
	if errors.As(err, &ne); ne.Op != "POST /signature/notification/document/…" {
		t.Fatal(ne.Op)
	}
	// задрахгүй хариу
	srv, _ := server(t, jsonReply(200, "{not json"))
	_, err = srv.Person.Summary(ctx, "PNOMN-12345678")
	noPII(t, err)

	// validation: хугацаа дууссан гэрчилгээ — кирилл нэр + PNOMN subject-тэй
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := leafTmpl()
	tmpl.Subject.CommonName = "Бат Дорж PNOMN-12345678"
	tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour)
	expired := mkCert(t, tmpl, testPKI(t).inter, &k.PublicKey, k)
	r, acsp := signedAuth(t, "QR", authOpts{leaf: expired})
	_, err = trusted(t).ValidateAuth(r, acsp, ValidateAuthOptions{})
	wantInvalid(t, err, "хугацаа дууссан (serial ")
	noPII(t, err)
	tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(time.Hour), time.Now().Add(48*time.Hour)
	future := mkCert(t, tmpl, testPKI(t).inter, &k.PublicKey, k)
	r, acsp = signedAuth(t, "QR", authOpts{leaf: future})
	_, err = trusted(t).ValidateAuth(r, acsp, ValidateAuthOptions{})
	wantInvalid(t, err, "хүчинтэй болоогүй")
	noPII(t, err)
}

// ── 0.1.4: roleLabel (CA !339) + Config.Language → Accept-Language ──

func TestRoleLabel(t *testing.T) {
	c, _ := server(t, jsonReply(200, `{"personEtsi":"PNOMN-1","representations":[
		{"orgEtsi":"NTRMN-1","role":"ceo","roleLabel":"Гүйцэтгэх захирал","rightType":"ADMIN","source":"REGISTRY","validFrom":"2026-10-01T00:00:00Z"},
		{"orgEtsi":"NTRMN-2","role":"Нягтлан","rightType":"MANAGER","source":"MANUAL","validFrom":"2026-10-01T00:00:00Z"}]}`))
	r, err := c.Organization.GetRepresentations(context.Background(), "PNOMN-1")
	if err != nil {
		t.Fatal(err)
	}
	if r.Representations[0].RoleLabel != "Гүйцэтгэх захирал" || r.Representations[1].RoleLabel != "" {
		t.Fatalf("representations roleLabel: %+v", r.Representations)
	}

	s, err := ParseSessionResult([]byte(`{"state":"COMPLETE","result":{"endResult":"OK"},
		"onBehalfOf":{"orgEtsi":"NTRMN-1","orgName":"Х ХХК","role":"ceo","roleLabel":"Chief Executive Officer","rightType":"ADMIN"}}`))
	if err != nil || s.OnBehalfOf == nil || s.OnBehalfOf.RoleLabel != "Chief Executive Officer" || s.OnBehalfOf.Role != "ceo" {
		t.Fatalf("session onBehalfOf: %+v, %v", s.OnBehalfOf, err)
	}
	old, err := ParseSessionResult([]byte(`{"state":"COMPLETE","onBehalfOf":{"orgEtsi":"NTRMN-1","role":"ceo","rightType":"ADMIN"}}`))
	if err != nil || old.OnBehalfOf == nil || old.OnBehalfOf.RoleLabel != "" {
		t.Fatalf("хуучин CA: %+v, %v", old.OnBehalfOf, err)
	}
	if b, _ := json.Marshal(OrgResult{OrgEtsi: "NTRMN-1"}); strings.Contains(string(b), "roleLabel") {
		t.Fatalf("хоосон roleLabel omitempty биш: %s", b)
	}
}

func TestLanguageHeader(t *testing.T) {
	for lang, want := range map[string]string{"": "", "en": "en", " mn ": "mn"} {
		var got string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got = r.Header.Get("Accept-Language")
			_, _ = io.WriteString(w, `{"personEtsi":"PNOMN-1","representations":[]}`)
		}))
		c, err := NewClient(Config{BaseURL: srv.URL, Credentials: creds, Trust: TrustConfig{AllowUntrusted: true}, Language: lang})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Organization.GetRepresentations(context.Background(), "PNOMN-1"); err != nil {
			t.Fatal(err)
		}
		srv.Close()
		if got != want {
			t.Errorf("Language %q → Accept-Language %q, хүлээсэн %q", lang, got, want)
		}
	}
}

// ── 0.1.5: rightTypeLabel / sourceLabel (CA !344) ──

func TestRightTypeSourceLabel(t *testing.T) {
	c, _ := server(t, jsonReply(200, `{"personEtsi":"PNOMN-1","representations":[
		{"orgEtsi":"NTRMN-1","role":"ceo","rightType":"ADMIN","rightTypeLabel":"Админ","source":"REGISTRY","sourceLabel":"Улсын бүртгэл","validFrom":"2026-10-01T00:00:00Z"},
		{"orgEtsi":"NTRMN-2","role":"Нягтлан","rightType":"MANAGER","source":"MANUAL","validFrom":"2026-10-01T00:00:00Z"}]}`))
	r, err := c.Organization.GetRepresentations(context.Background(), "PNOMN-1")
	if err != nil {
		t.Fatal(err)
	}
	r0, r1 := r.Representations[0], r.Representations[1]
	if r0.RightTypeLabel != "Админ" || r0.SourceLabel != "Улсын бүртгэл" || r1.RightTypeLabel != "" || r1.SourceLabel != "" {
		t.Fatalf("representations labels: %+v", r.Representations)
	}

	s, err := ParseSessionResult([]byte(`{"state":"COMPLETE","result":{"endResult":"OK"},
		"onBehalfOf":{"orgEtsi":"NTRMN-1","orgName":"Х ХХК","role":"ceo","rightType":"MANAGER","rightTypeLabel":"Signatory"}}`))
	if err != nil || s.OnBehalfOf == nil || s.OnBehalfOf.RightTypeLabel != "Signatory" || s.OnBehalfOf.RightType != "MANAGER" {
		t.Fatalf("session onBehalfOf: %+v, %v", s.OnBehalfOf, err)
	}
	old, err := ParseSessionResult([]byte(`{"state":"COMPLETE","onBehalfOf":{"orgEtsi":"NTRMN-1","role":"ceo","rightType":"ADMIN"}}`))
	if err != nil || old.OnBehalfOf == nil || old.OnBehalfOf.RightTypeLabel != "" {
		t.Fatalf("хуучин CA: %+v, %v", old.OnBehalfOf, err)
	}
	if b, _ := json.Marshal(OrgResult{OrgEtsi: "NTRMN-1"}); strings.Contains(string(b), "rightTypeLabel") {
		t.Fatalf("хоосон rightTypeLabel omitempty биш: %s", b)
	}
	if b, _ := json.Marshal(Representation{OrgEtsi: "NTRMN-1"}); strings.Contains(string(b), "rightTypeLabel") || strings.Contains(string(b), "sourceLabel") {
		t.Fatalf("хоосон label omitempty биш: %s", b)
	}
}

// TestMaskPathAllRoutes — хувь хүний таних тэмдэгтэй RP-API зам бүр (session ID-аас бусад) maskPath-аар нуугдана;
// шинэ зам нэмэгдээд regex-д ороогүй бол энд унана.
func TestMaskPathAllRoutes(t *testing.T) {
	const id = "PNOMN-12345678-ABCD-Q"
	for _, r := range rpRoutes {
		n := strings.Count(r.path, "{")
		if n == 0 || strings.Contains(strings.ToLower(r.path), "{session") {
			continue
		}
		args := make([]string, n)
		for i := range args {
			args[i] = id
		}
		if got := maskPath(r.expand(args...) + "?x=" + id); strings.Contains(got, "12345678") {
			t.Errorf("%s → %q", r.path, got)
		}
	}
	if got := maskPath("/signature/notification/linked/PNOMN-1"); got != "/signature/notification/linked/…" {
		t.Fatal(got)
	}
}
