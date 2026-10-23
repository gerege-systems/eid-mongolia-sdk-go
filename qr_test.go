package eid

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// testdata/qr_vectors.json — TS / .NET SDK-д ижил файл (cross-SDK гэрээ).
type qrVectors struct {
	MaxAgeSeconds int64           `json:"maxAgeSeconds"`
	Attributes    []string        `json:"attributes"`
	JWKS          json.RawMessage `json:"jwks"`
	Parse         []struct {
		In    string `json:"in"`
		Token string `json:"token"`
		Error string `json:"error"`
	} `json:"parse"`
	Verify []struct {
		Name   string `json:"name"`
		JWS    string `json:"jws"`
		Expect struct {
			Issuer     string   `json:"issuer"`
			Audience   string   `json:"audience"`
			SessionID  string   `json:"sessionID"`
			Nonce      string   `json:"nonce"`
			Attributes []string `json:"attributes"`
			Now        int64    `json:"now"`
		} `json:"expect"`
		Result *struct {
			Sub         string          `json:"sub"`
			Attrs       json.RawMessage `json:"attrs"`
			Unavailable []string        `json:"unavailable"`
		} `json:"result"`
		Error string `json:"error"`
	} `json:"verify"`
}

func loadQRVectors(t *testing.T) *qrVectors {
	t.Helper()
	b, err := os.ReadFile("testdata/qr_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v qrVectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return &v
}

func TestQRVectorsParse(t *testing.T) {
	v := loadQRVectors(t)
	if !reflect.DeepEqual(v.Attributes, QRAttributes) {
		t.Fatalf("каталог зөрсөн: %v", v.Attributes)
	}
	for _, c := range v.Parse {
		tok, err := ParseQR(c.In)
		if c.Error != "" {
			var qe *QRError
			if !errors.As(err, &qe) || qe.Code != c.Error || !errors.Is(err, ErrQRFormatInvalid) {
				t.Errorf("%q: want %s, got %v", c.In, c.Error, err)
			}
			continue
		}
		if err != nil || tok != c.Token {
			t.Errorf("%q: %q %v", c.In, tok, err)
		}
	}
}

func TestQRVectorsVerify(t *testing.T) {
	v := loadQRVectors(t)
	keys, err := ParseJWKS(v.JWKS)
	if err != nil {
		t.Fatal(err)
	}
	if time.Duration(v.MaxAgeSeconds)*time.Second != DefaultQRMaxAge {
		t.Fatal("maxAge зөрсөн")
	}
	for _, c := range v.Verify {
		t.Run(c.Name, func(t *testing.T) {
			e := c.Expect
			p, err := VerifyQRPresentation(c.JWS, keys, QRExpect{
				Issuer: e.Issuer, Audience: e.Audience, SessionID: e.SessionID, Nonce: e.Nonce,
				Attributes: e.Attributes, Now: time.Unix(e.Now, 0),
			})
			if c.Error != "" {
				if !errors.Is(err, ErrQRPresentationInvalid) {
					t.Fatalf("want %s, got %v (%+v)", c.Error, err, p)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, _ := json.Marshal(p.Attrs)
			var a, b any
			_ = json.Unmarshal(got, &a)
			_ = json.Unmarshal(c.Result.Attrs, &b)
			if p.Subject != c.Result.Sub || !reflect.DeepEqual(a, b) || !reflect.DeepEqual(p.Unavailable, c.Result.Unavailable) {
				t.Fatalf("got sub=%s attrs=%s unavailable=%v", p.Subject, got, p.Unavailable)
			}
			if p.SessionID != e.SessionID || p.JWS != c.JWS || p.IssuedAt.Unix() != 1792800000 {
				t.Fatalf("meta: %+v", p)
			}
		})
	}
}

// --- stub CA ---

type qrStub struct {
	key      *ecdsa.PrivateKey
	kid      string
	jwksHits atomic.Int32
	startReq map[string]any
	state    string // RUNNING → COMPLETE
	end      string
	nonce    string
	srv      *httptest.Server
	mutate   func(p map[string]any)
}

func (s *qrStub) jwks() []byte {
	raw, _ := s.key.PublicKey.Bytes()
	b, _ := json.Marshal(map[string]any{"keys": []any{map[string]any{
		"kty": "EC", "crv": "P-256", "kid": s.kid, "alg": "ES256", "use": "sig",
		"x": base64.RawURLEncoding.EncodeToString(raw[1:33]), "y": base64.RawURLEncoding.EncodeToString(raw[33:]),
	}}})
	return b
}

func (s *qrStub) sign(t *testing.T, p map[string]any) string {
	hb, _ := json.Marshal(map[string]any{"alg": "ES256", "kid": s.kid})
	pb, _ := json.Marshal(p)
	in := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	h := sha256.Sum256([]byte(in))
	r, ss, err := ecdsa.Sign(rand.Reader, s.key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	ss.FillBytes(sig[32:])
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func newQRStub(t *testing.T) (*qrStub, *Client) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s := &qrStub{key: k, kid: "k1", state: "COMPLETE", end: "OK"}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/.well-known/eid-jwks.json":
			if r.Header.Get("Authorization") != "" {
				t.Error("JWKS-д RP secret илгээгдэв")
			}
			s.jwksHits.Add(1)
			_, _ = w.Write(s.jwks())
		case r.Method == "POST" && r.URL.Path == "/authentication/qr":
			if r.Header.Get("Authorization") != "Bearer rp_sk_secret123" {
				t.Error("Bearer алга")
			}
			_ = json.NewDecoder(r.Body).Decode(&s.startReq)
			if strings.HasSuffix(s.startReq["qr"].(string), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") {
				w.WriteHeader(404)
				_, _ = w.Write([]byte(`{"error":"QR токен хүчингүй","code":"QR_TOKEN_INVALID"}`))
				return
			}
			s.nonce, _ = s.startReq["nonce"].(string)
			if s.nonce == "" {
				s.nonce = s.startReq["signatureProtocolParameters"].(map[string]any)["rpChallenge"].(string)
			}
			_, _ = w.Write([]byte(`{"sessionID":"sess-1","vc":"4821"}`))
		case r.URL.Path == "/session/sess-1":
			body := map[string]any{"state": s.state, "result": map[string]any{"endResult": s.end}}
			if s.state == "COMPLETE" && s.end == "OK" {
				p := map[string]any{"iss": DefaultQRIssuer, "aud": creds.RPUUID, "sid": "sess-1", "sub": "pairwise-1",
					"iat": time.Now().Unix(), "nonce": s.nonce, "attrs": map[string]any{"age_over_18": true}, "unavailable": []string{"phone"}}
				if s.mutate != nil {
					s.mutate(p)
				}
				body["presentation"] = map[string]any{"jws": s.sign(t, p), "claims": p}
			}
			_ = json.NewEncoder(w).Encode(body)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(s.srv.Close)
	c, err := NewClient(Config{BaseURL: s.srv.URL, Credentials: creds, Trust: TrustConfig{AllowUntrusted: true},
		QR: QRConfig{JWKSURL: s.srv.URL + "/.well-known/eid-jwks.json"}})
	if err != nil {
		t.Fatal(err)
	}
	return s, c
}

const qrTok = "q9Xk3vQh2m9cTqL8rW1xYb5nPdA0sE6uJgHtKoVfRiM"

func TestQRStartResult(t *testing.T) {
	s, c := newQRStub(t)
	ctx := context.Background()
	sess, err := c.QR.Start(ctx, QRStartRequest{QR: "EIDMN-QR1:" + qrTok, Attributes: []string{QRAttrAgeOver18, QRAttrPhone}})
	if err != nil {
		t.Fatal(err)
	}
	if sess.SessionID != "sess-1" || sess.VC != "4821" || sess.Nonce == "" {
		t.Fatalf("%+v", sess)
	}
	r := s.startReq
	if r["qr"] != QRPrefix+qrTok || r["relyingPartyUUID"] != creds.RPUUID || r["relyingPartyName"] != creds.RPName ||
		r["signatureProtocol"] != "ACSP_V2" || r["interactions"] != nil || r["nonce"] != nil {
		t.Fatalf("start body: %v", r)
	}
	if ch, _ := base64.StdEncoding.DecodeString(r["signatureProtocolParameters"].(map[string]any)["rpChallenge"].(string)); len(ch) != 32 {
		t.Fatal("rpChallenge 32 байт биш")
	}
	// QRSession JSON-оор хадгалагдаж дахин уншигдана (stateless RP).
	b, _ := json.Marshal(sess)
	var back QRSession
	_ = json.Unmarshal(b, &back)
	p, err := c.QR.Result(ctx, &back, &WaitOptions{MaxWait: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if p.Subject != "pairwise-1" || p.Attrs.AgeOver18 == nil || !*p.Attrs.AgeOver18 || p.Attrs.Phone != nil ||
		!reflect.DeepEqual(p.Unavailable, []string{"phone"}) {
		t.Fatalf("%+v", p)
	}
	// Кэш: дахин шалгахад JWKS татахгүй.
	if _, err := c.QR.Result(ctx, &back, &WaitOptions{MaxWait: 5 * time.Second}); err != nil || s.jwksHits.Load() != 1 {
		t.Fatal("кэш", s.jwksHits.Load(), err)
	}
	// Түлхүүр солигдвол (шинэ kid) нэг удаа дахин татна.
	s.key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s.kid = "k2"
	c.QR.mu.Lock()
	c.QR.lastAttempt = time.Time{}
	c.QR.mu.Unlock()
	if _, err := c.QR.Result(ctx, &back, &WaitOptions{MaxWait: 5 * time.Second}); err != nil || s.jwksHits.Load() != 2 {
		t.Fatal("rotation", s.jwksHits.Load(), err)
	}
}

func TestQRStartNonceAndErrors(t *testing.T) {
	s, c := newQRStub(t)
	ctx := context.Background()
	sess, err := c.QR.Start(ctx, QRStartRequest{QR: qrTok, Attributes: []string{QRAttrFullName}, Nonce: "order-42"})
	if err != nil || sess.Nonce != "order-42" || s.startReq["nonce"] != "order-42" {
		t.Fatal(sess, err)
	}
	// 404 QR_TOKEN_INVALID
	_, err = c.QR.Start(ctx, QRStartRequest{QR: strings.Repeat("A", 43), Attributes: []string{QRAttrAgeOver18}})
	var ae *APIError
	if !errors.Is(err, ErrQRTokenInvalid) || !errors.As(err, &ae) || ae.Status != 404 {
		t.Fatal(err)
	}
	// Клиент талын шалгалт — CA руу илгээхгүй.
	s.startReq = nil
	for _, a := range [][]string{nil, {"age_over_99"}, {"phone", "phone"}} {
		if _, err := c.QR.Start(ctx, QRStartRequest{QR: qrTok, Attributes: a}); !errors.Is(err, ErrQRAttributesInvalid) {
			t.Fatal(a, err)
		}
	}
	if _, err := c.QR.Start(ctx, QRStartRequest{QR: "hello", Attributes: []string{"phone"}}); !errors.Is(err, ErrQRFormatInvalid) {
		t.Fatal(err)
	}
	if s.startReq != nil {
		t.Fatal("буруу хүсэлт CA руу явсан")
	}
}

func TestQRResultFailures(t *testing.T) {
	s, c := newQRStub(t)
	ctx := context.Background()
	sess, err := c.QR.Start(ctx, QRStartRequest{QR: qrTok, Attributes: []string{QRAttrAgeOver18, QRAttrPhone}})
	if err != nil {
		t.Fatal(err)
	}
	wo := &WaitOptions{MaxWait: 2 * time.Second, ServerPoll: time.Second}

	s.end = "USER_REFUSED"
	var sf *SessionFailedError
	if _, err := c.QR.Result(ctx, sess, wo); !errors.As(err, &sf) || sf.EndResult != "USER_REFUSED" {
		t.Fatal(err)
	}
	s.end = "OK"
	s.mutate = func(p map[string]any) { p["aud"] = "other-rp" }
	if _, err := c.QR.Result(ctx, sess, wo); !errors.Is(err, ErrQRPresentationInvalid) {
		t.Fatal("aud", err)
	}
	s.mutate = func(p map[string]any) { p["attrs"] = map[string]any{"age_over_18": true, "civil_id": "1"} }
	if _, err := c.QR.Result(ctx, sess, wo); !errors.Is(err, ErrQRPresentationInvalid) {
		t.Fatal("extra attr", err)
	}
	s.mutate = nil
	sess2 := *sess
	sess2.Nonce = "replayed"
	if _, err := c.QR.Result(ctx, &sess2, wo); !errors.Is(err, ErrQRPresentationInvalid) {
		t.Fatal("nonce", err)
	}
	s.end = "TIMEOUT"
	if _, err := c.QR.Result(ctx, sess, wo); !errors.As(err, &sf) || sf.EndResult != "TIMEOUT" {
		t.Fatal("CA timeout", err)
	}
	if _, err := c.QR.Check(ctx, sess, 0); !errors.As(err, &sf) || sf.EndResult != "TIMEOUT" {
		t.Fatal("check CA timeout", err)
	}
	s.end = "OK"
	s.state = "RUNNING"
	if _, err := c.QR.Result(ctx, sess, &WaitOptions{MaxWait: time.Second, ServerPoll: time.Second}); !errors.Is(err, ErrQRPending) {
		t.Fatal("pending", err)
	}
	if r, err := c.QR.Check(ctx, sess, 0); err != nil || r.Complete || r.Presentation != nil {
		t.Fatal("check running", r, err)
	}
	s.state = "COMPLETE"
	if r, err := c.QR.Check(ctx, sess, 0); err != nil || !r.Complete || r.Presentation.Attrs.AgeOver18 == nil {
		t.Fatal("check complete", r, err)
	}
}

func TestQRJWKSUnavailable(t *testing.T) {
	s, c := newQRStub(t)
	c.QR.cfg.JWKSURL = s.srv.URL + "/missing"
	sess := &QRSession{SessionID: "sess-1", Nonce: "n", Attributes: []string{"age_over_18"}}
	if _, err := c.QR.Verify(context.Background(), "a.b.c", sess); !errors.Is(err, ErrQRJWKSUnavailable) {
		t.Fatal(err)
	}
	c.QR.cfg.JWKSURL = "http://example.com/jwks.json"
	c.QR.lastAttempt = time.Time{}
	if _, err := c.QR.Verify(context.Background(), "a.b.c", sess); !errors.Is(err, ErrQRJWKSUnavailable) {
		t.Fatal("http", err)
	}
}
