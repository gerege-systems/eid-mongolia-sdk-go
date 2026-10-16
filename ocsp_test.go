package eid

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

type ocspFixture struct {
	ca, leaf  *x509.Certificate
	caKey     crypto.Signer
	status    atomic.Int32 // ocsp.Good / Revoked / Unknown; -1 = 500
	thisAge   atomic.Int64 // thisUpdate = now - thisAge
	nextIn    atomic.Int64 // nextUpdate = thisUpdate + nextIn (0 → 24 ц)
	clock     atomic.Int64 // responder-ийн цагийн шилжилт (checker-ийн Now-тэй ижил)
	calls     atomic.Int32
	responder *x509.Certificate
	respKey   crypto.Signer
}

func ocspCert(t *testing.T, tmpl, parent *x509.Certificate, pub any, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newOCSPFixture(t *testing.T, delegated bool) (*ocspFixture, *httptest.Server) {
	t.Helper()
	f := &ocspFixture{}
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	caT := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	f.ca, f.caKey = ocspCert(t, caT, caT, &caKey.PublicKey, caKey), caKey
	f.respKey = caKey
	if delegated {
		rk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		rt := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "OCSP"}, NotBefore: now.Add(-time.Hour),
			NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}}
		f.responder, f.respKey = ocspCert(t, rt, f.ca, &rk.PublicKey, caKey), rk
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		req, err := ocsp.ParseRequest(body)
		if err != nil || f.status.Load() < 0 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		n := time.Now().Add(time.Duration(f.clock.Load()) - time.Duration(f.thisAge.Load()))
		next := time.Duration(f.nextIn.Load())
		if next == 0 {
			next = 24 * time.Hour
		}
		tmpl := ocsp.Response{Status: int(f.status.Load()), SerialNumber: req.SerialNumber, ThisUpdate: n, NextUpdate: n.Add(next),
			RevokedAt: n, Certificate: f.responder}
		signer := f.responder
		if signer == nil {
			signer = f.ca
		}
		der, err := ocsp.CreateResponse(f.ca, signer, tmpl, f.respKey)
		if err != nil {
			t.Error(err)
		}
		_, _ = w.Write(der)
	}))
	t.Cleanup(srv.Close)
	lk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	lt := &x509.Certificate{SerialNumber: big.NewInt(77), Subject: pkix.Name{CommonName: "BAT"}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(time.Hour), OCSPServer: []string{srv.URL}}
	f.leaf = ocspCert(t, lt, f.ca, &lk.PublicKey, caKey)
	return f, srv
}

func TestOCSPChecker(t *testing.T) {
	ctx := context.Background()
	for _, delegated := range []bool{false, true} {
		f, _ := newOCSPFixture(t, delegated)
		check := NewOCSPChecker(OCSPOptions{})
		f.status.Store(int32(ocsp.Revoked))
		if s, err := check(ctx, f.leaf, f.ca); err != nil || s != RevocationRevoked {
			t.Fatalf("revoked: %s %v", s, err)
		}
		f.status.Store(int32(ocsp.Unknown))
		if s, _ := check(ctx, f.leaf, f.ca); s != RevocationRevoked {
			t.Fatalf("unknown (олгогч мэдэхгүй) → revoked: %s", s)
		}
		f.status.Store(int32(ocsp.Good))
		f.thisAge.Store(int64(72 * time.Hour))
		if s, err := check(ctx, f.leaf, f.ca); s != RevocationUnknown || ocspKind(err) != OCSPInvalid {
			t.Fatalf("хуучин thisUpdate → unknown/invalid: %s %v", s, err)
		}
		f.thisAge.Store(0)
		if s, _ := check(ctx, f.leaf, f.ca); s != RevocationGood {
			t.Fatalf("good: %s", s)
		}
		before := f.calls.Load()
		f.status.Store(-1)
		if s, _ := check(ctx, f.leaf, f.ca); s != RevocationGood || f.calls.Load() != before {
			t.Fatalf("good кэшлэгдэнэ: %s calls %d→%d", s, before, f.calls.Load())
		}
	}
	f, _ := newOCSPFixture(t, false)
	f.status.Store(-1)
	check := NewOCSPChecker(OCSPOptions{})
	s, err := check(ctx, f.leaf, f.ca)
	var oe *OCSPError
	if s != RevocationUnknown || !errors.Is(err, ErrOCSPNoAnswer) || !errors.As(err, &oe) || oe.Kind != OCSPHTTPStatus ||
		oe.HTTPStatus != 500 || oe.Responder == "" {
		t.Fatalf("5xx → unknown/http_status: %s %v", s, err)
	}
	if s, err := check(ctx, f.leaf, nil); s != RevocationUnknown || ocspKind(err) != OCSPNoIssuer {
		t.Fatalf("issuer алга → unknown: %s %v", s, err)
	}
	// Өөр CA-ийн зурсан хариу (issuer буруу) → unknown.
	other, _ := newOCSPFixture(t, false)
	f.status.Store(int32(ocsp.Good))
	if s, err := check(ctx, f.leaf, other.ca); s != RevocationUnknown || ocspKind(err) != OCSPSignature {
		t.Fatalf("буруу issuer → signature: %s %v", s, err)
	}
	// Validator-ийн дүрэм: soft-fail → unchecked, hard-fail → ValidationError.
	v := &Validator{}
	f.status.Store(-1)
	fresh := NewOCSPChecker(OCSPOptions{})
	if s, err := v.CheckRevocationWith(ctx, f.leaf, fresh, RevocationSoftFail); err != nil || s != RevocationUnchecked {
		t.Fatalf("soft: %s %v", s, err)
	}
	_, err = v.CheckRevocationWith(ctx, f.leaf, fresh, RevocationHardFail)
	var ve *ValidationError
	if !errors.As(err, &ve) || !errors.Is(err, ErrOCSPNoAnswer) || ocspKind(err) != OCSPNoIssuer { // Validator{}: trust pool хоосон
		t.Fatalf("hard-fail: ValidationError + ErrOCSPNoAnswer: %v", err)
	}
}

func ocspKind(err error) OCSPErrorKind {
	var oe *OCSPError
	if errors.As(err, &oe) {
		return oe.Kind
	}
	return ""
}

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOCSPErrorKinds(t *testing.T) {
	ctx := context.Background()
	leafWith := func(u string) *x509.Certificate {
		return &x509.Certificate{SerialNumber: big.NewInt(9), OCSPServer: []string{u}}
	}
	f, _ := newOCSPFixture(t, false)
	// AIA алга.
	if s, err := NewOCSPChecker(OCSPOptions{})(ctx, &x509.Certificate{SerialNumber: big.NewInt(1)}, f.ca); s != RevocationUnknown ||
		ocspKind(err) != OCSPNoResponder {
		t.Fatalf("AIA алга: %s %v", s, err)
	}
	// Timeout.
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(300 * time.Millisecond):
		}
	}))
	defer slow.Close()
	hc := &http.Client{Timeout: 50 * time.Millisecond}
	if s, err := NewOCSPChecker(OCSPOptions{HTTPClient: hc})(ctx, leafWith(slow.URL), f.ca); s != RevocationUnknown || ocspKind(err) != OCSPTimeout {
		t.Fatalf("timeout: %s %v", s, err)
	}
	// Задрахгүй хариу (200 + хог).
	junk := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("not der")) }))
	defer junk.Close()
	if s, err := NewOCSPChecker(OCSPOptions{})(ctx, leafWith(junk.URL), f.ca); s != RevocationUnknown || ocspKind(err) != OCSPParse {
		t.Fatalf("parse: %s %v", s, err)
	}
	// Сүлжээ (холбогдохгүй порт).
	if s, err := NewOCSPChecker(OCSPOptions{})(ctx, leafWith("http://127.0.0.1:1/"), f.ca); s != RevocationUnknown ||
		ocspKind(err) != OCSPNetwork {
		t.Fatalf("network: %s %v", s, err)
	}
}

func TestOCSPObserveAndNextUpdateCache(t *testing.T) {
	ctx := context.Background()
	f, _ := newOCSPFixture(t, true)
	f.status.Store(int32(ocsp.Good))
	f.nextIn.Store(int64(time.Minute)) // NextUpdate 1 мин < CacheTTL 5 мин
	var mu sync.Mutex
	var obs []OCSPObservation
	check := NewOCSPChecker(OCSPOptions{
		Now:     func() time.Time { return time.Now().Add(time.Duration(f.clock.Load())) },
		Observe: func(o OCSPObservation) { mu.Lock(); obs = append(obs, o); mu.Unlock() },
	})
	if s, err := check(ctx, f.leaf, f.ca); s != RevocationGood || err != nil {
		t.Fatalf("good: %s %v", s, err)
	}
	if s, _ := check(ctx, f.leaf, f.ca); s != RevocationGood || f.calls.Load() != 1 {
		t.Fatalf("кэш: %s calls %d", s, f.calls.Load())
	}
	f.clock.Store(int64(90 * time.Second)) // NextUpdate (1 мин) өнгөрсөн, CacheTTL (5 мин) өнгөрөөгүй → дахин асууна
	if s, _ := check(ctx, f.leaf, f.ca); s != RevocationGood || f.calls.Load() != 2 {
		t.Fatalf("NextUpdate-ээр кэш дуусна: %s calls %d", s, f.calls.Load())
	}
	f.status.Store(-1)
	f.clock.Store(int64(10 * time.Minute))
	_, _ = check(ctx, f.leaf, f.ca)
	mu.Lock()
	defer mu.Unlock()
	if len(obs) != 4 {
		t.Fatalf("observe тоо %d", len(obs))
	}
	if o := obs[0]; o.Status != RevocationGood || o.Cached || o.Responder == "" || o.Duration <= 0 || o.Err != nil {
		t.Fatalf("obs[0] %+v", o)
	}
	if o := obs[1]; !o.Cached || o.Status != RevocationGood || o.Duration != 0 {
		t.Fatalf("obs[1] %+v", o)
	}
	if o := obs[3]; o.Status != RevocationUnknown || ocspKind(o.Err) != OCSPHTTPStatus || !strings.HasPrefix(o.Responder, "http://127.0.0.1") {
		t.Fatalf("obs[3] %+v", o)
	}
	// CacheTTL < 0 — кэшлэхгүй.
	f.status.Store(int32(ocsp.Good))
	before := f.calls.Load()
	nc := NewOCSPChecker(OCSPOptions{CacheTTL: -1})
	_, _ = nc(ctx, f.leaf, f.ca)
	_, _ = nc(ctx, f.leaf, f.ca)
	if f.calls.Load() != before+2 {
		t.Fatalf("CacheTTL<0: calls %d→%d", before, f.calls.Load())
	}
}

// Бодит CA (ocsp.eidmongolia.mn, 2026-10-16 14:28:56Z) — санамсаргүй serial 0123456789abcdef0123-ийн хариу (cert status
// unknown, иргэний мэдээлэлгүй): "eID OCSP Responder" гэрчилгээ (EKU OCSPSigning, eID Mongolia Issuing CA-ийн гаргасан)
// хариунд шигтгэгдсэн — RFC 6960 §4.2.2.2 delegated. unknown → RevocationRevoked (олгогч мэдэхгүй serial).
func TestOCSPRealDelegatedResponder(t *testing.T) {
	b, err := os.ReadFile("testdata/eid-mongolia-issuing-ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	p, _ := pem.Decode(b)
	issuer, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	der, err := os.ReadFile("testdata/ocsp-eid-delegated.der")
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := new(big.Int).SetString("0123456789abcdef0123", 16)
	leaf := &x509.Certificate{SerialNumber: serial, OCSPServer: []string{"http://ocsp.eidmongolia.mn/ocsp"}}
	hc := &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(der))), Header: http.Header{}, Request: r}, nil
	})}
	at := time.Date(2026, 10, 16, 14, 30, 0, 0, time.UTC)
	var got OCSPObservation
	check := NewOCSPChecker(OCSPOptions{HTTPClient: hc, Now: func() time.Time { return at }, Observe: func(o OCSPObservation) { got = o }})
	if s, err := check(context.Background(), leaf, issuer); s != RevocationRevoked || err != nil {
		t.Fatalf("бодит delegated хариу: %s %v", s, err)
	}
	if got.Responder != "http://ocsp.eidmongolia.mn/ocsp" || got.Err != nil {
		t.Fatalf("observe %+v", got)
	}
	resp, err := ocsp.ParseResponseForCert(der, leaf, issuer)
	if err != nil || resp.Certificate == nil || bytes.Equal(resp.Certificate.Raw, issuer.Raw) {
		t.Fatalf("delegated responder гэрчилгээ шигтгэгдээгүй: %v", err)
	}
	// Өөр олгогч (Gerege Issuing CA) — responder гэрчилгээ түүний гаргасан биш → signature.
	gb, _ := os.ReadFile("testdata/gerege-issuing-ca.pem")
	gp, _ := pem.Decode(gb)
	other, _ := x509.ParseCertificate(gp.Bytes)
	if s, err := NewOCSPChecker(OCSPOptions{HTTPClient: hc, Now: func() time.Time { return at }})(context.Background(), leaf, other); s != RevocationUnknown ||
		ocspKind(err) != OCSPSignature {
		t.Fatalf("өөр олгогч: %s %v", s, err)
	}
}

// TestOCSPIssuerSignedEmbeddedIssuer — завсрын олгогч (04 шиг: root-оор зурагдсан) өөрөө зурж, хариундаа ӨӨРИЙН
// гэрчилгээг шигтгэсэн OCSP хариу (RFC 6960 §4.2.2.2-оор хүчинтэй). x/crypto/ocsp үүнийг «bad signature on embedded
// certificate» гэж татгалздаг байв. Дахин олгосон (ижил subject+SPKI, өөр байт) хуулбарыг шигтгэсэн ч мөн; өөр түлхүүрээр
// зурсан бол → signature алдаа; delegated responder зам хэвээр (TestOCSPChecker).
func TestOCSPIssuerSignedEmbeddedIssuer(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootT := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Root"}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	root := ocspCert(t, rootT, rootT, &rootKey.PublicKey, rootKey)
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caT := &x509.Certificate{SerialNumber: big.NewInt(4), Subject: pkix.Name{CommonName: "Issuing CA"}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	ca := ocspCert(t, caT, root, &caKey.PublicKey, rootKey)
	caT.SerialNumber = big.NewInt(5) // дахин олгосон хуулбар: ижил subject + түлхүүр, өөр байт
	caCopy := ocspCert(t, caT, root, &caKey.PublicKey, rootKey)
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	var embed *x509.Certificate
	var signKey crypto.Signer = caKey
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, err := ocsp.ParseRequest(body)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		responder := embed
		if responder == nil {
			responder = ca
		}
		der, err := ocsp.CreateResponse(ca, responder, ocsp.Response{Status: ocsp.Good, SerialNumber: req.SerialNumber,
			ThisUpdate: time.Now(), NextUpdate: time.Now().Add(time.Hour), Certificate: embed}, signKey)
		if err != nil {
			t.Error(err)
		}
		_, _ = w.Write(der)
	}))
	t.Cleanup(srv.Close)
	lk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := ocspCert(t, &x509.Certificate{SerialNumber: big.NewInt(77), Subject: pkix.Name{CommonName: "BAT"}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(time.Hour), OCSPServer: []string{srv.URL}}, ca, &lk.PublicKey, caKey)

	for name, e := range map[string]*x509.Certificate{"issuer шигтгэсэн": ca, "дахин олгосон хуулбар": caCopy, "шигтгээгүй": nil} {
		embed, signKey = e, caKey
		if s, err := NewOCSPChecker(OCSPOptions{CacheTTL: -1})(ctx, leaf, ca); err != nil || s != RevocationGood {
			t.Fatalf("%s: %s %v", name, s, err)
		}
	}
	// Олгогчийг шигтгэсэн ч өөр түлхүүрээр зурсан → signature.
	embed, signKey = ca, otherKey
	if s, err := NewOCSPChecker(OCSPOptions{CacheTTL: -1})(ctx, leaf, ca); s != RevocationUnknown || ocspKind(err) != OCSPSignature {
		t.Fatalf("өөр түлхүүр: %s %v", s, err)
	}
}
