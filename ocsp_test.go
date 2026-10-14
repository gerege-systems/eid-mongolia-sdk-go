package eid

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
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
		n := time.Now().Add(-time.Duration(f.thisAge.Load()))
		tmpl := ocsp.Response{Status: int(f.status.Load()), SerialNumber: req.SerialNumber, ThisUpdate: n, NextUpdate: n.Add(24 * time.Hour),
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
		if s, _ := check(ctx, f.leaf, f.ca); s != RevocationUnknown {
			t.Fatalf("хуучин thisUpdate → unknown: %s", s)
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
	if s, err := check(ctx, f.leaf, f.ca); err != nil || s != RevocationUnknown {
		t.Fatalf("5xx → unknown: %s %v", s, err)
	}
	if s, _ := check(ctx, f.leaf, nil); s != RevocationUnknown {
		t.Fatalf("issuer алга → unknown: %s", s)
	}
	// Өөр CA-ийн зурсан хариу (issuer буруу) → unknown.
	other, _ := newOCSPFixture(t, false)
	f.status.Store(int32(ocsp.Good))
	if s, _ := check(ctx, f.leaf, other.ca); s != RevocationUnknown {
		t.Fatalf("буруу issuer: %s", s)
	}
	// Validator-ийн дүрэм: soft-fail → unchecked, hard-fail → ValidationError.
	v := &Validator{}
	f.status.Store(-1)
	fresh := NewOCSPChecker(OCSPOptions{})
	if s, err := v.CheckRevocationWith(ctx, f.leaf, fresh, RevocationSoftFail); err != nil || s != RevocationUnchecked {
		t.Fatalf("soft: %s %v", s, err)
	}
	if _, err := v.CheckRevocationWith(ctx, f.leaf, fresh, RevocationHardFail); err == nil {
		t.Fatal("hard-fail алдаа өгөх ёстой")
	}
}
