package validate

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func TestFreshAt(t *testing.T) {
	at := time.Date(2026, 10, 14, 4, 0, 1, 0, time.UTC)
	now := at.Add(30 * time.Second)
	z := time.Time{}
	h, d := time.Hour, 24*time.Hour
	for _, c := range []struct {
		name       string
		this, next time.Time
		want       bool
	}{
		{"after at", at.Add(5 * time.Second), at.Add(d), true},
		{"within max age, no next", at.Add(-23 * h), z, true},
		{"400 days, no next", at.Add(-400 * d), z, false},
		{"400 days, window covers at", at.Add(-400 * d), at.Add(h), true},
		{"window ended before at", at.Add(-2 * h), at.Add(-h), false},
		{"next within skew", at.Add(-2 * h), at.Add(-time.Minute), true},
		{"future thisUpdate", now.Add(RevocationClockSkew + time.Second), now.Add(d), false},
		{"thisUpdate within skew", now.Add(time.Minute), now.Add(d), true},
		{"zero thisUpdate", z, at.Add(d), false},
	} {
		if got := FreshAt(c.this, c.next, at, now); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}

type tCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTCA(t *testing.T, cn string, parent *tCA, serial int64, ca bool) *tCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: ca, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	pc, pk := tmpl, key
	if parent != nil {
		pc, pk = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, pc, &key.PublicKey, pk)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &tCA{cert: c, key: key}
}

func TestOCSPCertIDMatches(t *testing.T) {
	root := newTCA(t, "root", nil, 1, true)
	a := newTCA(t, "issuer A", root, 2, true)
	b := newTCA(t, "issuer B", root, 3, true)
	leaf := newTCA(t, "leaf", a, 77, false)
	now := time.Now()
	resp := func(hashIssuer *x509.Certificate, serial int64, h crypto.Hash) []byte {
		der, err := ocsp.CreateResponse(hashIssuer, a.cert, ocsp.Response{Status: ocsp.Good, SerialNumber: big.NewInt(serial),
			ThisUpdate: now, NextUpdate: now.Add(time.Hour), IssuerHash: h}, a.key)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	for _, c := range []struct {
		name string
		der  []byte
		want bool
	}{
		{"own issuer SHA-1", resp(a.cert, 77, crypto.SHA1), true},
		{"own issuer SHA-256", resp(a.cert, 77, crypto.SHA256), true},
		{"other issuer, same serial", resp(b.cert, 77, crypto.SHA1), false},
		{"other serial", resp(a.cert, 78, crypto.SHA1), false},
		{"garbage", []byte{0x30, 0x03, 0x0a, 0x01, 0x00}, false},
	} {
		if got := OCSPCertIDMatches(c.der, leaf.cert, a.cert); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}

func TestCRLFor(t *testing.T) {
	root := newTCA(t, "root", nil, 1, true)
	a := newTCA(t, "issuer A", root, 2, true)
	b := newTCA(t, "issuer B", root, 3, true)
	leaf := newTCA(t, "leaf", a, 77, false)
	crl := func(signer *tCA, issuerCert *x509.Certificate) *x509.RevocationList {
		der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: time.Now(),
			NextUpdate: time.Now().Add(time.Hour)}, issuerCert, signer.key)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseRevocationList(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	// b-ийн түлхүүрээр, A-ийн нэр/AKI-тай (CreateRevocationList нь гарын үсэгчийг issuerCert-ийн түлхүүртэй тулгадаггүй).
	forged := *a.cert
	forged.PublicKey = &b.key.PublicKey
	for _, c := range []struct {
		name string
		crl  *x509.RevocationList
		want bool
	}{
		{"own issuer", crl(a, a.cert), true},
		{"other issuer (B)", crl(b, b.cert), false},
		{"A name, B signature", crl(b, &forged), false},
	} {
		if got := CRLFor(c.crl, leaf.cert, a.cert); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}
