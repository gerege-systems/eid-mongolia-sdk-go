package eid

// rp-conformance/2 хатуужуулалт — корпуст орох боломжгүй (тохиргооны алдаа, хүсэлт илгээгдээгүй эсэх, ECDSA r/s
// хүрээ) хэсгүүдийн unit тест. Үлдсэнийг testdata/conformance (rp-validate/2, ocsp-checker/2) шалгана.

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
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"testing"
	"time"
)

func hardeningSelfSigned(t *testing.T, bits int) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "TEST ONLY Weak Root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestNewValidatorRejectsWeakPoolKeyAndUnknownLevel(t *testing.T) {
	weak := hardeningSelfSigned(t, 1024)
	if _, err := NewValidator(TrustConfig{TrustAnchorsPEM: []string{weak}, IntermediatesPEM: []string{}}); err == nil {
		t.Fatal("RSA 1024 trust anchor хүлээн авсан")
	}
	if _, err := NewValidator(TrustConfig{TrustAnchorsPEM: []string{NationalRootCAPEM}, IntermediatesPEM: []string{weak}}); err == nil {
		t.Fatal("RSA 1024 intermediate хүлээн авсан")
	}
	if _, err := NewValidator(TrustConfig{TrustAnchorsPEM: []string{NationalRootCAPEM}, RequiredLevel: "QUALIFED"}); err == nil {
		t.Fatal("үл мэдэх RequiredLevel QUALIFIED болж хүлээн авагдсан")
	}
	for _, l := range []CertificateLevel{"", LevelAdvanced, LevelQualified, LevelQSCD} {
		if _, err := NewValidator(TrustConfig{TrustAnchorsPEM: []string{NationalRootCAPEM}, RequiredLevel: l}); err != nil {
			t.Fatalf("%q: %v (бодит 01–04 гинж ≥ 2048 байх ёстой)", l, err)
		}
	}
}

func TestWeakRSAKey(t *testing.T) {
	n := new(big.Int).Lsh(big.NewInt(1), 2047) // 2048 бит
	for _, c := range []struct {
		k    *rsa.PublicKey
		weak bool
	}{
		{&rsa.PublicKey{N: n, E: 65537}, false},
		{&rsa.PublicKey{N: n, E: 3}, false},
		{&rsa.PublicKey{N: n, E: 65536}, true},
		{&rsa.PublicKey{N: n, E: 1}, true},
		{&rsa.PublicKey{N: new(big.Int).Rsh(n, 1), E: 65537}, true},
	} {
		if got := weakRSAKey(c.k); got != c.weak {
			t.Errorf("N %d бит E %d: %v ≠ %v", c.k.N.BitLen(), c.k.E, got, c.weak)
		}
	}
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if weakRSAKey(&ec.PublicKey) {
		t.Error("EC түлхүүр сул гэж үзэгдэв")
	}
}

func TestPathParametersRejectedBeforeRequest(t *testing.T) {
	sent := 0
	c, err := NewClient(Config{BaseURL: "https://rp.example.test/v3", Credentials: Credentials{RPUUID: "00000000-0000-4000-8000-000000000001",
		RPName: "Тест", APISecret: "rp_sk_test"}, HTTPClient: &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		sent++
		return nil, errors.New("хүсэлт илгээгдэх ёсгүй")
	})}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, id := range []string{"", ".", ".."} {
		if _, err := c.Session.Poll(ctx, id, 0); !errors.Is(err, ErrInvalidPathParameter) {
			t.Errorf("Session.Poll(%q): %v", id, err)
		}
		if _, err := c.Auth.NotificationByEtsi(ctx, id, []Interaction{{Type: "displayTextAndPIN", DisplayText60: "x"}}, nil); !errors.Is(err, ErrInvalidPathParameter) {
			t.Errorf("Auth.NotificationByEtsi(%q): %v", id, err)
		}
	}
	if sent != 0 {
		t.Fatalf("%d хүсэлт илгээгдэв", sent)
	}
	for _, p := range []string{"/session/abc?timeoutMs=1", "/.well-known/eid", "/authentication/notification/etsi/PNOMN-1", "/session/%2E%2E"} {
		if err := checkPathParams(p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
}

// ECDSA: 0 < r, s < n-ээс гадуурх гарын үсэг (r = n, s = 0, сөрөг) шалгалтад хэзээ ч тэнцэхгүй (crypto/ecdsa VerifyASN1
// хүрээг өөрөө шалгадаг — энэ тест үүнийг бэхэлнэ).
func TestECDSASignatureRange(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256([]byte("range"))
	good, err := k.Sign(rand.Reader, d[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPrehashedSignature(d[:], base64.StdEncoding.EncodeToString(good), &k.PublicKey, string(AlgECDSAWithSHA256), string(SHA256)) {
		t.Fatal("хүчинтэй гарын үсэг тэнцсэнгүй")
	}
	var rs struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(good, &rs); err != nil {
		t.Fatal(err)
	}
	n := elliptic.P256().Params().N
	for name, v := range map[string]struct{ R, S *big.Int }{
		"r=n":   {n, rs.S},
		"s=n":   {rs.R, n},
		"r+n":   {new(big.Int).Add(rs.R, n), rs.S},
		"s=0":   {rs.R, big.NewInt(0)},
		"r<0":   {new(big.Int).Neg(rs.R), rs.S},
		"s=n+s": {rs.R, new(big.Int).Add(rs.S, n)},
	} {
		sig, err := asn1.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if VerifyPrehashedSignature(d[:], base64.StdEncoding.EncodeToString(sig), &k.PublicKey, string(AlgECDSAWithSHA256), string(SHA256)) {
			t.Errorf("%s: хүрээнээс гадуурх гарын үсэг тэнцэв", name)
		}
	}
}
