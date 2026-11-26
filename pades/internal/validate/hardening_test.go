package validate

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// TestBoundedCert — баримтад суулгасан гэрчилгээний хязгаар (E4): RSA модуль ≤ 8192 бит, илтгэгч ≤ 2^32−1, serial ≤ 160
// бит. Том түлхүүр үүсгэхгүй — нийтийн түлхүүрийг (санамсаргүй сондгой модуль) жижиг түлхүүрээр зурна.
func TestBoundedCert(t *testing.T) {
	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(bits int, e int, serial *big.Int) *x509.Certificate {
		t.Helper()
		n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(bits-1)))
		if err != nil {
			t.Fatal(err)
		}
		n.SetBit(n, bits-1, 1).SetBit(n, 0, 1) // яг bits бит, сондгой
		tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "TEST ONLY bounds"},
			NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<31, 0)}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &rsa.PublicKey{N: n, E: e}, signer)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	max160 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 160), big.NewInt(1))
	cases := []struct {
		name string
		c    *x509.Certificate
		want bool
	}{
		{"rsa-2048", mk(2048, 65537, big.NewInt(7)), true},
		{"rsa-8192", mk(8192, 65537, big.NewInt(7)), true},
		{"rsa-8200", mk(8200, 65537, big.NewInt(7)), false},
		{"e-2^32-1", mk(2048, 1<<32-1, big.NewInt(7)), true},
		{"e-2^32+1", mk(2048, 1<<32+1, big.NewInt(7)), false},
		{"serial-160-bits", mk(2048, 65537, max160), true},
		{"serial-161-bits", mk(2048, 65537, new(big.Int).Lsh(big.NewInt(1), 160)), false},
	}
	for _, c := range cases {
		if got := boundedCert(c.c); got != c.want {
			t.Errorf("%s: %v, хүлээсэн %v", c.name, got, c.want)
		}
	}
	many := make([]*x509.Certificate, maxCMSCerts+1)
	for i := range many {
		many[i] = cases[0].c
	}
	if boundedCerts(many[:maxCMSCerts]) != true || boundedCerts(many) != false {
		t.Errorf("CMS-ийн гэрчилгээний хязгаар %d", maxCMSCerts)
	}
}
