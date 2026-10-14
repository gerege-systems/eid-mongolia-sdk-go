package core

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/timestamp"

	eidcrypto "github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/eidcrypto"
)

// TestPlaceholderMeasuredWithOpenSSLTSA — шийдвэр 10-07 (§15 Q3): placeholder-ийг бодит TSA token-оор хэмжинэ.
// Прод TSA (timeserver-mn) нь `openssl ts -reply` + tsa.cnf (RSA-3072 TSA cert, certs = chain.pem = 04+03+02,
// ess_cert_id_alg sha256, tsa_name yes). Энд яг тэр тохиргоог локал openssl-ээр ажиллуулж, бодит pki/chain-ийн
// 04/03/02 DER, RSA-4096 иргэн/04 түлхүүртэй (прод хэмжээ) CMS-ийн хэмжээг тогтооно. openssl байхгүй бол алгасна.
func TestPlaceholderMeasuredWithOpenSSLTSA(t *testing.T) {
	if testing.Short() {
		t.Skip("RSA-4096 үүсгэлт удаан")
	}
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl алга")
	}
	chainDir := filepath.Join("..", "eidcrypto", "chain")
	var chain []*x509.Certificate
	var chainPEM bytes.Buffer
	for _, f := range []string{"04-eid-mongolia-issuing-ca.pem", "03-gerege-issuing-ca.pem", "02-mongolian-national-issuing-ca-mddc.pem"} {
		raw, err := os.ReadFile(filepath.Join(chainDir, f)) // #nosec G304 -- тест
		if err != nil {
			t.Fatal(err)
		}
		chainPEM.Write(raw)
		b, _ := pem.Decode(raw)
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, c)
	}
	real04 := chain[0]
	// Туршилтын 04 — бодит 04-ийн subject, RSA-4096 (гарын үсгийн хэмжээ прод-той ижил).
	key04, _ := rsa.GenerateKey(rand.Reader, 4096)
	ca04 := &x509.Certificate{SerialNumber: big.NewInt(4), Subject: real04.Subject, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	ca04DER, _ := x509.CreateCertificate(rand.Reader, ca04, ca04, &key04.PublicKey, key04)
	ca04, _ = x509.ParseCertificate(ca04DER)
	// Прод-ийн эцсийн гэрчилгээний өргөтгөлүүдийн хэмжээтэй (бодлого, AIA, CDP, SKI/AKI).
	ext := func(tmpl *x509.Certificate) {
		tmpl.PolicyIdentifiers = []asn1.ObjectIdentifier{{2, 16, 496, 1, 101, 1, 2, 1}, {0, 4, 0, 194112, 1, 2}}
		tmpl.OCSPServer = []string{"http://ocsp.eidmongolia.mn"}
		tmpl.IssuingCertificateURL = []string{"http://ca.eidmongolia.mn/ca/eid-mongolia-issuing-ca.cer"}
		tmpl.CRLDistributionPoints = []string{"http://ca.eidmongolia.mn/crl"}
		tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-time.Hour), time.Now().Add(3*365*24*time.Hour)
	}
	issue := func(tmpl *x509.Certificate, pub crypto.PublicKey) *x509.Certificate {
		ext(tmpl)
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca04, pub, key04)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c
	}
	tsaKey, _ := rsa.GenerateKey(rand.Reader, 3072)
	tsaCert := issue(&x509.Certificate{SerialNumber: big.NewInt(5), Subject: pkix.Name{CommonName: "eID Mongolia TSA",
		Organization: []string{"Gerege Systems LLC"}, Country: []string{"MN"}}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{eidcrypto.TSAEKUExtension()}}, &tsaKey.PublicKey)
	citizenKey, _ := rsa.GenerateKey(rand.Reader, 4096)
	citizen := issue(&x509.Certificate{SerialNumber: new(big.Int).Lsh(big.NewInt(1), 126), Subject: pkix.Name{
		CommonName: "ОТГОНБАЯР,БАЯРСАЙХАН", SerialNumber: "PNOMN-12345678901", Country: []string{"MN"},
		ExtraNames: []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 42}, Value: "BAYARSAIKHAN"},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 4}, Value: "OTGONBAYAR"}}},
		KeyUsage: x509.KeyUsageContentCommitment}, &citizenKey.PublicKey)

	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	tsaKeyDER, _ := x509.MarshalPKCS8PrivateKey(tsaKey)
	write("tsa.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: tsaKeyDER}))
	write("tsa.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tsaCert.Raw}))
	write("chain.pem", chainPEM.Bytes())
	write("serial", []byte("6DA144D61CC8EE9939E357E635D07BD4\n"))
	cnf := write("tsa.cnf", []byte(strings.ReplaceAll(`[ tsa ]
default_tsa = tsa_config1
[ tsa_config1 ]
dir             = DIR
serial          = $dir/serial
crypto_device   = builtin
signer_cert     = $dir/tsa.crt
certs           = $dir/chain.pem
signer_key      = $dir/tsa.key
signer_digest   = sha256
default_policy  = 2.16.496.1.101.1.2.8
digests         = sha256, sha384, sha512
accuracy        = secs:1, millisecs:0, microsecs:0
clock_precision_digits = 0
ordering        = no
tsa_name        = yes
ess_cert_id_chain = no
ess_cert_id_alg = sha256
`, "DIR", dir)))

	prep, err := PrepareSignature(basePDF(t, true), time.Now(), "")
	if err != nil {
		t.Fatal(err)
	}
	attrs, err := SignedAttributes(prep.Digest, citizen)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := rsa.SignPKCS1v15(rand.Reader, citizenKey, crypto.SHA256, DTBS(attrs))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(sig)
	q, err := (&timestamp.Request{HashAlgorithm: crypto.SHA256, HashedMessage: sum[:], Certificates: true, Nonce: big.NewInt(1 << 62)}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	qf := write("q.tsq", q)
	rf := filepath.Join(dir, "r.tsr")
	cmd := exec.Command(openssl, "ts", "-reply", "-config", cnf, "-queryfile", qf, "-out", rf) // #nosec G204 -- тест
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("openssl ts -reply: %v\n%s", err, out)
	}
	resp, _ := os.ReadFile(rf) // #nosec G304 -- тест
	ts, err := timestamp.ParseResponse(resp)
	if err != nil {
		t.Fatal(err)
	}
	cms, err := AssembleCMS(attrs, citizen, chain, sig, ts.RawToken)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("хэмжилт: иргэн %dB, TSA cert %dB, token %dB, CMS %dB (placeholder %dB)",
		len(citizen.Raw), len(tsaCert.Raw), len(ts.RawToken), len(cms), PlaceholderBytes)
	if len(cms) > MeasuredMaxCMS {
		t.Fatalf("CMS %dB > MeasuredMaxCMS %dB — хэмжилтийг шинэчил (placeholder = 2×)", len(cms), MeasuredMaxCMS)
	}
	if PlaceholderBytes < 2*MeasuredMaxCMS {
		t.Fatalf("PlaceholderBytes %d < 2 × %d", PlaceholderBytes, MeasuredMaxCMS)
	}
	if _, err := EmbedCMS(prep.PDF, prep.ByteRange, cms); err != nil {
		t.Fatal(err)
	}
}
