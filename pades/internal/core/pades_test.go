package core

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- VRI түлхүүрийн стандарт
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/pkcs7"
	"github.com/go-pdf/fpdf"
)

type testCert struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

var testSerial int64 = 100

func issue(t *testing.T, parent *testCert, tmpl *x509.Certificate, bits int) *testCert {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	testSerial++
	tmpl.SerialNumber = big.NewInt(testSerial)
	tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)
	pc, pk := tmpl, key
	if parent != nil {
		pc, pk = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, pc, &key.PublicKey, pk)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCert{cert: c, key: key}
}

func caTmpl(cn string) *x509.Certificate {
	return &x509.Certificate{Subject: pkix.Name{CommonName: cn}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
}

func basePDF(t *testing.T, compress bool) []byte {
	t.Helper()
	d := fpdf.New("P", "mm", "A4", "")
	d.SetCompression(compress)
	d.AddPage()
	d.SetFont("Helvetica", "", 12)
	d.Cell(40, 10, "PAdES test")
	var b bytes.Buffer
	if err := d.Output(&b); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// signOnce — prepare → RSA PKCS#1 v1.5 гарын үсэг DTBS дээр → CMS → embed. Буцаах: гаралт, /Contents утга.
func signOnce(t *testing.T, doc []byte, signer *testCert, chain []*x509.Certificate) ([]byte, []byte) {
	t.Helper()
	p, err := PrepareSignature(doc, time.Now(), "")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(p.PDF, doc) {
		t.Fatal("prepared нь оролтын prefix биш")
	}
	attrs, err := SignedAttributes(p.Digest, signer.cert)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := rsa.SignPKCS1v15(rand.Reader, signer.key, crypto.SHA256, DTBS(attrs))
	if err != nil {
		t.Fatal(err)
	}
	cms, err := AssembleCMS(attrs, signer.cert, chain, sig, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := EmbedCMS(p.PDF, p.ByteRange, cms)
	if err != nil {
		t.Fatal(err)
	}
	// digitorus/pkcs7 (validator-ийн задлагч) CMS-ийг баталгаажуулна.
	p7, err := pkcs7.Parse(cms)
	if err != nil {
		t.Fatal(err)
	}
	p7.Content = append(bytes.Clone(out[:p.ByteRange[1]]), out[p.ByteRange[2]:]...)
	if err := p7.Verify(); err != nil {
		t.Fatalf("CMS verify: %v", err)
	}
	contents, err := SignatureContents(out, p.ByteRange)
	if err != nil {
		t.Fatal(err)
	}
	if len(contents) != PlaceholderBytes || !bytes.Equal(contents[:len(cms)], cms) || strings.Trim(string(contents[len(cms):]), "\x00") != "" {
		t.Fatal("SignatureContents нь CMS + тэг дүүргэлт биш")
	}
	return out, contents
}

func TestPrepareEmbedVerifies(t *testing.T) {
	root := issue(t, nil, caTmpl("T Root"), 2048)
	ica := issue(t, root, caTmpl("T Issuing"), 2048)
	leaf := issue(t, ica, &x509.Certificate{Subject: pkix.Name{CommonName: "Citizen"},
		KeyUsage: x509.KeyUsageContentCommitment | x509.KeyUsageDigitalSignature}, 2048)
	for _, compress := range []bool{false, true} {
		out, contents := signOnce(t, basePDF(t, compress), leaf, []*x509.Certificate{ica.cert})
		withDSS, err := AppendDSS(out, DSS{Certs: [][]byte{ica.cert.Raw, leaf.cert.Raw}, Contents: contents})
		if err != nil {
			t.Fatal(err)
		}
		// VRI түлхүүр = SHA1(/Contents-ийн бүтэн байт, тэг дүүргэлттэй) — Acrobat/iText/pyHanko-гийн тооцоо.
		vri := sha1.Sum(contents)
		if !bytes.Contains(withDSS[len(out):], []byte("/"+strings.ToUpper(hex.EncodeToString(vri[:]))+" <<")) {
			t.Fatal("VRI түлхүүр SHA1(/Contents) биш")
		}
		if !bytes.HasPrefix(withDSS, out) {
			t.Fatal("DSS revision prefix биш")
		}
		// хоёр дахь зурагч (өмнөх DSS-ийг хадгалж нэмнэ)
		out2, contents2 := signOnce(t, withDSS, leaf, []*x509.Certificate{ica.cert})
		if _, err := AppendDSS(out2, DSS{Certs: [][]byte{ica.cert.Raw, root.cert.Raw}, Contents: contents2}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEmbedOverflow(t *testing.T) {
	p, err := PrepareSignature(basePDF(t, false), time.Now(), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EmbedCMS(p.PDF, p.ByteRange, make([]byte, PlaceholderBytes+1)); err == nil {
		t.Fatal("хэт урт CMS хүлээн авав")
	}
}
