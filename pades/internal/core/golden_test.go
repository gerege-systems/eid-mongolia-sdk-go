package core

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

var updateGolden = flag.Bool("update-pades-golden", false, "testdata/pades_golden.json-ийг дахин бичих")

type padesGolden struct {
	MessageDigest string `json:"messageDigest"`
	SignedAttrs   string `json:"signedAttrs"`
	DTBS          string `json:"dtbs"`
}

// TestSignedAttrsGolden — signedAttrs DER + DTBS тогтмол cert (testdata/golden_signer.crt) ба тогтмол
// messageDigest-ээс байт-ижил (docs/PADES_SIGNING.md §13). Утас зурах 32 байтыг өөрчилдөг аливаа засвар
// (attr-ийн дараалал, ESSCertIDv2-ийн хэлбэр) энд баригдана.
func TestSignedAttrsGolden(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "golden_signer.crt"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode(raw)
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	md := sha256.Sum256([]byte("eID Mongolia PAdES golden"))
	attrs, err := SignedAttributes(md[:], cert)
	if err != nil {
		t.Fatal(err)
	}
	got := padesGolden{MessageDigest: hex.EncodeToString(md[:]), SignedAttrs: hex.EncodeToString(attrs), DTBS: hex.EncodeToString(DTBS(attrs))}
	path := filepath.Join("testdata", "pades_golden.json")
	if *updateGolden {
		out, _ := json.MarshalIndent(got, "", "  ")
		if err := os.WriteFile(path, append(out, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want := padesGolden{}
	data, err := os.ReadFile(path) // #nosec G304 -- тест
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &want); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("golden зөрөв:\nавсан   %+v\nхүлээсэн %+v", got, want)
	}
}

// TestCMSOpenSSLVerify — угсарсан CMS-ийг OpenSSL (бие даасан хэрэгжүүлэлт) `cms -verify -binary`-ээр
// detached контенттой шалгана: гарын үсэг, messageDigest, signedAttrs-ийн DER. openssl байхгүй бол алгасна.
func TestCMSOpenSSLVerify(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl алга")
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(77), Subject: pkix.Name{CommonName: "OpenSSL check"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageContentCommitment}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	content := []byte("detached PDF ByteRange bytes")
	md := sha256.Sum256(content)
	attrs, err := SignedAttributes(md[:], cert)
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, DTBS(attrs))
	cms, err := AssembleCMS(attrs, cert, nil, sig, nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cmsFile, contentFile := filepath.Join(dir, "sig.der"), filepath.Join(dir, "content.bin")
	_ = os.WriteFile(cmsFile, cms, 0o600)
	_ = os.WriteFile(contentFile, content, 0o600)
	cmd := exec.Command(openssl, "cms", "-verify", "-binary", "-inform", "DER", "-in", cmsFile, "-content", contentFile, // #nosec G204 -- тест
		"-noverify", "-out", os.DevNull)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("openssl cms -verify: %v\n%s", err, out)
	}
	// Өөр контент → унах ёстой (messageDigest).
	_ = os.WriteFile(contentFile, append(content, 'x'), 0o600)
	if out, err := exec.Command(openssl, "cms", "-verify", "-binary", "-inform", "DER", "-in", cmsFile, "-content", contentFile, // #nosec G204 -- тест
		"-noverify", "-out", os.DevNull).CombinedOutput(); err == nil {
		t.Fatalf("өөрчилсөн контентыг openssl хүлээн авав: %s", out)
	}
}
