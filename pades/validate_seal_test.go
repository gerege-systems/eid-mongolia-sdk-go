package pades

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/core"
)

// Тамганы дардас (APPEARANCE_SPEC.md §6) — ValidatePDF conformance (pades/testdata/validate, v12). Эерэг тохиолдлууд нь
// golden/output-ийн тамгатай гаралт; сөрөг хоёр нь гэрчилгээтэй таарахгүй дардастай 2 дахь гарын үсэг (иргэний гарын
// үсэгтэй golden/output/quartz-pdf13.pdf дээр, timestamp/DSS-гүй) — эхний иргэний гарын үсэг modified_after_signing.
func sealVCases() []vCase {
	return []vCase{
		{Name: "seal-visible", Input: "golden/output/seal-visible.pdf", Offline: true},
		{Name: "seal-visible-en", Input: "golden/output/seal-visible-en.pdf", Offline: true},
		{Name: "seal-after-two-citizens", Input: "golden/output/seal-visible-third.pdf", Offline: true},
		{Name: "seal-stamp-citizen-cert", Input: "validate/input/seal-stamp-citizen-cert.pdf", Offline: true},
		{Name: "citizen-stamp-seal-cert", Input: "validate/input/citizen-stamp-seal-cert.pdf", Offline: true},
	}
}

// sealVInputs — сөрөг оролтууд (-update): иргэний гэрчилгээ + тамганы дардас; e-Seal гэрчилгээ + иргэний дардас.
func sealVInputs(t *testing.T, p *goldenPKI) map[string][]byte {
	t.Helper()
	if p.seal == nil {
		t.Fatal("pki/seal.pem алга — эхлээд `go test ./pades -run '^TestGolden$' -update`")
	}
	base, err := os.ReadFile(filepath.Join(goldenDir, "output", "quartz-pdf13.pdf"))
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{
		"seal-stamp-citizen-cert": vMismatchedStamp(t, p, base, p.citizen, true),
		"citizen-stamp-seal-cert": vMismatchedStamp(t, p, base, p.seal, false),
	}
}

// vMismatchedStamp — base-д signer-ийн 2 дахь гарын үсгийг (B-B: timestamp, DSS-гүй) 1-р хуудсанд 340, 36, 220 × 64 pt
// дардастай нэмнэ; дардасны хувилбар = seal (гэрчилгээнээс үл хамааран — Prepare-ийн зам үүнийг хэзээ ч гаргахгүй).
func vMismatchedStamp(t *testing.T, p *goldenPKI, base []byte, signer *gCert, seal bool) []byte {
	t.Helper()
	docID := docIDFromPage(base)
	if docID == "" {
		t.Fatal("base: docId алга")
	}
	name := core.SignerDisplayName(signer.cert)
	at := goldenTime.In(signingZone)
	vis := core.Visible{Page: 1, X: 34000, Y: 3600, W: 22000, H: 6400, Name: name, Lang: "mn",
		Date: at.Format("2006-01-02 15:04") + " (+08)", URL: pageVerifyURL + docID + "/2", Seal: seal}
	prep, err := core.PrepareSignatureVisible(base, at, name, "", vis)
	if err != nil {
		t.Fatal(err)
	}
	attrs, err := core.SignedAttributesWithRole(prep.Digest, signer.cert, "")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := rsa.SignPKCS1v15(nil, signer.key, crypto.SHA256, core.DTBS(attrs))
	if err != nil {
		t.Fatal(err)
	}
	cms, err := core.AssembleCMS(attrs, signer.cert, []*x509.Certificate{p.ca04.cert, p.ca03.cert, p.ca02.cert}, sig, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := core.EmbedCMS(prep.PDF, prep.ByteRange, cms)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
