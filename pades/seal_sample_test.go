package pades

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

// TestSealSampleForAdobe — sample for the owner (PR #65): citizen A (visible stamp + verify page) → citizen B (visible
// stamp, second-signature flow) → SealPDF default: the organisation e-Seal stamp (APPEARANCE_SPEC.md §6), auto-placed on
// the last non-verify page, preferred bottom-right, not exact. All three signatures stay Valid and unmodified. With EID_SAMPLE_DIR set the three PDFs and the test root
// (DER) are written there for opening in Adobe Acrobat; otherwise the test only asserts.
func TestSealSampleForAdobe(t *testing.T) {
	ctx := context.Background()
	p := loadOrCreatePKI(t)
	vopts := VerifyOptions{Roots: [][]byte{p.root.cert.Raw}, Issuers: [][]byte{p.ca04.cert.Raw}, Time: goldenNow}
	stamp := func() *Appearance { return &Appearance{X: 340, Y: 36, Width: 220, Height: 64} }

	// Citizen B — a second citizen leaf with the same profile as the golden citizen (RSA 2048, nonRepudiation +
	// digitalSignature, PNOMN serial, GIVENNAME/SURNAME, same OCSP/CRL).
	bKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(77002), Subject: pkix.Name{CommonName: "TESTOVA SAMPLE", SerialNumber: "PNOMN-00000000002",
		Country: []string{"MN"}, ExtraNames: []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 42}, Value: "SAMPLE"},
			{Type: asn1.ObjectIdentifier{2, 5, 4, 4}, Value: "TESTOVA"}}},
		NotBefore: p.citizen.cert.NotBefore, NotAfter: p.citizen.cert.NotAfter, KeyUsage: x509.KeyUsageContentCommitment | x509.KeyUsageDigitalSignature,
		OCSPServer: p.citizen.cert.OCSPServer, CRLDistributionPoints: p.citizen.cert.CRLDistributionPoints}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca04.cert, &bKey.PublicKey, p.ca04.key)
	if err != nil {
		t.Fatal(err)
	}
	bLeaf, _ := x509.ParseCertificate(der)
	pB := *p
	pB.citizen = &gCert{cert: bLeaf, key: bKey} // liveResponder answers OCSP only for the known serial

	citizen := func(in []byte, pk *goldenPKI) (*Completed, *Placement) {
		t.Helper()
		o := testOpts(p, pk.citizen.cert)
		o.Appearance = stamp()
		prep, err := Prepare(in, o)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := rsa.SignPKCS1v15(nil, pk.citizen.key, crypto.SHA256, prep.DTBS)
		if err != nil {
			t.Fatal(err)
		}
		res, err := Complete(ctx, prep.State, sig, completeOpts(pk))
		if err != nil {
			t.Fatal(err)
		}
		return res, prep.Placement
	}

	a, aPl := citizen(readInput(t, "libreoffice-contract.pdf"), p)
	b, bPl := citizen(a.PDF, &pB)

	// e-Seal: SealPDF default (visible seal stamp, automatic placement).
	sKey, sLeaf := sealLeaf(t, p, x509.KeyUsageContentCommitment, 88008)
	so := sealOpts(p, sLeaf)
	so.SignerName = sLeaf.Subject.CommonName
	sealed, err := SealPDF(ctx, &fakeSealer{cert: sLeaf.Raw, key: sKey}, "NTRMN-6235972", b.PDF, so)
	if err != nil {
		t.Fatal(err)
	}

	if !a.HasPage || b.HasPage || sealed.HasPage || a.RevIndex != 1 || b.RevIndex != 2 || sealed.RevIndex != 3 {
		t.Fatalf("revs: %d/%v %d/%v %d/%v", a.RevIndex, a.HasPage, b.RevIndex, b.HasPage, sealed.RevIndex, sealed.HasPage)
	}
	if !bytes.HasPrefix(b.PDF, a.PDF) || !bytes.HasPrefix(sealed.PDF, b.PDF) {
		t.Fatal("not a pure incremental append")
	}
	// Placement (pt): A and B as the golden libreoffice-contract-visible(-second); the seal (x = 612 − 220 − 36) stacks
	// above them.
	wantPl := []Placement{{Page: 2, X: 340, Y: 60, Width: 220, Height: 64, Status: "moved"},
		{Page: 2, X: 340, Y: 132, Width: 220, Height: 64, Status: "moved"},
		{Page: 2, X: 356, Y: 204, Width: 220, Height: 64, Status: "moved"}}
	for i, pl := range []*Placement{aPl, bPl, sealed.Placement} {
		if pl == nil || *pl != wantPl[i] {
			g, _ := json.Marshal([]*Placement{aPl, bPl, sealed.Placement})
			t.Errorf("placement %d: %s", i, g)
		}
	}

	rep, err := Verify(sealed.PDF, vopts)
	if err != nil || rep.Indication != Valid || len(rep.Signatures) != 3 {
		g, _ := json.Marshal(rep)
		t.Fatalf("%v %s", err, g)
	}
	wantUsage := []string{"sign", "sign", "seal"}
	wantName := []string{"GOLDEN TESTOV", "SAMPLE TESTOVA", "Gerege Systems LLC"}
	for i, s := range rep.Signatures {
		if s.Indication != Valid || len(s.Problems) != 0 || s.SignatureLevel != "PAdES-BASELINE-LT" || !s.Visible || s.CoversWholeDocument ||
			!s.ExtendedBySignaturesOnly || s.LaterSignatures != 2-i || s.VisibleLaterSignature != (i < 2) || s.Certificate == nil ||
			s.Certificate.Usage != wantUsage[i] || s.SignerName != wantName[i] {
			g, _ := json.Marshal(s)
			t.Errorf("signature %d: %s", i, g)
		}
	}

	dir := os.Getenv("EID_SAMPLE_DIR")
	if dir == "" {
		return
	}
	for name, data := range map[string][]byte{"1-citizen-a.pdf": a.PDF, "2-citizen-b.pdf": b.PDF, "3-sealed.pdf": sealed.PDF,
		"test-root.cer": p.root.cert.Raw} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil { // #nosec G306 -- test sample
			t.Fatal(err)
		}
	}
}
