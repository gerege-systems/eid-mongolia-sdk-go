package validate

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	pades "github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/core"
	"github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/padestest"
)

// TestOwnVisibleSeal — тамганы дардас (APPEARANCE_SPEC.md §6): хувилбарыг ЗӨВХӨН гарын үсэг зурагчийн гэрчилгээ сонгоно.
// e-Seal гэрчилгээ + тамганы дардас → хүлээн авна (mn, en); иргэний гэрчилгээ + тамганы дардас, e-Seal гэрчилгээ + иргэний
// дардас → өмнөх гарын үсэг modified_after_signing (prod-ийн profileOwnSigner; өргөн жагсаалт дардсыг дахин үүсгэдэггүй).
func TestOwnVisibleSeal(t *testing.T) {
	p := padestest.New(t)
	v := padesValidator(p)
	v.Extract = isolated(t)
	tsa := p.TSAServer(t, nil)
	alice := p.Citizen(t, "ALICE", "BOLD", "1111111111", 2048)
	bob := p.Citizen(t, "BOB", "DORJ", "2222222222", 2048)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	seal := padestest.Issue(t, p.CA04, &x509.Certificate{Subject: pkix.Name{CommonName: "Test Org LLC", Country: []string{"MN"}},
		KeyUsage: x509.KeyUsageContentCommitment}, key)
	if !sealCertificate(seal.Cert.Raw) || sealCertificate(bob.Cert.Raw) {
		t.Fatal("sealCertificate: e-Seal / иргэний ангилал буруу")
	}
	one := p.Sign(t, padesBase(t), alice, padestest.SignOptions{TSAURL: tsa, SigningTime: visTime})
	sealSpec := func(name, lang string) *pades.Visible {
		return &pades.Visible{Page: 1, X: 3600, Y: 3600, W: 22000, H: 6400, Name: name, Lang: lang,
			Date: visTime.Format("2006-01-02 15:04") + " (+08)", Seal: true}
	}
	first := func(t *testing.T, doc []byte) SignatureReport {
		t.Helper()
		rep := mustPDF(t, v, doc)
		for _, s := range rep.Signatures {
			if s.SignerName == "ALICE BOLD" {
				return s
			}
		}
		t.Fatalf("ALICE алга: %+v", rep)
		return SignatureReport{}
	}

	for _, lang := range []string{"mn", "en"} {
		t.Run("e-Seal + тамганы дардас ("+lang+")", func(t *testing.T) {
			doc := p.Sign(t, one, seal, padestest.SignOptions{TSAURL: tsa, SigningTime: visTime, Visible: sealSpec("Test Org LLC", lang)})
			rep := mustPDF(t, v, doc)
			if rep.Indication != Valid || len(rep.Signatures) != 2 {
				t.Fatalf("%+v", rep)
			}
			for _, s := range rep.Signatures {
				if s.Indication != Valid || len(s.Problems) != 0 {
					t.Fatalf("%s: %s %v", s.SignerName, s.Indication, s.Problems)
				}
				if s.SignerName == "ALICE BOLD" && (!s.ExtendedBySignaturesOnly || !s.VisibleLaterSignature || s.LaterSignatures != 1) {
					t.Fatalf("иргэн: ext=%v visLater=%v later=%d", s.ExtendedBySignaturesOnly, s.VisibleLaterSignature, s.LaterSignatures)
				}
				if s.SignerName == "Test Org LLC" && (s.Certificate == nil || s.Certificate.Usage != "seal" || !s.Visible) {
					t.Fatalf("тамга: %+v", s)
				}
			}
		})
	}
	t.Run("иргэний гэрчилгээ + тамганы дардас → татгалзана", func(t *testing.T) {
		wantModified(t, first(t, p.Sign(t, one, bob, padestest.SignOptions{TSAURL: tsa, SigningTime: visTime, Visible: sealSpec("BOB DORJ", "mn")})))
	})
	t.Run("e-Seal гэрчилгээ + иргэний дардас → татгалзана", func(t *testing.T) {
		spec := visSpec("Test Org LLC", 2, nil)
		spec.Role = ""
		wantModified(t, first(t, p.Sign(t, one, seal, padestest.SignOptions{TSAURL: tsa, SigningTime: visTime, Visible: spec})))
	})
	t.Run("тамганы дардасны content өөрчлөлт → татгалзана", func(t *testing.T) {
		spec := sealSpec("Test Org LLC", "mn")
		spec.Tamper = replaceBody("form", "\n1 w\n", "\n9 w\n")
		wantModified(t, first(t, p.Sign(t, one, seal, padestest.SignOptions{TSAURL: tsa, SigningTime: visTime, Visible: spec})))
	})
}
