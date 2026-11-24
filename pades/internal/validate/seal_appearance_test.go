package validate

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"regexp"
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

// TestOwnVisibleSealQR — QR-тэй тамганы дардас (APPEARANCE_SPEC.md §6.5, §6.3): e-Seal гэрчилгээнд form stream-ийн эхний
// /EIDVerify тэмдэг хувилбарыг шийднэ — тэмдэгтэй бол QR-тэй тамга (§5 алхам 6-ийн шалгалттай), тэмдэггүй бол QR-гүй (§6.2).
// Хоёр дардасны docId зөрөх (verify хуудасгүй баримтад) нь өөрчлөлт биш. Бусад бүх хослол → эхний гарын үсэг
// modified_after_signing.
func TestOwnVisibleSealQR(t *testing.T) {
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
	const otherDocID = "0f1e2d3c-4b5a-4968-8776-5a4b3c2d1e0f"
	url := func(doc string, rev int) string {
		return "https://ca.eidmongolia.mn/verify/" + doc + "/" + string(rune('0'+rev))
	}
	qrSeal := func(name, lang, u string) *pades.Visible {
		return &pades.Visible{Page: 1, X: 3600, Y: 3600, W: 22000, H: 6400, Name: name, Lang: lang,
			Date: visTime.Format("2006-01-02 15:04") + " (+08)", URL: u, Seal: true}
	}
	sign := func(doc []byte, who *padestest.Cert, vis *pades.Visible) []byte {
		return p.Sign(t, doc, who, padestest.SignOptions{TSAURL: tsa, SigningTime: visTime, Visible: vis})
	}
	one := sign(padesBase(t), alice, nil)
	first := func(t *testing.T, doc []byte) SignatureReport {
		t.Helper()
		for _, s := range mustPDF(t, v, doc).Signatures {
			if s.SignerName == "ALICE BOLD" {
				return s
			}
		}
		t.Fatal("ALICE алга")
		return SignatureReport{}
	}
	allValid := func(t *testing.T, doc []byte, n int) {
		t.Helper()
		rep := mustPDF(t, v, doc)
		if rep.Indication != Valid || len(rep.Signatures) != n {
			t.Fatalf("%+v", rep)
		}
		for _, s := range rep.Signatures {
			if s.Indication != Valid || len(s.Problems) != 0 || !s.Visible && s.SignerName != "ALICE BOLD" {
				t.Fatalf("%s: %s %v visible=%v", s.SignerName, s.Indication, s.Problems, s.Visible)
			}
		}
	}

	for _, lang := range []string{"mn", "en"} {
		t.Run("e-Seal + QR-тэй тамга ("+lang+")", func(t *testing.T) {
			allValid(t, sign(one, seal, qrSeal("Test Org LLC", lang, url(visDocID, 2))), 2)
		})
	}
	t.Run("QR-гүй тамга хүлээн авагдсаар (маркергүй)", func(t *testing.T) {
		allValid(t, sign(one, seal, qrSeal("Test Org LLC", "mn", "")), 2)
	})
	t.Run("хоёр дардас өөр docId-тай (verify хуудасгүй) — өөрчлөлт биш", func(t *testing.T) {
		c1 := sign(one, bob, visSpec("BOB DORJ", 2, nil)) // visDocID
		allValid(t, sign(c1, seal, qrSeal("Test Org LLC", "mn", url(otherDocID, 3))), 3)
		s1 := sign(one, seal, qrSeal("Test Org LLC", "mn", url(otherDocID, 2)))
		allValid(t, sign(s1, bob, visSpec("BOB DORJ", 3, nil)), 3)
	})

	rejects := map[string]func() []byte{
		"иргэний гэрчилгээ + QR-тэй тамга": func() []byte { return sign(one, bob, qrSeal("BOB DORJ", "mn", url(visDocID, 2))) },
		"e-Seal + QR тамга, маркерын rev буруу": func() []byte {
			return sign(one, seal, qrSeal("Test Org LLC", "mn", url(visDocID, 3)))
		},
		"e-Seal + QR тамга + үүргийн мөр (CMS claimedRole)": func() []byte {
			vis := qrSeal("Test Org LLC", "mn", url(visDocID, 2))
			vis.Role, vis.Tamper = "Захирал, Тест ХХК (NTRMN-1234567)", &pades.VisibleTamper{SealRole: true}
			return sign(one, seal, vis)
		},
		"e-Seal + иргэний дардас (QR, үүрэггүй)": func() []byte {
			spec := visSpec("Test Org LLC", 2, nil)
			spec.Role = ""
			return sign(one, seal, spec)
		},
		"e-Seal + маркер + QR-гүй content": func() []byte {
			vis := qrSeal("Test Org LLC", "mn", "")
			marker := "/EIDVerify <</URL (" + url(visDocID, 2) + ")>> BDC\n"
			vis.Tamper = &pades.VisibleTamper{Body: func(role string, b []byte) []byte {
				if role != "form" {
					return b
				}
				i, j := bytes.Index(b, []byte(">>\nstream\n"))+len(">>\nstream\n"), bytes.LastIndex(b, []byte("\nendstream"))
				c := append(append([]byte(marker), b[i:j]...), "EMC\n"...)
				head := regexp.MustCompile(`^<< /Length \d+`).ReplaceAll(bytes.Clone(b[:i]), fmt.Appendf(nil, "<< /Length %d", len(c)))
				return append(append(head, c...), "\nendstream"...)
			}}
			return sign(one, seal, vis)
		},
		"e-Seal + QR тамга 44 pt (модуль < 1 pt)": func() []byte {
			vis := qrSeal("Test Org LLC", "mn", url(visDocID, 2))
			vis.H, vis.Tamper = 4400, &pades.VisibleTamper{NoMinModule: true}
			return sign(one, seal, vis)
		},
	}
	for name, build := range rejects {
		t.Run(name+" → татгалзана", func(t *testing.T) { wantModified(t, first(t, build())) })
	}
}
