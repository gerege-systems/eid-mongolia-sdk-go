package validate

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"slices"
	"testing"
	"time"

	pades "github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/core"
	"github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/padestest"
)

// PAdES (иргэний CMS, internal/pdfsign/pades) — нийтийн шалгагч §8: таних, олон revision (R_sig + R_dss), LTV.

func padesValidator(p *padestest.PKI) *Validator {
	roots := x509.NewCertPool()
	roots.AddCert(p.Root.Cert)
	return &Validator{Roots: roots, Intermediates: p.Chain(), Issuers: []*x509.Certificate{p.CA04.Cert}, Status: good}
}

func padesBase(t *testing.T) []byte {
	t.Helper()
	// Эхний зурагчийн суурь — баталгаажуулалтын хуудастай (pdfcpu merge → xref stream).
	return legacyWithPage(t, minimalPDF(t))
}

func wantPAdESValid(t *testing.T, s SignatureReport, level string) {
	t.Helper()
	if s.Indication != Valid || len(s.Problems) != 0 {
		t.Fatalf("хүлээсэн valid, авсан %s %v", s.Indication, s.Problems)
	}
	if s.SignerNameSource != SignerNameCertificate || s.Certificate == nil || s.Certificate.Usage != "sign" {
		t.Fatalf("signer: %q %q %+v", s.SignerName, s.SignerNameSource, s.Certificate)
	}
	if s.SignatureLevel != level {
		t.Fatalf("level %q, хүлээсэн %q (ltv %+v)", s.SignatureLevel, level, s.LTV)
	}
}

func TestPAdESOneAndTwoSigners(t *testing.T) {
	p := padestest.New(t)
	v := padesValidator(p)
	v.Extract = isolated(t) // prod-ийн зам (worker → Extract → profileOwnSigner)
	tsa := p.TSAServer(t, nil)
	alice := p.Citizen(t, "ALICE", "BOLD", "1111111111", 2048)
	bob := p.Citizen(t, "BOB", "DORJ", "2222222222", 2048)
	for name, base := range map[string][]byte{"classic xref": minimalPDF(t), "xref stream (хуудастай)": padesBase(t)} {
		t.Run(name, func(t *testing.T) {
			one := p.Sign(t, base, alice, padestest.SignOptions{TSAURL: tsa})
			rep := mustPDF(t, v, one)
			if rep.Indication != Valid || len(rep.Signatures) != 1 {
				t.Fatalf("1 зурагч: %+v", rep)
			}
			s := rep.Signatures[0]
			wantPAdESValid(t, s, "PAdES-BASELINE-LT")
			if s.SignerName != "ALICE BOLD" || s.CoversWholeDocument || !s.ExtendedBySignaturesOnly || s.LaterSignatures != 0 {
				t.Fatalf("1 зурагч: %q whole=%v ext=%v later=%d", s.SignerName, s.CoversWholeDocument, s.ExtendedBySignaturesOnly, s.LaterSignatures)
			}

			two := p.Sign(t, one, bob, padestest.SignOptions{TSAURL: tsa})
			if !bytes.HasPrefix(two, one) {
				t.Fatal("2 дахь гарын үсэг өмнөх байтыг өөрчилсөн")
			}
			rep = mustPDF(t, v, two)
			if rep.Indication != Valid || len(rep.Signatures) != 2 {
				t.Fatalf("2 зурагч: %+v", rep)
			}
			for _, s := range rep.Signatures {
				wantPAdESValid(t, s, "PAdES-BASELINE-LT")
			}
			names := []string{rep.Signatures[0].SignerName, rep.Signatures[1].SignerName}
			slices.Sort(names)
			if names[0] != "ALICE BOLD" || names[1] != "BOB DORJ" {
				t.Fatalf("нэрс %v", names)
			}
			// R_dss-ийн улмаас аль аль нь бүтэн хамраагүй: эхнийх нь дараа 1 гарын үсэг, сүүлийнх 0.
			later := []int{rep.Signatures[0].LaterSignatures, rep.Signatures[1].LaterSignatures}
			slices.Sort(later)
			if later[0] != 0 || later[1] != 1 {
				t.Fatalf("later_signatures %v", later)
			}
		})
	}
}

func TestPAdESLevelsAndLTVMissing(t *testing.T) {
	p := padestest.New(t)
	v := padesValidator(p)
	tsa := p.TSAServer(t, nil)
	c := p.Citizen(t, "C", "D", "3333333333", 2048)
	base := minimalPDF(t)

	s := only(t, mustPDF(t, v, p.Sign(t, base, c, padestest.SignOptions{NoDSS: true})))
	wantPAdESValid(t, s, "PAdES-BASELINE-B")
	if s.LTV == nil || s.LTV.Complete {
		t.Fatalf("DSS-гүй LTV %+v", s.LTV)
	}
	s = only(t, mustPDF(t, v, p.Sign(t, base, c, padestest.SignOptions{TSAURL: tsa, NoDSS: true})))
	wantPAdESValid(t, s, "PAdES-BASELINE-T")

	s = only(t, mustPDF(t, v, p.Sign(t, base, c, padestest.SignOptions{TSAURL: tsa, DropOCSP: true})))
	wantPAdESValid(t, s, "PAdES-BASELINE-T")
	if s.LTV == nil || s.LTV.Complete || !slices.Contains(s.LTV.Missing, c.Cert.Subject.CommonName) {
		t.Fatalf("иргэний OCSP-гүй LTV %+v", s.LTV)
	}
}

// R_dss-ийн дараа гарын үсэггүй агуулгын засвар → эхний гарын үсэг modified_after_signing; DSS-ийн stream-ийг
// өөр агуулгаар ижил дугаараар дарж бичих → мөн өөрчлөлт.
func TestPAdESEditsAfterDSS(t *testing.T) {
	p := padestest.New(t)
	v := padesValidator(p)
	c := p.Citizen(t, "C", "D", "4444444444", 2048)
	signed := p.Sign(t, minimalPDF(t), c, padestest.SignOptions{TSAURL: p.TSAServer(t, nil)})
	f := newFixture(t, signed)
	wantModified(t, only(t, mustPDF(t, v, appendRev(t, signed, rev{objs: map[int]string{f.page: pdfText(with(f.pageDict, "Rotate", int64(90)))}}))))
	dss := f.cat["DSS"].(pdfRef).num
	dd := f.dict(dss)
	certRef := dd["Certs"].(pdfArr)[0].(pdfRef).num
	wantModified(t, only(t, mustPDF(t, v, appendRev(t, signed, rev{objs: map[int]string{certRef: stream("", "EVIL")}}))))
}

// signingCertificateV2 таарахгүй (өөр гэрчилгээний hash) ETSI.CAdES гарын үсэг — malformed.
func TestPAdESSigningCertV2Mismatch(t *testing.T) {
	p := padestest.New(t)
	c := p.Citizen(t, "C", "D", "5555555555", 2048)
	other := p.Citizen(t, "O", "P", "6666666666", 2048)
	prep, err := pades.PrepareSignature(minimalPDF(t), timeNow(), "")
	if err != nil {
		t.Fatal(err)
	}
	attrs, err := pades.SignedAttributes(prep.Digest, other.Cert) // буруу cert-ийн ESSCertIDv2
	if err != nil {
		t.Fatal(err)
	}
	sig := signRSA(t, c, pades.DTBS(attrs))
	cms, err := pades.AssembleCMS(attrs, c.Cert, p.Chain(), sig, nil)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := pades.EmbedCMS(prep.PDF, prep.ByteRange, cms)
	if err != nil {
		t.Fatal(err)
	}
	s := only(t, mustPDF(t, padesValidator(p), doc))
	if s.Indication != Invalid || !slices.Contains(s.Problems, ProblemMalformed) {
		t.Fatalf("хүлээсэн malformed, авсан %s %v", s.Indication, s.Problems)
	}
}

func timeNow() time.Time { return time.Now() }

func signRSA(t *testing.T, c *padestest.Cert, digest []byte) []byte {
	t.Helper()
	sig, err := c.Key.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}
