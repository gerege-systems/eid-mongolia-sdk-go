package pades

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/validate"
)

// Цуцлалтын нотолгооны тохирол/шинэлэг байдал: онлайн OCSP/CRL (ValidatePDF), Complete-ийн DSS цуглуулалт. Offline
// (DSS) тохиолдлууд — validate golden v4 (validate_v4_test.go, TestValidateGolden).

func tOCSP(t *testing.T, p *goldenPKI, hashIssuer *x509.Certificate, serial *big.Int, status int, this, next, revokedAt time.Time) []byte {
	t.Helper()
	out, err := ocsp.CreateResponse(hashIssuer, p.ca04.cert, ocsp.Response{Status: status, SerialNumber: serial, ThisUpdate: this,
		NextUpdate: next, RevokedAt: revokedAt, RevocationReason: ocsp.KeyCompromise, IssuerHash: crypto.SHA1}, p.ca04.key)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func tCRL(t *testing.T, iss *gCert, this, next time.Time, revoked ...*big.Int) []byte {
	t.Helper()
	var es []x509.RevocationListEntry
	for _, s := range revoked {
		es = append(es, x509.RevocationListEntry{SerialNumber: s, RevocationTime: goldenTime.Add(-2 * time.Hour).UTC()})
	}
	out, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(11), ThisUpdate: this, NextUpdate: next,
		RevokedCertificateEntries: es}, iss.cert, iss.key)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// overrideLTV — иргэний OCSP (ocsp.pki.test/04, иргэний serial) ба 04-ийн CRL-ийг тогтмол хариугаар; бусад → next
// (nil бол 404).
type overrideLTV struct {
	next       http.RoundTripper
	citizen    *big.Int
	ocsp, crl  []byte
	ocspCalls  int
	crlCalls   int
	otherCalls int
}

func (o *overrideLTV) RoundTrip(r *http.Request) (*http.Response, error) {
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(r.Body)
	}
	resp := func(b []byte) (*http.Response, error) {
		status := http.StatusOK
		if b == nil {
			status = http.StatusNotFound
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(b)), Header: http.Header{}, Request: r}, nil
	}
	switch {
	case r.URL.Host == "ocsp.pki.test" && r.URL.Path == "/04":
		if req, err := ocsp.ParseRequest(body); err == nil && req.SerialNumber.Cmp(o.citizen) == 0 {
			o.ocspCalls++
			return resp(o.ocsp)
		}
	case r.URL.Host == "crl.pki.test" && r.URL.Path == "/04.crl" && o.crl != nil:
		o.crlCalls++
		return resp(o.crl)
	}
	o.otherCalls++
	if o.next == nil {
		return resp(nil)
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return o.next.RoundTrip(r)
}

func readValidateInput(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(validateDir, "input", name)) // #nosec G304 -- тест
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func validateOpts(t *testing.T, rt http.RoundTripper) ValidateOptions {
	t.Helper()
	return ValidateOptions{Time: goldenNow, Roots: vPEMs(t, []string{"golden/pki/root.pem"}),
		Issuers: vPEMs(t, []string{"golden/pki/04.pem", "validate/pki/05.pem"}), HTTPClient: &http.Client{Transport: rt}}
}

// TestValidatePDFOnlineRevocationEvidence — онлайн OCSP/CRL хариу ЭНЭ гэрчилгээ + олгогчийнх, шинэлэг байх ёстой;
// онлайн «good» нь DSS-ийн цуцалсан нотолгоог давахгүй.
func TestValidatePDFOnlineRevocationEvidence(t *testing.T) {
	p := loadOrCreatePKI(t)
	ca05 := v4CA05(t, p)
	cit := p.citizen.cert
	T := goldenTime.UTC()
	fresh := T.Add(25 * time.Second)
	day := 24 * time.Hour
	noRev := readValidateInput(t, "dss-no-revocation.pdf") // DSS-д иргэний нотолгоо алга → дүгнэлт онлайн хариунаас
	crlRevoked := readValidateInput(t, "dss-crl-revoked.pdf")
	cases := []struct {
		name       string
		doc        []byte
		ocsp, crl  []byte
		indication Indication
		problems   string
	}{
		{"fresh good", noRev, tOCSP(t, p, p.ca04.cert, cit.SerialNumber, ocsp.Good, fresh, fresh.Add(day), time.Time{}), nil, Valid, ""},
		{"stale good (no nextUpdate)", noRev, tOCSP(t, p, p.ca04.cert, cit.SerialNumber, ocsp.Good, T.Add(-400*day), time.Time{}, time.Time{}), nil, Indeterminate, "revocation_unavailable"},
		{"expired good", noRev, tOCSP(t, p, p.ca04.cert, cit.SerialNumber, ocsp.Good, T.Add(-2*day), T.Add(-day), time.Time{}), nil, Indeterminate, "revocation_unavailable"},
		{"other serial", noRev, tOCSP(t, p, p.ca04.cert, big.NewInt(9999), ocsp.Good, fresh, fresh.Add(day), time.Time{}), nil, Indeterminate, "revocation_unavailable"},
		{"other issuer CertID", noRev, tOCSP(t, p, p.ca03.cert, cit.SerialNumber, ocsp.Good, fresh, fresh.Add(day), time.Time{}), nil, Indeterminate, "revocation_unavailable"},
		{"stale revoked still revoked", noRev, tOCSP(t, p, p.ca04.cert, cit.SerialNumber, ocsp.Revoked, T.Add(-400*day), time.Time{}, T.Add(-401*day)), nil, Invalid, "revoked"},
		{"CRL wrong issuer (05)", noRev, nil, tCRL(t, ca05, T.Add(-time.Hour), T.Add(30*day)), Indeterminate, "revocation_unavailable"},
		{"CRL stale", noRev, nil, tCRL(t, p.ca04, T.Add(-60*day), T.Add(-30*day)), Indeterminate, "revocation_unavailable"},
		{"CRL fresh clean", noRev, nil, tCRL(t, p.ca04, T.Add(-time.Hour), T.Add(30*day)), Valid, ""},
		{"CRL revoked", noRev, nil, tCRL(t, p.ca04, T.Add(-time.Hour), T.Add(30*day), cit.SerialNumber), Invalid, "revoked"},
		{"online good, DSS CRL revoked", crlRevoked, tOCSP(t, p, p.ca04.cert, cit.SerialNumber, ocsp.Good, fresh, fresh.Add(day), time.Time{}), nil, Invalid, "revoked"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rt := &overrideLTV{citizen: cit.SerialNumber, ocsp: c.ocsp, crl: c.crl}
			rep, err := ValidatePDF(context.Background(), c.doc, validateOpts(t, rt))
			if err != nil {
				t.Fatal(err)
			}
			s := rep.Signatures[0]
			if rep.Indication != c.indication || strings.Join(s.Problems, ",") != c.problems {
				t.Fatalf("%s %v, хүлээсэн %s %q (revocation %+v)", rep.Indication, s.Problems, c.indication, c.problems, s.Certificate.Revocation)
			}
		})
	}
}

// TestCompleteRevokedIsHardFailure — олгогчийн гарын үсэгтэй «revoked» (OCSP эсвэл CRL) Complete-д ErrCertificateRevoked
// (LTV_UNAVAILABLE), дахин оролдохгүй; нөгөө эх сурвалж «good» байсан ч DSS угсрахгүй.
func TestCompleteRevokedIsHardFailure(t *testing.T) {
	p, rt, c, in, _ := ltvGolden(t)
	cit := p.citizen.cert
	T := goldenTime.UTC()
	fresh := T.Add(5 * time.Second)
	clean := tCRL(t, p.ca04, T.Add(-time.Hour), T.Add(30*24*time.Hour))
	for _, tc := range []struct {
		name      string
		ocsp, crl []byte
	}{
		{"OCSP revoked, CRL clean", tOCSP(t, p, p.ca04.cert, cit.SerialNumber, ocsp.Revoked, fresh, fresh.Add(24*time.Hour), T.Add(-time.Hour)), clean},
		{"OCSP good, CRL revoked", tOCSP(t, p, p.ca04.cert, cit.SerialNumber, ocsp.Good, fresh, fresh.Add(24*time.Hour), time.Time{}),
			tCRL(t, p.ca04, T.Add(-time.Hour), T.Add(30*24*time.Hour), cit.SerialNumber)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &flakyLTV{next: &overrideLTV{next: rt, citizen: cit.SerialNumber, ocsp: tc.ocsp, crl: tc.crl}}
			var sleeps []time.Duration
			withSleeps(t, f, &sleeps)
			_, _, err := runGoldenWith(context.Background(), t, p, f, c, in, nil)
			if ErrorCode(err) != CodeLTVUnavailable || !errors.Is(err, ErrCertificateRevoked) {
				t.Fatalf("%v", err)
			}
			noSubjectCN(t, err, cit)
			for _, d := range sleeps {
				if d >= time.Second {
					t.Fatalf("revoked дээр дахин оролдсон: %v", sleeps)
				}
			}
		})
	}
}

// noSubjectCN — LTV алдааны текстэд иргэний CN (овог, нэр — PII) орохгүй; serial-аар заана.
func noSubjectCN(t *testing.T, err error, cit *x509.Certificate) {
	t.Helper()
	msg := err.Error()
	if cit.Subject.CommonName == "" || strings.Contains(msg, cit.Subject.CommonName) || !strings.Contains(msg, cit.SerialNumber.Text(16)) {
		t.Fatalf("алдаанд CN эсвэл serial-гүй: %q", msg)
	}
}

// TestCollectLTVRejectsForeignEvidence — Complete-ийн DSS-д өөр олгогчийн CertID-тэй, хуучирсан OCSP ба өөр
// олгогчийн CRL орохгүй (иргэнд хүчинтэй нотолгоо алга → LTV_UNAVAILABLE).
func TestCollectLTVRejectsForeignEvidence(t *testing.T) {
	p, rt, c, in, _ := ltvGolden(t)
	ca05 := v4CA05(t, p)
	cit := p.citizen.cert
	T := goldenTime.UTC()
	fresh := T.Add(5 * time.Second)
	foreignCRL := tCRL(t, ca05, T.Add(-time.Hour), T.Add(30*24*time.Hour))
	for _, tc := range []struct {
		name string
		ocsp []byte
	}{
		{"other issuer CertID", tOCSP(t, p, p.ca03.cert, cit.SerialNumber, ocsp.Good, fresh, fresh.Add(24*time.Hour), time.Time{})},
		{"expired", tOCSP(t, p, p.ca04.cert, cit.SerialNumber, ocsp.Good, fresh, T.Add(-time.Hour), time.Time{})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &flakyLTV{next: &overrideLTV{next: rt, citizen: cit.SerialNumber, ocsp: tc.ocsp, crl: foreignCRL}}
			var sleeps []time.Duration
			withSleeps(t, f, &sleeps)
			_, _, err := runGoldenWith(context.Background(), t, p, f, c, in, intp(0))
			if ErrorCode(err) != CodeLTVUnavailable || errors.Is(err, ErrCertificateRevoked) {
				t.Fatalf("%v", err)
			}
			noSubjectCN(t, err, cit)
		})
	}
}

// TestDeepNestingNoCrash — ~3 MB давхарлалт (digitorus рекурсийн stack overflow — recover барихгүй fatal) нь
// Prepare / ValidatePDF / Verify / Complete-д PDF_INVALID (ErrPDFStructure) болно; сонгодог объект ба ObjStm.
func TestDeepNestingNoCrash(t *testing.T) {
	p := loadOrCreatePKI(t)
	for _, objstm := range []bool{false, true} {
		doc := v4DeepPDF(3<<20, objstm)
		if _, err := ValidatePDF(context.Background(), doc, ValidateOptions{Offline: true}); ErrorCode(err) != CodePDFInvalid || !errors.Is(err, ErrPDFStructure) {
			t.Fatalf("ValidatePDF objstm=%v: %v", objstm, err)
		}
		if _, err := Verify(doc, VerifyOptions{}); ErrorCode(err) != CodePDFInvalid || !errors.Is(err, ErrPDFStructure) {
			t.Fatalf("Verify objstm=%v: %v", objstm, err)
		}
		_, err := Prepare(doc, PrepareOptions{SignerCert: p.citizen.cert.Raw, Chain: [][]byte{p.ca04.cert.Raw, p.ca03.cert.Raw, p.ca02.cert.Raw}})
		if ErrorCode(err) != CodePDFInvalid || !errors.Is(err, ErrPDFStructure) {
			t.Fatalf("Prepare objstm=%v: %v", objstm, err)
		}
		st := &prepState{DocID: "x", SignerCert: p.citizen.cert.Raw, SignedAttrs: []byte{1}, RevIndex: 1, PDF: doc, PreparedSHA256: sha256Hex(doc)}
		state, err := st.encode()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Complete(context.Background(), state, []byte{1}, CompleteOptions{}); ErrorCode(err) != CodeStateInvalid || !errors.Is(err, ErrPDFStructure) {
			t.Fatalf("Complete objstm=%v: %v", objstm, err)
		}
	}
}

// TestCheckStructureBoundary — гүн MaxNesting хүртэл зөвшөөрнө, MaxNesting+1 татгалзана (сонгодог хувилбарт Catalog
// толь = 1 түвшин; ObjStm-д объект нь массив өөрөө).
func TestCheckStructureBoundary(t *testing.T) {
	for _, objstm := range []bool{false, true} {
		n := validate.MaxNesting - 1
		if objstm {
			n = validate.MaxNesting
		}
		if err := validate.CheckStructure(v4DeepPDF(n, objstm)); err != nil {
			t.Fatalf("objstm=%v гүн %d: %v", objstm, validate.MaxNesting, err)
		}
		if err := validate.CheckStructure(v4DeepPDF(n+1, objstm)); !errors.Is(err, validate.ErrStructure) {
			t.Fatalf("objstm=%v гүн %d: %v", objstm, validate.MaxNesting+1, err)
		}
	}
}

// TestCheckStructureCorpus — репогийн бүх тестийн PDF (golden, validate, CA-ийн корпус) хуурамч татгалзалгүй.
func TestCheckStructureCorpus(t *testing.T) {
	n := 0
	walk := func(root string) error {
		return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".pdf") || strings.Contains(path, "deep-nesting") {
				return err
			}
			b, err := os.ReadFile(path) // #nosec G304 -- тест
			if err != nil {
				return err
			}
			n++
			if err := validate.CheckStructure(b); err != nil {
				t.Errorf("%s: %v", path, err)
			}
			return nil
		})
	}
	var err error
	for _, root := range []string{"testdata", filepath.Join("internal", "validate", "testdata"), filepath.Join("internal", "core", "testdata")} {
		if err == nil {
			err = walk(root)
		}
	}
	if err != nil || n < 20 {
		t.Fatalf("%v (%d файл)", err, n)
	}
}
