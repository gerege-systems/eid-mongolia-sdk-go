package pades

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/sign"

	eid "github.com/gerege-systems/eid-mongolia-sdk-go"
)

// liveTransport — goldenPKI-ийн хариуг шууд үүсгэнэ (тодорхойлогдоогүй — golden биш тестэд).
type liveTransport struct{ h http.Handler }

func (l liveTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	l.h.ServeHTTP(rec, r)
	return rec.Result(), nil
}

func readInput(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(goldenDir, "input", name)) // #nosec G304 -- тест
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func testOpts(p *goldenPKI, leaf *x509.Certificate) PrepareOptions {
	return PrepareOptions{SignerCert: leaf.Raw, Chain: [][]byte{p.ca04.cert.Raw, p.ca03.cert.Raw, p.ca02.cert.Raw},
		SigningTime: goldenTime, VerifyPage: true, FileName: "test.pdf"}
}

func completeOpts(p *goldenPKI) CompleteOptions {
	return CompleteOptions{HTTPClient: &http.Client{Transport: liveTransport{p.liveResponder(nil)}}, TSAURL: "http://tsa.pki.test/",
		Now: func() time.Time { return goldenNow }, Roots: [][]byte{p.root.cert.Raw}}
}

// TestEndToEndECDSA — P-256 иргэн (токен/утас): prepare → r‖s ба DER гарын үсэг → complete → Verify valid B-LT.
func TestEndToEndECDSA(t *testing.T) {
	p := loadOrCreatePKI(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(77001), Subject: pkix.Name{CommonName: "ECDSA TEST", SerialNumber: "PNOMN-00000000001",
		ExtraNames: []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 42}, Value: "ECDSA"}, {Type: asn1.ObjectIdentifier{2, 5, 4, 4}, Value: "TEST"}}},
		NotBefore: p.citizen.cert.NotBefore, NotAfter: p.citizen.cert.NotAfter, KeyUsage: x509.KeyUsageContentCommitment | x509.KeyUsageDigitalSignature,
		OCSPServer: p.citizen.cert.OCSPServer, CRLDistributionPoints: p.citizen.cert.CRLDistributionPoints}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca04.cert, &key.PublicKey, p.ca04.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	// liveResponder нь мэдэгдэх serial-д л хариулна — ECDSA leaf-ийг нэмнэ.
	p2 := *p
	p2.citizen = &gCert{cert: leaf}
	for _, raw := range []bool{true, false} {
		prep, err := Prepare(readInput(t, "quartz-pdf13.pdf"), testOpts(p, leaf))
		if err != nil {
			t.Fatal(err)
		}
		der, err := ecdsa.SignASN1(rand.Reader, key, prep.DTBS)
		if err != nil {
			t.Fatal(err)
		}
		sig := der
		if raw {
			var rs struct{ R, S *big.Int }
			if _, err := asn1.Unmarshal(der, &rs); err != nil {
				t.Fatal(err)
			}
			sig = make([]byte, 64)
			rs.R.FillBytes(sig[:32])
			rs.S.FillBytes(sig[32:])
		}
		res, err := Complete(context.Background(), prep.State, sig, completeOpts(&p2))
		if err != nil {
			t.Fatalf("raw=%v: %v", raw, err)
		}
		rep, err := Verify(res.PDF, VerifyOptions{Roots: [][]byte{p.root.cert.Raw}, Issuers: [][]byte{p.ca04.cert.Raw}, Time: goldenNow})
		if err != nil || rep.Indication != Valid || len(rep.Signatures) != 1 || rep.Signatures[0].SignatureLevel != "PAdES-BASELINE-LT" {
			b, _ := json.Marshal(rep)
			t.Fatalf("raw=%v: %v %s", raw, err, b)
		}
		if !res.HasPage || res.RevIndex != 1 || len(res.PriorCMSSHA256) != 0 || res.DocID == "" {
			t.Fatalf("raw=%v: %+v", raw, res.RevIndex)
		}
	}
}

func TestCompleteRejects(t *testing.T) {
	p := loadOrCreatePKI(t)
	prep, err := Prepare(readInput(t, "quartz-pdf13.pdf"), testOpts(p, p.citizen.cert))
	if err != nil {
		t.Fatal(err)
	}
	// Буруу гарын үсэг (өөр DTBS).
	bad, _ := p.citizen.key.Sign(rand.Reader, make([]byte, 32), crypto.SHA256)
	if _, err := Complete(context.Background(), prep.State, bad, completeOpts(p)); ErrorCode(err) != CodeSignatureInvalid {
		t.Fatalf("буруу гарын үсэг: %v", err)
	}
	// Эвдэрсэн state (prepared PDF өөрчлөгдсөн).
	st := bytes.Clone(prep.State)
	st[len(st)-10] ^= 1
	sig, _ := p.citizen.key.Sign(rand.Reader, prep.DTBS, crypto.SHA256)
	if _, err := Complete(context.Background(), st, sig, completeOpts(p)); ErrorCode(err) != CodeStateInvalid {
		t.Fatalf("эвдэрсэн state: %v", err)
	}
	// TSA унасан.
	o := completeOpts(p)
	o.TSAURL = "http://down.pki.test/"
	if _, err := Complete(context.Background(), prep.State, sig, o); ErrorCode(err) != CodeTSAUnavailable {
		t.Fatalf("TSA: %v", err)
	}
	// Гадны TSA-гийн итгэлгүй гинж (өөр root).
	o = completeOpts(p)
	o.Roots = [][]byte{p.citizen.cert.Raw}
	if _, err := Complete(context.Background(), prep.State, sig, o); ErrorCode(err) != CodeTSAUnavailable {
		t.Fatalf("TSA root: %v", err)
	}
}

func TestPrepareRejects(t *testing.T) {
	p := loadOrCreatePKI(t)
	o := testOpts(p, p.citizen.cert)
	cases := map[string]struct {
		doc  []byte
		opts func(*PrepareOptions)
		code string
	}{
		"not pdf":   {doc: []byte("hello"), code: CodePDFInvalid},
		"too large": {doc: append([]byte("%PDF-1.4\n"), make([]byte, MaxInputBytes)...), code: CodePDFTooLarge},
		"broken":    {doc: []byte("%PDF-1.4\n1 0 obj\n<<>>\nendobj\n"), code: CodePDFInvalid},
		"encrypted": {doc: readInput(t, "encrypted.pdf"), code: CodePDFEncrypted},
		"stamped":   {doc: readInput(t, "stamped.pdf"), code: CodePDFForeignSignature},
		"bad docId": {doc: readInput(t, "quartz-pdf13.pdf"), opts: func(o *PrepareOptions) { o.DocID = "NOT-A-UUID" }, code: CodeRequestInvalid},
		"no file":   {doc: readInput(t, "quartz-pdf13.pdf"), opts: func(o *PrepareOptions) { o.FileName = " ‮ " }, code: CodeRequestInvalid},
		"bad cert":  {doc: readInput(t, "quartz-pdf13.pdf"), opts: func(o *PrepareOptions) { o.SignerCert = []byte{1} }, code: CodeSignerInvalid},
		"long role": {doc: readInput(t, "quartz-pdf13.pdf"), opts: func(o *PrepareOptions) { o.ClaimedRole = strings.Repeat("я", 901) }, code: CodeRequestInvalid},
		"bad lang":  {doc: readInput(t, "quartz-pdf13.pdf"), opts: func(o *PrepareOptions) { o.Lang = "de" }, code: CodeRequestInvalid},
	}
	for name, c := range cases {
		oo := o
		if c.opts != nil {
			c.opts(&oo)
		}
		if _, err := Prepare(c.doc, oo); ErrorCode(err) != c.code {
			t.Errorf("%s: хүлээсэн %s, авсан %v", name, c.code, err)
		}
	}
}

// certified — digitorus/pdfsign-ээр DocMDP P=1 certification гарын үсэг.
func certified(t *testing.T, p *goldenPKI, doc []byte) []byte {
	t.Helper()
	rdr, err := pdf.NewReader(bytes.NewReader(doc), int64(len(doc)))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err = sign.Sign(bytes.NewReader(doc), &out, rdr, int64(len(doc)), sign.SignData{
		Signer: p.citizen.key, DigestAlgorithm: crypto.SHA256, Certificate: p.citizen.cert,
		CertificateChains: [][]*x509.Certificate{{p.citizen.cert, p.ca04.cert}},
		Signature: sign.SignDataSignature{CertType: sign.CertificationSignature, DocMDPPerm: sign.DoNotAllowAnyChangesPerms,
			Info: sign.SignDataSignatureInfo{Name: "cert", Date: time.Now()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// TestVerifyPageDeterministic — ижил оролт → ижил prepared байт (хуудас + QR + font subset), docID-г хуудаснаас уншина.
func TestVerifyPageDeterministic(t *testing.T) {
	p := loadOrCreatePKI(t)
	o := testOpts(p, p.citizen.cert)
	o.DocID = "6f0c2b9e-3a1d-4c55-9b7e-0a1b2c3d4e5f"
	a, err := Prepare(readInput(t, "quartz-pdf13.pdf"), o)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Prepare(readInput(t, "quartz-pdf13.pdf"), o)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.State, b.State) || !bytes.Equal(a.DTBS, b.DTBS) {
		t.Fatal("prepare тодорхойлогдоогүй")
	}
	st, _ := decodeState(a.State)
	if got := docIDFromPage(st.PDF); got != o.DocID {
		t.Fatalf("docIDFromPage = %q", got)
	}
	// Хуудасгүй: docID шинээр үүснэ, хуудас нэмэгдэхгүй.
	o.VerifyPage, o.DocID = false, ""
	c, err := Prepare(readInput(t, "quartz-pdf13.pdf"), o)
	if err != nil || !uuidRe.MatchString(c.DocID) {
		t.Fatalf("%v %q", err, c.DocID)
	}
	if st, _ := decodeState(c.State); st.HasPage || docIDFromPage(st.PDF) != "" {
		t.Fatal("хуудас нэмэгдэх ёсгүй")
	}
}

// rawPDF — объектуудаас (1…n) classic xref-тэй PDF.
func rawPDF(objs ...string) []byte {
	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n")
	offs := make([]int, len(objs))
	for i, o := range objs {
		offs[i] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", i+1, o)
	}
	x := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n0000000000 65535 f\r\n", len(objs)+1)
	for _, o := range offs {
		fmt.Fprintf(&b, "%010d 00000 n\r\n", o)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objs)+1, x)
	return b.Bytes()
}

// TestDocMDPLocked — Catalog /Perms /DocMDP эсвэл Sig-ийн /Reference /TransformParams /P 1 → PDF_LOCKED.
func TestDocMDPLocked(t *testing.T) {
	sig := "<< /Type /Sig /Reference [<< /Type /SigRef /TransformMethod /DocMDP /TransformParams << /P %d /V /1.2 >> >>] >>"
	doc := func(perm int) []byte {
		return rawPDF("<< /Type /Catalog /Pages 2 0 R /Perms << /DocMDP 4 0 R >> >>", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
			"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 10 10] >>", fmt.Sprintf(sig, perm))
	}
	for perm, want := range map[int]bool{1: true, 2: false} {
		if _, locked, _, err := scanSignatures(doc(perm)); err != nil || locked != want {
			t.Fatalf("P=%d: locked=%v %v", perm, locked, err)
		}
	}
	// digitorus/pdfsign /Perms бичдэггүй — Sig-ийн /Reference-ээр (PRECHECKS.md).
	p := loadOrCreatePKI(t)
	if _, err := Prepare(certified(t, p, readInput(t, "quartz-pdf13.pdf")), testOpts(p, p.citizen.cert)); ErrorCode(err) != CodePDFLocked {
		t.Fatal(err)
	}
}

// TestSigningTimeZone — ижил агшин (UTC / +08 / өөр бүс) → ижил DTBS ба state; /M нь +08'00'.
func TestSigningTimeZone(t *testing.T) {
	p := loadOrCreatePKI(t)
	var first *Prepared
	for _, tm := range []time.Time{goldenTime, goldenTime.UTC(), goldenTime.In(time.FixedZone("-05", -5*3600))} {
		o := testOpts(p, p.citizen.cert)
		o.SigningTime, o.DocID = tm, "6f0c2b9e-3a1d-4c55-9b7e-0a1b2c3d4e5f"
		got, err := Prepare(readInput(t, "quartz-pdf13.pdf"), o)
		if err != nil {
			t.Fatal(err)
		}
		if first == nil {
			first = got
			st, _ := decodeState(got.State)
			if !bytes.Contains(st.PDF, []byte("/M (D:20261014120000+08'00')")) {
				t.Fatal("/M +08 биш")
			}
			continue
		}
		if !bytes.Equal(first.DTBS, got.DTBS) || !bytes.Equal(first.State, got.State) {
			t.Fatalf("%s: DTBS/state зөрөв", tm.Location())
		}
	}
}

// TestCRLMirror — үндэсний CRL нь eID-ийн https толин руу; бусад URL хэвээр.
func TestCRLMirror(t *testing.T) {
	f := newFetcher(nil)
	for in, want := range map[string]string{
		"http://esign.gov.mn/MNICA-2022.crl": "https://crl.eidmongolia.mn/MNICA-2022.crl",
		"http://esign.gov.mn/MNRCA-2021.crl": "https://crl.eidmongolia.mn/MNRCA-2021.crl",
		"http://crl.eidmongolia.mn/crl/ca":   "http://crl.eidmongolia.mn/crl/ca",
		"http://esign.gov.mn/OTHER.crl":      "http://esign.gov.mn/OTHER.crl",
	} {
		if got, err := f.target(in); err != nil || got != want {
			t.Fatalf("%s → %s %v", in, got, err)
		}
	}
	if _, err := f.target("ldap://x"); err == nil {
		t.Fatal("ldap")
	}
}

// TestRegistrationAndPSS — RSASSA-PSS гарын үсэг → REQUEST_INVALID (PKCS#1 v1.5 шаардлагатай); Completed →
// eid.PDFSignatureRegistration (CA dto-тэй ижил талбарууд).
func TestRegistrationAndPSS(t *testing.T) {
	p := loadOrCreatePKI(t)
	o := testOpts(p, p.citizen.cert)
	o.FileName = "Гэрээ.pdf"
	prep, err := Prepare(readInput(t, "quartz-pdf13.pdf"), o)
	if err != nil {
		t.Fatal(err)
	}
	pss, err := rsa.SignPSS(rand.Reader, p.citizen.key, crypto.SHA256, prep.DTBS, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Complete(context.Background(), prep.State, pss, completeOpts(p)); ErrorCode(err) != CodeRequestInvalid ||
		!strings.Contains(err.Error(), "PKCS#1 v1.5") {
		t.Fatalf("PSS: %v", err)
	}
	sig, _ := rsa.SignPKCS1v15(nil, p.citizen.key, crypto.SHA256, prep.DTBS)
	done, err := Complete(context.Background(), prep.State, sig, completeOpts(p))
	if err != nil {
		t.Fatal(err)
	}
	reg, err := Registration(done, RegistrationOptions{Medium: eid.PDFMediumPhone, SessionID: "s1"})
	if err != nil {
		t.Fatal(err)
	}
	if reg.DocID != done.DocID || reg.RevIndex != 1 || reg.PageSHA256 != done.PageSHA256 || reg.PageSHA256 == "" ||
		reg.FileName != "Гэрээ.pdf" || reg.SignerEtsi != "PNOMN-00000000000" || !bytes.Equal(reg.CMS, done.CMS) ||
		reg.SigRevSHA256 != done.SigRevSHA256 || reg.OutSHA256 != done.OutSHA256 || reg.InSHA256 != done.InSHA256 || reg.PriorCMSSHA256 != nil {
		t.Fatalf("%+v", reg)
	}
	// 2 дахь гарын үсэг: prior CMS, page үгүй.
	o2 := testOpts(p, p.citizen.cert)
	o2.FileName = "Гэрээ.pdf"
	prep2, err := Prepare(done.PDF, o2)
	if err != nil {
		t.Fatal(err)
	}
	sig2, _ := rsa.SignPKCS1v15(nil, p.citizen.key, crypto.SHA256, prep2.DTBS)
	done2, err := Complete(context.Background(), prep2.State, sig2, completeOpts(p))
	if err != nil {
		t.Fatal(err)
	}
	reg2, err := Registration(done2, RegistrationOptions{Medium: eid.PDFMediumToken})
	if err != nil || reg2.RevIndex != 2 || reg2.PageSHA256 != "" || reg2.DocID != done.DocID ||
		len(reg2.PriorCMSSHA256) != 1 || reg2.PriorCMSSHA256[0] != sha256Hex(done.CMS) || len(done2.PriorRevisionSHA256) != 1 {
		t.Fatalf("%v %+v", err, reg2)
	}
	// Өмнөх гарын үсгийн revision = тэр гарын үсгийн SigRevSHA256 (CA горим A-ийн sig_rev_sha256-тай ижил тодорхойлолт:
	// doc[0 : ByteRange[2]+ByteRange[3]]); Registration хосыг PriorSignatures-д бөглөнө (CA руу илгээхгүй).
	if done2.PriorRevisionSHA256[0] != done.SigRevSHA256 || len(reg2.PriorSignatures) != 1 ||
		reg2.PriorSignatures[0] != (eid.PDFPriorSignature{CMSSHA256: sha256Hex(done.CMS), RevisionSHA256: done.SigRevSHA256}) {
		t.Fatalf("%+v %+v", done2.PriorRevisionSHA256, reg2.PriorSignatures)
	}
	// Хуудасгүй эхний гарын үсэг CA-д бүртгэгдэхгүй.
	if _, err := Registration(&Completed{RevIndex: 1, FileName: "a.pdf"}, RegistrationOptions{}); ErrorCode(err) != CodeRequestInvalid {
		t.Fatal(err)
	}
}

// TestAppearanceRejects — APPEARANCE_SPEC.md §1, §3: байршил/хэмжээ буруу, багтахгүй бол REQUEST_INVALID.
func TestAppearanceRejects(t *testing.T) {
	p := loadOrCreatePKI(t)
	doc := readInput(t, "quartz-pdf13.pdf") // 612 × 792, 1 хуудас
	vis := func(a Appearance) func(*PrepareOptions) {
		return func(o *PrepareOptions) { o.Appearance = &a }
	}
	ok := Appearance{X: 36, Y: 36, Width: 220, Height: 64}
	cases := map[string]func(*PrepareOptions){
		"хуудас алга":          vis(Appearance{Page: 2, X: 36, Y: 36, Width: 220, Height: 64}),
		"сөрөг page":           vis(Appearance{Page: -1, X: 36, Y: 36, Width: 220, Height: 64}),
		"хуудаснаас гарна":     vis(Appearance{X: 500, Y: 36, Width: 220, Height: 64}),
		"дээш гарна":           vis(Appearance{X: 36, Y: 760, Width: 220, Height: 64}),
		"нам (QR < 1 pt)":      vis(Appearance{X: 36, Y: 36, Width: 220, Height: 44}),
		"нарийн (бичвэр)":      vis(Appearance{X: 36, Y: 36, Width: 90, Height: 64}),
		"тэг өргөн":            vis(Appearance{X: 36, Y: 36, Width: 0, Height: 64}),
		"NaN":                  vis(Appearance{X: math.NaN(), Y: 36, Width: 220, Height: 64}),
		"хэл":                  vis(Appearance{X: 36, Y: 36, Width: 220, Height: 64, Lang: "de"}),
		"/Name бичигдэхгүй":    func(o *PrepareOptions) { vis(ok)(o); o.SignerName = "a stream b" },
		"role удирдах тэмдэгт": func(o *PrepareOptions) { vis(ok)(o); o.ClaimedRole = "a‎b" },
	}
	for name, f := range cases {
		o := testOpts(p, p.citizen.cert)
		f(&o)
		if _, err := Prepare(doc, o); ErrorCode(err) != CodeRequestInvalid {
			t.Errorf("%s: хүлээсэн REQUEST_INVALID, авсан %v", name, err)
		}
	}
	// Хамгийн бага (45 pt өндөр) хүлээн авна; гарын үсэгтэй, хуудасгүй, docId-гүй баримтад → REQUEST_INVALID.
	o := testOpts(p, p.citizen.cert)
	vis(Appearance{X: 36, Y: 36, Width: 220, Height: 45})(&o)
	if _, err := Prepare(doc, o); err != nil {
		t.Fatalf("45 pt: %v", err)
	}
	signed, err := os.ReadFile(filepath.Join(goldenDir, "output", "quartz-pdf13-nopage.pdf"))
	if err != nil {
		t.Fatal(err)
	}
	o = testOpts(p, p.citizen.cert)
	o.DocID, o.VerifyPage = "", false
	vis(ok)(&o)
	if _, err := Prepare(signed, o); ErrorCode(err) != CodeRequestInvalid {
		t.Fatalf("docId-гүй: %v", err)
	}
}
