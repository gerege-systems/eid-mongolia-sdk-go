package pades

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"fmt"
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
		Roots: [][]byte{p.root.cert.Raw}, SigningTime: goldenTime, VerifyPage: true, FileName: "test.pdf"}
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
			t.Fatalf("raw=%v: meta %+v", raw, res.Meta(false))
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

// TestBindingJSON — options JSON (lowerCamelCase), үл мэдэгдэх түлхүүр, алдааны JSON.
func TestBindingJSON(t *testing.T) {
	o, err := ParsePrepareOptions(`{"signerCert":"AQI=","verifyPage":true,"fileName":"a.pdf","signingTime":"2026-10-14T12:00:00+08:00","docId":"x"}`)
	if err != nil || !o.VerifyPage || o.FileName != "a.pdf" || len(o.SignerCert) != 2 || !o.SigningTime.Equal(goldenTime) {
		t.Fatalf("%v %+v", err, o)
	}
	if _, err := ParseCompleteOptions(`{"tsaUrl":"x","bogus":1}`); ErrorCode(err) != CodeRequestInvalid {
		t.Fatal(err)
	}
	var e struct{ Code, Message string }
	if err := json.Unmarshal([]byte(ErrorJSON(newErr(CodePDFLocked, "m", nil))), &e); err != nil || e.Code != CodePDFLocked {
		t.Fatal(e)
	}
}

// TestFetcherJS — js/WASM: зөвхөн allowlist host-ийг https болгоно.
func TestFetcherJS(t *testing.T) {
	f := &fetcher{js: true}
	if u, err := f.target("http://ocsp.eidmongolia.mn/ocsp"); err != nil || u != "https://ocsp.eidmongolia.mn/ocsp" {
		t.Fatal(u, err)
	}
	if _, err := f.target("http://esign.gov.mn/MNRCA-2021.crl"); err == nil {
		t.Fatal("allowlist-гүй host fetch хийгдэх ёсгүй")
	}
	if _, err := f.target("ldap://x"); err == nil {
		t.Fatal("ldap")
	}
	f.js = false
	if u, _ := f.target("http://esign.gov.mn/MNRCA-2021.crl"); u != "http://esign.gov.mn/MNRCA-2021.crl" {
		t.Fatal(u)
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

// TestDocMDPLocked — Catalog /Perms /DocMDP-ийн /Reference /TransformParams /P 1 (CA docMDPLocked-тэй ижил). Тэмдэглэл:
// digitorus/pdfsign-ийн certification гарын үсэг /Perms бичдэггүй тул (ISO 32000-1 §12.8.4-д нийцэхгүй) түгжээгүй гэж үзнэ.
func TestDocMDPLocked(t *testing.T) {
	sig := "<< /Type /Sig /Reference [<< /Type /SigRef /TransformMethod /DocMDP /TransformParams << /P %d /V /1.2 >> >>] >>"
	doc := func(perm int) []byte {
		return rawPDF("<< /Type /Catalog /Pages 2 0 R /Perms << /DocMDP 4 0 R >> >>", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
			"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 10 10] >>", fmt.Sprintf(sig, perm))
	}
	if !docMDPLocked(doc(1)) || docMDPLocked(doc(2)) {
		t.Fatal("docMDPLocked")
	}
	if docMDPLocked(certified(t, loadOrCreatePKI(t), readInput(t, "quartz-pdf13.pdf"))) {
		t.Fatal("pdfsign /Perms бичдэггүй — CA-ийн дүрмээр түгжээгүй")
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
