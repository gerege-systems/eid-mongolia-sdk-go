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
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/pdf"
	"golang.org/x/crypto/ocsp"
)

// ValidatePDF-ийн conformance багц (pades/testdata/validate/, README.md) — TS SDK-ийн validatePdf ба CA-ийн
// /v3/validate/pdf ижил багцаар ижил тайлан гаргана. Шинэчлэх: `go test ./pades -run ValidateGolden -update`.

var validateDir = filepath.Join("testdata", "validate")

type vCase struct {
	Name  string `json:"name"`
	Input string `json:"input"` // testdata-аас харьцангуй: golden/output/<x>.pdf, golden/input/<x>.pdf, validate/input/<x>.pdf
	// Offline — ValidateOptions.Offline. Онлайн тохиолдолд OCSP/CRL-ийн хариу = HTTP (түлхүүр → validate/http/<файл>);
	// жагсаалтад байхгүй хүсэлт → HTTP 404.
	Offline bool              `json:"offline"`
	HTTP    map[string]string `json:"http,omitempty"`
	// NationalRoots — Roots хоосон (SDK-д шигтгэсэн бодит Mongolian National Root CA): тестийн гинж итгэмжлэгдэхгүй.
	NationalRoots bool `json:"nationalRoots,omitempty"`
	// Time — шалгах цаг (тэг бол manifest.time).
	Time   time.Time       `json:"time,omitzero"`
	Expect json.RawMessage `json:"expect"` // Report эсвэл {"error": "<код>"}
}

type vManifest struct {
	Comment string    `json:"comment"`
	Time    time.Time `json:"time"`
	Roots   []string  `json:"roots"`   // PEM (testdata-аас харьцангуй)
	Issuers []string  `json:"issuers"` // eID олгогч гэж үзэх тестийн CA
	Cases   []vCase   `json:"cases"`
}

// vHTTP — онлайн тохиолдлын хариу (-update үед үүсгэнэ).
type vHTTP struct {
	method, url string
	body        []byte // хүсэлтийн бие (түлхүүрт)
	resp        []byte
}

func vCases() []vCase {
	return []vCase{
		{Name: "valid-lt", Input: "golden/output/quartz-pdf13.pdf", Offline: true},
		{Name: "valid-lt-en", Input: "golden/output/quartz-pdf13-en.pdf", Offline: true},
		{Name: "valid-nopage", Input: "golden/output/quartz-pdf13-nopage.pdf", Offline: true},
		{Name: "objstm", Input: "golden/output/quartz-objstm.pdf", Offline: true},
		{Name: "linearized", Input: "golden/output/quartz-linearized.pdf", Offline: true},
		{Name: "desktop-objstm-nopage", Input: "golden/output/desktop-objstm-nopage.pdf", Offline: true},
		{Name: "multi-revision", Input: "golden/output/quartz-pdf13-second.pdf", Offline: true},
		{Name: "multi-revision-nopage", Input: "golden/output/quartz-pdf13-nopage-second.pdf", Offline: true},
		{Name: "visible", Input: "golden/output/quartz-pdf13-visible.pdf", Offline: true},
		{Name: "visible-en", Input: "golden/output/quartz-pdf13-visible-en.pdf", Offline: true},
		{Name: "visible-second", Input: "golden/output/quartz-pdf13-visible-second.pdf", Offline: true},
		{Name: "visible-twice", Input: "golden/output/quartz-pdf13-visible-twice.pdf", Offline: true},
		{Name: "visible-rotated90", Input: "golden/output/quartz-rotated90-visible.pdf", Offline: true},
		{Name: "tampered", Input: "validate/input/tampered.pdf", Offline: true},
		{Name: "modified-after-signing", Input: "validate/input/modified-after-signing.pdf", Offline: true},
		{Name: "untrusted-root", Input: "golden/output/quartz-pdf13.pdf", Offline: true, NationalRoots: true},
		{Name: "qualified-phone", Input: "validate/input/qualified-phone.pdf", Offline: true},
		{Name: "online-good", Input: "golden/output/quartz-pdf13.pdf"},
		{Name: "online-revoked", Input: "golden/output/quartz-pdf13.pdf"},
		{Name: "online-revoked-after-signing", Input: "golden/output/quartz-pdf13.pdf"},
		{Name: "online-crl-revoked", Input: "golden/output/quartz-pdf13.pdf"},
		{Name: "online-unavailable", Input: "golden/output/quartz-pdf13.pdf"},
		{Name: "legacy-stamp", Input: "golden/input/stamped.pdf", Offline: true, NationalRoots: true},
		{Name: "no-signature", Input: "golden/input/quartz-pdf13.pdf", Offline: true},
		{Name: "not-pdf", Input: "validate/input/not-pdf.pdf", Offline: true},
	}
}

// vResponses — онлайн тохиолдлын OCSP/CRL хариу (тестийн 04-ийн түлхүүрээр). Шалгах цаг = goldenNow.
func vResponses(t *testing.T, p *goldenPKI) map[string][]vHTTP {
	t.Helper()
	cit := p.citizen.cert
	req, err := ocsp.CreateRequest(cit, p.ca04.cert, nil)
	if err != nil {
		t.Fatal(err)
	}
	th := goldenTime.Add(5 * time.Second).UTC()
	resp := func(status int, revokedAt time.Time) []byte {
		out, err := ocsp.CreateResponse(p.ca04.cert, p.ca04.cert, ocsp.Response{Status: status, SerialNumber: cit.SerialNumber,
			ThisUpdate: th, NextUpdate: th.Add(24 * time.Hour), RevokedAt: revokedAt, RevocationReason: ocsp.KeyCompromise,
			IssuerHash: crypto.SHA1}, p.ca04.key)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	crl := func(revoked ...x509.RevocationListEntry) []byte {
		out, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(7),
			ThisUpdate: goldenTime.Add(-time.Hour), NextUpdate: goldenTime.Add(7 * 24 * time.Hour),
			RevokedCertificateEntries: revoked}, p.ca04.cert, p.ca04.key)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	ocspURL, crlURL := cit.OCSPServer[0], cit.CRLDistributionPoints[0]
	return map[string][]vHTTP{
		"online-good":    {{http.MethodPost, ocspURL, req, resp(ocsp.Good, time.Time{})}},
		"online-revoked": {{http.MethodPost, ocspURL, req, resp(ocsp.Revoked, goldenTime.Add(-time.Hour).UTC())}},
		// Цагийн тэмдгээс (T+1с) хойш цуцлагдсан: гарын үсэг хүчинтэй хэвээр.
		"online-revoked-after-signing": {{http.MethodPost, ocspURL, req, resp(ocsp.Revoked, goldenTime.Add(3*time.Second).UTC())}},
		// OCSP хариугүй (404) → CDP CRL.
		"online-crl-revoked": {{http.MethodGet, crlURL, nil, crl(x509.RevocationListEntry{SerialNumber: cit.SerialNumber,
			RevocationTime: goldenTime.Add(-2 * time.Hour).UTC()})}},
	}
}

func vHTTPKey(method, url string, body []byte) string {
	return method + " " + url + " " + sha256hex(body)[:16]
}

// vTransport — case.HTTP-ийн тогтмол хариу; байхгүй → 404.
type vTransport struct{ files map[string][]byte }

func (vt vTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(r.Body)
	}
	b, ok := vt.files[vHTTPKey(r.Method, r.URL.String(), body)]
	status := http.StatusOK
	if !ok {
		status = http.StatusNotFound
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(b)), Header: http.Header{}, Request: r}, nil
}

// vRun — нэг тохиолдол: тайлан эсвэл {"error": code}-ийн JSON.
func vRun(t *testing.T, m *vManifest, c vCase) []byte {
	t.Helper()
	doc, err := os.ReadFile(filepath.Join("testdata", c.Input)) // #nosec G304 -- тест
	if err != nil {
		t.Fatal(err)
	}
	o := ValidateOptions{Offline: c.Offline, Time: m.Time}
	if !c.Time.IsZero() {
		o.Time = c.Time
	}
	if !c.NationalRoots {
		o.Roots = vPEMs(t, m.Roots)
	}
	o.Issuers = vPEMs(t, m.Issuers)
	files := map[string][]byte{}
	for k, f := range c.HTTP {
		b, err := os.ReadFile(filepath.Join(validateDir, f)) // #nosec G304 -- тест
		if err != nil {
			t.Fatal(err)
		}
		files[k] = b
	}
	o.HTTPClient = &http.Client{Transport: vTransport{files}}
	rep, err := ValidatePDF(context.Background(), doc, o)
	var out []byte
	if err != nil {
		code := ErrorCode(err)
		if code == "" {
			t.Fatalf("%s: %v", c.Name, err)
		}
		out, _ = json.Marshal(map[string]string{"error": code})
	} else {
		out, _ = json.Marshal(rep)
	}
	return out
}

func vPEMs(t *testing.T, files []string) [][]byte {
	t.Helper()
	var out [][]byte
	for _, f := range files {
		raw, err := os.ReadFile(filepath.Join("testdata", f)) // #nosec G304 -- тест
		if err != nil {
			t.Fatal(err)
		}
		b, _ := pem.Decode(raw)
		if b == nil {
			t.Fatalf("%s: PEM алга", f)
		}
		out = append(out, b.Bytes)
	}
	return out
}

func TestValidateGolden(t *testing.T) {
	mpath := filepath.Join(validateDir, "manifest.json")
	if *update {
		vUpdate(t, mpath)
	}
	raw, err := os.ReadFile(mpath) // #nosec G304 -- тест
	if err != nil {
		t.Fatal(err)
	}
	var m vManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Cases) != len(vCases()) {
		t.Fatalf("manifest %d тохиолдол, код %d (-update)", len(m.Cases), len(vCases()))
	}
	for _, c := range m.Cases {
		got := vRun(t, &m, c)
		var want bytes.Buffer
		if err := json.Compact(&want, c.Expect); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want.Bytes()) {
			t.Errorf("%s:\nавсан    %s\nхүлээсэн %s", c.Name, got, want.Bytes())
		}
	}
}

// vUpdate — оролт (tampered, modified-after-signing, qualified-phone, not-pdf), онлайн хариу, хүлээгдэх тайланг бичнэ.
func vUpdate(t *testing.T, mpath string) {
	t.Helper()
	p := loadOrCreatePKI(t)
	in := filepath.Join(validateDir, "input")
	if err := os.MkdirAll(in, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(validateDir, "http"), 0o755); err != nil {
		t.Fatal(err)
	}
	base, err := os.ReadFile(filepath.Join(goldenDir, "output", "quartz-pdf13.pdf"))
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, b []byte) {
		if err := os.WriteFile(filepath.Join(in, name), b, 0o644); err != nil { // #nosec G306 -- тест
			t.Fatal(err)
		}
	}
	// tampered: гарын үсгийн мужийн доторх толгойн binary тайлбарын нэг байт.
	tampered := bytes.Clone(base)
	tampered[10] ^= 0x01
	write("tampered.pdf", tampered)
	write("modified-after-signing.pdf", vAppendInfo(t, base))
	write("not-pdf.pdf", []byte("not a pdf\n"))
	write("qualified-phone.pdf", vSignQualified(t, p))

	m := vManifest{
		Comment: "ValidatePDF conformance — ТЕСТИЙН PKI (golden/pki). Go pades.ValidatePDF, TS validatePdf, CA validate.ValidatePDF " +
			"ижил тайлан (JSON) гаргана. roots/issuers = PEM, time = шалгах цаг; online тохиолдлын HTTP хариу = http/ (key: METHOD URL " +
			"sha256(body)[:8] hex), жагсаалтад байхгүй хүсэлт → 404.",
		Time:    goldenNow.UTC(),
		Roots:   []string{"golden/pki/root.pem"},
		Issuers: []string{"golden/pki/04.pem"},
	}
	resps := vResponses(t, p)
	for _, c := range vCases() {
		for i, h := range resps[c.Name] {
			if c.HTTP == nil {
				c.HTTP = map[string]string{}
			}
			name := fmt.Sprintf("http/%s-%d.der", c.Name, i)
			if err := os.WriteFile(filepath.Join(validateDir, name), h.resp, 0o644); err != nil { // #nosec G306 -- тест
				t.Fatal(err)
			}
			c.HTTP[vHTTPKey(h.method, h.url, h.body)] = name
		}
		c.Expect = vRun(t, &m, c)
		m.Cases = append(m.Cases, c)
	}
	out, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(mpath, append(out, '\n'), 0o644); err != nil { // #nosec G306 -- тест
		t.Fatal(err)
	}
}

// vAppendInfo — гарын үсгийн дараа /Info-г өөрчилсөн incremental revision (гарын үсэггүй, DSS-гүй) нэмнэ.
func vAppendInfo(t *testing.T, doc []byte) []byte {
	t.Helper()
	r, err := pdf.NewReader(bytes.NewReader(doc), int64(len(doc)))
	if err != nil {
		t.Fatal(err)
	}
	tr := r.Trailer()
	info, root := tr.Key("Info").GetPtr(), tr.Key("Root").GetPtr()
	prev := bytes.LastIndex(doc, []byte("startxref"))
	var prevOff int
	if _, err := fmt.Sscan(string(doc[prev+len("startxref"):]), &prevOff); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	b.Write(doc)
	objOff := b.Len()
	fmt.Fprintf(&b, "%d 0 obj\n<< /Producer (modified after signing) >>\nendobj\n", info.GetID())
	xref := b.Len()
	fmt.Fprintf(&b, "xref\n%d 1\n%010d 00000 n \ntrailer\n<< /Size %d /Root %d 0 R /Info %d 0 R /Prev %d >>\nstartxref\n%d\n%%%%EOF\n",
		info.GetID(), objOff, tr.Key("Size").Int64(), root.GetID(), info.GetID(), prevOff, xref)
	return b.Bytes()
}

// vQualifiedCert — «утасны» SIGN гэрчилгээ: qcStatements QcCompliance (eid.CertificateLevelOf → QUALIFIED). Тестийн 04-өөр;
// validate/pki/-д хадгална (дахин -update-д хэвээр).
func vQualifiedCert(t *testing.T, p *goldenPKI) *gCert {
	t.Helper()
	dir := filepath.Join(validateDir, "pki")
	certPath, keyPath := filepath.Join(dir, "citizen-qc.pem"), filepath.Join(dir, "citizen-qc.key.pem")
	if raw, err := os.ReadFile(certPath); err == nil { // #nosec G304 -- тест
		kraw, err := os.ReadFile(keyPath) // #nosec G304 -- тест
		if err != nil {
			t.Fatal(err)
		}
		cb, _ := pem.Decode(raw)
		kb, _ := pem.Decode(kraw)
		c, err1 := x509.ParseCertificate(cb.Bytes)
		k, err2 := x509.ParsePKCS1PrivateKey(kb.Bytes)
		if err1 != nil || err2 != nil {
			t.Fatal(err1, err2)
		}
		return &gCert{cert: c, key: k}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	qc, _ := asn1.Marshal([]any{[]any{asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 1}}})
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2001), NotBefore: p.citizen.cert.NotBefore, NotAfter: p.citizen.cert.NotAfter,
		Subject: pkix.Name{CommonName: "TESTOV QUALIFIED", SerialNumber: "PNOMN-00000000001", Country: []string{"MN"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier{2, 5, 4, 42}, Value: "QUALIFIED"},
				{Type: asn1.ObjectIdentifier{2, 5, 4, 4}, Value: "TESTOV"},
			}},
		KeyUsage:   x509.KeyUsageContentCommitment | x509.KeyUsageDigitalSignature,
		OCSPServer: []string{"http://ocsp.pki.test/04"}, CRLDistributionPoints: []string{"http://crl.pki.test/04.crl"},
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 3}, Value: qc}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca04.cert, &key.PublicKey, p.ca04.key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	_ = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)                                 // #nosec G306 -- тест
	_ = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o644) // #nosec G306 -- ТЕСТИЙН түлхүүр
	return &gCert{cert: c, key: key}
}

// vSignQualified — quartz-pdf13.pdf-д qcStatements-тэй гэрчилгээгээр PAdES-BASELINE-LT (golden-ийн TSA/CRL, OCSP = 04).
func vSignQualified(t *testing.T, p *goldenPKI) []byte {
	t.Helper()
	qc := vQualifiedCert(t, p)
	input, err := os.ReadFile(filepath.Join(goldenDir, "input", "quartz-pdf13.pdf"))
	if err != nil {
		t.Fatal(err)
	}
	prep, err := Prepare(input, PrepareOptions{SignerCert: qc.cert.Raw, Chain: [][]byte{p.ca04.cert.Raw, p.ca03.cert.Raw, p.ca02.cert.Raw},
		SigningTime: goldenTime, DocID: "b1c2d3e4-f5a6-4b7c-8d9e-0f1a2b3c4d5e"})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := rsa.SignPKCS1v15(nil, qc.key, crypto.SHA256, prep.DTBS)
	if err != nil {
		t.Fatal(err)
	}
	live := p.liveResponder(t)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body []byte
		if r.Body != nil {
			body, _ = io.ReadAll(r.Body)
		}
		if r.Host == "ocsp.pki.test" && strings.HasSuffix(r.URL.Path, "/04") {
			if req, err := ocsp.ParseRequest(body); err == nil && req.SerialNumber.Cmp(qc.cert.SerialNumber) == 0 {
				th := goldenTime.Add(3 * time.Second).UTC()
				out, err := ocsp.CreateResponse(p.ca04.cert, p.ca04.cert, ocsp.Response{Status: ocsp.Good, SerialNumber: req.SerialNumber,
					ThisUpdate: th, NextUpdate: th.Add(7 * 24 * time.Hour), IssuerHash: crypto.SHA1}, p.ca04.key)
				if err != nil {
					http.Error(w, err.Error(), 500)
					return
				}
				_, _ = w.Write(out)
				return
			}
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		live.ServeHTTP(w, r)
	})
	nonceReader = &seededReader{seed: []byte("validate-nonce:qualified-phone")}
	defer func() { nonceReader = rand.Reader }()
	res, err := Complete(context.Background(), prep.State, sig, CompleteOptions{
		HTTPClient: &http.Client{Transport: handlerTransport{h}}, TSAURL: "http://tsa.pki.test/",
		Now: func() time.Time { return goldenNow }, Roots: [][]byte{p.root.cert.Raw}})
	if err != nil {
		t.Fatal(err)
	}
	return res.PDF
}

type handlerTransport struct{ h http.Handler }

func (ht handlerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	ht.h.ServeHTTP(rec, r)
	return rec.Result(), nil
}
