package pades

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/timestamp"
	"golang.org/x/crypto/ocsp"

	"github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/eidcrypto"
)

// Golden vector-ууд (docs/PADES_CLIENT_SIDE.md §12) — pades/testdata/golden/:
//
//	manifest.json — тохиолдол бүрийн оролт, options, хүлээгдэх digest/DTBS/prepared/out sha256 (эсвэл алдааны код)
//	pki/*.pem     — ЗӨВХӨН тестийн RSA гинж (root → 02 → 03 → 04 → иргэн/TSA); AIA/CDP нь *.pki.test (сүлжээгүй)
//	http/*.der    — тогтмол TSA/OCSP/CRL хариу (fixture); Complete-ийг сүлжээгүй, тодорхойлогдсон байдлаар давтана
//
// Шинэчлэх: `go test ./pades -run Golden -update` (PKI алга бол шинээр үүсгэнэ; хариуг дахин бичнэ).
var update = flag.Bool("update", false, "pades/testdata/golden-ийг дахин бичих")

var (
	goldenDir  = filepath.Join("testdata", "golden")
	goldenTime = time.Date(2026, 10, 14, 12, 0, 0, 0, time.FixedZone("+08", 8*3600))
	goldenNow  = goldenTime.Add(30 * time.Second)
)

type goldenCase struct {
	Name   string         `json:"name"`
	Input  string         `json:"input"` // input/<file> эсвэл "case:<name>" (өмнөх тохиолдлын гаралт)
	Prep   PrepareOptions `json:"prepare"`
	Expect goldenExpect   `json:"expect"`
}

type goldenExpect struct {
	Error          string   `json:"error,omitempty"`
	InputSHA256    string   `json:"inputSha256,omitempty"`
	DocID          string   `json:"docId,omitempty"`
	Digest         string   `json:"digest,omitempty"`
	DTBS           string   `json:"dtbs,omitempty"`
	PreparedSHA256 string   `json:"preparedSha256,omitempty"`
	ByteRange      [4]int64 `json:"byteRange,omitempty"`
	OutSHA256      string   `json:"outSha256,omitempty"`
	RevIndex       int      `json:"revIndex,omitempty"`
	HasPage        bool     `json:"hasPage,omitempty"`
	PageSHA256     string   `json:"pageSha256,omitempty"`
	SigRevSHA256   string   `json:"sigRevSha256,omitempty"`
	CMSSHA256      string   `json:"cmsSha256,omitempty"`
	PriorCMSSHA256 []string `json:"priorCmsSha256,omitempty"`
}

type goldenManifest struct {
	Comment     string            `json:"comment"`
	Profile     string            `json:"profile"`
	SigningTime time.Time         `json:"signingTime"`
	Now         time.Time         `json:"now"`
	NonceSeed   string            `json:"nonceSeed"`
	HTTP        map[string]string `json:"http"` // "METHOD url sha256(body)[:16]" → http/<file>
	Cases       []goldenCase      `json:"cases"`
}

// goldenCases — тохиолдлын тодорхойлолт (хүлээгдэх утгыг -update бичнэ).
func goldenCases() []goldenCase {
	page := func(docID, file string) PrepareOptions {
		return PrepareOptions{VerifyPage: true, DocID: docID, FileName: file, Lang: "mn"}
	}
	return []goldenCase{
		{Name: "quartz-pdf13", Input: "input/quartz-pdf13.pdf", Prep: page("6f0c2b9e-3a1d-4c55-9b7e-0a1b2c3d4e5f", "Гэрээ №1 (Quartz).pdf")},
		{Name: "quartz-objstm", Input: "input/quartz-objstm.pdf", Prep: page("1b2c3d4e-5f60-4718-8a9b-0c1d2e3f4a5b", "objstm.pdf")},
		{Name: "quartz-linearized", Input: "input/quartz-linearized.pdf", Prep: page("2c3d4e5f-6071-4829-9bac-1d2e3f4a5b6c", "linearized.pdf")},
		{Name: "desktop-objstm-nopage", Input: "input/desktop-objstm.pdf", Prep: PrepareOptions{DocID: "3d4e5f60-7182-493a-acbd-2e3f4a5b6c7d"}},
		{Name: "quartz-pdf13-second", Input: "case:quartz-pdf13", Prep: PrepareOptions{VerifyPage: true, FileName: "ignored.pdf",
			Reason: "Тест ХХК-ийг төлөөлж", ClaimedRole: "Захирал, Тест ХХК (NTRMN-1234567)"}},
		{Name: "stamped-foreign", Input: "input/stamped.pdf", Prep: page("", "stamped.pdf")},
		{Name: "encrypted", Input: "input/encrypted.pdf", Prep: page("", "enc.pdf")},
	}
}

// ── тестийн PKI ──

type gCert struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

type goldenPKI struct {
	root, ca02, ca03, ca04, citizen, tsa *gCert
}

func (p *goldenPKI) chain() []*x509.Certificate {
	return []*x509.Certificate{p.ca04.cert, p.ca03.cert, p.ca02.cert}
}

func (p *goldenPKI) byName() map[string]*gCert {
	return map[string]*gCert{"root": p.root, "02": p.ca02, "03": p.ca03, "04": p.ca04, "citizen": p.citizen, "tsa": p.tsa}
}

func loadOrCreatePKI(t *testing.T) *goldenPKI {
	t.Helper()
	dir := filepath.Join(goldenDir, "pki")
	if _, err := os.Stat(filepath.Join(dir, "root.pem")); err != nil {
		if !*update {
			t.Fatalf("golden PKI алга — `go test ./pades -run Golden -update`: %v", err)
		}
		createPKI(t, dir)
	}
	p := &goldenPKI{}
	ptrs := map[string]**gCert{"root": &p.root, "02": &p.ca02, "03": &p.ca03, "04": &p.ca04, "citizen": &p.citizen, "tsa": &p.tsa}
	for name, ptr := range ptrs {
		raw, err := os.ReadFile(filepath.Join(dir, name+".pem")) // #nosec G304 -- тест
		if err != nil {
			t.Fatal(err)
		}
		c := &gCert{}
		for {
			var b *pem.Block
			b, raw = pem.Decode(raw)
			if b == nil {
				break
			}
			switch b.Type {
			case "CERTIFICATE":
				c.cert, err = x509.ParseCertificate(b.Bytes)
			case "RSA PRIVATE KEY":
				c.key, err = x509.ParsePKCS1PrivateKey(b.Bytes)
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		*ptr = c
	}
	return p
}

func createPKI(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	nb, na := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	serial := int64(1000)
	issue := func(parent *gCert, tmpl *x509.Certificate, bits int) *gCert {
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}
		serial++
		tmpl.SerialNumber, tmpl.NotBefore, tmpl.NotAfter = big.NewInt(serial), nb, na
		pc, pk := tmpl, key
		if parent != nil {
			pc, pk = parent.cert, parent.key
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, pc, &key.PublicKey, pk)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return &gCert{cert: c, key: key}
	}
	ca := func(cn string, ocspURL, crlURL string) *x509.Certificate {
		c := &x509.Certificate{Subject: pkix.Name{CommonName: cn, Country: []string{"MN"}}, IsCA: true, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
		if ocspURL != "" {
			c.OCSPServer = []string{ocspURL}
		}
		if crlURL != "" {
			c.CRLDistributionPoints = []string{crlURL}
		}
		return c
	}
	p := &goldenPKI{}
	p.root = issue(nil, ca("TEST ONLY Golden National Root CA", "", ""), 2048)
	p.ca02 = issue(p.root, ca("TEST ONLY Golden National Issuing CA", "", "http://crl.pki.test/root.crl"), 2048)
	p.ca03 = issue(p.ca02, ca("TEST ONLY Golden Gerege Issuing CA", "", "http://crl.pki.test/02.crl"), 2048)
	p.ca04 = issue(p.ca03, ca("TEST ONLY Golden eID Mongolia Issuing CA", "http://ocsp.pki.test/03", "http://crl.pki.test/03.crl"), 2048)
	p.citizen = issue(p.ca04, &x509.Certificate{
		Subject: pkix.Name{CommonName: "TESTOV GOLDEN", SerialNumber: "PNOMN-00000000000", Country: []string{"MN"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier{2, 5, 4, 42}, Value: "GOLDEN"},
				{Type: asn1.ObjectIdentifier{2, 5, 4, 4}, Value: "TESTOV"},
			}},
		KeyUsage:   x509.KeyUsageContentCommitment | x509.KeyUsageDigitalSignature,
		OCSPServer: []string{"http://ocsp.pki.test/04"}, CRLDistributionPoints: []string{"http://crl.pki.test/04.crl"},
	}, 2048)
	p.tsa = issue(p.ca04, &x509.Certificate{Subject: pkix.Name{CommonName: "TEST ONLY Golden TSA"},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtraExtensions: []pkix.Extension{eidcrypto.TSAEKUExtension()},
		OCSPServer: []string{"http://ocsp.pki.test/04"}, CRLDistributionPoints: []string{"http://crl.pki.test/04.crl"}}, 2048)
	for name, c := range p.byName() {
		var b bytes.Buffer
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw})
		_ = pem.Encode(&b, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(c.key)})
		if err := os.WriteFile(filepath.Join(dir, name+".pem"), b.Bytes(), 0o644); err != nil { // #nosec G306 -- тестийн түлхүүр
			t.Fatal(err)
		}
	}
}

// ── тогтмол HTTP (TSA, OCSP, CRL) ──

// liveResponder — -update үед хариуг үүсгэнэ (TSA genTime = T+1с, OCSP thisUpdate = T+3с).
func (p *goldenPKI) liveResponder(_ *testing.T) http.Handler {
	byKey := map[string]*gCert{"03": p.ca03, "04": p.ca04, "02": p.ca02, "root": p.root}
	all := []*gCert{p.ca02, p.ca03, p.ca04, p.citizen, p.tsa}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body []byte
		if r.Body != nil {
			body, _ = io.ReadAll(r.Body)
		}
		switch {
		case r.Host == "tsa.pki.test":
			req, err := timestamp.ParseRequest(body)
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			ts := &timestamp.Timestamp{HashAlgorithm: req.HashAlgorithm, HashedMessage: req.HashedMessage,
				Time: goldenTime.Add(time.Second).UTC(), Policy: asn1.ObjectIdentifier{2, 16, 496, 1, 101, 1, 2, 8},
				Nonce: req.Nonce, AddTSACertificate: true, Certificates: p.chain()}
			out, err := ts.CreateResponse(p.tsa.cert, p.tsa.key)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			_, _ = w.Write(out)
		case r.Host == "ocsp.pki.test":
			iss := byKey[strings.TrimPrefix(r.URL.Path, "/")]
			req, err := ocsp.ParseRequest(body)
			if iss == nil || err != nil {
				http.Error(w, "bad", 400)
				return
			}
			var serial *big.Int
			for _, c := range all {
				if c.cert.SerialNumber.Cmp(req.SerialNumber) == 0 {
					serial = c.cert.SerialNumber
				}
			}
			if serial == nil {
				http.Error(w, "unknown", 404)
				return
			}
			th := goldenTime.Add(3 * time.Second).UTC()
			out, err := ocsp.CreateResponse(iss.cert, iss.cert, ocsp.Response{Status: ocsp.Good, SerialNumber: serial,
				ThisUpdate: th, NextUpdate: th.Add(7 * 24 * time.Hour), IssuerHash: crypto.SHA1}, iss.key)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			_, _ = w.Write(out)
		case r.Host == "crl.pki.test":
			iss := byKey[strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), ".crl")]
			if iss == nil {
				http.Error(w, "unknown", 404)
				return
			}
			out, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1),
				ThisUpdate: goldenTime.Add(-time.Hour), NextUpdate: goldenTime.Add(30 * 24 * time.Hour)}, iss.cert, iss.key)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			_, _ = w.Write(out)
		default:
			http.Error(w, "host", 404)
		}
	})
}

func httpKey(r *http.Request, body []byte) string {
	s := sha256.Sum256(body)
	return r.Method + " " + r.URL.String() + " " + hex.EncodeToString(s[:8])
}

// replayTransport — manifest.HTTP-ийн тогтмол хариуг өгнө; -update үед live-аас бичнэ.
type replayTransport struct {
	t      *testing.T
	m      *goldenManifest
	live   http.Handler
	record map[string][]byte
}

func (rt *replayTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(r.Body)
	}
	key := httpKey(r, body)
	var out []byte
	status := 200
	if *update {
		rec := httptest.NewRecorder()
		r2 := r.Clone(context.Background())
		r2.Body = io.NopCloser(bytes.NewReader(body))
		rt.live.ServeHTTP(rec, r2)
		status, out = rec.Code, rec.Body.Bytes()
		if status == 200 {
			rt.record[key] = out
		}
	} else {
		file, ok := rt.m.HTTP[key]
		if !ok {
			rt.t.Errorf("golden HTTP fixture алга: %s (-update)", key)
			status = 404
		} else {
			b, err := os.ReadFile(filepath.Join(goldenDir, file)) // #nosec G304 -- тест
			if err != nil {
				return nil, err
			}
			out = b
		}
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(out)), Header: http.Header{}, Request: r}, nil
}

// seededReader — TSA nonce-ийн тодорхойлогдсон эх.
type seededReader struct {
	seed []byte
	n    int
}

func (s *seededReader) Read(p []byte) (int, error) {
	for i := range p {
		if s.n%32 == 0 {
			h := sha256.Sum256(append(s.seed, byte(s.n/32)))
			s.seed = h[:]
		}
		p[i] = s.seed[s.n%32]
		s.n++
	}
	return len(p), nil
}

func sha256hex(b []byte) string { return sha256Hex(b) }

// runGolden — нэг тохиолдол: Prepare → иргэний RSA гарын үсэг → Complete (тогтмол HTTP). Гаралт ба хүлээгдэх утга.
func runGolden(t *testing.T, p *goldenPKI, rt *replayTransport, c goldenCase, input []byte) (goldenExpect, []byte) {
	t.Helper()
	var got goldenExpect
	got.InputSHA256 = sha256hex(input)
	o := c.Prep
	o.SignerCert = p.citizen.cert.Raw
	o.Chain = [][]byte{p.ca04.cert.Raw, p.ca03.cert.Raw, p.ca02.cert.Raw}
	o.SigningTime = goldenTime
	prep, err := Prepare(input, o)
	if err != nil {
		got.Error = ErrorCode(err)
		if got.Error == "" {
			t.Fatalf("%s: %v", c.Name, err)
		}
		return got, nil
	}
	st, err := decodeState(prep.State)
	if err != nil {
		t.Fatal(err)
	}
	got.DocID, got.Digest, got.DTBS = prep.DocID, hex.EncodeToString(prep.Digest), hex.EncodeToString(prep.DTBS)
	got.PreparedSHA256, got.ByteRange = st.PreparedSHA256, st.ByteRange
	sig, err := rsa.SignPKCS1v15(nil, p.citizen.key, crypto.SHA256, prep.DTBS)
	if err != nil {
		t.Fatal(err)
	}
	nonceReader = &seededReader{seed: []byte("golden-nonce:" + c.Name)}
	defer func() { nonceReader = rand.Reader }()
	res, err := Complete(context.Background(), prep.State, sig, CompleteOptions{
		HTTPClient: &http.Client{Transport: rt}, TSAURL: "http://tsa.pki.test/",
		Now: func() time.Time { return goldenNow }, Roots: [][]byte{p.root.cert.Raw}})
	if err != nil {
		got.Error = ErrorCode(err)
		t.Logf("%s: %v", c.Name, err)
		return got, nil
	}
	got.OutSHA256, got.RevIndex, got.HasPage, got.PageSHA256 = res.OutSHA256, res.RevIndex, res.HasPage, res.PageSHA256
	got.SigRevSHA256, got.CMSSHA256, got.PriorCMSSHA256 = res.SigRevSHA256, sha256hex(res.CMS), res.PriorCMSSHA256
	return got, res.PDF
}

// TestGolden — бүх тохиолдлын prepare/complete-ийг manifest-тэй байт-түвшинд (sha256) тулгана. Дараа нь гаралт бүрийг
// Verify-ээр шалгана.
func TestGolden(t *testing.T) {
	requireReferenceDeflate(t)
	p := loadOrCreatePKI(t)
	mpath := filepath.Join(goldenDir, "manifest.json")
	var m goldenManifest
	if raw, err := os.ReadFile(mpath); err == nil { // #nosec G304 -- тест
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
	} else if !*update {
		t.Fatal(err)
	}
	rt := &replayTransport{t: t, m: &m, live: p.liveResponder(t), record: map[string][]byte{}}
	want := map[string]goldenExpect{}
	for _, c := range m.Cases {
		want[c.Name] = c.Expect
	}
	outputs := map[string][]byte{}
	var cases []goldenCase
	for _, c := range goldenCases() {
		var input []byte
		if name, ok := strings.CutPrefix(c.Input, "case:"); ok {
			input = outputs[name]
			if input == nil {
				t.Fatalf("%s: %s-ийн гаралт алга", c.Name, name)
			}
		} else {
			b, err := os.ReadFile(filepath.Join(goldenDir, c.Input)) // #nosec G304 -- тест
			if err != nil {
				t.Fatal(err)
			}
			input = b
		}
		got, out := runGolden(t, p, rt, c, input)
		outputs[c.Name] = out
		if out != nil {
			rep, err := Verify(out, VerifyOptions{Roots: [][]byte{p.root.cert.Raw}, Issuers: [][]byte{p.ca04.cert.Raw}, Time: goldenNow})
			if err != nil || rep.Indication != Valid {
				t.Errorf("%s: Verify: %v %+v", c.Name, err, rep)
			}
		}
		if !*update {
			gj, _ := json.Marshal(got)
			wj, _ := json.Marshal(want[c.Name])
			if !bytes.Equal(gj, wj) {
				t.Errorf("%s golden зөрөв:\nавсан    %s\nхүлээсэн %s", c.Name, gj, wj)
			}
		}
		c.Expect = got
		cases = append(cases, c)
	}
	if !*update {
		return
	}
	m = goldenManifest{
		Comment: "eID PAdES core golden vectors — ТЕСТИЙН PKI (pki/*.pem, хувийн түлхүүртэй) — бодит гинжид итгэгдэхгүй. " +
			"prepare: signerCert = pki/citizen.pem, chain = 04/03/02, roots = pki/root.pem, signingTime; иргэний гарын үсэг = RSA PKCS#1 v1.5 (citizen key) DTBS дээр; " +
			"complete: TSA = http://tsa.pki.test/, HTTP хариу = http/ (key: METHOD URL sha256(body)[:8] hex), nonce = SHA-256 гинж (seed \"golden-nonce:<case>\"), now.",
		Profile: ProfileVersion, SigningTime: goldenTime, Now: goldenNow, NonceSeed: "golden-nonce:<case>",
		HTTP: map[string]string{}, Cases: cases,
	}
	httpDir := filepath.Join(goldenDir, "http")
	_ = os.RemoveAll(httpDir)
	if err := os.MkdirAll(httpDir, 0o755); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(rt.record))
	for k := range rt.record {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i, k := range keys {
		name := fmt.Sprintf("http/%02d-%s.der", i, sha256hex([]byte(k))[:12])
		if err := os.WriteFile(filepath.Join(goldenDir, name), rt.record[k], 0o644); err != nil { // #nosec G306 -- тест
			t.Fatal(err)
		}
		m.HTTP[k] = name
	}
	out, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(mpath, append(out, '\n'), 0o644); err != nil { // #nosec G306 -- тест
		t.Fatal(err)
	}
}

// requireReferenceDeflate — golden-ий байт нь Go-ийн compress/flate-аас хамаарна (verify хуудасны fpdf font/content,
// QR PNG, xref stream). Go 1.27-д flate-ийн гаралт өөрчлөгдсөн (2026-10-14 шалгасан: ижил оролтод өөр байт) — CA (Go
// 1.26) ба энэ manifest Go 1.25/1.26-ийн flate-аар. Өөр flate-тай toolchain-д гаралт хүчинтэй PDF хэвээр ч байт-ижил биш.
func requireReferenceDeflate(t *testing.T) {
	t.Helper()
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	_, _ = w.Write([]byte{1, 0, 0, 1, 2, 0, 1, 0, 0, 2, 3, 0})
	_ = w.Close()
	if hex.EncodeToString(b.Bytes()) != "789c62646060646260646060626600040000ffff0043000b" {
		t.Fatalf("%s-ийн compress/flate нь golden-ий (Go 1.25/1.26) flate-аас өөр — Go 1.25/1.26-аар build/test хийнэ", runtime.Version())
	}
}
