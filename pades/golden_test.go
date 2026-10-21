package pades

import (
	"bytes"
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
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/pdf"
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
	SignedAttrs    string   `json:"signedAttrs,omitempty"` // DER SET (hex)
	Signature      string   `json:"signature,omitempty"`   // иргэний гарын үсэг DTBS дээр (hex) — SDK-ууд түлхүүргүйгээр complete-д өгнө
	PreparedSHA256 string   `json:"preparedSha256,omitempty"`
	ByteRange      [4]int64 `json:"byteRange,omitempty"`
	OutSHA256      string   `json:"outSha256,omitempty"`
	RevIndex       int      `json:"revIndex,omitempty"`
	HasPage        bool     `json:"hasPage,omitempty"`
	PageSHA256     string   `json:"pageSha256,omitempty"`
	SigRevSHA256   string   `json:"sigRevSha256,omitempty"`
	CMSSHA256      string   `json:"cmsSha256,omitempty"`
	PriorCMSSHA256 []string `json:"priorCmsSha256,omitempty"`
	// Placement — the visible stamp's final rect and status (PLACEMENT_SPEC.md); absent for invisible signatures.
	Placement *Placement `json:"placement,omitempty"`
	// Suggestion — SuggestPlacement(input, appearance) (PLACEMENT_SPEC.md §6b); equals Placement in every field it
	// shares. SuggestionError — its error code when it fails (only on cases whose Prepare fails too).
	Suggestion      *Suggestion `json:"suggestion,omitempty"`
	SuggestionError string      `json:"suggestionError,omitempty"`
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
		{Name: "quartz-pdf13-en", Input: "input/quartz-pdf13.pdf", Prep: PrepareOptions{VerifyPage: true, DocID: "71829304-b5c6-4d7e-9ef1-6c7d8e9fa0b1",
			FileName: "Contract No.1 (Quartz).pdf", Lang: "en"}},
		{Name: "quartz-objstm", Input: "input/quartz-objstm.pdf", Prep: page("1b2c3d4e-5f60-4718-8a9b-0c1d2e3f4a5b", "objstm.pdf")},
		{Name: "quartz-linearized", Input: "input/quartz-linearized.pdf", Prep: page("2c3d4e5f-6071-4829-9bac-1d2e3f4a5b6c", "linearized.pdf")},
		{Name: "desktop-objstm-nopage", Input: "input/desktop-objstm.pdf", Prep: PrepareOptions{DocID: "3d4e5f60-7182-493a-acbd-2e3f4a5b6c7d"}},
		{Name: "quartz-pdf13-second", Input: "case:quartz-pdf13", Prep: PrepareOptions{VerifyPage: true, FileName: "ignored.pdf",
			Reason: "Тест ХХК-ийг төлөөлж", ClaimedRole: "Захирал, Тест ХХК (NTRMN-1234567)"}},
		{Name: "quartz-pdf13-nopage", Input: "input/quartz-pdf13.pdf", Prep: PrepareOptions{DocID: "4e5f6071-8293-4a4b-8bce-3f4a5b6c7d8e"}},
		{Name: "quartz-objstm-nopage", Input: "input/quartz-objstm.pdf", Prep: PrepareOptions{DocID: "5f607182-93a4-4b5c-9cdf-4a5b6c7d8e9f"}},
		{Name: "quartz-linearized-nopage", Input: "input/quartz-linearized.pdf", Prep: PrepareOptions{DocID: "60718293-a4b5-4c6d-8de0-5b6c7d8e9fa0"}},
		{Name: "quartz-pdf13-nopage-second", Input: "case:quartz-pdf13-nopage", Prep: PrepareOptions{DocID: "4e5f6071-8293-4a4b-8bce-3f4a5b6c7d8e",
			Reason: "Тест ХХК-ийг төлөөлж", ClaimedRole: "Захирал, Тест ХХК (NTRMN-1234567)"}},
		// Харагдах гарын үсэг (APPEARANCE_SPEC.md, golden v3): эхний гарын үсэг оролтын сүүлийн хуудсан дээр (mn, en),
		// 2 дахь нь 2 хуудастай баримтын 1-р хуудсан дээр (onBehalfOf — үүргийн мөртэй), 2 дахь харагдах нь эхний
		// харагдах дээр, /Rotate 90 хуудас.
		{Name: "quartz-pdf13-visible", Input: "input/quartz-pdf13.pdf", Prep: visible(page("8a9b0c1d-2e3f-4a5b-8c6d-7e8f9a0b1c2d", "Гэрээ №1 (Quartz).pdf"),
			Appearance{X: 36, Y: 36, Width: 220, Height: 64})},
		{Name: "quartz-pdf13-visible-en", Input: "input/quartz-pdf13.pdf", Prep: visible(PrepareOptions{VerifyPage: true,
			DocID: "9b0c1d2e-3f4a-4b5c-9d7e-8f9a0b1c2d3e", FileName: "Contract No.1 (Quartz).pdf", Lang: "en"},
			Appearance{X: 36, Y: 36, Width: 220, Height: 64})},
		{Name: "quartz-pdf13-visible-second", Input: "case:quartz-pdf13", Prep: visible(PrepareOptions{Reason: "Тест ХХК-ийг төлөөлж",
			ClaimedRole: "Захирал, Тест ХХК (NTRMN-1234567)"}, Appearance{Page: 1, X: 340, Y: 36, Width: 236, Height: 72})},
		{Name: "quartz-pdf13-visible-twice", Input: "case:quartz-pdf13-visible", Prep: visible(PrepareOptions{Lang: "en"},
			Appearance{Page: 1, X: 340, Y: 36, Width: 220, Height: 64})},
		{Name: "quartz-rotated90-visible", Input: "input/quartz-rotated90.pdf", Prep: visible(page("ac1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f", "rotated.pdf"),
			Appearance{X: 36, Y: 36, Width: 220, Height: 64})},
		// Stamp placement (PLACEMENT_SPEC.md, golden v5): the requested spot overlaps page content → the stamp moves.
		// (a) LibreOffice-converted contract whose last-page footer sits under the default spot (prod 2026-10-19) and a
		// second signer on the same page; (b) a full-width table at the bottom of an A4 page; (c) /Rotate 90 with a
		// footer across the visible bottom; (d) an existing visible signature at the bottom-right (second signer);
		// (e) a page full of text — nothing is free, the stamp stays at the requested spot ("overlap").
		{Name: "libreoffice-contract-visible", Input: "input/libreoffice-contract.pdf", Prep: visible(page("b1c2d3e4-f5a6-4b7c-8d9e-0f1a2b3c4d5e", "ТЕСТ гэрээ.pdf"),
			Appearance{X: 340, Y: 36, Width: 220, Height: 64})},
		{Name: "libreoffice-contract-visible-second", Input: "case:libreoffice-contract-visible", Prep: visible(PrepareOptions{Reason: "Тест ХХК-ийг төлөөлж",
			ClaimedRole: "Захирал, Тест ХХК (NTRMN-1234567)"}, Appearance{Page: 2, X: 340, Y: 36, Width: 220, Height: 64})},
		{Name: "table-bottom-visible", Input: "input/table-bottom.pdf", Prep: visible(page("c2d3e4f5-a6b7-4c8d-9e0f-1a2b3c4d5e6f", "table.pdf"),
			Appearance{X: 340, Y: 36, Width: 220, Height: 64})},
		{Name: "rotated90-footer-visible", Input: "input/rotated90-footer.pdf", Prep: visible(page("d3e4f5a6-b7c8-4d9e-8f1a-2b3c4d5e6f70", "landscape.pdf"),
			Appearance{X: 536, Y: 36, Width: 220, Height: 64})},
		{Name: "quartz-pdf13-visible-third", Input: "case:quartz-pdf13-visible-second", Prep: visible(PrepareOptions{Lang: "en"},
			Appearance{Page: 1, X: 340, Y: 36, Width: 220, Height: 64})},
		{Name: "full-page-visible", Input: "input/full-page.pdf", Prep: visible(page("e4f5a6b7-c8d9-4e0f-9a2b-3c4d5e6f7081", "full.pdf"),
			Appearance{X: 340, Y: 36, Width: 220, Height: 64})},
		{Name: "stamped-foreign", Input: "input/stamped.pdf", Prep: page("", "stamped.pdf")},
		{Name: "encrypted", Input: "input/encrypted.pdf", Prep: page("", "enc.pdf")},
		// appearance.page 0 / absent = the last page that is not an eID verify page (PLACEMENT_SPEC §1a, golden v6):
		// (a) after the first signature's verify page the stamp goes to the content page, (b) a second page-0 signer
		// lands there too (above the first stamp), (c) two verify pages are both skipped, (d) an explicit page number is
		// kept even when it is the verify page, (e) a verify-looking page for another docId stays a content page.
		{Name: "page0-after-verify", Input: "case:quartz-pdf13", Prep: visible(PrepareOptions{Lang: "en"},
			Appearance{X: 340, Y: 36, Width: 220, Height: 64})},
		{Name: "page0-after-verify-second", Input: "case:page0-after-verify", Prep: visible(PrepareOptions{},
			Appearance{X: 340, Y: 36, Width: 220, Height: 64})},
		{Name: "page0-two-verify", Input: "input/two-verify.pdf", Prep: visible(PrepareOptions{DocID: "f5a6b7c8-d9e0-4f1a-8b2c-3d4e5f607182"},
			Appearance{X: 340, Y: 36, Width: 220, Height: 64})},
		{Name: "page-explicit-verify", Input: "case:quartz-pdf13", Prep: visible(PrepareOptions{},
			Appearance{Page: 2, X: 340, Y: 36, Width: 220, Height: 64})},
		{Name: "page0-fake-verify", Input: "input/fake-verify.pdf", Prep: visible(PrepareOptions{DocID: "f5a6b7c8-d9e0-4f1a-8b2c-3d4e5f607182"},
			Appearance{X: 340, Y: 36, Width: 220, Height: 64})},
		// appearance.exact (PLACEMENT_SPEC §6a, golden v7): the signer's own position is never moved — (a) over the
		// table → "overlap" at 340, 36 (table-bottom-visible moves to 340, 168); (b) exactly at that free spot →
		// "requested", prepared bytes identical to table-bottom-visible; (c) /Rotate 90 over the footer → "overlap";
		// (d) page 0 on a signed document still skips the verify page (prepared bytes = page0-after-verify); (e) a rect past the page edge → REQUEST_INVALID.
		{Name: "exact-on-content", Input: "input/table-bottom.pdf", Prep: visible(page("c2d3e4f5-a6b7-4c8d-9e0f-1a2b3c4d5e6f", "table.pdf"),
			Appearance{X: 340, Y: 36, Width: 220, Height: 64, Exact: true})},
		{Name: "exact-free", Input: "input/table-bottom.pdf", Prep: visible(page("c2d3e4f5-a6b7-4c8d-9e0f-1a2b3c4d5e6f", "table.pdf"),
			Appearance{X: 340, Y: 168, Width: 220, Height: 64, Exact: true})},
		{Name: "exact-rotated90-on-footer", Input: "input/rotated90-footer.pdf", Prep: visible(page("d3e4f5a6-b7c8-4d9e-8f1a-2b3c4d5e6f70", "landscape.pdf"),
			Appearance{X: 536, Y: 36, Width: 220, Height: 64, Exact: true})},
		{Name: "exact-page0-after-verify", Input: "case:quartz-pdf13", Prep: visible(PrepareOptions{Lang: "en"},
			Appearance{X: 340, Y: 36, Width: 220, Height: 64, Exact: true})},
		{Name: "exact-out-of-bounds", Input: "input/table-bottom.pdf", Prep: visible(page("c2d3e4f5-a6b7-4c8d-9e0f-1a2b3c4d5e6f", "table.pdf"),
			Appearance{X: 400, Y: 36, Width: 220, Height: 64, Exact: true})},
		// Object generations (PLACEMENT_SPEC §1a, golden v8): input/verify-gen1.pdf has its verify page, Link and URI
		// action as generation 1/2 objects. (a) first signature (invisible, docId = the page's); (b) second signer, page
		// 0: docId is read from the generation-1 Link and the generation-1 verify page is skipped → page 1; (c) explicit
		// page 2: the widget goes on the generation-1 page, which the increment rewrites as `6 1 obj`.
		{Name: "verify-gen1", Input: "input/verify-gen1.pdf", Prep: PrepareOptions{DocID: "f5a6b7c8-d9e0-4f1a-8b2c-3d4e5f607182"}},
		{Name: "page0-verify-gen1", Input: "case:verify-gen1", Prep: visible(PrepareOptions{Lang: "en"},
			Appearance{X: 340, Y: 36, Width: 220, Height: 64})},
		{Name: "page-explicit-verify-gen1", Input: "case:verify-gen1", Prep: visible(PrepareOptions{},
			Appearance{Page: 2, X: 340, Y: 36, Width: 220, Height: 64})},
	}
}

func visible(o PrepareOptions, a Appearance) PrepareOptions {
	o.Appearance = &a
	return o
}

// dssUnique — PROFILE.md §7: /DSS /Certs /OCSPs /CRLs-ийн stream бүрийн агуулга (DER) баримтад ганц удаа (citizen ба TSA
// гинжийн давхцал, хоёр дахь гарын үсгийн R_dss өмнөх DSS-ийн объектыг заалтаар дахин ашиглана).
func dssUnique(t *testing.T, name string, doc []byte) {
	t.Helper()
	r, err := pdf.NewReader(bytes.NewReader(doc), int64(len(doc)))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	dss := r.Trailer().Key("Root").Key("DSS")
	seen := map[[32]byte]string{}
	for _, key := range []string{"Certs", "OCSPs", "CRLs"} {
		arr := dss.Key(key)
		for i := range arr.Len() {
			data, err := io.ReadAll(arr.Index(i).Reader())
			if err != nil {
				t.Fatalf("%s: DSS /%s[%d]: %v", name, key, i, err)
			}
			sum := sha256.Sum256(data)
			if prev, dup := seen[sum]; dup {
				t.Errorf("%s: DSS /%s[%d] нь %s-тэй ижил агуулгатай (давхардал)", name, key, i, prev)
			}
			seen[sum] = fmt.Sprintf("/%s[%d]", key, i)
		}
	}
	if len(seen) == 0 {
		t.Errorf("%s: DSS хоосон", name)
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
		c := &gCert{}
		for _, file := range []string{name + ".pem", name + ".key.pem"} {
			raw, err := os.ReadFile(filepath.Join(dir, file)) // #nosec G304 -- тест
			if err != nil {
				t.Fatal(err)
			}
			b, _ := pem.Decode(raw)
			if b == nil {
				t.Fatalf("%s: PEM алга", file)
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
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(c.key)})
		if err := os.WriteFile(filepath.Join(dir, name+".pem"), certPEM, 0o644); err != nil { // #nosec G306 -- тест
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name+".key.pem"), keyPEM, 0o644); err != nil { // #nosec G306 -- ТЕСТИЙН түлхүүр
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
			out, err := ts.CreateResponseWithOpts(p.tsa.cert, p.tsa.key, crypto.SHA256)
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
	if file, ok := rt.m.HTTP[key]; ok && *update {
		// Байгаа fixture-ийг хэвээр (OCSP producedAt цагаас хамаардаг) — өмнөх тохиолдлууд байт-ижил үлдэнэ.
		b, err := os.ReadFile(filepath.Join(goldenDir, file)) // #nosec G304 -- тест
		if err != nil {
			return nil, err
		}
		rt.record[key], out = b, b
	} else if *update {
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
	got, out, _ := runGoldenWith(context.Background(), t, p, rt, c, input, nil)
	return got, out
}

// runGoldenWith — runGolden + transport, ctx, LTVRetries-ийг өгнө; Complete-ийн алдааг буцаана.
func runGoldenWith(ctx context.Context, t *testing.T, p *goldenPKI, rt http.RoundTripper, c goldenCase, input []byte, ltvRetries *int) (goldenExpect, []byte, error) {
	t.Helper()
	var got goldenExpect
	got.InputSHA256 = sha256hex(input)
	o := c.Prep
	o.SignerCert = p.citizen.cert.Raw
	o.Chain = [][]byte{p.ca04.cert.Raw, p.ca03.cert.Raw, p.ca02.cert.Raw}
	o.SigningTime = goldenTime
	var sugErr error
	if o.Appearance != nil {
		sug, err := SuggestPlacement(input, *o.Appearance)
		if err != nil {
			sugErr = err
			got.SuggestionError = ErrorCode(err)
		} else {
			got.Suggestion = &sug
		}
	}
	prep, err := Prepare(input, o)
	if err != nil {
		got.Error = ErrorCode(err)
		if got.Error == "" {
			t.Fatalf("%s: %v", c.Name, err)
		}
		return got, nil, err
	}
	if sugErr != nil {
		t.Errorf("%s: SuggestPlacement: %v (Prepare ok)", c.Name, sugErr)
	}
	// page0-two-verify: an unsigned input whose verify pages carry the docId the caller passes to Prepare — the one
	// case where SuggestPlacement (no docId: nothing skipped on unsigned input) differs (PLACEMENT_SPEC.md §6b).
	if s, pl := got.Suggestion, prep.Placement; s != nil && c.Name != "page0-two-verify" &&
		(pl == nil || *pl != (Placement{Page: s.Page, X: s.X, Y: s.Y, Width: s.Width, Height: s.Height, Status: s.Status})) {
		t.Errorf("%s: SuggestPlacement %+v ≠ Prepared.Placement %+v", c.Name, *s, pl)
	}
	st, err := decodeState(prep.State)
	if err != nil {
		t.Fatal(err)
	}
	got.DocID, got.Digest, got.DTBS = prep.DocID, hex.EncodeToString(prep.Digest), hex.EncodeToString(prep.DTBS)
	got.PreparedSHA256, got.ByteRange = st.PreparedSHA256, st.ByteRange
	got.Placement = prep.Placement
	sig, err := rsa.SignPKCS1v15(nil, p.citizen.key, crypto.SHA256, prep.DTBS)
	if err != nil {
		t.Fatal(err)
	}
	got.SignedAttrs, got.Signature = hex.EncodeToString(st.SignedAttrs), hex.EncodeToString(sig)
	nonceReader = &seededReader{seed: []byte("golden-nonce:" + c.Name)}
	defer func() { nonceReader = rand.Reader }()
	res, err := Complete(ctx, prep.State, sig, CompleteOptions{
		HTTPClient: &http.Client{Transport: rt}, TSAURL: "http://tsa.pki.test/",
		Now: func() time.Time { return goldenNow }, Roots: [][]byte{p.root.cert.Raw}, LTVRetries: ltvRetries})
	if err != nil {
		got.Error = ErrorCode(err)
		t.Logf("%s: %v", c.Name, err)
		return got, nil, err
	}
	got.OutSHA256, got.RevIndex, got.HasPage, got.PageSHA256 = res.OutSHA256, res.RevIndex, res.HasPage, res.PageSHA256
	got.SigRevSHA256, got.CMSSHA256, got.PriorCMSSHA256 = res.SigRevSHA256, sha256hex(res.CMS), res.PriorCMSSHA256
	return got, res.PDF, nil
}

// TestGolden — бүх тохиолдлын prepare/complete-ийг manifest-тэй байт-түвшинд (sha256) тулгана. Дараа нь гаралт бүрийг
// Verify-ээр шалгана.
func TestGolden(t *testing.T) {
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
		if *update && out != nil {
			if err := os.MkdirAll(filepath.Join(goldenDir, "output"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(goldenDir, "output", c.Name+".pdf"), out, 0o644); err != nil { // #nosec G306 -- тест
				t.Fatal(err)
			}
		}
		if out != nil {
			dssUnique(t, c.Name, out)
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
	oldHTTP := m.HTTP
	m = goldenManifest{
		Comment: "eID PAdES core golden vectors — ТЕСТИЙН PKI (pki/*.pem, хувийн түлхүүртэй) — бодит гинжид итгэгдэхгүй. " +
			"prepare: signerCert = pki/citizen.pem, chain = 04/03/02, roots = pki/root.pem, signingTime; иргэний гарын үсэг = RSA PKCS#1 v1.5 (citizen key) DTBS дээр; " +
			"complete: TSA = http://tsa.pki.test/, HTTP хариу = http/ (key: METHOD URL sha256(body)[:8] hex), nonce = SHA-256 гинж (seed \"golden-nonce:<case>\"), now.",
		Profile: ProfileVersion, SigningTime: goldenTime, Now: goldenNow, NonceSeed: "golden-nonce:<case>",
		HTTP: map[string]string{}, Cases: cases,
	}
	// Байгаа fixture-ийн нэр хэвээр; шинэ түлхүүр дараагийн дугаараас (түлхүүрээр эрэмбэлж). Ашиглагдаагүйг устгана.
	httpDir := filepath.Join(goldenDir, "http")
	if err := os.MkdirAll(httpDir, 0o755); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(rt.record))
	next := 0
	for k := range rt.record {
		if name, ok := oldHTTP[k]; ok {
			m.HTTP[k] = name
			var i int
			if _, err := fmt.Sscanf(name, "http/%d-", &i); err == nil && i >= next {
				next = i + 1
			}
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		name := fmt.Sprintf("http/%02d-%s.der", next, sha256hex([]byte(k))[:12])
		next++
		if err := os.WriteFile(filepath.Join(goldenDir, name), rt.record[k], 0o644); err != nil { // #nosec G306 -- тест
			t.Fatal(err)
		}
		m.HTTP[k] = name
	}
	for k, name := range oldHTTP {
		if _, used := m.HTTP[k]; !used {
			_ = os.Remove(filepath.Join(goldenDir, name))
		}
	}
	out, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(mpath, append(out, '\n'), 0o644); err != nil { // #nosec G306 -- тест
		t.Fatal(err)
	}
}
