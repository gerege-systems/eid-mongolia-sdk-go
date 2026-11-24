package pades

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"sync"
	"testing"

	dpdf "github.com/digitorus/pdf"
	pdfcpuapi "github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"

	eid "github.com/gerege-systems/eid-mongolia-sdk-go"
)

// Experiment (2026-11-24): an organisation e-Seal leaving a visible imprint at the bottom-right of EVERY page of a
// citizen-signed PDF. Test code only — SealPDF itself stays invisible; the visible seal is built from the same
// Prepare → Sealer.Seal(DTBS) → Complete steps SealPDF wraps, with PrepareOptions.Appearance. Mechanisms:
//
//	V2 — one visible seal signature per page (N revisions)                     → TestSealVisibleStampEveryPage
//	V3 — one seal field with N widgets (/Kids or one widget in N /Annots)      → rejected by the validator:
//	     pades/internal/validate/seal_stamp_test.go (V3) and revisions_review2_test.go:135
//	V4 — one seal + the imprint as page content / /Stamp annotations in its own revision → rejected (modified after
//	     the citizen signature): pades/internal/validate/seal_stamp_test.go (V4a, V4b), revisions_test.go:367/:391
//	V4 on an UNSIGNED document (imprint drawn first, one seal covering it)    → TestSealAfterImprintUnsigned

// countingTransport — counts HTTP requests per host (TSA / OCSP / CRL) for the calls-per-file figure.
type countingTransport struct {
	next http.RoundTripper
	mu   sync.Mutex
	n    map[string]int
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.mu.Lock()
	c.n[r.URL.Host]++
	c.mu.Unlock()
	return c.next.RoundTrip(r)
}

func pageCount(t *testing.T, doc []byte) int {
	t.Helper()
	r, err := dpdf.NewReader(bytes.NewReader(doc), int64(len(doc)))
	if err != nil {
		t.Fatal(err)
	}
	return r.NumPage()
}

// sealStampRect — fixed bottom-right imprint (pt, APPEARANCE_SPEC §1 coordinates); Exact: never moved off content,
// overlap with page content or the citizen's stamp is accepted (owner, 2026-11-24).
var sealStampRect = Appearance{X: 340, Y: 36, Width: 220, Height: 64, Exact: true}

// TestSealVisibleStampEveryPage — V2: a citizen PIN2 signature (visible stamp at the default spot + verify page) on the
// 2-page libreoffice-contract.pdf (→ 3 pages; no clean ≥3-page unsigned fixture exists: two-verify.pdf carries fake
// verify pages), then one visible seal signature per page, each its own revision, Exact bottom-right.
//
// Conclusion: every signature — the citizen's and all N seals — stays Valid PAdES-BASELINE-LT; each earlier one is
// extended by signatures only and reports visible_later_signature. Cost per page: one Sealer.Seal call, one TSA call,
// one full revision (+DSS), ~165 KB each. Limits: MaxSignatures (16) caps the file at 15 sealed pages after one citizen
// signature; MaxOutputBytes (10 MB) is the other ceiling.
func TestSealVisibleStampEveryPage(t *testing.T) {
	ctx := context.Background()
	p := loadOrCreatePKI(t)
	key, leaf := sealLeaf(t, p, x509.KeyUsageContentCommitment, 88006)
	vopts := VerifyOptions{Roots: [][]byte{p.root.cert.Raw}, Issuers: [][]byte{p.ca04.cert.Raw}, Time: goldenNow}

	// Citizen: visible stamp at the default bottom-right spot (page 0 = last content page) + verify page.
	co := testOpts(p, p.citizen.cert)
	co.Appearance = &Appearance{X: 340, Y: 36, Width: 220, Height: 64}
	cprep, err := Prepare(readInput(t, "libreoffice-contract.pdf"), co)
	if err != nil {
		t.Fatal(err)
	}
	csig, err := rsa.SignPKCS1v15(nil, p.citizen.key, crypto.SHA256, cprep.DTBS)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := Complete(ctx, cprep.State, csig, completeOpts(p))
	if err != nil {
		t.Fatal(err)
	}
	pages := pageCount(t, signed.PDF)
	if pages != 3 || cprep.Placement == nil || cprep.Placement.Page != 2 {
		t.Fatalf("citizen: pages=%d placement=%+v", pages, cprep.Placement)
	}

	// N seals, one per page.
	sealer := &fakeSealer{cert: leaf.Raw, key: key}
	so := sealOpts(p, leaf)
	ct := &countingTransport{next: so.Complete.HTTPClient.Transport, n: map[string]int{}}
	so.Complete.HTTPClient = &http.Client{Transport: ct}
	type sealObs struct {
		Page            int
		Status          string
		OverlapsCitizen bool
		Growth          int
	}
	var obs []sealObs
	sealCalls := 0
	doc := signed.PDF
	for pg := 1; pg <= pages; pg++ {
		a := sealStampRect
		a.Page = pg
		prep, err := Prepare(doc, PrepareOptions{SignerCert: leaf.Raw, Chain: so.Chain, Reason: so.Reason, SigningTime: so.SigningTime, Appearance: &a})
		if err != nil {
			t.Fatalf("seal page %d: Prepare: %v", pg, err)
		}
		r, err := sealer.Seal(ctx, "NTRMN-6235972", prep.DTBS, eid.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		sealCalls++
		res, err := Complete(ctx, prep.State, r.Signature, so.Complete)
		if err != nil {
			t.Fatalf("seal page %d: Complete: %v", pg, err)
		}
		if !bytes.HasPrefix(res.PDF, doc) || res.RevIndex != pg+1 || res.HasPage {
			t.Fatalf("seal page %d: rev=%d page=%v append=%v", pg, res.RevIndex, res.HasPage, bytes.HasPrefix(res.PDF, doc))
		}
		pl, cp := prep.Placement, cprep.Placement
		over := pl.Page == cp.Page && pl.X < cp.X+cp.Width && cp.X < pl.X+pl.Width && pl.Y < cp.Y+cp.Height && cp.Y < pl.Y+pl.Height
		obs = append(obs, sealObs{Page: pl.Page, Status: pl.Status, OverlapsCitizen: over, Growth: len(res.PDF) - len(doc)})
		doc = res.PDF
	}

	rep, err := Verify(doc, vopts)
	if err != nil {
		t.Fatal(err)
	}
	type sigObs struct {
		Usage        string
		Indication   Indication
		Problems     []string
		Whole        bool
		Extended     bool
		Later        int
		VisibleLater bool
		Visible      bool
		Level        string
	}
	var got []sigObs
	for _, s := range rep.Signatures {
		u := ""
		if s.Certificate != nil {
			u = s.Certificate.Usage
		}
		got = append(got, sigObs{u, s.Indication, s.Problems, s.CoversWholeDocument, s.ExtendedBySignaturesOnly, s.LaterSignatures,
			s.VisibleLaterSignature, s.Visible, s.SignatureLevel})
	}
	observed, _ := json.Marshal(map[string]any{"report": rep.Indication, "sigs": got, "seals": obs, "sealCalls": sealCalls,
		"http": ct.n, "citizenPlacement": cprep.Placement, "citizenSize": len(signed.PDF), "finalSize": len(doc)})

	if rep.Indication != Valid || len(got) != pages+1 {
		t.Fatalf("report: %s", observed)
	}
	// Observed (CI 2026-11-24): every signature Valid, PAdES-BASELINE-LT, no problems, visible. None covers the whole
	// file — even the last seal is followed by its own DSS revision — but each is extended by signatures/LTV only;
	// every earlier one reports visible_later_signature.
	for i, s := range got {
		wantUsage := "seal"
		if i == 0 {
			wantUsage = "sign"
		}
		last := i == len(got)-1
		if s.Usage != wantUsage || s.Indication != Valid || len(s.Problems) != 0 || s.Level != "PAdES-BASELINE-LT" || !s.Visible ||
			s.Whole || !s.Extended || s.Later != len(got)-1-i || s.VisibleLater == last {
			t.Errorf("signature %d: %s", i, observed)
		}
	}
	// Exact bottom-right sits on page content on all three pages ("overlap", accepted), and on page 2 over the
	// citizen's stamp (moved by placement to y=60).
	for i, o := range obs {
		if o.Page != i+1 || o.Status != "overlap" || o.OverlapsCitizen != (o.Page == 2) {
			t.Errorf("seal %d placement: %s", i+1, observed)
		}
	}
	// Cost: one Sealer.Seal + one TSA request per page; each seal revision (+DSS) adds ~165 KB (the stamp's
	// appearance embeds its fonts every time) — 317 KB citizen-signed → 818 KB after 3 seals.
	if sealCalls != pages || ct.n["tsa.pki.test"] != pages {
		t.Errorf("calls: %s", observed)
	}
	for _, o := range obs {
		if o.Growth < 150_000 || o.Growth > 185_000 {
			t.Errorf("growth: %s", observed)
		}
	}
	if MaxSignatures != 16 {
		t.Errorf("MaxSignatures = %d: the per-page seal limit (MaxSignatures-1 pages after one citizen signature) changed", MaxSignatures)
	}
}

// TestSealAfterImprintUnsigned — V4 on an UNSIGNED document: the imprint is drawn into every page first (here with
// pdfcpu's text watermark — the SDK writer has no page-content stamping API, so in production this would be a
// pre-processing step or new product code), then one invisible SealPDF covers the whole file.
//
// Conclusion: the single seal is Valid (only its own DSS revision follows it) — but the imprint must be on the pages BEFORE
// any signature; on a citizen-signed PDF it is a content change (see V4 above).
func TestSealAfterImprintUnsigned(t *testing.T) {
	p := loadOrCreatePKI(t)
	key, leaf := sealLeaf(t, p, x509.KeyUsageContentCommitment, 88007)
	in := readInput(t, "libreoffice-contract.pdf")
	wm, err := pdfcpuapi.TextWatermark("SEALED WITH E-SEAL", "pos:br, off:-20 20, rot:0, points:12, scale:1 abs", true, false, types.POINTS)
	if err != nil {
		t.Fatal(err)
	}
	var stamped bytes.Buffer
	if err := pdfcpuapi.AddWatermarks(bytes.NewReader(in), &stamped, nil, wm, nil); err != nil {
		t.Fatal(err)
	}
	if n := pageCount(t, stamped.Bytes()); n != 2 {
		t.Fatalf("pages: %d", n)
	}
	res, err := SealPDF(context.Background(), &fakeSealer{cert: leaf.Raw, key: key}, "NTRMN-6235972", stamped.Bytes(), sealOpts(p, leaf))
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Verify(res.PDF, VerifyOptions{Roots: [][]byte{p.root.cert.Raw}, Issuers: [][]byte{p.ca04.cert.Raw}, Time: goldenNow})
	if err != nil || rep.Indication != Valid || len(rep.Signatures) != 1 {
		b, _ := json.Marshal(rep)
		t.Fatalf("%v %s", err, b)
	}
	// Like every Complete output, the seal is followed by its DSS revision: not "whole document", but extended by LTV only.
	if s := rep.Signatures[0]; s.Indication != Valid || len(s.Problems) != 0 || s.CoversWholeDocument || !s.ExtendedBySignaturesOnly ||
		s.LaterSignatures != 0 || s.Certificate == nil || s.Certificate.Usage != "seal" || s.SignatureLevel != "PAdES-BASELINE-LT" {
		b, _ := json.Marshal(s)
		t.Fatalf("%s", b)
	}
}
