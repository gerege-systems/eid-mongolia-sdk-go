package pades

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"testing"

	dpdf "github.com/digitorus/pdf"
	"github.com/go-pdf/fpdf"
)

func pageCount(t *testing.T, doc []byte) int {
	t.Helper()
	r, err := dpdf.NewReader(bytes.NewReader(doc), int64(len(doc)))
	if err != nil {
		t.Fatal(err)
	}
	return r.NumPage()
}

// smallPDF — w × h pt нэг хуудас (дээд талд бичвэр).
func smallPDF(t *testing.T, w, h float64) []byte {
	t.Helper()
	d := fpdf.NewCustom(&fpdf.InitType{UnitStr: "pt", Size: fpdf.SizeType{Wd: w, Ht: h}})
	d.AddPage()
	d.SetFont("Helvetica", "", 6)
	d.Text(4, 12, "RECEIPT")
	var b bytes.Buffer
	if err := d.Output(&b); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// Харагдах тамганы дардас — SealPDF-ийн анхдагч (APPEARANCE_SPEC.md §6, PLACEMENT_SPEC.md): өмнөх гарын үсэг бүр
// хүчинтэй, өөрчлөгдөөгүй ("extended by signatures only"), гаралт нь оролтын цэвэр incremental append.

type sealFixture struct {
	p      *goldenPKI
	sealer *fakeSealer
	leaf   *x509.Certificate
	vopts  VerifyOptions
}

func newSealFixture(t *testing.T, serial int64) *sealFixture {
	t.Helper()
	p := loadOrCreatePKI(t)
	key, leaf := sealLeaf(t, p, x509.KeyUsageContentCommitment, serial)
	return &sealFixture{p: p, sealer: &fakeSealer{cert: leaf.Raw, key: key}, leaf: leaf,
		vopts: VerifyOptions{Roots: [][]byte{p.root.cert.Raw}, Issuers: [][]byte{p.ca04.cert.Raw}, Time: goldenNow}}
}

func (f *sealFixture) seal(t *testing.T, in []byte, o SealOptions) *Completed {
	t.Helper()
	so := sealOpts(f.p, f.leaf)
	so.Appearance, so.Invisible = o.Appearance, o.Invisible
	res, err := SealPDF(context.Background(), f.sealer, "NTRMN-6235972", in, so)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(res.PDF, in) {
		t.Fatal("not a pure incremental append")
	}
	return res
}

// citizenVisible — иргэний харагдах гарын үсэг (анхдагч байршил, page 0); эхнийх бол verify хуудас нэмнэ.
func citizenVisible(t *testing.T, p *goldenPKI, in []byte, docID string) (*Completed, *Placement) {
	t.Helper()
	o := testOpts(p, p.citizen.cert)
	o.DocID = docID
	o.Appearance = &Appearance{X: 340, Y: 36, Width: 220, Height: 64}
	prep, err := Prepare(in, o)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := rsa.SignPKCS1v15(nil, p.citizen.key, crypto.SHA256, prep.DTBS)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Complete(context.Background(), prep.State, sig, completeOpts(p))
	if err != nil {
		t.Fatal(err)
	}
	return res, prep.Placement
}

// wantAllValid — бүх гарын үсэг Valid PAdES-BASELINE-LT, асуудалгүй, usage дарааллаар; сүүлийнхээс бусад нь зөвхөн
// гарын үсгээр өргөтгөгдсөн, visible бол visible_later_signature.
func (f *sealFixture) wantAllValid(t *testing.T, doc []byte, usages []string, visible []bool) {
	t.Helper()
	rep, err := Verify(doc, f.vopts)
	if err != nil || rep.Indication != Valid || len(rep.Signatures) != len(usages) {
		b, _ := json.Marshal(rep)
		t.Fatalf("%v %s", err, b)
	}
	for i, s := range rep.Signatures {
		laterVisible := false
		for _, v := range visible[i+1:] {
			laterVisible = laterVisible || v
		}
		if s.Indication != Valid || len(s.Problems) != 0 || s.SignatureLevel != "PAdES-BASELINE-LT" || s.Certificate == nil ||
			s.Certificate.Usage != usages[i] || !s.ExtendedBySignaturesOnly || s.LaterSignatures != len(usages)-1-i ||
			s.VisibleLaterSignature != laterVisible || s.Visible != visible[i] {
			b, _ := json.Marshal(s)
			t.Errorf("signature %d: %s", i, b)
		}
	}
}

func wantPlacement(t *testing.T, got *Placement, want Placement) {
	t.Helper()
	if got == nil || *got != want {
		g, _ := json.Marshal(got)
		t.Errorf("placement: %s, want %+v", g, want)
	}
}

// TestSealPDFVisibleAfterCitizen — иргэний харагдах гарын үсэг + verify хуудастай 3 хуудастай баримт → SealPDF анхдагч:
// дардас баримтын сүүлийн (verify биш) 2-р хуудсанд, иргэний дардсын (340, 60) дээр шилжинэ; хоёулаа Valid.
func TestSealPDFVisibleAfterCitizen(t *testing.T) {
	f := newSealFixture(t, 88010)
	signed, cpl := citizenVisible(t, f.p, readInput(t, "libreoffice-contract.pdf"), "")
	wantPlacement(t, cpl, Placement{Page: 2, X: 340, Y: 60, Width: 220, Height: 64, Status: "moved"})
	res := f.seal(t, signed.PDF, SealOptions{})
	if res.RevIndex != 2 || res.HasPage || pageCount(t, res.PDF) != 3 {
		t.Fatalf("rev=%d page=%v pages=%d", res.RevIndex, res.HasPage, pageCount(t, res.PDF))
	}
	wantPlacement(t, res.Placement, Placement{Page: 2, X: 356, Y: 132, Width: 220, Height: 64, Status: "moved"})
	f.wantAllValid(t, res.PDF, []string{"sign", "seal"}, []bool{true, true})
}

// TestSealPDFSealCitizenSeal — тамга → иргэн (харагдах) → тамга: өмнөх гарын үсэг бүр хүчинтэй хэвээр.
func TestSealPDFSealCitizenSeal(t *testing.T) {
	f := newSealFixture(t, 88011)
	s1 := f.seal(t, readInput(t, "quartz-pdf13.pdf"), SealOptions{})
	c, _ := citizenVisible(t, f.p, s1.PDF, "0a1b2c3d-4e5f-4a6b-8c7d-8e9fa0b1c2d3")
	if !bytes.HasPrefix(c.PDF, s1.PDF) || c.HasPage || c.RevIndex != 2 {
		t.Fatalf("citizen: rev=%d page=%v", c.RevIndex, c.HasPage)
	}
	s2 := f.seal(t, c.PDF, SealOptions{})
	if s2.RevIndex != 3 {
		t.Fatalf("rev=%d", s2.RevIndex)
	}
	f.wantAllValid(t, s2.PDF, []string{"seal", "sign", "seal"}, []bool{true, true, true})
}

// TestSealPDFAutoPlacement — гарын үсэггүй баримт, автомат байршил (x = 612 − 220 − 36, y = 36): чөлөөтэй → requested;
// footer-тэй → moved; бүтэн хуудас бичвэр → overlap (баруун доод буланд). Verify хуудас нэмэгдэхгүй.
func TestSealPDFAutoPlacement(t *testing.T) {
	f := newSealFixture(t, 88012)
	cases := []struct {
		input string
		pages int
		want  Placement
	}{
		{"quartz-pdf13.pdf", 1, Placement{Page: 1, X: 356, Y: 36, Width: 220, Height: 64, Status: "requested"}},
		{"libreoffice-contract.pdf", 2, Placement{Page: 2, X: 356, Y: 60, Width: 220, Height: 64, Status: "moved"}},
		{"full-page.pdf", 1, Placement{Page: 1, X: 356, Y: 36, Width: 220, Height: 64, Status: "overlap"}},
	}
	for _, c := range cases {
		t.Run(c.input, func(t *testing.T) {
			res := f.seal(t, readInput(t, c.input), SealOptions{})
			if res.HasPage || res.RevIndex != 1 || pageCount(t, res.PDF) != c.pages {
				t.Fatalf("page=%v rev=%d pages=%d", res.HasPage, res.RevIndex, pageCount(t, res.PDF))
			}
			wantPlacement(t, res.Placement, c.want)
			f.wantAllValid(t, res.PDF, []string{"seal"}, []bool{true})
		})
	}
}

// TestSealPDFExplicitAppearance — дуудагч байршлыг өгнө (иргэний Appearance-тэй ижил): Exact нь хэзээ ч шилжихгүй,
// Exact биш нь PLACEMENT_SPEC-ээр; иргэний гарын үсэгтэй баримт дээр хоёулаа Valid.
func TestSealPDFExplicitAppearance(t *testing.T) {
	f := newSealFixture(t, 88013)
	signed, _ := citizenVisible(t, f.p, readInput(t, "libreoffice-contract.pdf"), "")
	exact := f.seal(t, signed.PDF, SealOptions{Appearance: &Appearance{Page: 1, X: 36, Y: 600, Width: 200, Height: 60, Lang: "en", Exact: true}})
	if pl := exact.Placement; pl == nil || pl.Page != 1 || pl.X != 36 || pl.Y != 600 || pl.Width != 200 || pl.Height != 60 || pl.Status == "moved" {
		t.Errorf("exact: %+v", pl)
	}
	f.wantAllValid(t, exact.PDF, []string{"sign", "seal"}, []bool{true, true})
	// Тодорхой хуудас: 3 = иргэний verify хуудас (тодорхой дугаар хэвээр, PLACEMENT_SPEC §1a).
	onVerify := f.seal(t, signed.PDF, SealOptions{Appearance: &Appearance{Page: 3, X: 340, Y: 36, Width: 220, Height: 64}})
	if pl := onVerify.Placement; pl == nil || pl.Page != 3 {
		t.Errorf("page 3: %+v", pl)
	}
	f.wantAllValid(t, onVerify.PDF, []string{"sign", "seal"}, []bool{true, true})
}

// TestSealPDFInvisible — Invisible: өмнөх (v0.29) SealPDF-тэй байт-ижил: Sealer-т очих DTBS = хуучин Prepare-ийн
// (Appearance-гүй) DTBS (prepared PDF + signedAttrs ижил), Placement nil, дардасгүй.
func TestSealPDFInvisible(t *testing.T) {
	f := newSealFixture(t, 88014)
	for _, name := range []string{"quartz-pdf13.pdf", "libreoffice-contract.pdf"} {
		in := readInput(t, name)
		res := f.seal(t, in, SealOptions{Invisible: true, Appearance: &Appearance{X: 36, Y: 36, Width: 220, Height: 64}})
		so := sealOpts(f.p, f.leaf)
		old, err := Prepare(in, PrepareOptions{SignerCert: f.leaf.Raw, Chain: so.Chain, SignerName: so.SignerName, Reason: so.Reason,
			SigningTime: so.SigningTime})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(f.sealer.digest, old.DTBS) || res.Placement != nil {
			t.Fatalf("%s: DTBS differs from the pre-visible SealPDF (or placement %+v)", name, res.Placement)
		}
		f.wantAllValid(t, res.PDF, []string{"seal"}, []bool{false})
	}
}

// TestSealPDFSmallPages — автомат дардас жижиг хуудсанд (APPEARANCE_SPEC.md §6.4): 58 мм-ийн баримт (164 pt өргөн) →
// 156 × 64 pt, x = 4, харагдана; дардас багтахгүй жижиг хуудас → үл харагдах тамга (Placement nil), алдаагүй. Дуудагчийн
// өгсөн Appearance нь багтахгүй бол REQUEST_INVALID хэвээр.
func TestSealPDFSmallPages(t *testing.T) {
	f := newSealFixture(t, 88015)
	receipt := f.seal(t, smallPDF(t, 164, 600), SealOptions{})
	wantPlacement(t, receipt.Placement, Placement{Page: 1, X: 4, Y: 36, Width: 156, Height: 64, Status: "requested"})
	f.wantAllValid(t, receipt.PDF, []string{"seal"}, []bool{true})

	tiny := smallPDF(t, 40, 60)
	res := f.seal(t, tiny, SealOptions{})
	if res.Placement != nil {
		t.Fatalf("tiny page: placement %+v", res.Placement)
	}
	f.wantAllValid(t, res.PDF, []string{"seal"}, []bool{false})

	so := sealOpts(f.p, f.leaf)
	so.Appearance = &Appearance{X: 0, Y: 0, Width: 40, Height: 60}
	if _, err := SealPDF(context.Background(), f.sealer, "NTRMN-6235972", tiny, so); ErrorCode(err) != CodeRequestInvalid {
		t.Fatalf("explicit appearance on a tiny page: %v", err)
	}
}

// TestSealPDFVerifyPageFirst — verify хуудас эхэнд (VerifyPagePosition first): автомат дардас баримтын сүүлийн (verify
// биш) 3-р хуудсанд — хуудсыг нэг удаа шийдэж Prepare-д тодорхой дамжуулна.
func TestSealPDFVerifyPageFirst(t *testing.T) {
	f := newSealFixture(t, 88016)
	o := testOpts(f.p, f.p.citizen.cert)
	o.VerifyPagePosition = VerifyPageFirst
	prep, err := Prepare(readInput(t, "libreoffice-contract.pdf"), o)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := rsa.SignPKCS1v15(nil, f.p.citizen.key, crypto.SHA256, prep.DTBS)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := Complete(context.Background(), prep.State, sig, completeOpts(f.p))
	if err != nil {
		t.Fatal(err)
	}
	if pageCount(t, signed.PDF) != 3 {
		t.Fatalf("pages %d", pageCount(t, signed.PDF))
	}
	res := f.seal(t, signed.PDF, SealOptions{})
	if pl := res.Placement; pl == nil || pl.Page != 3 || pl.Width != 220 || pl.Height != 64 {
		t.Fatalf("placement %+v", pl)
	}
	f.wantAllValid(t, res.PDF, []string{"sign", "seal"}, []bool{false, true})
}

// padPDF — doc-д n байт өгөгдөлтэй, хаанаас ч заагдаагүй нэг stream объекттой incremental update (classic xref) нэмнэ.
func padPDF(t *testing.T, doc []byte, n int) []byte {
	t.Helper()
	r, err := dpdf.NewReader(bytes.NewReader(doc), int64(len(doc)))
	if err != nil {
		t.Fatal(err)
	}
	tr := r.Trailer()
	root, info := tr.Key("Root").GetPtr(), tr.Key("Info").GetPtr()
	num := tr.Key("Size").Int64()
	var prev int
	if _, err := fmt.Sscan(string(doc[bytes.LastIndex(doc, []byte("startxref"))+len("startxref"):]), &prev); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	b.Write(doc)
	b.WriteString("\n")
	off := b.Len()
	fmt.Fprintf(&b, "%d 0 obj\n<< /Length %d >>\nstream\n", num, n)
	b.Write(bytes.Repeat([]byte{'0'}, n))
	b.WriteString("\nendstream\nendobj\n")
	x := b.Len()
	infoRef := ""
	if tr.Key("Info").Kind() != dpdf.Null {
		infoRef = fmt.Sprintf(" /Info %d 0 R", info.GetID())
	}
	fmt.Fprintf(&b, "xref\n%d 1\n%010d 00000 n \ntrailer\n<< /Size %d /Root %d 0 R%s /Prev %d >>\nstartxref\n%d\n%%%%EOF\n",
		num, off, num+1, root.GetID(), infoRef, prev, x)
	return b.Bytes()
}

// TestSealPDFNearSizeLimit — оролт хэмжээний хязгаарт ойр: үл харагдах тамга багтах ч автомат дардасны фонт (~82 KB)
// гаралтыг хэтрүүлэх тул SealPDF анхдагч нь үл харагдах тамга руу шилжинэ (Placement nil, Valid); дуудагчийн
// Appearance-тэй бол PDF_TOO_LARGE хэвээр.
func TestSealPDFNearSizeLimit(t *testing.T) {
	f := newSealFixture(t, 88017)
	base := readInput(t, "quartz-pdf13.pdf")
	so := sealOpts(f.p, f.leaf)
	invisible := PrepareOptions{SignerCert: f.leaf.Raw, Chain: so.Chain, Reason: so.Reason, SigningTime: so.SigningTime}
	overhead := func(doc []byte, a *Appearance) int {
		t.Helper()
		o := invisible
		o.Appearance = a
		prep, err := Prepare(doc, o)
		if err != nil {
			t.Fatal(err)
		}
		st, err := decodeState(prep.State)
		if err != nil {
			t.Fatal(err)
		}
		return len(st.PDF) - len(doc)
	}
	probe := padPDF(t, base, 1000)
	inv, vis := overhead(probe, nil), overhead(probe, defaultSealAppearance(probe))
	if vis-inv < 40_000 {
		t.Fatalf("overheads: invisible %d, visible %d", inv, vis)
	}
	// len(doc) + inv ≤ MaxInputBytes < len(doc) + vis (Prepare: len(prepared) + 256 KiB ≤ MaxOutputBytes).
	target := MaxOutputBytes - (256 << 10) - (inv+vis)/2
	doc := padPDF(t, base, 1000+target-len(probe))
	if d := len(doc) - target; d < -100 || d > 100 || len(doc) > MaxInputBytes { // /Length, startxref digits differ slightly
		t.Fatalf("size %d, target %d, max %d", len(doc), target, MaxInputBytes)
	}
	o := invisible
	o.Appearance = defaultSealAppearance(doc)
	if _, err := Prepare(doc, o); ErrorCode(err) != CodePDFTooLarge {
		t.Fatalf("automatic stamp should not fit: %v", err)
	}
	res := f.seal(t, doc, SealOptions{})
	if res.Placement != nil {
		t.Fatalf("placement %+v", res.Placement)
	}
	f.wantAllValid(t, res.PDF, []string{"seal"}, []bool{false})
	so.Appearance = &Appearance{X: 340, Y: 36, Width: 220, Height: 64}
	if _, err := SealPDF(context.Background(), f.sealer, "NTRMN-6235972", doc, so); ErrorCode(err) != CodePDFTooLarge {
		t.Fatalf("explicit appearance: %v", err)
	}
}
