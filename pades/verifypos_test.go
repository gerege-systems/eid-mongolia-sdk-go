package pades

import (
	"bytes"
	"testing"

	"github.com/digitorus/pdf"
)

// outPages — the output's pages in /Pages order: whether each is this document's verify page and how many signature
// widgets it carries.
func outPages(t *testing.T, doc []byte, docID string) (verify []bool, widgets []int) {
	t.Helper()
	r, err := pdf.NewReader(bytes.NewReader(doc), int64(len(doc)))
	if err != nil {
		t.Fatal(err)
	}
	var walk func(v pdf.Value)
	walk = func(v pdf.Value) {
		if v.Key("Type").Name() == "Pages" {
			for i := range v.Key("Kids").Len() {
				walk(v.Key("Kids").Index(i))
			}
			return
		}
		isV, n := false, 0
		an := v.Key("Annots")
		for i := range an.Len() {
			a := an.Index(i)
			switch a.Key("Subtype").Name() {
			case "Link":
				isV = isV || a.Key("A").Key("URI").RawString() == pageVerifyURL+docID
			case "Widget":
				n++
			}
		}
		verify, widgets = append(verify, isV), append(widgets, n)
	}
	walk(r.Trailer().Key("Root").Key("Pages"))
	return verify, widgets
}

// TestVerifyPagePosition — PAGE_SPEC §8a / PLACEMENT_SPEC §1b: "first" puts the verify page at page 1, appearance and
// placement page numbers stay the input's, "last"/empty are byte-identical, a bad value is REQUEST_INVALID.
func TestVerifyPagePosition(t *testing.T) {
	p := loadOrCreatePKI(t)
	doc := readInput(t, "libreoffice-contract.pdf") // 2 pages
	base := func(pos string, a *Appearance) PrepareOptions {
		o := testOpts(p, p.citizen.cert)
		o.DocID, o.VerifyPagePosition, o.Appearance = "0a1b2c3d-4e5f-4a6b-8c7d-8e9fa0b1c2d3", pos, a
		return o
	}
	state := func(o PrepareOptions, in []byte) (*Prepared, *prepState) {
		t.Helper()
		prep, err := Prepare(in, o)
		if err != nil {
			t.Fatal(err)
		}
		st, err := decodeState(prep.State)
		if err != nil {
			t.Fatal(err)
		}
		return prep, st
	}
	_, def := state(base("", nil), doc)
	_, last := state(base(VerifyPageLast, nil), doc)
	if !bytes.Equal(def.PDF, last.PDF) {
		t.Fatal(`"last" differs from the default`)
	}
	if v, _ := outPages(t, def.PDF, "0a1b2c3d-4e5f-4a6b-8c7d-8e9fa0b1c2d3"); len(v) != 3 || v[0] || !v[2] {
		t.Fatalf("default: verify pages %v", v)
	}
	_, first := state(base(VerifyPageFirst, nil), doc)
	if v, _ := outPages(t, first.PDF, "0a1b2c3d-4e5f-4a6b-8c7d-8e9fa0b1c2d3"); len(v) != 3 || !v[0] || v[1] || v[2] {
		t.Fatalf("first: verify pages %v", v)
	}
	// An invisible signature's widget goes on output page 1 (core firstPage) — with "first" that is the verify page.
	if _, w := outPages(t, first.PDF, "0a1b2c3d-4e5f-4a6b-8c7d-8e9fa0b1c2d3"); w[0] != 1 {
		t.Fatalf("first: invisible widget per page %v", w)
	}

	stamp := func(page int) *Appearance { return &Appearance{Page: page, X: 340, Y: 36, Width: 220, Height: 64} }
	for _, c := range []struct{ in, want int }{{0, 2}, {1, 1}, {2, 2}} {
		prep, st := state(base(VerifyPageFirst, stamp(c.in)), doc)
		if prep.Placement.Page != c.want {
			t.Errorf("page %d: placement.page %d, want %d (input numbering)", c.in, prep.Placement.Page, c.want)
		}
		_, w := outPages(t, st.PDF, prep.DocID)
		if w[c.want] != 1 || w[0]+w[1]+w[2] != 1 {
			t.Errorf("page %d: widgets per output page %v, want one on output page %d", c.in, w, c.want+1)
		}
		// The same stamp with the page last: identical placement.
		lp, _ := state(base("", stamp(c.in)), doc)
		if *lp.Placement != *prep.Placement {
			t.Errorf("page %d: placement first %+v ≠ last %+v", c.in, *prep.Placement, *lp.Placement)
		}
	}
	if _, err := Prepare(doc, base(VerifyPageFirst, stamp(3))); ErrorCode(err) != CodeRequestInvalid {
		t.Errorf("page 3 of a 2-page input: %v", err)
	}
	for _, bad := range []string{"middle", "First", " first"} {
		if _, err := Prepare(doc, base(bad, nil)); ErrorCode(err) != CodeRequestInvalid {
			t.Errorf("%q: %v", bad, err)
		}
	}
	// No page added → the option has no effect.
	np := base(VerifyPageFirst, nil)
	np.VerifyPage = false
	_, a := state(np, doc)
	np.VerifyPagePosition = ""
	_, b := state(np, doc)
	if !bytes.Equal(a.PDF, b.PDF) {
		t.Fatal("verifyPagePosition changed a document without a verify page")
	}
}
