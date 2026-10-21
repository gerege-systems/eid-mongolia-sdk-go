package pades

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSuggestPlacementErrors — the checks SuggestPlacement shares with Prepare (PLACEMENT_SPEC.md §6b).
func TestSuggestPlacementErrors(t *testing.T) {
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(goldenDir, "input", name)) // #nosec G304 -- тест
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	table, enc := read("table-bottom.pdf"), read("encrypted.pdf")
	a := Appearance{X: 340, Y: 36, Width: 220, Height: 64}
	for _, tc := range []struct {
		name string
		doc  []byte
		a    Appearance
		code string
	}{
		{"not-pdf", []byte("hello"), a, CodePDFInvalid},
		{"encrypted", enc, a, CodePDFEncrypted},
		{"page-beyond", table, Appearance{Page: 2, X: 340, Y: 36, Width: 220, Height: 64}, CodeRequestInvalid},
		{"outside", table, Appearance{X: 400, Y: 36, Width: 220, Height: 64, Exact: true}, CodeRequestInvalid},
		{"outside-auto", table, Appearance{X: 400, Y: 36, Width: 220, Height: 64}, CodeRequestInvalid},
		{"negative", table, Appearance{X: -1, Y: 36, Width: 220, Height: 64}, CodeRequestInvalid},
		{"zero-size", table, Appearance{X: 1, Y: 36, Width: 0, Height: 64}, CodeRequestInvalid},
	} {
		if _, err := SuggestPlacement(tc.doc, tc.a); ErrorCode(err) != tc.code {
			t.Errorf("%s: %v, want %s", tc.name, err, tc.code)
		}
	}
	s, err := SuggestPlacement(table, Appearance{X: 340, Y: 36, Width: 220, Height: 64, Exact: true})
	if err != nil || s.Status != "overlap" || s.X != 340 || s.Y != 36 || s.PageCount != 1 || len(s.Pages) != 1 {
		t.Errorf("exact: %+v %v", s, err)
	}
}
