package validate

import (
	"fmt"
	"maps"
	"testing"
)

// TestSealImprintEveryPageShapes — experiment (2026-11-24): can ONE later signature revision (an organisation e-Seal
// after a citizen signature) put an imprint at the bottom-right of EVERY page without the earlier signature turning
// modified_after_signing? Two-page base, one signature revision on top, both profiles (testRevisions → later()).
//
// Already covered elsewhere (cited, not rebuilt):
//   - one merged field/widget listed in the /Annots of two pages → rejected (revisions_review2_test.go:135);
//   - one widget twice in one /Annots → rejected (revisions_review2_test.go:137);
//   - a non-signature Text annotation added via /Annots in the signature's own revision → rejected
//     (revisions_review2_test.go:82);
//   - a new content stream / overwritten content stream / FreeText annotation in a revision between two real
//     signatures → modified in both profiles (revisions_test.go:367, :377, :391);
//   - a page re-written in the signature revision with any key besides /Annots → rejected (revisions_own_test.go:164).
//
// Built here: the remaining every-page shapes in the signature's own revision.
func TestSealImprintEveryPageShapes(t *testing.T) {
	const (
		page     = "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]"
		twoPages = "<</Type/Pages/Count 2/Kids[3 0 R 6 0 R]>>"
		catalog  = "<</Type/Catalog/Pages 2 0 R/AcroForm<</Fields[21 0 R]/SigFlags 3>>>>"
		sig      = "<</Type/Sig/Filter/Adobe.PPKLite/ByteRange[0 100000 100010 100000]/Contents<00>>>"
		rect     = "/Rect[340 36 560 100]"
	)
	base := map[int]string{2: twoPages, 3: page + "/Contents 4 0 R>>", 6: page + "/Contents 4 0 R>>"}
	merge := func(ms ...map[int]string) map[int]string {
		out := map[int]string{}
		for _, m := range ms {
			maps.Copy(out, m)
		}
		return out
	}
	kid := func(pg int) string {
		return fmt.Sprintf("<</Type/Annot/Subtype/Widget/Parent 21 0 R%s/P %d 0 R/F 4>>", rect, pg)
	}
	stampAnnot := func(pg int) string {
		return fmt.Sprintf("<</Type/Annot/Subtype/Stamp%s/P %d 0 R/F 4/Contents(e-Seal)>>", rect, pg)
	}
	cases := []struct {
		name string
		objs map[int]string
		want LaterChanges
	}{
		// Control: one visible signature widget on one page (the V1/V2 shape, per page) is a signature-only extension,
		// reported as visible_later_signature.
		{"control: one visible widget on page 2", merge(sigObjs("", ""), map[int]string{
			21: "<</Type/Annot/Subtype/Widget/FT/Sig/T(Signature 1)/V 20 0 R" + rect + "/P 6 0 R/F 4>>",
			6:  page + "/Contents 4 0 R/Annots[21 0 R]>>",
		}), LaterChanges{true, 1, true}},
		// V3: one signature field whose /Kids are one widget per page — the field may not have /Kids and a widget with
		// /Parent has no allowed role → modified_after_signing for the earlier signature.
		{"V3: one seal field, /Kids = one widget per page", map[int]string{
			1: catalog, 20: sig,
			21: "<</FT/Sig/T(Signature 1)/V 20 0 R/Kids[22 0 R 23 0 R]>>", 22: kid(3), 23: kid(6),
			3: page + "/Contents 4 0 R/Annots[22 0 R]>>", 6: page + "/Contents 4 0 R/Annots[23 0 R]>>",
		}, LaterChanges{}},
		// V4a: invisible seal + the imprint appended to every page's /Contents in the same revision → rejected.
		{"V4a: imprint as page content on every page", merge(sigObjs("", ""), map[int]string{
			3:  page + "/Contents[4 0 R 30 0 R]>>",
			6:  page + "/Contents[4 0 R 30 0 R]>>",
			30: stream("", "q 1 0 0 RG 340 36 220 64 re S Q"),
		}), LaterChanges{}},
		// V4b: invisible seal + a /Stamp annotation on every page in the same revision → rejected.
		{"V4b: /Stamp annotation on every page", merge(sigObjs("", ""), map[int]string{
			3:  page + "/Contents 4 0 R/Annots[31 0 R]>>",
			6:  page + "/Contents 4 0 R/Annots[32 0 R]>>",
			31: stampAnnot(3), 32: stampAnnot(6),
		}), LaterChanges{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := shadowBase(base)
			doc := appendRev(t, b, rev{objs: tc.objs})
			if got := testRevisions(doc).later(int64(len(b))); got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}
