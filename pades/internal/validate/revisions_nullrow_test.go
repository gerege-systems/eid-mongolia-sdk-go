package validate

import (
	"bytes"
	"fmt"
	"testing"
)

// macOS Quartz ашиглагдаагүй дугаарыг «0000000000 00000 n» (байрлал 0 = файлын толгой) гэж бичдэг. Ийм мөр
// тодорхойлогдоогүй объект (ISO 32000-1 §7.3.10): хүчинтэй LTV revision-ийг унагахгүй, гэхдээ тэр дугаараар
// shadow хийх, ашиглагдаж буй объектыг ийм мөрөөр «устгах»-ыг зөвшөөрөхгүй.
func TestLaterChangesNullXrefRow(t *testing.T) {
	nullRow := func(extra map[int]string) []byte {
		b := shadowBase(extra)
		return bytes.Replace(b, []byte("0000000000 65535 f \n"), []byte("0000000000 65535 f \n9 1\n0000000000 00000 n \n"), 1)
	}
	if v, err := openView(nullRow(nil), newPDFBudget()); err != nil || v.xref[9].inUse() {
		t.Fatalf("байрлал 0-ийн мөр ашиглагдаж буйд тооцогдов: %v", err)
	}
	dss := map[int]string{1: "<</Type/Catalog/Pages 2 0 R/DSS<</Certs[22 0 R]>>>>", 22: stream("", "DER")}
	page9 := map[int]string{3: "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents[4 0 R 9 0 R]>>"}
	cases := []struct {
		name string
		base map[int]string
		rev  rev
		want LaterChanges
	}{
		{"хяналт: DSS revision", nil, rev{objs: dss}, LaterChanges{true, 0, false}},
		{"хяналт: гарын үсэг", nil, rev{objs: sigObjs("/Rect[0 0 0 0]", "")}, LaterChanges{true, 1, false}},
		{"тэг мөрийн дугаар руу суурь заасан, хожим DSS stream-ээр бөглөсөн", page9,
			rev{objs: map[int]string{1: dss[1], 9: stream("", "BT (evil) Tj ET"), 22: dss[22]}}, LaterChanges{}},
		{"тэг мөрийн дугаарыг хожим үүрэггүй объектоор тодорхойлсон", nil,
			rev{objs: map[int]string{1: dss[1], 9: stream("", "BT (evil) Tj ET"), 22: dss[22]}}, LaterChanges{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := nullRow(tc.base)
			if got := testRevisions(appendRev(t, base, tc.rev)).later(int64(len(base))); got != tc.want {
				t.Fatalf("авсан %+v, хүлээсэн %+v", got, tc.want)
			}
		})
	}
	// Хожмын хэсэг ашиглагдаж буй объектыг (4 — хуудасны агуулга) байрлал 0-ийн «n» мөрөөр «устгасан».
	t.Run("ашиглагдаж буй объектыг тэг мөрөөр устгасан", func(t *testing.T) {
		base := nullRow(nil)
		f := newFixture(t, base)
		b := bytes.NewBuffer(bytes.Clone(base))
		x := b.Len()
		fmt.Fprintf(b, "xref\n4 1\n0000000000 00000 n \ntrailer\n<</Size 40/Root 1 0 R/Prev %d>>\nstartxref\n%d\n%%%%EOF\n", f.v.sections[0].off, x)
		if got := testRevisions(b.Bytes()).later(int64(len(base))); got != (LaterChanges{}) {
			t.Fatalf("зөвшөөрөгдлөө: %+v", got)
		}
	})
}
