package validate

import (
	"bytes"
	"fmt"
	"maps"
	"testing"
)

// Хоёр дахь бие даасан review (2026-10-05). Аль нь засвараас ӨМНӨХ код дээр давтагдсаныг changelog-д
// тэмдэглэсэн. Fixture-үүд хоргүй орлуулагч (Text annotation, энгийн толь) ашиглана.

// knownSignatures — ангилагчийн түвшний тестэд Extract-ийг дуурайна: баримт доторх /ByteRange + /Contents-тэй,
// /Type нь Sig эсвэл байхгүй толь бүрийг «задалж шалгасан гарын үсэг» гэж бүртгэнэ (extract.go-ийн шүүлттэй ижил).
func knownSignatures(doc []byte) map[int][]int64 {
	known := map[int][]int64{}
	if v, err := openView(doc, newPDFBudget()); err == nil {
		for num, e := range v.xref {
			if !e.inUse() {
				continue
			}
			o, _ := v.get(num)
			d, _ := o.(pdfDict)
			br, _ := d["ByteRange"].(pdfArr)
			if t := d["Type"]; d["Contents"] == nil || br == nil || t != nil && t != pdfName("Sig") {
				continue
			}
			var r []int64
			for _, x := range br {
				n, _ := x.(int64)
				r = append(r, n)
			}
			known[num] = r
		}
	}
	return known
}

// bothProfiles — өргөн жагсаалтын тестүүд profileBroad-ийн дүнг шалгана. later() нь давхар profileOwnSigner-ээр
// ажиллуулж, нарийн горим өргөнөөс ХЭЗЭЭ Ч илүү зөвшөөрөхгүйг (өргөнд татгалзсан бүхэн нарийнд ч татгалзана)
// тохиолдол бүрд батална.
type bothProfiles struct{ broad, own *revisions }

func testRevisions(doc []byte) bothProfiles {
	known := knownSignatures(doc)
	return bothProfiles{newRevisions(doc, known, profileBroad), newRevisions(doc, known, profileOwnSigner)}
}

func (b bothProfiles) later(end int64) LaterChanges {
	got := b.broad.later(end)
	if own := b.own.later(end); own.SignaturesOnly && (!got.SignaturesOnly || own.Signatures != got.Signatures || own.Visible) {
		panic(fmt.Sprintf("profileOwnSigner %+v зөвшөөрсөн боловч profileBroad %+v", own, got))
	}
	return got
}

func TestLaterChangesSecondReview(t *testing.T) {
	merge := func(ms ...map[int]string) map[int]string {
		out := map[int]string{}
		for _, m := range ms {
			maps.Copy(out, m)
		}
		return out
	}
	const (
		sig       = "<</Type/Sig/Filter/Adobe.PPKLite/ByteRange[0 100000 100010 100000]/Contents<00>>>"
		page      = "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R"
		textAnnot = "<</Type/Annot/Subtype/Text/Rect[10 10 30 30]/Contents(note)>>"
		catalog   = "<</Type/Catalog/Pages 2 0 R"
		twoPages  = "<</Type/Pages/Count 2/Kids[3 0 R 6 0 R]>>"
		page6     = "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R"
	)
	widget := func(extra string) string { return "<</Type/Annot/Subtype/Widget/FT/Sig/T(S)/V 20 0 R" + extra + ">>" }
	indirectAnnots := map[int]string{3: page + "/Annots 5 0 R>>", 5: "[]"}
	cases := []struct {
		name string
		base map[int]string
		rev  rev
		want LaterChanges
	}{
		// S1. done нь үүрэг хооронд хуваалцагддаг байсан.
		{"S1: дүрслэлийн дэд модонд орсон массив хуудасны /Annots болж, гарын үсэг биш annotation нэмсэн", nil,
			rev{objs: merge(sigObjs("/Rect[0 0 9 9]/AP<</N 23 0 R>>", ""), map[int]string{
				3:  page + "/Annots 30 0 R>>",
				23: stream("/Type/XObject/Subtype/Form/BBox[0 0 9 9]/Resources<</Properties<</P 30 0 R>>>>", "q Q"),
				30: "[31 0 R]", 31: textAnnot,
			})}, LaterChanges{}},
		{"S1: хуучин /Annots массивыг (өөрчлөгдөөгүй) DSS-ийн шинэ үүрэгт ашигласан", indirectAnnots,
			rev{objs: map[int]string{1: catalog + "/DSS<</Certs 5 0 R>>>>"}}, LaterChanges{}},
		{"S1: хуучин stream-ийг (өөрчлөгдөөгүй) LTV stream болгож DSS-т нэмсэн", nil,
			rev{objs: map[int]string{1: catalog + "/DSS<</Certs[4 0 R]>>>>"}}, LaterChanges{}},
		{"S1: шинэ widget-ийн /AP хуучин (өөрчлөгдөөгүй) stream руу", nil,
			rev{objs: sigObjs("/Rect[0 0 9 9]/AP<</N 4 0 R>>", "")}, LaterChanges{}},
		{"S1 хяналт: шууд бус /Annots массивт гарын үсгийн widget нэмэгдсэн", indirectAnnots,
			rev{objs: merge(sigObjs("/Rect[10 10 50 50]", ""), map[int]string{5: "[21 0 R]"})}, LaterChanges{true, 1, true}},
		{"S1 хяналт: суурийн DSS массив + VRI ижил массивыг заасан", map[int]string{1: catalog + "/DSS<</Certs 5 0 R/VRI<</AB<</Cert 5 0 R>>>>>>>>", 5: "[7 0 R]", 7: stream("", "DER")},
			rev{objs: map[int]string{5: "[7 0 R 22 0 R]", 22: stream("", "DER2")}}, LaterChanges{true, 0, false}},

		// S2. /Type /DocTimeStamp-ийг Extract шалгадаггүй.
		{"S2: дараагийн «гарын үсэг» нь DocTimeStamp", nil,
			rev{objs: merge(sigObjs("", ""), map[int]string{20: "<</Type/DocTimeStamp/Filter/Adobe.PPKLite/SubFilter/ETSI.RFC3161/ByteRange[0 100000 100010 100000]/Contents<00>>>"})}, LaterChanges{}},

		// S3. appended() объектын төрлийг шалгадаггүй байсан.
		{"S3: хуудас биш толь /Annots авсан", map[int]string{3: page + "/Resources<</Properties<</X 9 0 R>>>>>>", 9: "<</Foo 1>>"},
			rev{objs: merge(sigObjs("", ""), map[int]string{9: "<</Foo 1/Annots[21 0 R]>>"})}, LaterChanges{}},
		{"S3: хуудас биш толь /Annots авсан (widget /P-гүй)", map[int]string{3: page + "/Resources<</Properties<</X 9 0 R>>>>>>", 9: "<</Foo 1>>"},
			rev{objs: merge(sigObjs("", ""), map[int]string{9: "<</Foo 1/Annots[21 0 R]>>", 21: widget("")})}, LaterChanges{}},
		{"S3: /Annots массивыг хоёр хуудас хуваалцсан (widget /P-гүй)", map[int]string{2: twoPages, 3: page + "/Annots 5 0 R>>", 5: "[]", 6: page6 + "/Annots 5 0 R>>"},
			rev{objs: merge(sigObjs("", ""), map[int]string{5: "[21 0 R]", 21: widget("/Rect[1 1 9 9]")})}, LaterChanges{}},
		{"S3: шууд бус /Kids массивт widget нэмэгдсэн", map[int]string{2: "<</Type/Pages/Count 1/Kids 5 0 R>>", 5: "[3 0 R]"},
			rev{objs: merge(sigObjs("", ""), map[int]string{5: "[3 0 R 21 0 R]"})}, LaterChanges{}},
		{"S3: /Annots массивыг өөр объект (хоёр дахь хуудас) давхар заасан", map[int]string{2: twoPages, 3: page + "/Annots 5 0 R>>", 5: "[]", 6: page6 + "/Annots 5 0 R>>"},
			rev{objs: merge(sigObjs("/Rect[1 1 9 9]", ""), map[int]string{5: "[21 0 R]"})}, LaterChanges{}},
		{"S3: /Annots массивыг хуудас биш объект давхар заасан", map[int]string{3: page + "/Annots 5 0 R/Resources<</Properties<</X 9 0 R>>>>>>", 5: "[]", 9: "<</Other 5 0 R>>"},
			rev{objs: merge(sigObjs("/Rect[1 1 9 9]", ""), map[int]string{5: "[21 0 R]"})}, LaterChanges{}},
		{"S3: хуудасны модонд байхгүй /Type /Page толь /Annots авсан", map[int]string{3: page + "/Resources<</Properties<</X 9 0 R>>>>>>", 9: page + ">>"},
			rev{objs: merge(sigObjs("/Rect[1 1 9 9]", ""), map[int]string{9: page + "/Annots[21 0 R]>>"})}, LaterChanges{}},

		// Тэмдэглэлүүд.
		{"Perms: хуучин, Sig биш объект руу", nil, rev{objs: sigObjs("", "/Perms<</DocMDP 4 0 R>>")}, LaterChanges{}},
		{"Perms хяналт: шинэ гарын үсгийн толь руу", nil, rev{objs: sigObjs("", "/Perms<</DocMDP 20 0 R>>")}, LaterChanges{true, 1, false}},
		{"Perms хяналт: суурьт байсан /Perms хэвээр", map[int]string{1: catalog + "/Perms<</DocMDP 9 0 R>>>>", 9: "<</Type/Sig>>"},
			rev{objs: sigObjs("", "/Perms<</DocMDP 9 0 R>>")}, LaterChanges{true, 1, false}},
		{"SigFlags: 1, 3-аас өөр утга", nil, rev{objs: merge(sigObjs("", ""), map[int]string{1: catalog + "/AcroForm<</Fields[21 0 R]/SigFlags 2>>>>"})}, LaterChanges{}},
		{"SigFlags: буурсан (3 → 1)", map[int]string{1: catalog + "/AcroForm<</Fields[]/SigFlags 3>>>>"},
			rev{objs: merge(sigObjs("", ""), map[int]string{1: catalog + "/AcroForm<</Fields[21 0 R]/SigFlags 1>>>>"})}, LaterChanges{}},
		{"SigFlags: хасагдсан", map[int]string{1: catalog + "/AcroForm<</Fields[]/SigFlags 3>>>>"},
			rev{objs: merge(sigObjs("", ""), map[int]string{1: catalog + "/AcroForm<</Fields[21 0 R]>>>>"})}, LaterChanges{}},
		{"SigFlags хяналт: 1 → 3", map[int]string{1: catalog + "/AcroForm<</Fields[]/SigFlags 1>>>>"}, rev{objs: sigObjs("", "")}, LaterChanges{true, 1, false}},
		{"нэг Sig толийг хоёр талбар /V-ээр заасан", nil,
			rev{objs: merge(sigObjs("", ""), map[int]string{1: catalog + "/AcroForm<</Fields[21 0 R 25 0 R]/SigFlags 3>>>>", 25: widget("")})}, LaterChanges{}},
		{"widget /P хуудас биш объект руу", nil, rev{objs: merge(sigObjs("", ""), map[int]string{21: widget("/P 2 0 R")})}, LaterChanges{}},
		{"widget /P өөр хуудас руу (өөр хуудасны /Annots-д орсон)", map[int]string{2: twoPages, 6: page6 + ">>"},
			rev{objs: merge(sigObjs("", ""), map[int]string{21: widget("/Rect[1 1 9 9]/P 3 0 R"), 6: page6 + "/Annots[21 0 R]>>"})}, LaterChanges{}},
		{"нэг widget хоёр хуудасны /Annots-д", map[int]string{2: twoPages, 6: page6 + ">>"},
			rev{objs: merge(sigObjs("", ""), map[int]string{21: widget("/Rect[1 1 9 9]"), 3: page + "/Annots[21 0 R]>>", 6: page6 + "/Annots[21 0 R]>>"})}, LaterChanges{}},
		{"нэг widget нэг /Annots-д хоёр удаа", nil,
			rev{objs: merge(sigObjs("", ""), map[int]string{21: widget("/Rect[1 1 9 9]"), 3: page + "/Annots[21 0 R 21 0 R]>>"})}, LaterChanges{}},
		{"widget хяналт: /P нь /Annots-д орсон хуудас", map[int]string{2: twoPages, 6: page6 + ">>"},
			rev{objs: merge(sigObjs("", ""), map[int]string{21: widget("/Rect[1 1 9 9]/P 6 0 R"), 6: page6 + "/Annots[21 0 R]>>"})}, LaterChanges{true, 1, true}},
		{"ByteRange 0-ээс эхлээгүй", nil, rev{objs: merge(sigObjs("", ""), map[int]string{20: "<</Type/Sig/ByteRange[5 100000 100010 100000]/Contents<00>>>"})}, LaterChanges{}},
		{"ByteRange a ≥ b", nil, rev{objs: merge(sigObjs("", ""), map[int]string{20: "<</Type/Sig/ByteRange[0 100010 100000 100020]/Contents<00>>>"})}, LaterChanges{}},
		{"ByteRange бодит тоотой", nil, rev{objs: merge(sigObjs("", ""), map[int]string{20: "<</Type/Sig/ByteRange[0 100000.0 100010 100000]/Contents<00>>>"})}, LaterChanges{}},
		{"нэмэгдсэн объект дотор тайлбар", nil, rev{objs: merge(sigObjs("", ""), map[int]string{21: "<</Type/Annot%c\n/Subtype/Widget/FT/Sig/T(S)/V 20 0 R>>"})}, LaterChanges{}},
		{"нэмэгдсэн объект дотор NUL", nil, rev{objs: merge(sigObjs("", ""), map[int]string{21: "<</Type/Annot\x00/Subtype/Widget/FT/Sig/T(S)/V 20 0 R>>"})}, LaterChanges{}},
		{"хяналт", nil, rev{objs: merge(sigObjs("", ""), map[int]string{20: sig, 21: widget("/P 3 0 R")})}, LaterChanges{true, 1, false}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := shadowBase(tc.base)
			doc := appendRev(t, base, tc.rev)
			if got := testRevisions(doc).later(int64(len(base))); got != tc.want {
				t.Fatalf("авсан %+v, хүлээсэн %+v", got, tc.want)
			}
		})
	}
}

// Нэмэгдсэн хэсгийн trailer: тайлбар/NUL, танихгүй түлхүүр, суурьт байсан /Info-г орхих.
func TestLaterChangesAppendedTrailer(t *testing.T) {
	base := bytes.Replace(shadowBase(map[int]string{9: "<</Producer(x)>>"}), []byte("/Size 40/Root 1 0 R"), []byte("/Size 40/Info 9 0 R/Root 1 0 R"), 1)
	plain := appendRev(t, base, rev{objs: sigObjs("", "")})
	tail := func(old, new string) []byte {
		out := append(bytes.Clone(base), bytes.Replace(plain[len(base):], []byte(old), []byte(new), 1)...)
		if bytes.Equal(out, plain) {
			t.Fatalf("fixture өөрчлөгдсөнгүй: %q", old)
		}
		return out
	}
	if got := testRevisions(plain).later(int64(len(base))); got != (LaterChanges{true, 1, false}) {
		t.Fatalf("хяналт: %+v", got)
	}
	cases := map[string][]byte{
		"суурьт байсан /Info орхигдсон":     tail("  /Info 9 0 R\n", ""),
		"/Info өөр объект руу":              tail("  /Info 9 0 R\n", "  /Info 4 0 R\n"),
		"trailer ба толийн хооронд тайлбар": tail("trailer\n<<\n", "trailer\n%c\n<<\n"),
		"trailer толь дотор NUL":            tail("  /Root", "\x00  /Root"),
		"танихгүй trailer түлхүүр":          tail("  /Root", "  /Foo 1\n  /Root"),
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := testRevisions(doc).later(int64(len(base))); got != (LaterChanges{}) {
				t.Fatalf("зөвшөөрөгдлөө: %+v", got)
			}
		})
	}
}

// S2. later_signatures-д тоологдсон толь бүр Extract-ийн буцаасан (задалж, криптографаар шалгасан) гарын
// үсэгтэй нэг бүрчлэн таарах ёстой.
func TestLaterChangesRequireExtractedSignature(t *testing.T) {
	base := shadowBase(nil)
	doc := appendRev(t, base, rev{objs: sigObjs("", "")})
	for name, known := range map[string]map[int][]int64{
		"Extract буцаагаагүй": {},
		"өөр объект":          {21: {0, 100000, 100010, 100000}},
		"ByteRange таарахгүй": {20: {0, 100000, 100010, 99999}},
		"задраагүй (хоосон)":  {20: nil},
	} {
		if got := newRevisions(doc, known, profileBroad).later(int64(len(base))); got != (LaterChanges{}) {
			t.Fatalf("%s: зөвшөөрөгдлөө: %+v", name, got)
		}
	}
	if got := newRevisions(doc, map[int][]int64{20: {0, 100000, 100010, 100000}}, profileBroad).later(int64(len(base))); got != (LaterChanges{true, 1, false}) {
		t.Fatalf("хяналт: %+v", got)
	}
}

// Нэмэгдсэн xref stream-ийн толь болон ObjStm доторх объектод тайлбар нуух.
func TestLaterChangesStrictXrefStreamAndObjStm(t *testing.T) {
	base := shadowBase(nil)
	objs := sigObjs("", "")
	delete(objs, 21)
	const widget = "<</Type/Annot/Subtype/Widget/FT/Sig/T(S)/V 20 0 R>>"
	plain := appendRev(t, base, rev{objs: objs, compressed: map[int]string{21: widget}})
	if got := testRevisions(plain).later(int64(len(base))); got != (LaterChanges{true, 1, false}) {
		t.Fatalf("хяналт: %+v", got)
	}
	inXref := append(bytes.Clone(base), bytes.Replace(plain[len(base):], []byte("<</Type/XRef"), []byte("<<%c\n/Type/XRef"), 1)...)
	inObjStm := appendRev(t, base, rev{objs: objs, compressed: map[int]string{21: "<</Type/Annot%c\n/Subtype/Widget/FT/Sig/T(S)/V 20 0 R>>"}})
	for name, doc := range map[string][]byte{"xref stream-ийн толь дотор тайлбар": inXref, "ObjStm доторх объектод тайлбар": inObjStm} {
		if bytes.Equal(doc, plain) {
			t.Fatal("fixture өөрчлөгдсөнгүй")
		}
		if got := testRevisions(doc).later(int64(len(base))); got != (LaterChanges{}) {
			t.Fatalf("%s: зөвшөөрөгдлөө: %+v", name, got)
		}
	}
}
