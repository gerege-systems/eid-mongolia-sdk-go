package validate

import (
	"bytes"
	"maps"
	"testing"
)

// Бие даасан review-ийн олдворууд (2026-10-05). Аль нь засвараас ӨМНӨХ код дээр давтагдсаныг
// changelog-д тэмдэглэсэн; давтагдаагүй нь регрессийн тест болж үлдэнэ.

// applyRevs — суурь дээр revs-ийг дараалан нэмж, алхам бүрийн ӨМНӨХ уртыг буцаана.
func applyRevs(t *testing.T, base []byte, revs ...rev) (doc []byte, ends []int) {
	t.Helper()
	doc = base
	for _, r := range revs {
		ends = append(ends, len(doc))
		doc = appendRev(t, doc, r)
	}
	return doc, ends
}

func TestLaterChangesReviewFindings(t *testing.T) {
	merge := func(ms ...map[int]string) map[int]string {
		out := map[int]string{}
		for _, m := range ms {
			maps.Copy(out, m)
		}
		return out
	}
	const sig = "<</Type/Sig/Filter/Adobe.PPKLite/ByteRange[0 100000 100010 100000]/Contents<00>"
	widget := func(extra string) string {
		return "<</Type/Annot/Subtype/Widget/FT/Sig/T(Signature 1)/V 20 0 R/P 3 0 R" + extra + ">>"
	}
	page := "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R"
	form := stream("/Type/XObject/Subtype/Form/BBox[0 0 100 40]", "q Q")
	jsNames := "/Names<</JavaScript<</Names[(a)<</S/JavaScript/JS 22 0 R>>]>>>>"
	emptyField := func(annot string) map[int]string {
		return map[int]string{
			1:  "<</Type/Catalog/Pages 2 0 R/AcroForm<</Fields[10 0 R]>>>>",
			3:  page + "/Annots[10 0 R]>>",
			10: "<<" + annot + "/FT/Sig/T(Sig)/Rect[10 10 200 60]/P 3 0 R>>",
		}
	}
	original4 := stream("", "BT (signed) Tj ET")
	packedSig := sigObjs("", "") // widget (21)-гүй: тэр нь ObjStm дотор бичигдэнэ
	delete(packedSig, 21)
	cases := []struct {
		name string
		base map[int]string
		revs []rev
		want LaterChanges
	}{
		// 1. Зөвшөөрөл (эцэг → хүүхэд) нь түлхүүрийн замаар биш, объектын хосоор бүртгэгддэг байсан.
		{"1: Catalog-ийн шууд DSS + суурийн /Names JavaScript-ийн сул заалт", map[int]string{1: "<</Type/Catalog/Pages 2 0 R" + jsNames + ">>"},
			[]rev{{objs: map[int]string{1: "<</Type/Catalog/Pages 2 0 R" + jsNames + "/DSS<</Certs[22 0 R]>>>>", 22: stream("", "app.alert(1)")}}}, LaterChanges{}},
		{"1: шууд /Perms + суурийн /OpenAction-ийн сул заалт → Sig толь үйлдэл болно", map[int]string{1: "<</Type/Catalog/Pages 2 0 R/OpenAction 20 0 R>>"},
			[]rev{{objs: merge(sigObjs("/Rect[0 0 0 0]", "/OpenAction 20 0 R/Perms<</DocMDP 20 0 R>>"), map[int]string{20: sig + "/S/JavaScript/JS(app.alert(1))>>"})}}, LaterChanges{}},
		{"1: шууд AcroForm/Fields + суурийн /Outlines-ийн сул заалт", map[int]string{1: "<</Type/Catalog/Pages 2 0 R/Outlines 21 0 R>>"},
			[]rev{{objs: sigObjs("/Rect[0 0 0 0]", "/Outlines 21 0 R")}}, LaterChanges{}},
		{"1: суурийн өнчин объектын сул заалтыг хожим бөглөсөн", map[int]string{9: "<</Later 20 0 R>>"},
			[]rev{{objs: sigObjs("/Rect[0 0 0 0]", "")}}, LaterChanges{}},
		{"1: Sig толь зөвшөөрөгдөөгүй түлхүүртэй", nil,
			[]rev{{objs: merge(sigObjs("", ""), map[int]string{20: sig + "/S/JavaScript/JS(x)>>"})}}, LaterChanges{}},
		{"1: Sig толь хуучин объект руу заасан", nil,
			[]rev{{objs: merge(sigObjs("", ""), map[int]string{20: sig + "/Reference[<</TransformMethod/FieldMDP/Data 4 0 R>>]>>"})}}, LaterChanges{}},
		{"1: Sig толийн энгийн түлхүүр шууд бус заалттай", nil,
			[]rev{{objs: merge(sigObjs("", ""), map[int]string{20: sig + "/Prop_Build 4 0 R>>"})}}, LaterChanges{}},
		{"1: Sig толийн /Reference-д танихгүй түлхүүр", nil,
			[]rev{{objs: merge(sigObjs("", ""), map[int]string{20: sig + "/Reference[<</TransformMethod/FieldMDP/JS(x)>>]>>"})}}, LaterChanges{}},
		{"1 хяналт: Sig толийн зөвшөөрөгдсөн түлхүүрүүд, /Data → Catalog", nil,
			[]rev{{objs: merge(sigObjs("", ""), map[int]string{20: sig + "/SubFilter/adbe.pkcs7.detached/M(D:2026)/Name(N)/Reason(R)/Location(L)/Prop_Build<</App<</Name/X>>>>" +
				"/Reference[<</Type/SigRef/TransformMethod/FieldMDP/TransformParams<</Type/TransformParams/Action/All/V/1.2>>/DigestMethod/SHA256/Data 1 0 R>>]>>"})}}, LaterChanges{true, 1, false}},
		{"1: DSS stream /Type-тэй", nil,
			[]rev{{objs: map[int]string{1: "<</Type/Catalog/Pages 2 0 R/DSS<</Certs[22 0 R]>>>>", 22: stream("/Type/EmbeddedFile", "x")}}}, LaterChanges{}},
		{"1: DSS stream-ийг шинэ дүрслэл давхар заасан", nil,
			[]rev{{objs: merge(sigObjs("/Rect[0 0 9 9]/AP<</N 23 0 R>>", "/DSS<</Certs[22 0 R]>>"), map[int]string{
				22: stream("", "q Q"), 23: stream("/Type/XObject/Subtype/Form/BBox[0 0 9 9]/Resources<</XObject<</X 22 0 R>>>>", "/X Do"),
			})}}, LaterChanges{}},
		{"1: дүрслэл Sig толийг нөөц болгож давхар заасан", nil,
			[]rev{{objs: merge(sigObjs("/Rect[0 0 9 9]/AP<</N 23 0 R>>", ""), map[int]string{
				23: stream("/Type/XObject/Subtype/Form/BBox[0 0 9 9]/Resources<</ExtGState<</G 20 0 R>>>>", "q Q"),
			})}}, LaterChanges{}},
		{"4: гарын үсэггүй revision зөвхөн /Version өөрчилсөн", nil,
			[]rev{{objs: map[int]string{1: "<</Type/Catalog/Pages 2 0 R/Version/2.0>>"}}}, LaterChanges{}},
		{"1: бөглөгдсөн талбар нь widget биш (Stamp) давхар үүрэгтэй", emptyField("/Type/Annot/Subtype/Stamp"),
			[]rev{{objs: map[int]string{10: "<</Type/Annot/Subtype/Stamp/FT/Sig/T(Sig)/Rect[10 10 200 60]/P 3 0 R/V 20 0 R>>", 20: sig + ">>"}}}, LaterChanges{}},
		{"1: хаанаас ч заагдаагүй шинэ объект суулгасан", nil,
			[]rev{{objs: merge(sigObjs("", ""), map[int]string{30: stream("", "BT (planted) Tj ET")})}}, LaterChanges{}},
		{"1: widget-ийн /P шинэ объект руу", nil,
			[]rev{{objs: merge(sigObjs("", ""), map[int]string{21: "<</Type/Annot/Subtype/Widget/FT/Sig/V 20 0 R/P 22 0 R>>", 22: page + ">>"})}}, LaterChanges{}},

		// 2. Хэсэг хоорондын «сүүдэрлэгдсэн» тодорхойлолт: нийлүүлсэн xref-ээр бол өөрчлөгдөөгүй.
		{"2: завсрын revision агуулгыг сольж, дараагийнх нь буцаасан", nil,
			[]rev{{objs: map[int]string{4: stream("", "BT (EVIL) Tj ET")}}, {objs: merge(sigObjs("", ""), map[int]string{4: original4})}}, LaterChanges{}},
		{"2 хяналт: завсрын revision ижил утгаар дахин бичсэн", nil,
			[]rev{{objs: map[int]string{4: original4}}, {objs: merge(sigObjs("", ""), map[int]string{4: original4})}}, LaterChanges{true, 1, false}},
		{"2: ObjStm дотор xref-т бүртгэлгүй объект", nil,
			[]rev{{objs: packedSig, compressed: map[int]string{21: widget("")}, unlisted: map[int]string{4: "<</Hidden true>>"}}}, LaterChanges{}},
		{"2 хяналт: ObjStm-тэй гарын үсгийн revision (widget нь ObjStm дотор)", nil,
			[]rev{{objs: packedSig, compressed: map[int]string{21: widget("")}}}, LaterChanges{true, 1, false}},
		{"2: хуучин объектыг ObjStm руу зөөсөн (утга ижил ч хэлбэр өөр — fail closed)", nil,
			[]rev{{objs: sigObjs("", ""), compressed: map[int]string{3: page + ">>"}}}, LaterChanges{}},

		// 3. Бүхэл ба бодит тоо тэнцүү гэж үздэг байсан.
		{"3: /Rotate 90 → 90.0", map[int]string{3: page + "/Rotate 90>>"},
			[]rev{{objs: merge(sigObjs("", ""), map[int]string{3: page + "/Rotate 90.0>>"})}}, LaterChanges{}},

		// 4. /Version, /Extensions.
		{"4: /Version бууруулсан (толгой 1.7)", nil, []rev{{objs: sigObjs("", "/Version/1.4")}}, LaterChanges{}},
		{"4: /Version хэлбэр буруу", nil, []rev{{objs: sigObjs("", "/Version/2.0x")}}, LaterChanges{}},
		{"4: суурийн Catalog-ийн /Version-оос доош", map[int]string{1: "<</Type/Catalog/Pages 2 0 R/Version/2.0>>"}, []rev{{objs: sigObjs("", "/Version/1.7")}}, LaterChanges{}},
		{"4 хяналт: /Version өссөн", nil, []rev{{objs: sigObjs("", "/Version/2.0")}}, LaterChanges{true, 1, false}},
		{"4 хяналт: /Version толгойтой тэнцүү", nil, []rev{{objs: sigObjs("", "/Version/1.7")}}, LaterChanges{true, 1, false}},
		{"4: /Extensions нэмэгдсэн", nil, []rev{{objs: sigObjs("", "/Extensions<</ADBE<</BaseVersion/1.7/ExtensionLevel 8>>>>")}}, LaterChanges{}},
		{"4: /Extensions өөрчлөгдсөн", map[int]string{1: "<</Type/Catalog/Pages 2 0 R/Extensions<</ADBE<</BaseVersion/1.7/ExtensionLevel 3>>>>>>"},
			[]rev{{objs: sigObjs("", "/Extensions<</ADBE<</BaseVersion/1.7/ExtensionLevel 8>>>>")}}, LaterChanges{}},

		// 5. Объектуудын хоорондох NUL / тайлбар.
		{"5: объектуудын хооронд NUL", nil, []rev{{objs: sigObjs("", ""), raw: "\x00\x00"}}, LaterChanges{}},
		{"5: объектуудын хооронд тайлбар", nil, []rev{{objs: sigObjs("", ""), raw: "% 30 0 obj <<>> endobj\n"}}, LaterChanges{}},

		// 6. visible_later_signature.
		{"6: /AP + /Rect [0 0 0 0]", nil, []rev{{objs: merge(sigObjs("", ""), map[int]string{21: widget("/Rect[0 0 0 0]/AP<</N 22 0 R>>"), 22: form})}}, LaterChanges{true, 1, true}},
		{"6: /AP, /Rect-гүй", nil, []rev{{objs: merge(sigObjs("", ""), map[int]string{21: widget("/AP<</N 22 0 R>>"), 22: form})}}, LaterChanges{true, 1, true}},
		{"6: хоосон биш /Rect, /F Hidden", nil, []rev{{objs: merge(sigObjs("", ""), map[int]string{21: widget("/Rect[10 10 110 50]/F 2")})}}, LaterChanges{true, 1, true}},
		{"6: /AP + /F Hidden|NoView", nil, []rev{{objs: merge(sigObjs("", ""), map[int]string{21: widget("/Rect[0 0 0 0]/F 34/AP<</N 22 0 R>>"), 22: form})}}, LaterChanges{true, 1, true}},
		{"6: урвуу /Rect", nil, []rev{{objs: merge(sigObjs("", ""), map[int]string{21: widget("/Rect[110 50 10 10]")})}}, LaterChanges{true, 1, true}},
		{"6: бөглөгдсөн талбар /AP-тэй, суурьт Hidden", emptyField("/Type/Annot/Subtype/Widget/F 2"),
			[]rev{{objs: map[int]string{10: "<</Type/Annot/Subtype/Widget/F 2/FT/Sig/T(Sig)/Rect[10 10 200 60]/P 3 0 R/V 20 0 R/AP<</N 22 0 R>>>>", 20: sig + ">>", 22: form}}}, LaterChanges{true, 1, true}},
		{"6: бөглөгдсөн талбар /AP-гүй, суурийн /Rect хоосон биш", emptyField("/Type/Annot/Subtype/Widget"),
			[]rev{{objs: map[int]string{10: "<</Type/Annot/Subtype/Widget/FT/Sig/T(Sig)/Rect[10 10 200 60]/P 3 0 R/V 20 0 R>>", 20: sig + ">>"}}}, LaterChanges{true, 1, true}},
		{"6 хяналт: /Rect [0 0 0 0], /AP-гүй", nil, []rev{{objs: merge(sigObjs("", ""), map[int]string{21: widget("/Rect[0 0 0 0]")})}}, LaterChanges{true, 1, false}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := shadowBase(tc.base)
			doc, _ := applyRevs(t, base, tc.revs...)
			if got := testRevisions(doc).later(int64(len(base))); got != tc.want {
				t.Fatalf("авсан %+v, хүлээсэн %+v", got, tc.want)
			}
		})
	}
}

// 2. Classic xref-ийн мөр яг 20 байт биш (viewer «засаж» уншина).
func TestLaterChangesLooseXrefEntry(t *testing.T) {
	base := shadowBase(nil)
	doc := appendRev(t, base, rev{objs: sigObjs("", "")})
	if got := testRevisions(doc).later(int64(len(base))); got != (LaterChanges{true, 1, false}) {
		t.Fatalf("хяналт: %+v", got)
	}
	for name, repl := range map[string]string{"зайгүй": " 00000 n\n", "нэмэлт зай": " 00000 n  \n", "таб": " 00000\tn \n", "20 байт, LF LF": " 00000 n\n\n"} {
		loose := append(bytes.Clone(base), bytes.ReplaceAll(doc[len(base):], []byte(" 00000 n \n"), []byte(repl))...)
		if bytes.Equal(loose, doc) {
			t.Fatal("fixture өөрчлөгдсөнгүй")
		}
		if got := testRevisions(loose).later(int64(len(base))); got != (LaterChanges{}) {
			t.Fatalf("%s: зөвшөөрөгдлөө: %+v", name, got)
		}
	}
}

// 7. Хуримтлагдсан олон алхам: revision 2 = халдагчийн «зөвхөн гарын үсэг» (LTV stream мэт хоргүй объект
// суулгана), revision 3 = түүнийг идэвхжүүлж хуудасны агуулга болгоно. Эхний (A) болон revision 2-ийн (B)
// гарын үсэг ХОЁУЛАА өөрчлөгдсөн гэж гарах ёстой; A нь дараагийн бүх revision-оор хуримтлуулж үнэлэгдэнэ.
func TestLaterChangesCumulativeMultiStep(t *testing.T) {
	base := shadowBase(nil)
	const dss = "/DSS<</Certs[22 0 R]>>"
	plant := rev{objs: merge2(sigObjs("/Rect[0 0 0 0]", dss), 22, stream("", "BT (INJECTED) Tj ET"))}
	second := func(extra map[int]string) rev {
		objs := map[int]string{
			1:  "<</Type/Catalog/Pages 2 0 R/AcroForm<</Fields[21 0 R 25 0 R]/SigFlags 3>>" + dss + ">>",
			24: "<</Type/Sig/Filter/Adobe.PPKLite/ByteRange[0 200000 200010 100000]/Contents<00>>>",
			25: "<</Type/Annot/Subtype/Widget/FT/Sig/T(Signature 2)/V 24 0 R/P 3 0 R/F 132/Rect[0 0 0 0]>>",
		}
		maps.Copy(objs, extra)
		return rev{objs: objs}
	}
	activated := "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents[4 0 R 22 0 R]>>"
	cases := []struct {
		name string
		rev3 rev
		a, b LaterChanges
	}{
		{"хяналт: гурав дахь revision зөвхөн гарын үсэг", second(nil), LaterChanges{true, 2, false}, LaterChanges{true, 1, false}},
		{"суулгасан объектыг хуудасны агуулга болгож, гарын үсэг зурсан", second(map[int]string{3: activated}), LaterChanges{}, LaterChanges{}},
		{"суулгасан объектыг гарын үсэггүйгээр идэвхжүүлсэн", rev{objs: map[int]string{3: activated}}, LaterChanges{}, LaterChanges{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc, ends := applyRevs(t, base, plant, tc.rev3)
			r := testRevisions(doc)
			if got := r.later(int64(ends[0])); got != tc.a {
				t.Fatalf("A: авсан %+v, хүлээсэн %+v", got, tc.a)
			}
			if got := r.later(int64(ends[1])); got != tc.b {
				t.Fatalf("B: авсан %+v, хүлээсэн %+v", got, tc.b)
			}
		})
	}
}
