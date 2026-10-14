package validate

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/sign"
	pdfcpuapi "github.com/pdfcpu/pdfcpu/pkg/api"
)

// profileOwnSigner — prod-ийн горим: нэмэгдсэн revision бүр манай signing service-ийн бичдэг яг хэлбэртэй.

// Манай signer-ийн БОДИТ гаралт (pdfsign → digitorus/pdfsign) суурийн төрөл бүрд: хэлбэрийг эндээс гаргаж,
// profileOwnSigner-ийн дүрмүүд түүнтэй таарч буйг батална. 2 ба 3 гарын үсэг, prod-ийн зам (Extract, worker).
func TestOwnSignerRealOutputShape(t *testing.T) {
	p := newPKI(t)
	tsaURL := tsaServer(t, p.tsa, p.issuing.cert)
	withPage := legacyWithPage(t, minimalPDF(t))
	var optimized bytes.Buffer
	if err := pdfcpuapi.Optimize(bytes.NewReader(minimalPDF(t)), &optimized, nil); err != nil {
		t.Fatal(err)
	}
	bases := []struct {
		name   string
		doc    []byte
		stream bool // суурийн xref нь stream
	}{
		{"classic xref, баталгаажуулалтын хуудасгүй (fpdf)", minimalPDF(t), false},
		{"xref stream, баталгаажуулалтын хуудастай (pdfcpu merge)", withPage, true},
		{"xref stream, баталгаажуулалтын хуудасгүй (pdfcpu optimize)", optimized.Bytes(), true},
	}
	for _, b := range bases {
		t.Run(b.name, func(t *testing.T) {
			doc := b.doc
			var ends []int
			for i := 0; i < 3; i++ {
				ends = append(ends, len(doc))
				doc = signPDF(t, doc, p.leaf, []*x509.Certificate{p.issuing.cert}, tsaURL)
				if i == 0 {
					continue
				}
				// Prod-ийн зам: Extract (анхдагч), мөн тусгаарлагдсан worker.
				for _, v := range []*Validator{p.validator(good), {Roots: p.validator(good).Roots, Intermediates: []*x509.Certificate{p.issuing.cert},
					Issuers: []*x509.Certificate{p.issuing.cert}, Status: good, Extract: isolated(t)}} {
					rep := mustPDF(t, v, doc)
					if rep.Indication != Valid || len(rep.Signatures) != i+1 {
						t.Fatalf("%d гарын үсэг: %s", i+1, rep.Indication)
					}
					for j, s := range rep.Signatures[:i] {
						wantExtended(t, s, i-j, false)
					}
				}
				// Хэлбэр: энэ алхамд нэмэгдсэн зүйл.
				r := newRevisions(doc, knownSignatures(doc), profileOwnSigner)
				base, fin := r.view(ends[i]), r.view(len(doc))
				if base == nil || fin == nil || len(fin.sections) != len(base.sections)+1 {
					t.Fatal("харагдац / xref хэсгийн тоо")
				}
				c := newClassifier(base, fin, true, r.known)
				c.own = true
				if err := c.run(); err != nil {
					t.Fatalf("алхам %d: %v", i+1, err)
				}
				sec := fin.sections[0]
				isStream := sec.trailer["Type"] == pdfName("XRef")
				// xref stream-тэй суурьт digitorus дөрөв дэх объект (xref stream) бичдэг боловч түүнийгээ
				// xref-т бүртгэдэггүй тул «шинэ объект» нь аль ч суурьт яг гурав.
				roles := map[string]int{}
				for n := range c.isNew {
					roles[c.role[n]]++
				}
				want := map[string]int{"sig": 1, "field": 1, "catalog": 1}
				if len(c.infra) != 0 {
					t.Fatalf("xref-т бүртгэлтэй бүтцийн объект: %v", c.infra)
				}
				_, hasInfo := sec.trailer["Info"]
				_, baseInfo := base.trailer["Info"]
				for n := range c.changed {
					if !c.isNew[n] {
						t.Fatalf("хуучин объект %d өөрчлөгдсөн", n)
					}
				}
				// classic: trailer-ийг хуулдаг тул /Info хэвээр; stream: /Info хэзээ ч бичигдэхгүй.
				if isStream != b.stream || !maps.Equal(roles, want) || c.root == base.trailer["Root"].(pdfRef).num ||
					isStream && hasInfo || !isStream && hasInfo != baseInfo {
					t.Fatalf("хэлбэр: stream=%v шинэ объектууд=%v /Info=%v (суурь %v)", isStream, roles, hasInfo, baseInfo)
				}
			}
		})
	}
}

// ownObjs — digitorus-ийн хэлбэртэй (криптографгүй) гарын үсгийн revision: Sig толь 20, үл харагдах widget 21,
// ШИНЭ дугаартай Catalog 22.
func ownObjs() map[int]string {
	return map[int]string{
		20: "<</Type/Sig/Filter/Adobe.PPKLite/SubFilter/adbe.pkcs7.detached/Prop_Build<</App<</Name/Digitorus#20PDFSign>>>>" +
			"/ByteRange[0 100000 100010 100000]/Contents<00>/TransformMethod/FieldMDP/TransformParams<</Type/TransformParams/Action/All/V/1.2>>/Name(N)/M(D:20261005162810+08'00')>>",
		21: "<</Type/Annot/Subtype/Widget/Rect[0 0 0 0]/P 3 0 R/F 132/FT/Sig/T(Signature 1)/V 20 0 R>>",
		22: "<</Type/Catalog/Pages 2 0 R/AcroForm<</Fields[21 0 R]/SigFlags 3>>>>",
	}
}

func TestOwnSignerProfile(t *testing.T) {
	const (
		page    = "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R"
		catalog = "<</Type/Catalog/Pages 2 0 R"
		acro    = "/AcroForm<</Fields[21 0 R]/SigFlags 3>>"
		wHead   = "<</Type/Annot/Subtype/Widget"
		wTail   = "/P 3 0 R/F 132/FT/Sig/T(Signature 1)/V 20 0 R>>"
		sigHead = "<</Filter/Adobe.PPKLite/ByteRange[0 100000 100010 100000]/Contents<00>"
	)
	form := stream("/Type/XObject/Subtype/Form/BBox[0 0 100 40]", "q Q")
	own := func(over map[int]string) rev {
		objs := ownObjs()
		maps.Copy(objs, over)
		return rev{objs: objs, root: 22}
	}
	ok1 := LaterChanges{true, 1, false}
	emptyField := map[int]string{
		1:  catalog + "/AcroForm<</Fields[10 0 R]/SigFlags 3>>>>",
		3:  page + "/Annots[10 0 R]>>",
		10: "<</Type/Annot/Subtype/Widget/FT/Sig/T(Sig)/Rect[10 10 200 60]/P 3 0 R>>",
	}
	cases := []struct {
		name  string
		base  map[int]string
		rev   rev
		broad LaterChanges // өргөн жагсаалтын дүн (нарийн горимын дүрэм л татгалзаж буйг харуулна)
		own   LaterChanges
	}{
		{"хяналт: манай signer-ийн хэлбэр (classic xref)", nil, own(nil), ok1, ok1},
		{"хяналт: манай signer-ийн хэлбэр (xref stream)", nil, rev{objs: ownObjs(), root: 22, stream: true, unlistedXref: true}, ok1, ok1},
		// PAdES бичигч xref stream-ийг өөрийгөө Index-д бүртгэдэг (ISO 32000-1 §7.5.8.3; qpdf-ийн анхааруулга), digitorus
		// бүртгэдэггүй — хоёулаа зөвшөөрөгдөнө.
		{"xref stream объект өөрийгөө xref-т бүртгэсэн (PAdES бичигч)", nil, rev{objs: ownObjs(), root: 22, stream: true}, ok1, ok1},

		{"харагдах widget: /Rect + /AP", nil, own(map[int]string{21: wHead + "/Rect[10 10 110 50]/AP<</N 23 0 R>>" + wTail, 23: form}), LaterChanges{true, 1, true}, LaterChanges{}},
		{"хоосон биш /Rect, /AP-гүй", nil, own(map[int]string{21: wHead + "/Rect[10 10 110 50]" + wTail}), LaterChanges{true, 1, true}, LaterChanges{}},
		{"/Rect [0 0 0 0] боловч /AP-тэй", nil, own(map[int]string{21: wHead + "/Rect[0 0 0 0]/AP<</N 23 0 R>>" + wTail, 23: form}), LaterChanges{true, 1, true}, LaterChanges{}},
		{"/Rect байхгүй", nil, own(map[int]string{21: wHead + wTail}), ok1, LaterChanges{}},
		{"/Rect бодит тоогоор [0.0 0 0 0]", nil, own(map[int]string{21: wHead + "/Rect[0.0 0 0 0]" + wTail}), ok1, LaterChanges{}},
		{"зөвхөн DSS (гарын үсэггүй revision; 10-07-аас зөвшөөрнө)", nil, rev{objs: map[int]string{22: catalog + "/DSS<</Certs[23 0 R]>>>>", 23: stream("", "DER")}, root: 22}, LaterChanges{true, 0, false}, LaterChanges{true, 0, false}},
		{"DSS + гарын үсэг", nil, own(map[int]string{22: catalog + acro + "/DSS<</Certs[23 0 R]>>>>", 23: stream("", "DER")}), ok1, LaterChanges{}},
		{"/Perms нэмэгдсэн", nil, own(map[int]string{22: catalog + acro + "/Perms<</DocMDP 20 0 R>>>>"}), ok1, LaterChanges{}},
		{"нэг revision-д хоёр гарын үсэг", nil, own(map[int]string{
			22: catalog + "/AcroForm<</Fields[21 0 R 24 0 R]/SigFlags 3>>>>", 23: ownObjs()[20],
			24: "<</Type/Annot/Subtype/Widget/Rect[0 0 0 0]/P 3 0 R/F 132/FT/Sig/T(Signature 2)/V 23 0 R>>",
		}), LaterChanges{true, 2, false}, LaterChanges{}},
		{"суурийн хоосон талбар бөглөгдсөн", emptyField, rev{objs: map[int]string{
			10: "<</Type/Annot/Subtype/Widget/FT/Sig/T(Sig)/Rect[10 10 200 60]/P 3 0 R/V 20 0 R>>", 20: ownObjs()[20],
			22: catalog + "/AcroForm<</Fields[10 0 R]/SigFlags 3>>>>",
		}, root: 22}, LaterChanges{true, 1, true}, LaterChanges{}},
		// PAdES бичигч widget-ийг хуудасны /Annots-д нэмдэг (ISO 32000-1 §12.5.2; Adobe/pyHanko) — нарийн горимд
		// зөвшөөрөгдөнө; бусад түлхүүр өөрчлөгдвөл татгалзана.
		{"гарын үсгийн revision хуудасны /Annots-д widget нэмсэн", nil, own(map[int]string{3: page + "/Annots[21 0 R]>>"}), ok1, ok1},
		{"гарын үсгийн revision хуудасны /Annots-д widget + өөр түлхүүр", nil, own(map[int]string{3: page + "/Annots[21 0 R]/Rotate 90>>"}), LaterChanges{}, LaterChanges{}},
		// 5-р шат (1): манай задлагчийн «ижил утга» нь viewer-ийн уншилт биш — digitorus хуучин объектыг хэзээ ч
		// дахин бичдэггүй тул нарийн горимд нэмэгдсэн xref-ийн мөр бүр цоо шинэ дугаар байх ёстой.
		{"гарын үсгийн revision хуудсыг ижил утгаар дахин бичсэн", nil, own(map[int]string{3: page + ">>"}), ok1, LaterChanges{}},
		{"гарын үсгийн revision content stream-ийг ижил утгаар дахин бичсэн", nil, own(map[int]string{4: stream("", "BT (signed) Tj ET")}), ok1, LaterChanges{}},
		{"нэмэгдсэн xref-т ашиглагдаагүй дугаарын free мөр", nil, rev{objs: ownObjs(), root: 22, free: []int{35}}, ok1, LaterChanges{}},

		// 5-р шат (2): Sig толь / widget-ийн чөлөөт бичвэрүүд.
		{"хяналт: кирилл /Name /Reason /Location (UTF-16BE)", nil, own(map[int]string{20: sigText("/Name<FEFF04110430044200200411043E043B0434>/Reason<FEFF04260430044504380020043304300440044B043D002004AF044D0433>/Location<FEFF04230411>")}), ok1, ok1},
		{"хяналт: /M-гүй (TSA-тай үед digitorus бичдэггүй), /ContactInfo-тэй", nil, own(map[int]string{20: sigText("/Name(BAT BOLD)/ContactInfo(info@example.mn)")}), ok1, ok1},
		{"/Name дотор объектын бичлэг", nil, own(map[int]string{20: sigText("/Name(x 99 0 obj <<>> endobj)")}), ok1, LaterChanges{}},
		{"/Reason дотор stream", nil, own(map[int]string{20: sigText("/Reason(a stream b)")}), ok1, LaterChanges{}},
		{"/Location дотор %%EOF", nil, own(map[int]string{20: sigText("/Location(x%%EOF)")}), ok1, LaterChanges{}},
		{"/ContactInfo дотор startxref", nil, own(map[int]string{20: sigText("/ContactInfo(startxref 5)")}), ok1, LaterChanges{}},
		{"/Name дотор trailer (escape-ээр нуусан)", nil, own(map[int]string{20: sigText(`/Name(t\162ailer)`)}), ok1, LaterChanges{}},
		{"/Name дотор мөр шилжилт", nil, own(map[int]string{20: sigText("/Name(a\nb)")}), ok1, LaterChanges{}},
		{"/Name дотор NUL", nil, own(map[int]string{20: sigText("/Name<410042>")}), ok1, LaterChanges{}},
		{"/Name 256 байтаас урт", nil, own(map[int]string{20: sigText("/Name(" + strings.Repeat("A", 257) + ")")}), ok1, LaterChanges{}},
		{"/Name BOM-гүй ASCII биш байт", nil, own(map[int]string{20: sigText("/Name<C0C1>")}), ok1, LaterChanges{}},
		{"/Name UTF-16BE дотор U+000A", nil, own(map[int]string{20: sigText("/Name<FEFF0041000A0042>")}), ok1, LaterChanges{}},
		{"/Name UTF-16BE сондгой урттай", nil, own(map[int]string{20: sigText("/Name<FEFF004100>")}), ok1, LaterChanges{}},
		{"/Name UTF-16BE-ээр бичсэн endobj", nil, own(map[int]string{20: sigText("/Name<FEFF0065006E0064006F0062006A>")}), ok1, LaterChanges{}},
		{"/Name UTF-16BE-ийн түүхий байт нь endobj (U+656E U+646F U+626A)", nil, own(map[int]string{20: sigText("/Name<FEFF656E646F626A>")}), ok1, LaterChanges{}},
		{"/Name бичвэр биш (нэр)", nil, own(map[int]string{20: sigText("/Name/X")}), ok1, LaterChanges{}},
		{"/M хэлбэр буруу", nil, own(map[int]string{20: sigText("/M(D:2026)")}), ok1, LaterChanges{}},
		{"/M Z төгсгөлтэй (digitorus үргэлж ±HH'mm' бичдэг)", nil, own(map[int]string{20: sigText("/M(D:20261005162810Z)")}), ok1, LaterChanges{}},
		{"/T «Signature N» биш", nil, own(map[int]string{21: wHead + "/Rect[0 0 0 0]/P 3 0 R/F 132/FT/Sig/T(Sig)/V 20 0 R>>"}), ok1, LaterChanges{}},
		{"/T Signature 0", nil, own(map[int]string{21: wHead + "/Rect[0 0 0 0]/P 3 0 R/F 132/FT/Sig/T(Signature 0)/V 20 0 R>>"}), ok1, LaterChanges{}},
		{"/T дотор объектын бичлэг", nil, own(map[int]string{21: wHead + "/Rect[0 0 0 0]/P 3 0 R/F 132/FT/Sig/T(Signature 1 0 obj)/V 20 0 R>>"}), ok1, LaterChanges{}},
		{"/T UTF-16BE-ээр", nil, own(map[int]string{21: wHead + "/Rect[0 0 0 0]/P 3 0 R/F 132/FT/Sig/T<FEFF005300690067006E006100740075007200650020" + "0031>/V 20 0 R>>"}), ok1, LaterChanges{}},
		{"илүү шинэ объект: хоосон толь", nil, own(map[int]string{23: "<<>>"}), LaterChanges{}, LaterChanges{}},
		{"илүү шинэ объект: Sig толиос заагдсан", nil, own(map[int]string{20: sigHead + "/Type/Sig/Reference[<</Data 22 0 R>>]>>"}), ok1, LaterChanges{}},
		{"Catalog-ийг ижил дугаараар дарж бичсэн", nil, rev{objs: map[int]string{1: catalog + acro + ">>", 20: ownObjs()[20], 21: ownObjs()[21]}}, ok1, LaterChanges{}},
		{"/SigFlags 1", nil, own(map[int]string{22: catalog + "/AcroForm<</Fields[21 0 R]/SigFlags 1>>>>"}), ok1, LaterChanges{}},
		{"/AcroForm шууд бус", nil, own(map[int]string{22: catalog + "/AcroForm 23 0 R>>", 23: "<</Fields[21 0 R]/SigFlags 3>>"}), ok1, LaterChanges{}},
		{"/Fields шууд бус", nil, own(map[int]string{22: catalog + "/AcroForm<</Fields 23 0 R/SigFlags 3>>>>", 23: "[21 0 R]"}), ok1, LaterChanges{}},
		{"widget /F 4", nil, own(map[int]string{21: "<</Type/Annot/Subtype/Widget/Rect[0 0 0 0]/P 3 0 R/F 4/FT/Sig/T(Signature 1)/V 20 0 R>>"}), ok1, LaterChanges{}},
		{"widget нэмэлт түлхүүр /TU", nil, own(map[int]string{21: wHead + "/Rect[0 0 0 0]/TU(x)" + wTail}), ok1, LaterChanges{}},
		{"widget /Type-гүй", nil, own(map[int]string{21: "<</Subtype/Widget/Rect[0 0 0 0]/P 3 0 R/F 132/FT/Sig/T(Signature 1)/V 20 0 R>>"}), ok1, LaterChanges{}},
		{"Sig толь /Type-гүй", nil, own(map[int]string{20: sigHead + ">>"}), ok1, LaterChanges{}},
		{"Sig толь /Reference-тэй", nil, own(map[int]string{20: sigHead + "/Type/Sig/Reference[<</TransformMethod/FieldMDP>>]>>"}), ok1, LaterChanges{}},
		{"нэмэгдсэн revision-д ObjStm", nil, rev{objs: map[int]string{20: ownObjs()[20], 22: ownObjs()[22]}, compressed: map[int]string{21: ownObjs()[21]}, root: 22}, ok1, LaterChanges{}},
		{"гарын үсэггүй хоосон revision", nil, rev{}, LaterChanges{true, 0, false}, LaterChanges{}},
		{"/Version /1.7 нэмэгдсэн (digitorus зөвхөн /1.5 бичдэг)", nil, own(map[int]string{22: catalog + "/Version/1.7" + acro + ">>"}), ok1, LaterChanges{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := shadowBase(tc.base)
			doc := appendRev(t, base, tc.rev)
			known := knownSignatures(doc)
			if got := newRevisions(doc, known, profileBroad).later(int64(len(base))); got != tc.broad {
				t.Fatalf("profileBroad: авсан %+v, хүлээсэн %+v", got, tc.broad)
			}
			if got := newRevisions(doc, known, profileOwnSigner).later(int64(len(base))); got != tc.own {
				t.Fatalf("profileOwnSigner: авсан %+v, хүлээсэн %+v", got, tc.own)
			}
		})
	}
}

// sigText — ownObjs()-ийн Sig толь, /Name /M-ийн оронд өгсөн бичвэрийн түлхүүрүүдтэй.
func sigText(text string) string {
	return "<</Type/Sig/Filter/Adobe.PPKLite/SubFilter/adbe.pkcs7.detached/ByteRange[0 100000 100010 100000]/Contents<00>" + text + ">>"
}

// /Version: digitorus зөвхөн толгой 1.5-аас доош, суурийн Catalog /Version-гүй үед /Version /1.5 нэмдэг.
func TestOwnSignerProfileVersion(t *testing.T) {
	base := bytes.Replace(shadowBase(nil), []byte("%PDF-1.7"), []byte("%PDF-1.4"), 1)
	for version, want := range map[string]LaterChanges{"/Version/1.5": {true, 1, false}, "/Version/1.6": {}, "/Version/2.0": {}} {
		objs := ownObjs()
		objs[22] = "<</Type/Catalog" + version + "/Pages 2 0 R/AcroForm<</Fields[21 0 R]/SigFlags 3>>>>"
		doc := appendRev(t, base, rev{objs: objs, root: 22})
		if got := newRevisions(doc, knownSignatures(doc), profileBroad).later(int64(len(base))); got != (LaterChanges{true, 1, false}) {
			t.Fatalf("%s profileBroad: %+v", version, got)
		}
		if got := newRevisions(doc, knownSignatures(doc), profileOwnSigner).later(int64(len(base))); got != want {
			t.Fatalf("%s profileOwnSigner: авсан %+v, хүлээсэн %+v", version, got, want)
		}
	}
}

// trailer-ийн /Info: суурьт байсан бол хэвээр. Ганц үл хамаарах: манай signer-ийн xref STREAM хэсэг /Info-г
// орхидог (digitorus sign/pdfxref_stream.go) — зөвхөн profileOwnSigner-т, зөвхөн xref stream хэсэгт.
func TestOwnSignerProfileInfoOmittedInXrefStream(t *testing.T) {
	base := bytes.Replace(shadowBase(map[int]string{9: "<</Producer(x)>>"}), []byte("/Size 40/Root 1 0 R"), []byte("/Size 40/Info 9 0 R/Root 1 0 R"), 1)
	cases := []struct {
		name       string
		rev        rev
		broad, own LaterChanges
	}{
		{"classic, /Info хэвээр", rev{objs: ownObjs(), root: 22}, LaterChanges{true, 1, false}, LaterChanges{true, 1, false}},
		{"xref stream, /Info хэвээр", rev{objs: ownObjs(), root: 22, stream: true, unlistedXref: true}, LaterChanges{true, 1, false}, LaterChanges{true, 1, false}},
		{"xref stream, /Info орхигдсон (digitorus)", rev{objs: ownObjs(), root: 22, stream: true, unlistedXref: true, noInfo: true}, LaterChanges{}, LaterChanges{true, 1, false}},
		{"classic, /Info орхигдсон", rev{objs: ownObjs(), root: 22, noInfo: true}, LaterChanges{}, LaterChanges{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := appendRev(t, base, tc.rev)
			if got := newRevisions(doc, knownSignatures(doc), profileBroad).later(int64(len(base))); got != tc.broad {
				t.Fatalf("profileBroad: авсан %+v, хүлээсэн %+v", got, tc.broad)
			}
			if got := newRevisions(doc, knownSignatures(doc), profileOwnSigner).later(int64(len(base))); got != tc.own {
				t.Fatalf("profileOwnSigner: авсан %+v, хүлээсэн %+v", got, tc.own)
			}
		})
	}
	// /Info-г өөр объект руу заах нь аль ч горимд, аль ч хэлбэрт татгалзагдана.
	doc := appendRev(t, base, rev{objs: ownObjs(), root: 22, stream: true, unlistedXref: true})
	other := append(bytes.Clone(base), bytes.Replace(doc[len(base):], []byte("/Info 9 0 R"), []byte("/Info 4 0 R"), 1)...)
	if got := newRevisions(other, knownSignatures(other), profileOwnSigner).later(int64(len(base))); bytes.Equal(other, doc) || got != (LaterChanges{}) {
		t.Fatalf("/Info өөр объект руу: %+v", got)
	}
}

// Олон алхам: алхам бүр манай signer-ийн хэлбэртэй байх ёстой.
func TestOwnSignerProfileMultiStep(t *testing.T) {
	base := shadowBase(nil)
	second := func(extraCatalog string, extra map[int]string) rev {
		objs := map[int]string{
			30: ownObjs()[20][:len("<</Type/Sig")] + "/Filter/Adobe.PPKLite/ByteRange[0 200000 200010 100000]/Contents<00>>>",
			31: "<</Type/Annot/Subtype/Widget/Rect[0 0 0 0]/P 3 0 R/F 132/FT/Sig/T(Signature 2)/V 30 0 R>>",
			32: "<</Type/Catalog/Pages 2 0 R/AcroForm<</Fields[21 0 R 31 0 R]/SigFlags 3>>" + extraCatalog + ">>",
		}
		maps.Copy(objs, extra)
		return rev{objs: objs, root: 32}
	}
	cases := []struct {
		name string
		rev2 rev
		a, b LaterChanges
	}{
		{"хяналт: хоёр дахь revision ч манай хэлбэр", second("", nil), LaterChanges{true, 2, false}, LaterChanges{true, 1, false}},
		{"хоёр дахь revision DSS нэмсэн", second("/DSS<</Certs[33 0 R]>>", map[int]string{33: stream("", "DER")}), LaterChanges{}, LaterChanges{}},
		{"хоёр дахь revision эхний талбарыг /Fields-ээс хассан", rev{objs: map[int]string{
			30: second("", nil).objs[30], 31: second("", nil).objs[31], 32: "<</Type/Catalog/Pages 2 0 R/AcroForm<</Fields[31 0 R]/SigFlags 3>>>>",
		}, root: 32}, LaterChanges{}, LaterChanges{}},
		// 5-р шат (3): шинэ талбарын /T суурийн талбарын нэртэй давхцахгүй.
		{"хоёр дахь revision-ийн талбар эхнийхтэй ижил /T-тэй", second("", map[int]string{
			31: "<</Type/Annot/Subtype/Widget/Rect[0 0 0 0]/P 3 0 R/F 132/FT/Sig/T(Signature 1)/V 30 0 R>>",
		}), LaterChanges{}, LaterChanges{}},
		{"хоёр дахь revision гарын үсэггүй", rev{objs: map[int]string{32: "<</Type/Catalog/Pages 2 0 R/AcroForm<</Fields[21 0 R]/SigFlags 3>>>>"}, root: 32}, LaterChanges{}, LaterChanges{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc, ends := applyRevs(t, base, rev{objs: ownObjs(), root: 22}, tc.rev2)
			r := newRevisions(doc, knownSignatures(doc), profileOwnSigner)
			if got := r.later(int64(ends[0])); got != tc.a {
				t.Fatalf("A: авсан %+v, хүлээсэн %+v", got, tc.a)
			}
			if got := r.later(int64(ends[1])); got != tc.b {
				t.Fatalf("B: авсан %+v, хүлээсэн %+v", got, tc.b)
			}
		})
	}
}

// Prod-ийн оролтын цэгүүд (Extract, worker) зөвхөн profileOwnSigner хэрэглэнэ: өргөн жагсаалтад зөвшөөрөгддөг
// «хуудсыг ижил утгаар дахин бичсэн» гарын үсэггүй revision prod-ийн замаар modified_after_signing хэвээр гарна.
// (2026-10-07-нээс «зөвхөн DSS/LTV» revision prod-д ч зөвшөөрөгдөнө — TestProductionAcceptsDSSOnlyRevision.)
func TestProductionUsesOwnSignerProfile(t *testing.T) {
	p := newPKI(t)
	signed := signPDF(t, minimalPDF(t), p.leaf, []*x509.Certificate{p.issuing.cert}, "")
	f := newFixture(t, signed)
	doc := appendRev(t, signed, rev{objs: map[int]string{f.page: pdfText(f.pageDict)}})
	wantExtended(t, only(t, mustPDF(t, broadValidator(p), doc)), 0, false) // хяналт: өргөн жагсаалт зөвшөөрнө
	wantModified(t, only(t, mustPDF(t, p.validator(good), doc)))           // Validator-ийн анхдагч зам = Extract
	raws, err := Extract(doc)
	if err != nil || len(raws) != 1 || raws[0].LaterSignaturesOnly {
		t.Fatalf("Extract: %v %+v", err, raws)
	}
	v := p.validator(good)
	v.Extract = isolated(t) // worker (RunWorker → Extract)
	wantModified(t, only(t, mustPDF(t, v, doc)))
	if profileOwnSigner != 0 {
		t.Fatal("profileOwnSigner нь тэг утга (анхдагч) байх ёстой")
	}
}

// Шийдвэр 10-07 (docs/PADES_SIGNING.md §15 Q7): гарын үсгийн дараах зөвхөн DSS/LTV revision (манай R_dss эсвэл
// Adobe-ийн «Add verification information») prod-ийн горимд өөрчлөлт биш; харин хоосон гарын үсэггүй revision
// ба DSS-тэй хамт агуулгын засвар хэвээр татгалзагдана.
func TestProductionAcceptsDSSOnlyRevision(t *testing.T) {
	p := newPKI(t)
	signed := signPDF(t, minimalPDF(t), p.leaf, []*x509.Certificate{p.issuing.cert}, "")
	f := newFixture(t, signed)
	dss, cert := f.newNum(), f.newNum()
	dssRev := map[int]string{
		f.root: pdfText(with(f.cat, "DSS", pdfRef{dss, 0})),
		dss:    pdfText(pdfDict{"Certs": pdfArr{pdfRef{cert, 0}}}),
		cert:   stream("", "DER"),
	}
	doc := appendRev(t, signed, rev{objs: dssRev})
	v := p.validator(good)
	v.Extract = isolated(t)
	wantExtended(t, only(t, mustPDF(t, v, doc)), 0, false)

	// Adobe маягийн: Catalog-ийг ижил дугаараар дахин бичиж /Extensions ADBE, /Info-г ModDate-тэй дахин бичсэн.
	adobe := map[int]string{
		f.root: pdfText(with(with(f.cat, "DSS", pdfRef{dss, 0}), "Extensions",
			pdfDict{"ADBE": pdfDict{"BaseVersion": pdfName("1.7"), "ExtensionLevel": int64(5)}})),
		dss:  pdfText(pdfDict{"Certs": pdfArr{pdfRef{cert, 0}}}),
		cert: stream("", "DER"),
	}
	wantExtended(t, only(t, mustPDF(t, v, appendRev(t, signed, rev{objs: adobe}))), 0, false)

	// Сөрөг: DSS-тэй нэг revision-д хуудас өөрчлөгдсөн; /Extensions-д заалт; DSS-гүй зөвхөн /Extensions.
	bad := maps.Clone(dssRev)
	bad[f.page] = pdfText(with(f.pageDict, "Rotate", int64(90)))
	wantModified(t, only(t, mustPDF(t, v, appendRev(t, signed, rev{objs: bad}))))
	refExt := maps.Clone(adobe)
	refExt[f.root] = pdfText(with(with(f.cat, "DSS", pdfRef{dss, 0}), "Extensions", pdfDict{"ADBE": pdfRef{cert, 0}}))
	wantModified(t, only(t, mustPDF(t, v, appendRev(t, signed, rev{objs: refExt}))))
	extOnly := map[int]string{f.root: pdfText(with(f.cat, "Extensions",
		pdfDict{"ADBE": pdfDict{"BaseVersion": pdfName("1.7"), "ExtensionLevel": int64(5)}}))}
	wantModified(t, only(t, mustPDF(t, v, appendRev(t, signed, rev{objs: extOnly}))))
}

// 5-р шат (2): бодит signer-ийн кирилл бичвэр (digitorus ASCII биш бичвэрийг BOM-той UTF-16BE-ээр, literal
// string дотор бичдэг — байтууд нь 0x00, 0x04 … агуулна) нарийн горимд 2 ба 3 гарын үсэгтэй хэвээр давна.
func TestOwnSignerCyrillicStringsRealOutput(t *testing.T) {
	p := newPKI(t)
	tsaURL := tsaServer(t, p.tsa, p.issuing.cert)
	signWith := func(doc []byte, name, location, reason, tsa string) []byte {
		rs := bytes.NewReader(doc)
		rdr, err := pdf.NewReader(rs, int64(len(doc)))
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		err = sign.Sign(rs, &out, rdr, int64(len(doc)), sign.SignData{
			Signer: p.leaf.key, DigestAlgorithm: crypto.SHA256, Certificate: p.leaf.cert,
			CertificateChains: [][]*x509.Certificate{{p.leaf.cert, p.issuing.cert}},
			TSA:               sign.TSA{URL: tsa},
			Signature: sign.SignDataSignature{CertType: sign.ApprovalSignature,
				Info: sign.SignDataSignatureInfo{Name: name, Location: location, Reason: reason, Date: time.Now()}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return out.Bytes()
	}
	withPage := legacyWithPage(t, minimalPDF(t))
	// TSA-гүй (→ /M бичигдэнэ) ба TSA-тай (→ /M-гүй) хоёр дараалал. Хоёр горимыг нэг баримтад холихгүй:
	// digitorus /Contents-ийн placeholder-оо эхний тэг цуваагаар хайдаг тул холимог нь баримтыг эвддэг
	// (устсан pdfsign.verifyEmbedded үүнээс хамгаалдаг байв; энд digitorus-ийг шууд дуудаж байгаа).
	type variant struct {
		base string
		doc  []byte
		tsa  string
	}
	for _, vr := range []variant{{"classic xref, TSA-гүй", minimalPDF(t), ""}, {"classic xref, TSA", minimalPDF(t), tsaURL},
		{"xref stream, TSA-гүй", withPage, ""}, {"xref stream, TSA", withPage, tsaURL}} {
		base, doc := vr.base, vr.doc
		for i := 0; i < 3; i++ {
			doc = signWith(doc, fmt.Sprintf("Бат-Эрдэнэ Доржийн Өлзий %d", i+1), "Улаанбаатар хот", "eID Mongolia цахим гарын үсэг", vr.tsa)
			if i == 0 {
				continue
			}
			rep := mustPDF(t, p.validator(good), doc)
			if len(rep.Signatures) != i+1 {
				t.Fatalf("%s: гарын үсэг %d", base, len(rep.Signatures))
			}
			for j, s := range rep.Signatures[:i] {
				if s.SignerName != fmt.Sprintf("Бат-Эрдэнэ Доржийн Өлзий %d", j+1) {
					t.Fatalf("%s: нэр %q", base, s.SignerName)
				}
				wantExtended(t, s, i-j, false)
			}
		}
	}
}
