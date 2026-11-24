package pades

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	eid "github.com/gerege-systems/eid-mongolia-sdk-go"
)

// QR-тэй тамганы дардас (APPEARANCE_SPEC.md §6.5) ба Prepare-ийн docId дүрэм (§6.6) — golden v13-ийн гаралт дээр.

const (
	qrSealDocID = "8c9d0e1f-2a3b-4c4d-8e5f-6a7b8c9d0e1f" // golden seal-qr-visible
	pageDocID   = "6f0c2b9e-3a1d-4c55-9b7e-0a1b2c3d4e5f" // golden quartz-pdf13 (verify хуудас)
	otherDocID  = "0f1e2d3c-4b5a-4968-8776-5a4b3c2d1e0f"
)

func readTestdata(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", rel)) // #nosec G304 -- тест
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// sealSources — precheck-ийн stampSources (e-Seal гарын үсэг → байрлал); eID олгогч/timestamp-ийг шалгахгүй (B-B
// сөрөг оролтод ч).
func sealSources(t *testing.T, doc []byte) map[uint32]int {
	t.Helper()
	sigs, _, _, err := scanSignatures(doc)
	if err != nil {
		t.Fatal(err)
	}
	leaves := make([]*x509.Certificate, len(sigs))
	for i, s := range sigs {
		if leaves[i], _, err = checkPriorSignature(doc, s); err != nil {
			t.Fatal(err)
		}
	}
	return stampSources(sigs, leaves)
}

// TestResolveDocID — §6.6-ийн салаа бүр: гарын үсэггүй → opts эсвэл санамсаргүй; гарын үсэгтэй → (2.1) verify хуудас
// (маркераас түрүүлнэ), (2.2) маркертай дардас, олдсонтой opts.docId зөрвөл REQUEST_INVALID, (3) opts.docId, (4) хоосон —
// гарын үсэгтэй баримтад санамсаргүй docId хэзээ ч үүсгэхгүй.
func TestResolveDocID(t *testing.T) {
	pageAndMarker := readTestdata(t, "validate/input/seal-qr-docid-vs-page.pdf") // хуудас 6f0c…, маркер 0f1e…
	sealQR := readTestdata(t, "golden/output/seal-qr-visible.pdf")               // маркер 8c9d…, хуудасгүй
	sealV12 := readTestdata(t, "golden/output/seal-visible.pdf")                 // хуудас ба маркер алга
	invisible := readTestdata(t, "golden/output/quartz-pdf13-nopage.pdf")        // үл харагдах, хуудас алга
	unsigned := readInput(t, "quartz-pdf13.pdf")
	const random = "<random>"
	cases := []struct {
		name   string
		doc    []byte
		newDoc bool
		given  string
		want   string // docId | random | "" (err бол хамаарахгүй)
		err    bool
	}{
		{"(2.1) verify хуудас маркераас түрүүлнэ", pageAndMarker, false, "", pageDocID, false},
		{"(2.1) хуудас = opts", pageAndMarker, false, pageDocID, pageDocID, false},
		{"(2.1) хуудас ≠ opts (маркертай тэнцүү ч)", pageAndMarker, false, otherDocID, "", true},
		{"(2.2) маркер", sealQR, false, "", qrSealDocID, false},
		{"(2.2) маркер = opts", sealQR, false, qrSealDocID, qrSealDocID, false},
		{"(2.2) маркер ≠ opts", sealQR, false, otherDocID, "", true},
		{"(3) олдсонгүй → opts (opt-in)", sealV12, false, otherDocID, otherDocID, false},
		{"(4) QR-гүй тамгатай, opts-гүй → хоосон", sealV12, false, "", "", false},
		{"(4) үл харагдах гарын үсэгтэй, opts-гүй → хоосон", invisible, false, "", "", false},
		{"(1) гарын үсэггүй → санамсаргүй", unsigned, true, "", random, false},
		{"(1) гарын үсэггүй → opts", unsigned, true, otherDocID, otherDocID, false},
	}
	for _, c := range cases {
		var seals map[uint32]int
		if !c.newDoc {
			seals = sealSources(t, c.doc)
		}
		got, err := resolveDocID(c.doc, c.newDoc, seals, c.given)
		switch {
		case c.err:
			if ErrorCode(err) != CodeRequestInvalid {
				t.Errorf("%s: хүлээсэн REQUEST_INVALID, авсан %q %v", c.name, got, err)
			}
		case err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.want == random:
			if !uuidRe.MatchString(got) || got == otherDocID {
				t.Errorf("%s: санамсаргүй UUID хүлээсэн, авсан %q", c.name, got)
			}
		case got != c.want:
			t.Errorf("%s: %q, хүлээсэн %q", c.name, got, c.want)
		}
	}
}

// stampPDF — docIDFromStamps-ийн синтетик баримт: 1 Catalog, 2 Pages, 3 Page, дараа нь objs (4-өөс). Дардасны stream =
// маркер (docId, rev) + EMC.
func stampPDF(objs ...string) []byte {
	return rawPDF(append([]string{"<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>"}, objs...)...)
}

func stampStream(docID string, rev int, extra string) string {
	c := fmt.Sprintf("/EIDVerify <</URL (https://ca.eidmongolia.mn/verify/%s/%d)>> BDC\nEMC\n", docID, rev)
	return fmt.Sprintf("<< /Length %d%s >>\nstream\n%sendstream", len(c), extra, c)
}

func stampWidget(sig, form string) string {
	return "<< /Type /Annot /Subtype /Widget /Rect [0 0 0 0] /P 3 0 R /F 4 /FT /Sig /T (S) /V " + sig + " /AP << /N " + form + " 0 R >> >>"
}

func stampSig(end int) string {
	return fmt.Sprintf("<< /Type /Sig /ByteRange [0 10 20 %d] /Contents <00> >>", end-20)
}

// TestDocIDFromStampsEarliest — §6.6 алхам 2.2: шалгасан e-Seal гарын үсгийн (seals) хамгийн эрт зурсан (ByteRange[2]+[3]
// бага) дардас — xref-ийн дарааллаар СҮҮЛД (объектын дугаар их) байсан ч; маркерын rev = байрлал; шууд бус /V, гарын
// үсэг бүрт ганц widget; /Filter алга эсвэл ШУУД null.
func TestDocIDFromStampsEarliest(t *testing.T) {
	const later, earlier, forged = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222",
		"33333333-3333-4333-8333-333333333333"
	// 4 widget (хожуу, бага дугаар) → 6 sig (end 200, байрлал 2); 7 widget (эрт, их дугаар) → 9 sig (end 50, байрлал 1).
	base := []string{stampWidget("6 0 R", "5"), stampStream(later, 2, ""), stampSig(200),
		stampWidget("9 0 R", "8"), stampStream(earlier, 1, ""), stampSig(50)}
	seals := map[uint32]int{6: 2, 9: 1}
	plus := func(extra ...string) []string { return append(append([]string{}, base...), extra...) }
	one := func(filter string, extra ...string) []string {
		return append([]string{stampWidget("6 0 R", "5"), stampStream(earlier, 1, filter), stampSig(50)}, extra...)
	}
	cases := []struct {
		name  string
		objs  []string
		seals map[uint32]int
		want  string
	}{
		{"эрт зурсан нь их дугаартай", base, seals, earlier},
		{"эрт зурсны маркерын rev 2 (байрлал 1) — үл тооно", []string{stampWidget("6 0 R", "5"), stampStream(later, 2, ""),
			stampSig(200), stampWidget("9 0 R", "8"), stampStream(earlier, 2, ""), stampSig(50)}, seals, later},
		{"эрт зурсан нь иргэн (seals-д алга) — үл тооно", base, map[uint32]int{6: 2}, later},
		{"шууд /V толь (end 0) — үл тооно", plus(
			"<< /FT /Sig /V << /Type /Sig /ByteRange [0 0 0 0] /Contents <00> >> /AP << /N 11 0 R >> >>", stampStream(forged, 1, "")),
			seals, earlier},
		{"зээлсэн /V (9-д 2 widget) — 9 бүхэлдээ үл тооно", plus(stampWidget("9 0 R", "11"), stampStream(forged, 1, "")), seals, later},
		{"шалгаагүй гарын үсэг рүү /V — үл тооно", plus(stampWidget("12 0 R", "11"), stampStream(forged, 1, ""), stampSig(30)),
			seals, earlier},
		{"/Filter [] — нэр дэвшигч биш", one(" /Filter []"), map[uint32]int{6: 1}, ""},
		{"/Filter /FlateDecode — нэр дэвшигч биш", one(" /Filter /FlateDecode"), map[uint32]int{6: 1}, ""},
		{"/Filter шууд null — нэр дэвшигч", one(" /Filter null"), map[uint32]int{6: 1}, earlier},
		{"/Filter шууд бус null — нэр дэвшигч биш", one(" /Filter 7 0 R", "null"), map[uint32]int{6: 1}, ""},
		{"seals хоосон", base, nil, ""},
	}
	for _, c := range cases {
		got, err := docIDFromStamps(stampPDF(c.objs...), c.seals)
		if err != nil || got != c.want {
			t.Errorf("%s: %q %v, хүлээсэн %q", c.name, got, err, c.want)
		}
	}
	v12 := readTestdata(t, "golden/output/seal-visible.pdf")
	if got, err := docIDFromStamps(v12, sealSources(t, v12)); err != nil || got != "" {
		t.Fatalf("QR-гүй тамга: %q %v", got, err)
	}
	qr := readTestdata(t, "golden/output/seal-qr-visible.pdf")
	if got, err := docIDFromStamps(qr, sealSources(t, qr)); err != nil || got != qrSealDocID {
		t.Fatalf("QR тамга: %q %v", got, err)
	}
}

// breakObj — n-р объектыг уншигдахгүй болгоно: толгойн үе 0 → 1 (xref-ийн бичлэгтэй зөрнө → задлах panic); урт хэвээр.
func breakObj(t *testing.T, doc []byte, n int) []byte {
	t.Helper()
	old := []byte(fmt.Sprintf("\n%d 0 obj\n", n))
	if bytes.Count(doc, old) != 1 {
		t.Fatalf("breakObj %d", n)
	}
	return bytes.Replace(doc, old, []byte(fmt.Sprintf("\n%d 1 obj\n", n)), 1)
}

// stampStreamLenRef — stampStream, гэхдээ /Length нь lenObj объект руу шууд бус лавлагаа.
func stampStreamLenRef(docID string, rev, lenObj int) string {
	c := fmt.Sprintf("/EIDVerify <</URL (https://ca.eidmongolia.mn/verify/%s/%d)>> BDC\nEMC\n", docID, rev)
	return fmt.Sprintf("<< /Length %d 0 R >>\nstream\n%sendstream", lenObj, c)
}

// TestDocIDFromStampsMalformed — §6.6 алхам 2.2: ЗӨВХӨН ганц widget-тэй нэр дэвшигчийн өөрийн /AP, /N, /Length, stream-ийн
// уншилт → алдаа (PDF_INVALID); бусад уншигдахгүй объект (шууд бус /FT, seal биш /V, 2+ widget-тэй гарын үсгийн эхний
// widget-ийн /AP, /N, /Length) алгасагдана. Эвдэрсэн хэсэг зөв нэр дэвшигчийн ӨМНӨ ба ДАРАА (xref-ийн дараалал) — ижил үр дүн.
func TestDocIDFromStampsMalformed(t *testing.T) {
	const good, other = "44444444-4444-4444-8444-444444444444", "55555555-5555-4555-8555-555555555555"
	ref := func(n int) string { return fmt.Sprintf("%d 0 R", n) }
	// Зөв нэр дэвшигч (a-аас 3 объект): widget → a+2 (end 50, байрлал 1), a+1 тэмдэгтэй дардас.
	valid := func(a int) []string {
		return []string{stampWidget(ref(a+2), fmt.Sprint(a+1)), stampStream(good, 1, ""), stampSig(50)}
	}
	type group struct {
		objs   []string
		broken []int // эвдэх объектууд
		seal   int   // group-ийн e-Seal гарын үсэг (байрлал 2), 0 — алга
	}
	// twoWidgets — e-Seal гарын үсэг (a+3, end 200) 2 widget-тэй; эхнийх (a) нь /AP a+1 0 R, хоёр дахь нь a+4.
	twoWidgets := func(a int, stream string, extra []string, broken ...int) group {
		objs := append([]string{"<< /FT /Sig /V " + ref(a+3) + " /AP " + ref(a+1) + " >>", "<< /N " + ref(a+2) + " >>",
			stream, stampSig(200), stampWidget(ref(a+3), fmt.Sprint(a+2))}, extra...)
		return group{objs, broken, a + 3}
	}
	// oneWidget — e-Seal гарын үсэг (a+3, end 200) ганц widget-тэй (a): /AP a+1 0 R → /N a+2 0 R.
	oneWidget := func(a int, stream string, extra []string, broken ...int) group {
		objs := append([]string{"<< /FT /Sig /V " + ref(a+3) + " /AP " + ref(a+1) + " >>", "<< /N " + ref(a+2) + " >>",
			stream, stampSig(200)}, extra...)
		return group{objs, broken, a + 3}
	}
	cases := []struct {
		name string
		bad  func(a, validSig int) group
		fail bool // true — PDF_INVALID (нэр дэвшигчийн өөрийн уншилт)
	}{
		{"(a) шууд бус /FT уншигдахгүй — алгасна", func(a, vs int) group {
			return group{[]string{"<< /FT " + ref(a+1) + " /V " + ref(vs) + " /AP << /N " + ref(a+2) + " >> >>", "/Sig",
				stampStream(other, 1, "")}, []int{a + 1}, 0}
		}, false},
		{"(b) seal биш /V уншигдахгүй — алгасна", func(a, _ int) group {
			return group{[]string{"<< /FT /Sig /V " + ref(a+1) + " /AP << /N " + ref(a+2) + " >> >>", stampSig(10),
				stampStream(other, 1, "")}, []int{a + 1}, 0}
		}, false},
		{"(c) 2 widget, эхнийх /AP уншигдахгүй — алгасна", func(a, _ int) group {
			return twoWidgets(a, stampStream(other, 2, ""), nil, a+1)
		}, false},
		{"(c) 2 widget, эхнийх /N уншигдахгүй — алгасна", func(a, _ int) group {
			return twoWidgets(a, stampStream(other, 2, ""), nil, a+2)
		}, false},
		{"(c) 2 widget, эхнийх /Length уншигдахгүй — алгасна", func(a, _ int) group {
			return twoWidgets(a, stampStreamLenRef(other, 2, a+5), []string{"47"}, a+5)
		}, false},
		{"ганц widget, /AP уншигдахгүй — PDF_INVALID", func(a, _ int) group {
			return oneWidget(a, stampStream(other, 2, ""), nil, a+1)
		}, true},
		{"ганц widget, /N уншигдахгүй — PDF_INVALID", func(a, _ int) group {
			return oneWidget(a, stampStream(other, 2, ""), nil, a+2)
		}, true},
		{"ганц widget, /Length уншигдахгүй — PDF_INVALID", func(a, _ int) group {
			return oneWidget(a, stampStreamLenRef(other, 2, a+4), []string{"47"}, a+4)
		}, true},
		{"ганц widget, шууд бус /DecodeParms уншигдахгүй — PDF_INVALID", func(a, _ int) group {
			return oneWidget(a, stampStream(other, 2, " /DecodeParms "+ref(a+4)), []string{"<< >>"}, a+4)
		}, true},
	}
	for _, c := range cases {
		n := len(c.bad(0, 0).objs)
		for _, badFirst := range []bool{true, false} {
			va, ba := 4+n, 4 // эвдэрсэн хэсэг эхэнд (бага дугаар)
			if !badFirst {
				va, ba = 4, 7
			}
			g := c.bad(ba, va+2)
			var objs []string
			if badFirst {
				objs = append(g.objs, valid(va)...)
			} else {
				objs = append(valid(va), g.objs...)
			}
			doc := stampPDF(objs...)
			for _, b := range g.broken {
				doc = breakObj(t, doc, b)
			}
			seals := map[uint32]int{uint32(va + 2): 1}
			if g.seal != 0 {
				seals[uint32(g.seal)] = 2
			}
			got, err := docIDFromStamps(doc, seals)
			switch {
			case c.fail && (err == nil || got != ""):
				t.Errorf("%s (эхэнд=%v): %q %v, хүлээсэн алдаа", c.name, badFirst, got, err)
			case !c.fail && (err != nil || got != good):
				t.Errorf("%s (эхэнд=%v): %q %v, хүлээсэн %q", c.name, badFirst, got, err, good)
			}
		}
	}
}

// appendUpdate — doc-д гарын үсэггүй incremental update (first-ээс эхэлсэн объектууд, /Prev-тэй classic xref) залгана.
func appendUpdate(t *testing.T, doc []byte, first int, objs []string) []byte {
	t.Helper()
	i := bytes.LastIndex(doc, []byte("startxref\n"))
	if i < 0 {
		t.Fatal("startxref алга")
	}
	var prev int
	if _, err := fmt.Sscanf(string(doc[i+len("startxref\n"):]), "%d", &prev); err != nil {
		t.Fatalf("startxref: %v", err)
	}
	b := bytes.NewBuffer(append([]byte{}, doc...))
	offs := make([]int, len(objs))
	for k, o := range objs {
		offs[k] = b.Len()
		fmt.Fprintf(b, "%d 0 obj\n%s\nendobj\n", first+k, o)
	}
	x := b.Len()
	fmt.Fprintf(b, "xref\n%d %d\n", first, len(objs))
	for _, o := range offs {
		fmt.Fprintf(b, "%010d 00000 n\r\n", o)
	}
	fmt.Fprintf(b, "trailer\n<< /Size %d /Root 1 0 R /Prev %d >>\nstartxref\n%d\n%%%%EOF\n", first+len(objs), prev, x)
	return b.Bytes()
}

// TestDocIDFromStampsManyWidgets — §6.6 алхам 2.2-ийн ажлын хэмжээ O(xref-ийн объект): гарын үсэггүй update 200 000 жижиг
// `<</FT/Sig/V <seal> 0 R>>` widget нэмнэ. Тоолох үе /V-г resolve хийхгүй (түүхий лавлагаа) — e-Seal гарын үсэг 256 KiB
// /Contents-тэй тул widget бүрд /V-г задалдаг (n × гарын үсгийн хэмжээ, ~50 GB) эсвэл квадрат хэрэгжүүлэлт go test-ийн
// timeout-д унана; шугаман нь хэдхэн секунд. Цагийн босго байхгүй.
func TestDocIDFromStampsManyWidgets(t *testing.T) {
	const good, n = "66666666-6666-4666-8666-666666666666", 200000
	big := "<< /Type /Sig /ByteRange [0 10 20 180] /Contents <" + strings.Repeat("00", 128<<10) + "> >>"
	// 4 widget → 6 (end 50, байрлал 1), 5 дардас; 7 = том e-Seal гарын үсэг (end 200, байрлал 2), widget-гүй.
	base := stampPDF(stampWidget("6 0 R", "5"), stampStream(good, 1, ""), stampSig(50), big)
	seals := map[uint32]int{6: 1, 7: 2}
	for _, c := range []struct {
		target, want string
	}{{"7", good}, {"6", ""}} { // 7 рүү: 7 нь 200 000 widget-тэй → үл тооно; 6 рүү: 6 нь 200 001 → "".
		objs := make([]string, n)
		for i := range objs {
			objs[i] = "<</FT/Sig/V " + c.target + " 0 R>>"
		}
		got, err := docIDFromStamps(appendUpdate(t, base, 8, objs), seals)
		if err != nil || got != c.want {
			t.Errorf("/V %s 0 R × %d: %q %v, хүлээсэн %q", c.target, n, got, err, c.want)
		}
	}
}

// TestCitizenOnlyDocIDUnchanged —алхам 2.2 ЗӨВХӨН e-Seal: verify хуудасгүй, иргэний QR дардастай (санамсаргүй docId)
// баримтад дараагийн иргэн v0.30.0-тэй ижил — харагдах docId-гүй → REQUEST_INVALID, үл харагдах → "" эсвэл opts.docId,
// харагдах opts.docId-тэй → түүгээр (дардасны docId-г хэзээ ч өвлөхгүй).
func TestCitizenOnlyDocIDUnchanged(t *testing.T) {
	p := loadOrCreatePKI(t)
	opts := func(docID string, visible bool) PrepareOptions {
		o := testOpts(p, p.citizen.cert)
		o.VerifyPage, o.FileName, o.DocID = false, "", docID
		if visible {
			o.Appearance = &Appearance{X: 340, Y: 36, Width: 220, Height: 64}
		}
		return o
	}
	prep, err := Prepare(readInput(t, "quartz-pdf13.pdf"), opts("", true))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := rsa.SignPKCS1v15(nil, p.citizen.key, crypto.SHA256, prep.DTBS)
	if err != nil {
		t.Fatal(err)
	}
	first, err := Complete(context.Background(), prep.State, sig, completeOpts(p))
	if err != nil {
		t.Fatal(err)
	}
	doc := first.PDF
	if first.HasPage || !bytes.Contains(doc, []byte("/verify/"+prep.DocID+"/1)>> BDC")) {
		t.Fatalf("суурь: хуудас %v, маркер алга", first.HasPage)
	}
	if _, err := Prepare(doc, opts("", true)); ErrorCode(err) != CodeRequestInvalid {
		t.Fatalf("харагдах, docId-гүй: %v", err)
	}
	for _, c := range []struct {
		docID   string
		visible bool
	}{{"", false}, {otherDocID, false}, {otherDocID, true}} {
		got, err := Prepare(doc, opts(c.docID, c.visible))
		if err != nil || got.DocID != c.docID {
			t.Fatalf("%+v: %v", c, err)
		}
	}
}

// TestPrepareDocIDRule — Prepare-ийн түвшинд: QR тамгатай баримтад иргэн (харагдах ба үл харагдах) тамганы docId-г авна,
// харагдах нь rev 2-оор зурна; opts.docId зөрвөл REQUEST_INVALID. QR-гүй тамгатай баримтад харагдах иргэн docId-гүй бол
// REQUEST_INVALID (v0.30.0-тэй ижил), opts.docId-тэй бол түүгээр (opt-in).
func TestPrepareDocIDRule(t *testing.T) {
	p := loadOrCreatePKI(t)
	opts := func(docID string, visible bool) PrepareOptions {
		o := testOpts(p, p.citizen.cert)
		o.VerifyPage, o.FileName, o.DocID = false, "", docID
		if visible {
			o.Appearance = &Appearance{X: 340, Y: 36, Width: 220, Height: 64}
		}
		return o
	}
	prepared := func(t *testing.T, doc []byte, o PrepareOptions) (string, []byte) {
		t.Helper()
		prep, err := Prepare(doc, o)
		if err != nil {
			t.Fatal(err)
		}
		st, err := decodeState(prep.State)
		if err != nil {
			t.Fatal(err)
		}
		return prep.DocID, st.PDF
	}
	marker := func(id string) []byte { return []byte("/EIDVerify <</URL (" + pageVerifyURL + id + "/2)>> BDC\n") }
	sealQR := readTestdata(t, "golden/output/seal-qr-visible.pdf")
	id, pdf := prepared(t, sealQR, opts("", true))
	if id != qrSealDocID || !bytes.Contains(pdf[len(sealQR):], marker(qrSealDocID)) {
		t.Fatalf("QR тамгын дараах иргэн: docId %q", id)
	}
	if id, _ := prepared(t, sealQR, opts("", false)); id != qrSealDocID {
		t.Fatalf("QR тамгын дараах үл харагдах иргэн: docId %q", id)
	}
	for _, visible := range []bool{true, false} {
		if _, err := Prepare(sealQR, opts(otherDocID, visible)); ErrorCode(err) != CodeRequestInvalid {
			t.Fatalf("opts.docId ≠ маркер (visible %v): %v", visible, err)
		}
	}
	sealV12 := readTestdata(t, "golden/output/seal-visible.pdf")
	if _, err := Prepare(sealV12, opts("", true)); ErrorCode(err) != CodeRequestInvalid {
		t.Fatalf("QR-гүй тамгын дараах иргэн, docId-гүй: %v", err)
	}
	id, pdf = prepared(t, sealV12, opts(otherDocID, true))
	if id != otherDocID || !bytes.Contains(pdf[len(sealV12):], marker(otherDocID)) {
		t.Fatalf("QR-гүй тамгын дараах иргэн, opts.docId: %q", id)
	}
}

// dtbsSealer — SealPDF-ийн Sealer: DTBS-ийг тэмдэглээд зогсооно (Complete-гүй — зөвхөн prepared байт хэрэгтэй).
type dtbsSealer struct {
	cert   []byte
	digest []byte
}

var errSealStop = errors.New("stop")

func (s *dtbsSealer) Certificate(context.Context, string) (*eid.SealCertificate, error) {
	return &eid.SealCertificate{OrgEtsi: "NTRMN-0000000", Certificate: s.cert, CertificateLevel: eid.LevelQualified}, nil
}

func (s *dtbsSealer) Seal(_ context.Context, _ string, digest []byte, _ eid.HashAlgorithm) (*eid.SealResult, error) {
	s.digest = digest
	return nil, errSealStop
}

// TestSealPDFStillQRless — энэ хувилбарт SealPDF QR-тэй тамга ГАРГАХГҮЙ: анхдагч автомат дардас ба тодорхой Appearance нь
// v0.30.0-ийн golden `seal-visible` / `seal-visible-en`-ийн DTBS-тэй байт-ижил (prepared PDF + signedAttrs; docId-гүй ч).
func TestSealPDFStillQRless(t *testing.T) {
	p := loadOrCreatePKI(t)
	if p.seal == nil {
		t.Fatal("pki/seal.pem алга")
	}
	var m goldenManifest
	if err := json.Unmarshal(readTestdata(t, "golden/manifest.json"), &m); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{}
	for _, c := range m.Cases {
		want[c.Name] = c.Expect.DTBS
	}
	chain := [][]byte{p.ca04.cert.Raw, p.ca03.cert.Raw, p.ca02.cert.Raw}
	for _, c := range []struct {
		golden, input string
		o             SealOptions
	}{
		{"seal-visible", "libreoffice-contract.pdf", SealOptions{Reason: "Нэхэмжлэх"}},
		{"seal-visible-en", "quartz-pdf13.pdf", SealOptions{Appearance: &Appearance{X: 340, Y: 36, Width: 220, Height: 64, Lang: "en"}}},
	} {
		s := &dtbsSealer{cert: p.seal.cert.Raw}
		c.o.SigningTime, c.o.Chain = goldenTime, chain
		if _, err := SealPDF(context.Background(), s, "NTRMN-0000000", readInput(t, c.input), c.o); !errors.Is(err, errSealStop) {
			t.Fatalf("%s: %v", c.golden, err)
		}
		if got := hex.EncodeToString(s.digest); want[c.golden] == "" || got != want[c.golden] {
			t.Errorf("%s: SealPDF DTBS %s ≠ golden %s", c.golden, got, want[c.golden])
		}
	}
}
