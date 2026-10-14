package validate

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/sign"
)

// ── Туслахууд: баримтын төгсгөлд гараар incremental revision нэмэх ──

// pdfText — задалсан утгыг буцааж PDF бичвэр болгоно (stream-ээс бусад).
func pdfText(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case bool:
		return strconv.FormatBool(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case pdfName:
		return "/" + string(x)
	case pdfStr:
		return fmt.Sprintf("<%x>", string(x))
	case pdfRef:
		return fmt.Sprintf("%d %d R", x.num, x.gen)
	case pdfArr:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = pdfText(e)
		}
		return "[" + strings.Join(parts, " ") + "]"
	case pdfDict:
		var b strings.Builder
		b.WriteString("<<")
		for _, k := range slices.Sorted(maps.Keys(x)) {
			fmt.Fprintf(&b, "/%s %s ", k, pdfText(x[k]))
		}
		return b.String() + ">>"
	}
	panic(fmt.Sprintf("pdfText: %T", v))
}

// with — толийг хуулж, kv хосуудаар (утга nil бол устгана) өөрчилнө.
func with(d pdfDict, kv ...any) pdfDict {
	out := maps.Clone(d)
	if out == nil {
		out = pdfDict{}
	}
	for i := 0; i < len(kv); i += 2 {
		if kv[i+1] == nil {
			delete(out, kv[i].(string))
		} else {
			out[kv[i].(string)] = kv[i+1]
		}
	}
	return out
}

func stream(dict, data string) string {
	return fmt.Sprintf("<<%s/Length %d>>\nstream\n%s\nendstream", dict, len(data), data)
}

// fixture — одоогийн баримтын гол объектууд (Catalog, эхний хуудас) ба чөлөөт дугаар.
type fixture struct {
	t        *testing.T
	v        *pdfView
	root     int
	cat      pdfDict
	page     int
	pageDict pdfDict
	next     int // ашиглагдаагүй эхний дугаар
}

func newFixture(t *testing.T, doc []byte) *fixture {
	t.Helper()
	v, err := openView(doc, newPDFBudget())
	if err != nil {
		t.Fatalf("openView: %v", err)
	}
	f := &fixture{t: t, v: v, root: v.trailer["Root"].(pdfRef).num, next: int(v.trailer["Size"].(int64))}
	f.cat = f.dict(f.root)
	kids, _ := f.v.resolve(f.dict(f.cat["Pages"].(pdfRef).num)["Kids"])
	f.page = kids.(pdfArr)[0].(pdfRef).num
	f.pageDict = f.dict(f.page)
	return f
}

func (f *fixture) dict(num int) pdfDict {
	f.t.Helper()
	o, err := f.v.get(num)
	if err != nil {
		f.t.Fatalf("объект %d: %v", num, err)
	}
	return o.(pdfDict)
}

// newNum — шинэ объектын дугаар.
func (f *fixture) newNum() int {
	f.next++
	return f.next - 1
}

// rev — нэмэх revision: objs (дугаар → бие), free (чөлөөлөх дугаарууд), compressed (ObjStm дотор бичих
// объектууд; байвал xref stream бичнэ), raw (xref-т бүртгэлгүй нэмэлт байт).
type rev struct {
	objs         map[int]string
	free         []int
	compressed   map[int]string
	unlisted     map[int]string // ObjStm-д бичигдэх боловч xref-т бүртгэгдэхгүй объектууд
	raw          string
	root         int  // 0 биш бол trailer-ийн /Root (digitorus Catalog-ийг шинэ дугаараар бичдэг)
	stream       bool // ObjStm-гүй ч xref stream бичнэ
	noInfo       bool // суурийн /Info-г trailer-т хуулахгүй
	unlistedXref bool // xref stream объектоо xref-т бүртгэхгүй (digitorus ингэдэг)
}

// appendRev — doc-ийн төгсгөлд r-ийг incremental revision болгож нэмнэ.
func appendRev(t *testing.T, doc []byte, r rev) []byte {
	t.Helper()
	f := newFixture(t, doc)
	prev := f.v.sections[0].off
	size := f.next
	info := "" // суурийн trailer-ийн /Info-г хэвээр авч явна (зөв incremental update)
	if ir, ok := f.v.trailer["Info"].(pdfRef); ok && !r.noInfo {
		info = fmt.Sprintf("  /Info %d %d R\n", ir.num, ir.gen)
	}
	root := f.root
	if r.root != 0 {
		root = r.root
	}
	b := bytes.NewBuffer(bytes.Clone(doc))
	b.WriteString("\n" + r.raw)
	offs := map[int]int{}
	for _, num := range slices.Sorted(maps.Keys(r.objs)) {
		offs[num] = b.Len()
		fmt.Fprintf(b, "%d 0 obj\n%s\nendobj\n", num, r.objs[num])
		size = max(size, num+1)
	}
	if r.compressed == nil && !r.stream {
		x := b.Len()
		b.WriteString("xref\n")
		for _, num := range slices.Sorted(maps.Keys(offs)) {
			fmt.Fprintf(b, "%d 1\n%010d 00000 n \n", num, offs[num])
		}
		for _, num := range r.free {
			fmt.Fprintf(b, "%d 1\n0000000000 00001 f \n", num)
		}
		fmt.Fprintf(b, "trailer\n<<\n  /Size %d\n%s  /Root %d 0 R\n  /Prev %d\n>>\nstartxref\n%d\n%%%%EOF\n", size, info, root, prev, x)
		return b.Bytes()
	}
	// ObjStm + xref stream (W [1 4 2], filter-гүй).
	var head, body strings.Builder
	nums := slices.Sorted(maps.Keys(r.compressed))
	for _, num := range nums {
		fmt.Fprintf(&head, "%d %d ", num, body.Len())
		body.WriteString(r.compressed[num] + " ")
		size = max(size, num+1)
	}
	for _, num := range slices.Sorted(maps.Keys(r.unlisted)) {
		fmt.Fprintf(&head, "%d %d ", num, body.Len())
		body.WriteString(r.unlisted[num] + " ")
	}
	stm, xr := size, size+1
	size += 2
	if len(nums)+len(r.unlisted) > 0 {
		offs[stm] = b.Len()
		fmt.Fprintf(b, "%d 0 obj\n%s\nendobj\n", stm, stream(fmt.Sprintf("/Type/ObjStm/N %d/First %d", len(nums)+len(r.unlisted), head.Len()), head.String()+body.String()))
	}
	xrOff := b.Len()
	if !r.unlistedXref {
		offs[xr] = xrOff
	}
	var data bytes.Buffer
	var index strings.Builder
	entry := func(num, kind, f2, f3 int) {
		fmt.Fprintf(&index, "%d 1 ", num)
		data.Write([]byte{byte(kind), byte(f2 >> 24), byte(f2 >> 16), byte(f2 >> 8), byte(f2), byte(f3 >> 8), byte(f3)})
	}
	for _, num := range slices.Sorted(maps.Keys(offs)) {
		entry(num, 1, offs[num], 0)
	}
	for i, num := range nums {
		entry(num, 2, stm, i)
	}
	fmt.Fprintf(b, "%d 0 obj\n<</Type/XRef/W[1 4 2]/Index[%s]/Size %d%s/Root %d 0 R/Prev %d/Length %d>>\nstream\n", xr, index.String(), size, info, root, prev, data.Len())
	b.Write(data.Bytes())
	fmt.Fprintf(b, "\nendstream\nendobj\nstartxref\n%d\n%%%%EOF\n", xrOff)
	return b.Bytes()
}

func signPDFVisible(t *testing.T, doc []byte, signer *testCA, tsaURL string) []byte {
	t.Helper()
	rs := bytes.NewReader(doc)
	rdr, err := pdf.NewReader(rs, int64(len(doc)))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err = sign.Sign(rs, &out, rdr, int64(len(doc)), sign.SignData{
		Signer:            signer.key,
		DigestAlgorithm:   crypto.SHA256,
		Certificate:       signer.cert,
		CertificateChains: [][]*x509.Certificate{{signer.cert}},
		TSA:               sign.TSA{URL: tsaURL},
		Signature: sign.SignDataSignature{
			CertType: sign.ApprovalSignature,
			Info:     sign.SignDataSignatureInfo{Name: "Харагдах", Date: time.Now()},
		},
		Appearance: sign.Appearance{Visible: true, Page: 1, LowerLeftX: 50, LowerLeftY: 50, UpperRightX: 250, UpperRightY: 120},
	})
	if err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// broadValidator — profileBroad-аар задалдаг шалгагч (prod-д байхгүй зам; өргөн жагсаалтын end-to-end тестэд).
func broadValidator(p *pki) *Validator {
	v := p.validator(good)
	v.Extract = func(_ context.Context, d []byte) ([]RawSignature, error) { return extractWith(d, profileBroad) }
	return v
}

// earlier — бүтэн файлыг хамраагүй (өмнөх) ганц гарын үсэг; бусад нь valid, бүтэн хамарсан байх ёстой.
func earlier(t *testing.T, rep *PDFReport, total int) SignatureReport {
	t.Helper()
	if len(rep.Signatures) != total {
		t.Fatalf("гарын үсэг %d, хүлээсэн %d", len(rep.Signatures), total)
	}
	var out []SignatureReport
	for _, s := range rep.Signatures {
		if !s.CoversWholeDocument {
			out = append(out, s)
		} else if s.Indication != Valid || s.ExtendedBySignaturesOnly || s.LaterSignatures != 0 || s.VisibleLaterSignature {
			t.Fatalf("сүүлийн гарын үсэг: %s %v %+v", s.Indication, s.Problems, s)
		}
	}
	if len(out) != total-1 {
		t.Fatalf("бүтэн хамраагүй гарын үсэг %d, хүлээсэн %d", len(out), total-1)
	}
	return out[0]
}

func wantExtended(t *testing.T, s SignatureReport, later int, visible bool) {
	t.Helper()
	if s.Indication != Valid || len(s.Problems) != 0 || s.CoversWholeDocument || !s.ExtendedBySignaturesOnly ||
		s.LaterSignatures != later || s.VisibleLaterSignature != visible {
		t.Fatalf("хүлээсэн valid + extended (later=%d visible=%v), авсан %s %v extended=%v later=%d visible=%v",
			later, visible, s.Indication, s.Problems, s.ExtendedBySignaturesOnly, s.LaterSignatures, s.VisibleLaterSignature)
	}
}

func wantModified(t *testing.T, s SignatureReport) {
	t.Helper()
	if s.Indication != Indeterminate || !slices.Equal(s.Problems, []string{ProblemModifiedAfter}) || s.CoversWholeDocument ||
		s.ExtendedBySignaturesOnly || s.LaterSignatures != 0 || s.VisibleLaterSignature {
		t.Fatalf("хүлээсэн modified_after_signing, авсан %s %v extended=%v later=%d visible=%v",
			s.Indication, s.Problems, s.ExtendedBySignaturesOnly, s.LaterSignatures, s.VisibleLaterSignature)
	}
}

// ── Эерэг: манай урсгал ──

// Манай хуучин stamp-ийн урсгал (verification хуудас + pdfcpu merge + давхар зурах; 2026-10-13-нд устсан ч файлууд нь хэвээр):
// өмнөх гарын үсэг бүр modified_after_signing БИШ, баримт бүхэлдээ valid.
func TestMultiSignatureOwnFlow(t *testing.T) {
	p := newPKI(t)
	tsaURL := tsaServer(t, p.tsa, p.issuing.cert)
	doc := minimalPDF(t)
	for i, tsa := range []string{"", tsaURL, tsaURL} {
		doc = signPDF(t, legacyWithPage(t, doc), p.leaf, []*x509.Certificate{p.issuing.cert}, tsa)
		if i == 0 {
			continue
		}
		rep := mustPDF(t, p.validator(good), doc)
		if rep.Indication != Valid || len(rep.Signatures) != i+1 {
			t.Fatalf("%d гарын үсэг: %s %+v", i+1, rep.Indication, rep.Signatures)
		}
		// Extract объектын дугаарын дарааллаар (= зурсан дарааллаар) буцаана.
		for j, s := range rep.Signatures[:i] {
			wantExtended(t, s, i-j, false)
		}
		if last := rep.Signatures[i]; !last.CoversWholeDocument || last.ExtendedBySignaturesOnly || last.LaterSignatures != 0 {
			t.Fatalf("сүүлийн гарын үсэг: %+v", last)
		}
	}
}

// Хуучин (classic) xref-тэй баримт дээр шууд давхар зурах.
func TestMultiSignatureClassicXref(t *testing.T) {
	p := newPKI(t)
	chain := []*x509.Certificate{p.issuing.cert}
	first := signPDF(t, minimalPDF(t), p.leaf, chain, "")
	second := signPDF(t, first, p.leaf, chain, tsaServer(t, p.tsa, p.issuing.cert))
	if !bytes.HasPrefix(second, first) {
		t.Fatal("эх revision өөрчлөгдсөн")
	}
	v := p.validator(good)
	rep := mustPDF(t, v, second)
	wantExtended(t, earlier(t, rep, 2), 1, false)
	if rep.Indication != Valid {
		t.Fatalf("баримт: %s", rep.Indication)
	}
	// Prod-ийн зам: шинжилгээ тусгаарлагдсан worker дотор хийгдэж, JSON-оор ижил дүн ирнэ.
	v.Extract = isolated(t)
	want, _ := json.Marshal(rep)
	if got, _ := json.Marshal(mustPDF(t, v, second)); !bytes.Equal(got, want) {
		t.Fatalf("worker:\n%s\nпроцесс дотор:\n%s", got, want)
	}
}

// digitorus/pdfsign-ийн ХАРАГДАХ гарын үсэг хуудасны объектыг дахин бичихдээ шууд бус /Resources-ийг
// шууд толь болгон хуулдаг — /Annots-оос өөр түлхүүр бүтцээрээ өөрчлөгдсөн тул зөвшөөрөгдөхгүй (fail
// closed; манай signing service харагдах гарын үсэг хэрэглэдэггүй). Зөв бичигдсэн харагдах гарын үсгийн
// эерэг тохиолдол: TestLaterChangesClassifier.
func TestMultiSignatureVisibleSignatureRewritingPageStaysModified(t *testing.T) {
	p := newPKI(t)
	first := signPDF(t, minimalPDF(t), p.leaf, []*x509.Certificate{p.issuing.cert}, "")
	second := signPDFVisible(t, first, p.leaf, tsaServer(t, p.tsa, p.issuing.cert))
	wantModified(t, earlier(t, mustPDF(t, p.validator(good), second), 2))
}

// ── Сөрөг: гарын үсгийн хооронд орсон revision. Тохиолдол бүр «хоёр дахь хүчинтэй гарын үсгийн
// өмнө халдагч revision нэмсэн» хэлбэртэй; эхний гарын үсэг modified_after_signing хэвээр үлдэх ёстой.
// "хяналт" нь яг ижил замаар хоргүй revision нэмдэг: зөвхөн хортой ялгаа л шийдвэрийг өөрчилдгийг батална. ──

func TestMultiSignatureRejectsNonSignatureChanges(t *testing.T) {
	p := newPKI(t)
	chain := []*x509.Certificate{p.issuing.cert}
	tsaURL := tsaServer(t, p.tsa, p.issuing.cert)
	first := signPDF(t, minimalPDF(t), p.leaf, chain, "")
	// ObjStm-тэй revision xref stream шаарддаг: digitorus-ийн reader холимог гинжийг (stream → table)
	// уншдаггүй тул суурь нь xref stream-тэй (pdfcpu-ийн гаралт) байна.
	merged := legacyWithPage(t, minimalPDF(t))
	firstStream := signPDF(t, merged, p.leaf, chain, "")
	evil := stream("", "BT /F1 40 Tf 20 700 Td (INJECTED) Tj ET")
	cases := []struct {
		name string
		ok   bool
		rev  func(f *fixture) rev
	}{
		{"хяналт: хуудсыг ижил утгаар дахин бичсэн", true, func(f *fixture) rev {
			return rev{objs: map[int]string{f.page: pdfText(f.pageDict)}}
		}},
		{"хяналт: зөвхөн DSS/LTV өгөгдөл", true, func(f *fixture) rev {
			dss, cert := f.newNum(), f.newNum()
			return rev{objs: map[int]string{
				f.root: pdfText(with(f.cat, "DSS", pdfRef{dss, 0})),
				dss:    pdfText(pdfDict{"Type": pdfName("DSS"), "Certs": pdfArr{pdfRef{cert, 0}}}),
				cert:   stream("", "DER"),
			}}
		}},
		{"a: хуудсанд шинэ content stream нэмсэн", false, func(f *fixture) rev {
			n := f.newNum()
			return rev{objs: map[int]string{
				f.page: pdfText(with(f.pageDict, "Contents", pdfArr{f.pageDict["Contents"], pdfRef{n, 0}})),
				n:      evil,
			}}
		}},
		{"a: хуудасны объектыг сольсон (MediaBox)", false, func(f *fixture) rev {
			return rev{objs: map[int]string{f.page: pdfText(with(f.pageDict, "MediaBox", pdfArr{int64(0), int64(0), int64(10), int64(10)}))}}
		}},
		{"a: content stream-ийг дарж бичсэн", false, func(f *fixture) rev {
			return rev{objs: map[int]string{f.pageDict["Contents"].(pdfRef).num: evil}}
		}},
		{"b: Catalog /OpenAction", false, func(f *fixture) rev {
			return rev{objs: map[int]string{f.root: pdfText(with(f.cat, "OpenAction", pdfDict{"S": pdfName("JavaScript"), "JS": pdfStr("app.alert(1)")}))}}
		}},
		{"b: Catalog /Pages өөр мод руу", false, func(f *fixture) rev {
			pages, page := f.newNum(), f.newNum()
			return rev{objs: map[int]string{
				f.root: pdfText(with(f.cat, "Pages", pdfRef{pages, 0})),
				pages:  pdfText(pdfDict{"Type": pdfName("Pages"), "Count": int64(1), "Kids": pdfArr{pdfRef{page, 0}}}),
				page:   pdfText(with(f.pageDict, "Parent", pdfRef{pages, 0})),
			}}
		}},
		{"c: гарын үсэг биш annotation нэмсэн", false, func(f *fixture) rev {
			n := f.newNum()
			return rev{objs: map[int]string{
				f.page: pdfText(with(f.pageDict, "Annots", pdfArr{pdfRef{n, 0}})),
				n: pdfText(pdfDict{"Type": pdfName("Annot"), "Subtype": pdfName("FreeText"), "Contents": pdfStr("INJECTED"),
					"Rect": pdfArr{int64(0), int64(0), int64(500), int64(500)}}),
			}}
		}},
		{"c: өмнөх annotation (эхний гарын үсгийн widget) өөрчлөгдсөн", false, func(f *fixture) rev {
			w := f.dict(f.cat["AcroForm"].(pdfDict)["Fields"].(pdfArr)[0].(pdfRef).num)
			return rev{objs: map[int]string{
				f.cat["AcroForm"].(pdfDict)["Fields"].(pdfArr)[0].(pdfRef).num: pdfText(with(w, "Rect", pdfArr{int64(0), int64(0), int64(300), int64(300)})),
			}}
		}},
		{"d: AcroForm /Fields эхний гарын үсгийн талбараа алдсан", false, func(f *fixture) rev {
			return rev{objs: map[int]string{f.root: pdfText(with(f.cat, "AcroForm", with(f.cat["AcroForm"].(pdfDict), "Fields", pdfArr{})))}}
		}},
		{"e: объект хожмын xref-т чөлөөлөгдсөн", false, func(f *fixture) rev {
			return rev{free: []int{f.pageDict["Contents"].(pdfRef).num}}
		}},
		{"хяналт: ObjStm дотор хуудсыг ижил утгаар", true, func(f *fixture) rev {
			return rev{compressed: map[int]string{f.page: pdfText(f.pageDict)}}
		}},
		{"f: ObjStm дотор нуусан хуудасны солилт", false, func(f *fixture) rev {
			return rev{compressed: map[int]string{f.page: pdfText(with(f.pageDict, "Rotate", int64(180)))}}
		}},
		{"g: xref-т бүртгэлгүй өгөгдөл", false, func(f *fixture) rev {
			return rev{objs: map[int]string{f.page: pdfText(f.pageDict)}, raw: "999 0 obj\n" + evil + "\nendobj\n"}
		}},
		{"h: шинэ объект аль ч зөвшөөрөгдсөн үүрэггүй, гэхдээ хуучин объектоос заагдсан", false, func(f *fixture) rev {
			n := f.newNum()
			return rev{objs: map[int]string{
				f.root: pdfText(with(f.cat, "DSS", pdfDict{"Certs": pdfArr{pdfRef{n, 0}}})),
				n:      stream("/Type/XObject/Subtype/Form/BBox[0 0 9 9]", "q Q"),
			}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			first := first
			if tc.rev(newFixture(t, first)).compressed != nil {
				first = firstStream
			}
			doc := appendRev(t, first, tc.rev(newFixture(t, first)))
			second := signPDF(t, doc, p.leaf, chain, tsaURL)
			if !bytes.HasPrefix(second, doc) {
				t.Fatal("эх revision өөрчлөгдсөн")
			}
			// Өргөн жагсаалт (зөвхөн тестээс хүрнэ): хяналтууд зөвшөөрөгдөнө.
			s := earlier(t, mustPDF(t, broadValidator(p), second), 2)
			if tc.ok {
				wantExtended(t, s, 1, false)
			} else {
				wantModified(t, s)
			}
			// Prod-ийн горим (profileOwnSigner): гарын үсгүүдийн хооронд орсон аливаа revision — хоргүй
			// хяналтууд ч — манай signer-ийн хэлбэр биш тул өөрчлөлт гэж гарна. Үл хамаарах: зөвхөн DSS/LTV
			// (шийдвэр 10-07, PADES_SIGNING.md §15 Q7).
			if tc.name == "хяналт: зөвхөн DSS/LTV өгөгдөл" {
				wantExtended(t, earlier(t, mustPDF(t, p.validator(good), second), 2), 1, false)
				return
			}
			wantModified(t, earlier(t, mustPDF(t, p.validator(good), second), 2))
		})
	}
}

// d: /Fields-ийн дарааллыг сольсон — хоёр гарын үсгийн дараа, гурав дахийн өмнө.
func TestMultiSignatureRejectsReorderedFields(t *testing.T) {
	p := newPKI(t)
	chain := []*x509.Certificate{p.issuing.cert}
	tsaURL := tsaServer(t, p.tsa, p.issuing.cert)
	second := signPDF(t, signPDF(t, minimalPDF(t), p.leaf, chain, ""), p.leaf, chain, tsaURL)
	f := newFixture(t, second)
	acro := f.cat["AcroForm"].(pdfDict)
	fields := acro["Fields"].(pdfArr)
	doc := appendRev(t, second, rev{objs: map[int]string{f.root: pdfText(with(f.cat, "AcroForm", with(acro, "Fields", pdfArr{fields[1], fields[0]})))}})
	rep := mustPDF(t, p.validator(good), signPDF(t, doc, p.leaf, chain, tsaURL))
	if len(rep.Signatures) != 3 {
		t.Fatalf("гарын үсэг %d", len(rep.Signatures))
	}
	for _, s := range rep.Signatures {
		if !s.CoversWholeDocument {
			wantModified(t, s)
		}
	}
}

// h: дараа нь гарын үсэг ОГТ нэмэгдээгүй засвар. LTV өгөгдөл / хоосон revision бол өөрчлөлт биш
// (later_signatures = 0), гарын үсэгтэй холбоотой мэт боловч гарын үсэггүй өөрчлөлт бол хэвээр.
func TestSingleSignatureFollowedByPlainEdit(t *testing.T) {
	p := newPKI(t)
	signed := signPDF(t, minimalPDF(t), p.leaf, []*x509.Certificate{p.issuing.cert}, "")
	f := newFixture(t, signed)
	acro := f.cat["AcroForm"].(pdfDict)
	dss, cert, field := f.newNum(), f.newNum(), f.newNum()
	cases := []struct {
		name string
		ok   bool
		rev  rev
	}{
		{"зөвхөн DSS/LTV", true, rev{objs: map[int]string{
			f.root: pdfText(with(f.cat, "DSS", pdfRef{dss, 0})),
			dss:    pdfText(pdfDict{"VRI": pdfDict{"ABCD": pdfDict{"Cert": pdfArr{pdfRef{cert, 0}}}}, "Certs": pdfArr{pdfRef{cert, 0}}}),
			cert:   stream("", "DER"),
		}}},
		{"агуулгын засвар", false, rev{objs: map[int]string{f.page: pdfText(with(f.pageDict, "Rotate", int64(90)))}}},
		{"гарын үсэггүй /SigFlags", false, rev{objs: map[int]string{f.root: pdfText(with(f.cat, "AcroForm", with(acro, "SigFlags", int64(1))))}}},
		{"гарын үсэггүй шинэ хоосон талбар", false, rev{objs: map[int]string{
			f.root: pdfText(with(f.cat, "AcroForm", with(acro, "Fields", append(slices.Clone(acro["Fields"].(pdfArr)), pdfRef{field, 0})))),
			field:  pdfText(pdfDict{"FT": pdfName("Sig"), "T": pdfStr("Empty"), "Rect": pdfArr{int64(0), int64(0), int64(200), int64(50)}}),
		}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := appendRev(t, signed, tc.rev)
			s := only(t, mustPDF(t, broadValidator(p), doc))
			if tc.ok {
				wantExtended(t, s, 0, false)
			} else {
				wantModified(t, s)
			}
			// Prod-ийн горим: гарын үсэггүй revision үргэлж өөрчлөлт — зөвхөн DSS/LTV-ээс бусад (шийдвэр 10-07).
			if tc.ok {
				wantExtended(t, only(t, mustPDF(t, p.validator(good), doc)), 0, false)
				return
			}
			wantModified(t, only(t, mustPDF(t, p.validator(good), doc)))
		})
	}
}

// ── Ангилагчийн түвшний тест (бодит криптографгүй): гараар бүтээсэн баримт дээр later()-ийг шууд дуудна.
// Shadow attack-ийн «суурьт урьдчилан бэлдсэн» хувилбаруудыг шалгахад бодит signer хэрэггүй. ──

// shadowBase — нэг хуудастай суурь баримт; extra нь нэмэлт объект / дарж бичих объектууд.
func shadowBase(extra map[int]string) []byte {
	objs := map[int]string{
		1: "<</Type/Catalog/Pages 2 0 R>>",
		2: "<</Type/Pages/Count 1/Kids[3 0 R]>>",
		3: "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R>>",
		4: stream("", "BT (signed) Tj ET"),
	}
	maps.Copy(objs, extra)
	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n")
	offs := map[int]int{}
	nums := slices.Sorted(maps.Keys(objs))
	for _, n := range nums {
		offs[n] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", n, objs[n])
	}
	x := b.Len()
	b.WriteString("xref\n0 1\n0000000000 65535 f \n")
	for _, n := range nums {
		fmt.Fprintf(&b, "%d 1\n%010d 00000 n \n", n, offs[n])
	}
	fmt.Fprintf(&b, "trailer\n<</Size 40/Root 1 0 R>>\nstartxref\n%d\n%%%%EOF\n", x)
	return b.Bytes()
}

// sigObjs — хуурамч (криптографгүй) гарын үсгийн revision: Sig толь 20, widget 21, шинэчилсэн Catalog.
func sigObjs(widgetExtra, catalogExtra string) map[int]string {
	return map[int]string{
		1:  "<</Type/Catalog/Pages 2 0 R/AcroForm<</Fields[21 0 R]/SigFlags 3>>" + catalogExtra + ">>",
		20: "<</Type/Sig/Filter/Adobe.PPKLite/ByteRange[0 100000 100010 100000]/Contents<00>>>",
		21: "<</Type/Annot/Subtype/Widget/FT/Sig/T(Signature 1)/V 20 0 R/P 3 0 R/F 132" + widgetExtra + ">>",
	}
}

func TestLaterChangesClassifier(t *testing.T) {
	merge := func(ms ...map[int]string) map[int]string {
		out := map[int]string{}
		for _, m := range ms {
			maps.Copy(out, m)
		}
		return out
	}
	form := stream("/Type/XObject/Subtype/Form/BBox[0 0 100 40]/Resources<</Font<</F1 23 0 R>>>>", "BT (visible) Tj ET")
	font := "<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>"
	emptyField := map[int]string{
		1:  "<</Type/Catalog/Pages 2 0 R/AcroForm<</Fields[10 0 R]>>>>",
		3:  "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R/Annots[10 0 R]>>",
		10: "<</Type/Annot/Subtype/Widget/FT/Sig/T(Sig)/Rect[10 10 200 60]/P 3 0 R>>",
	}
	filled := map[int]string{
		10: "<</Type/Annot/Subtype/Widget/FT/Sig/T(Sig)/Rect[10 10 200 60]/P 3 0 R/V 20 0 R/AP<</N 22 0 R>>>>",
		20: sigObjs("", "")[20], 22: form, 23: font,
	}
	cases := []struct {
		name string
		base map[int]string
		rev  rev
		want LaterChanges
	}{
		{"үл харагдах гарын үсэг", nil, rev{objs: sigObjs("/Rect[0 0 0 0]", "")}, LaterChanges{true, 1, false}},
		{"харагдах гарын үсэг: widget + AP + хуудасны Annots", nil, rev{objs: merge(sigObjs("/Rect[10 10 110 50]/AP<</N 22 0 R>>", ""), map[int]string{
			3: "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R/Annots[21 0 R]>>", 22: form, 23: font,
		})}, LaterChanges{true, 1, true}},
		{"хоосон биш Rect, AP-гүй", nil, rev{objs: sigObjs("/Rect[10 10 110 50]", "")}, LaterChanges{true, 1, true}},
		{"суурийн хоосон талбар бөглөгдсөн", emptyField, rev{objs: filled}, LaterChanges{true, 1, true}},
		{"суурийн хоосон талбар бөглөгдөхдөө Rect нь томорсон", emptyField, rev{objs: merge(filled, map[int]string{
			10: "<</Type/Annot/Subtype/Widget/FT/Sig/T(Sig)/Rect[0 0 612 792]/P 3 0 R/V 20 0 R/AP<</N 22 0 R>>>>",
		})}, LaterChanges{}},
		{"widget-д /AA үйлдэл", nil, rev{objs: sigObjs("/AA<</E<</S/JavaScript/JS(x)>>>>", "")}, LaterChanges{}},
		{"widget stream хэлбэртэй", nil, rev{objs: merge(sigObjs("", ""), map[int]string{21: stream("/FT/Sig/V 20 0 R", "q Q")})}, LaterChanges{}},
		{"AP-ийн дүрслэл суурийн объектыг дарж бичсэн", nil, rev{objs: merge(sigObjs("/Rect[0 0 9 9]/AP<</N 4 0 R>>", ""), map[int]string{4: form, 23: font})}, LaterChanges{}},
		// Shadow: суурийн хуудас «сул» заалттай (22 тодорхойлогдоогүй) — хожим 22-ыг гарын үсгийн дүрслэл
		// гэж тодорхойлбол хуудасны агуулга болно.
		{"сул заалтыг AP-аар бөглөсөн", map[int]string{3: "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents[4 0 R 22 0 R]>>"},
			rev{objs: merge(sigObjs("/Rect[0 0 9 9]/AP<</N 22 0 R>>", ""), map[int]string{22: form, 23: font})}, LaterChanges{}},
		{"сул заалтыг DSS stream-ээр бөглөсөн", map[int]string{3: "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents[4 0 R 22 0 R]>>"},
			rev{objs: map[int]string{1: "<</Type/Catalog/Pages 2 0 R/DSS<</Certs[22 0 R]>>>>", 22: stream("", "BT (evil) Tj ET")}}, LaterChanges{}},
		{"хяналт: DSS stream", nil, rev{objs: map[int]string{1: "<</Type/Catalog/Pages 2 0 R/DSS<</Certs[22 0 R]>>>>", 22: stream("", "DER")}}, LaterChanges{true, 0, false}},
		// Суурийн DSS массив нь хуудасны /Contents давхар үүрэгтэй: «сертификат» нэмэх нь агуулга нэмнэ.
		{"DSS массив хуудасны Contents давхар үүрэгтэй", map[int]string{
			1: "<</Type/Catalog/Pages 2 0 R/DSS<</Certs 5 0 R>>>>", 3: "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 5 0 R>>", 5: "[4 0 R]",
		}, rev{objs: map[int]string{5: "[4 0 R 22 0 R]", 22: stream("", "BT (evil) Tj ET")}}, LaterChanges{}},
		{"хяналт: суурийн DSS массивт сертификат нэмэгдсэн", map[int]string{1: "<</Type/Catalog/Pages 2 0 R/DSS<</Certs 5 0 R>>>>", 5: "[]"},
			rev{objs: map[int]string{5: "[22 0 R]", 22: stream("", "DER")}}, LaterChanges{true, 0, false}},
		// Stream-ийн өгөгдөл дотор «endstream endobj» нуусан: /Length-ийг 1 болгоход объект богино, өөр
		// агуулгатай болж задарна.
		{"шууд бус /Length хожим өөрчлөгдсөн", map[int]string{4: "<</Length 5 0 R>>\nstream\nq\nendstream\nendobj\nBT (signed) Tj ET\nendstream", 5: "36"},
			rev{objs: merge(sigObjs("", ""), map[int]string{5: "1"})}, LaterChanges{}},
		// Хуучин объектыг (хуудасны /Resources) өөр үүрэгт (AcroForm) дарж бичсэн — нуух халдлага.
		{"хуучин объектыг AcroForm болгож дарж бичсэн", map[int]string{
			3: "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R/Resources 5 0 R>>", 5: "<</Font<</F1 6 0 R>>>>", 6: "<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>",
		}, rev{objs: merge(sigObjs("", ""), map[int]string{1: "<</Type/Catalog/Pages 2 0 R/AcroForm 5 0 R>>", 5: "<</Fields[21 0 R]/SigFlags 3>>"})}, LaterChanges{}},
		{"Sig толь өөрчлөгдсөн объект руу заасан", nil, rev{objs: merge(sigObjs("", ""), map[int]string{
			20: "<</Type/Sig/ByteRange[0 100000 100010 100000]/Contents<00>/Reference[<</Data 22 0 R>>]>>", 22: form, 23: font,
		})}, LaterChanges{}},
		{"Catalog /Names нэмэгдсэн", nil, rev{objs: sigObjs("", "/Names<</JavaScript<</Names[(a)<</S/JavaScript/JS(x)>>]>>>>")}, LaterChanges{}},
		{"Catalog /Version (толгойноос багагүй)", nil, rev{objs: sigObjs("", "/Version/1.7")}, LaterChanges{true, 1, false}},
		{"d: AcroForm-д /NeedAppearances, /DA нэмсэн", nil, rev{objs: merge(sigObjs("", ""), map[int]string{
			1: "<</Type/Catalog/Pages 2 0 R/AcroForm<</Fields[21 0 R]/SigFlags 3/NeedAppearances true/DA(/F1 0 Tf)>>>>",
		})}, LaterChanges{}},
		{"хоёр дахин тодорхойлсон түлхүүр", nil, rev{objs: merge(sigObjs("", ""), map[int]string{21: "<</FT/Sig/V 20 0 R/Rect[0 0 0 0]/Rect[0 0 500 500]>>"})}, LaterChanges{}},
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

// xref-ийн түвшний заль: эдгээрт appendRev хүрэлцэхгүй тул байтаар бүтээнэ.
func TestLaterChangesXrefTricks(t *testing.T) {
	base := shadowBase(map[int]string{9: stream("", "BT (hidden) Tj ET")})
	f := newFixture(t, base)
	hidden := f.v.xref[9].off
	prev := f.v.sections[0].off
	tail := func(body, xref, trailer string) []byte {
		b := bytes.NewBuffer(bytes.Clone(base))
		b.WriteString(body)
		x := b.Len()
		fmt.Fprintf(b, "xref\n%strailer\n<<%s/Root 1 0 R/Prev %d>>\nstartxref\n%d\n%%%%EOF\n", xref, trailer, prev, x)
		return b.Bytes()
	}
	cases := map[string][]byte{
		// Хожмын xref нь гарын үсгийн мужийн доторх (нуусан) объект руу 4-ийг зааж агуулгыг сольсон.
		"хожмын xref мужийн доторх байт руу заасан": tail("", fmt.Sprintf("4 1\n%010d 00000 n \n", hidden), "/Size 40"),
		// /Size-ийг бууруулж объект нуух.
		"Size буурсан": tail("", "", "/Size 4"),
		// Суурийн xref-ийг алгассан гинж (/Prev-гүй шинэ xref нь ганцаараа).
		"хоосон revision (хяналт биш: /Info нэмсэн)": tail("", "", "/Size 40/Info 9 0 R"),
		"шифрлэлт нэмсэн":                            tail("", "", "/Size 40/Encrypt 9 0 R"),
		"hybrid XRefStm":                             tail("", "", "/Size 40/XRefStm 10"),
		"төгсгөлд хог":                               append(tail("", "", "/Size 40"), "% нэмэлт\n"...),
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := testRevisions(doc).later(int64(len(base))); got != (LaterChanges{}) {
				t.Fatalf("зөвшөөрөгдлөө: %+v", got)
			}
		})
	}
	// Хяналт: яг ижил замаар бичсэн хоосон revision нь өөрчлөлт биш.
	if got := testRevisions(tail("", "", "/Size 40")).later(int64(len(base))); got != (LaterChanges{SignaturesOnly: true}) {
		t.Fatalf("хоосон revision: %+v", got)
	}
}

// Суурийн /Size нь бага (9-р объект viewer-т «байхгүй»); хожмын trailer /Size-ийг өсгөж ил гаргана.
func TestLaterChangesSizeRevealsHiddenObject(t *testing.T) {
	hide := map[int]string{3: "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents[4 0 R 9 0 R]>>", 9: stream("", "BT (hidden) Tj ET")}
	base := bytes.Replace(shadowBase(hide), []byte("/Size 40"), []byte("/Size 05"), 1)
	doc := fmt.Appendf(bytes.Clone(base), "\nxref\ntrailer\n<</Size 40/Root 1 0 R/Prev %d>>\nstartxref\n%d\n%%%%EOF\n", bytes.LastIndex(base, []byte("xref\n0 1")), len(base)+1)
	if got := testRevisions(doc).later(int64(len(base))); got != (LaterChanges{}) {
		t.Fatalf("зөвшөөрөгдлөө: %+v", got)
	}
}

// Linearized толийн /L-ийг эцсийн файлын урттай таарахаар урьдчилан бэлдсэн суурь.
func TestLaterChangesLinearizedLengthTrick(t *testing.T) {
	base := shadowBase(map[int]string{1: "<</Type/Catalog/Pages 2 0 R/Linearized 1/L 000000>>"})
	final := len(appendRev(t, base, rev{}))
	armed := bytes.Replace(base, []byte("/L 000000"), fmt.Appendf(nil, "/L %06d", final), 1)
	if got := testRevisions(appendRev(t, base, rev{})).later(int64(len(base))); got != (LaterChanges{SignaturesOnly: true}) {
		t.Fatalf("хяналт: %+v", got)
	}
	if got := testRevisions(appendRev(t, armed, rev{})).later(int64(len(armed))); got != (LaterChanges{}) {
		t.Fatalf("зөвшөөрөгдлөө: %+v", got)
	}
}

// Дайсагнасан revision: гүн давхарлалт, асар том тоо — panic/гацалтгүй, зөвшөөрөгдөхгүй.
func TestLaterChangesHostileInput(t *testing.T) {
	base := shadowBase(nil)
	deep := strings.Repeat("[", 100_000) + strings.Repeat("]", 100_000)
	for name, r := range map[string]rev{
		"гүн давхарлалт": {objs: merge2(sigObjs("", ""), 22, deep)},
		"том тоо":        {objs: merge2(sigObjs("", ""), 22, "99999999999999999999999999")},
		"хязгааргүй hex": {objs: merge2(sigObjs("", ""), 22, "<00")},
		"g: задрахгүй":   {objs: merge2(sigObjs("", ""), 22, "<</A [ >>")},
	} {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			if got := testRevisions(appendRev(t, base, r)).later(int64(len(base))); got != (LaterChanges{}) {
				t.Fatalf("зөвшөөрөгдлөө: %+v", got)
			}
			if el := time.Since(start); el > 5*time.Second {
				t.Fatalf("хэт удаан: %s", el)
			}
		})
	}
}

func merge2(m map[int]string, num int, body string) map[int]string {
	out := maps.Clone(m)
	out[num] = body
	return out
}
