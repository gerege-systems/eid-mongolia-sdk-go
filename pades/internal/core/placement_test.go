package core

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"hash/adler32"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Placement vectors — pades/testdata/golden/placement (PLACEMENT_SPEC.md §8). Every native SDK checks its occupancy
// scanner and candidate search against vectors.json box-for-box. `go test ./pades/internal/core -run Placement
// -update-placement` regenerates the synthetic inputs (placement/input/*.pdf and the golden inputs listed in
// placementGoldenInputs) and rewrites vectors.json.
var updatePlacement = flag.Bool("update-placement", false, "pades/testdata/golden/placement-ийг дахин бичих")

var (
	goldenRoot    = filepath.Join("..", "..", "testdata", "golden")
	placementRoot = filepath.Join(goldenRoot, "placement")
)

// fxPDF — a minimal classic-xref PDF: objs[0] is object 1 (the Catalog).
func fxPDF(objs ...string) []byte {
	var b bytes.Buffer
	b.WriteString("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
	offs := make([]int, len(objs))
	for i, o := range objs {
		offs[i] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", i+1, o)
	}
	x := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n0000000000 65535 f \n", len(objs)+1)
	for _, o := range offs {
		fmt.Fprintf(&b, "%010d 00000 n \n", o)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objs)+1, x)
	return b.Bytes()
}

func fxStream(dict, data string) string {
	return fmt.Sprintf("<< %s/Length %d >>\nstream\n%s\nendstream", dict, len(data), data)
}

// fxZlib — FlateDecode stream built by hand: header (FDICT set with dictID when dictID ≥ 0), raw deflate of data,
// Adler-32; mutate edits the raw bytes (truncation, bad checksum, trailing bytes).
func fxZlib(dict, data string, dictID int64, mutate func([]byte) []byte) string {
	var raw bytes.Buffer
	w, _ := flate.NewWriter(&raw, flate.BestCompression)
	_, _ = w.Write([]byte(data))
	_ = w.Close()
	var z []byte
	if dictID < 0 {
		z = []byte{0x78, 0xDA}
	} else {
		cmf, flg := byte(0x78), byte(0xC0|0x20) // FLEVEL 3, FDICT
		flg += byte(31 - (int(cmf)*256+int(flg))%31)
		z = binary.BigEndian.AppendUint32([]byte{cmf, flg}, uint32(dictID))
	}
	z = append(z, raw.Bytes()...)
	z = binary.BigEndian.AppendUint32(z, adler32.Checksum([]byte(data)))
	if mutate != nil {
		z = mutate(z)
	}
	return fxStream(dict+"/Filter /FlateDecode ", string(z))
}

func fxFlate(dict, data string) string {
	var z bytes.Buffer
	w, _ := zlib.NewWriterLevel(&z, zlib.BestCompression)
	_, _ = w.Write([]byte(data))
	_ = w.Close()
	return fxStream(dict+"/Filter /FlateDecode ", z.String())
}

// fxHelvetica — Helvetica with /Widths 32…126 (deterministic, not the AFM values: the scanner reads only /Widths).
func fxHelvetica() string {
	var w []string
	for c := 32; c <= 126; c++ {
		w = append(w, fmt.Sprint(450+(c%7)*50))
	}
	return "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding /FirstChar 32 /LastChar 126 /Widths [" +
		strings.Join(w, " ") + "] >>"
}

// fxPage — Catalog, Pages, Page (+ extra page keys), content, Helvetica F1, then extra objects (numbered from 6).
func fxPage(pageKeys, content string, extra ...string) []byte {
	objs := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R " + pageKeys + " /Contents 4 0 R >>",
		fxStream("", content),
		fxHelvetica(),
	}
	return fxPDF(append(objs, extra...)...)
}

const letter = "/MediaBox [0 0 612 792]"

// fxLines — n text lines of s at x, from y down by lead (Helvetica size sz).
func fxLines(x, y, lead, sz float64, n int, s string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "BT /F1 %g Tf %g TL %g %g Td\n", sz, lead, x, y)
	for range n {
		fmt.Fprintf(&b, "(%s) Tj T*\n", s)
	}
	b.WriteString("ET\n")
	return b.String()
}

// placementGoldenInputs — synthetic inputs of the pades golden cases (pades/testdata/golden/input).
func placementGoldenInputs() map[string][]byte {
	res := "/Resources << /Font << /F1 5 0 R >> >>"
	// (b) A4: body text, then a 5-row full-width table at the bottom (y 40…160) under the default stamp.
	var tbl strings.Builder
	tbl.WriteString(fxLines(56.7, 780, 16, 16, 1, "Service agreement - annex 1"))
	tbl.WriteString(fxLines(56.7, 740, 14, 10, 20, "Body text line of the agreement that runs across most of the page width."))
	tbl.WriteString("0 0 0 RG 0.75 w\n")
	for i := range 6 {
		fmt.Fprintf(&tbl, "56.7 %d m 538.6 %d l S\n", 40+24*i, 40+24*i)
	}
	for _, x := range []float64{56.7, 90, 300, 420, 538.6} {
		fmt.Fprintf(&tbl, "%g 40 m %g 160 l S\n", x, x)
	}
	for r := range 5 {
		fmt.Fprintf(&tbl, "BT /F1 9 Tf 60 %d Td (%d) Tj 34 0 Td (Item %d description) Tj 210 0 Td (12) Tj 120 0 Td (1,200,000) Tj ET\n", 48+24*r, r+1, r+1)
	}
	// (c) /Rotate 90: drawn in the visible (landscape 792 x 612) space; a footer runs across the visible bottom.
	rot := "q 0 1 -1 0 612 0 cm\n" + fxLines(36, 560, 18, 18, 1, "Landscape report") +
		fxLines(36, 520, 14, 10, 10, "Rotated page body text, drawn in the visible landscape space of the page.") +
		fxLines(36, 40, 12, 9, 1, "Footer: this document is a test fixture only - it has no legal effect - page 1 of 1 - eID Mongolia placement golden case (c)") +
		"Q\n"
	// (e) every line of the page is text: no candidate is free (fallback).
	full := fxLines(36, 770, 12, 10, 64, "Full page of text. Full page of text. Full page of text. Full page of text. Full p")
	return map[string][]byte{
		"table-bottom.pdf":     fxPage("/MediaBox [0 0 595.28 841.89] "+res, tbl.String()),
		"rotated90-footer.pdf": fxPage(letter+" /Rotate 90 "+res, rot),
		"full-page.pdf":        fxPage(letter+" "+res, full),
		"two-verify.pdf":       verifyPagesInput(fxPage(letter+" "+res, fxLines(72, 700, 14, 10, 3, "Contract body text")), verifyDocA, verifyDocA),
		"fake-verify.pdf":      fakeVerifyInput(res),
		"verify-gen1.pdf":      verifyGen1Input(res),
	}
}

// verifyDocA / verifyDocB — docIds of the page-0 golden inputs (PLACEMENT_SPEC §1a).
const (
	verifyDocA = "f5a6b7c8-d9e0-4f1a-8b2c-3d4e5f607182"
	verifyDocB = "a6b7c8d9-e0f1-4a2b-9c3d-4e5f60718293"
)

// verifyPagesInput — base + one eID verify page (AppendVerifyPage, incremental) per docID.
func verifyPagesInput(base []byte, docIDs ...string) []byte {
	out := base
	for _, id := range docIDs {
		pd := PageData{Brand: "eID Mongolia", FileName: "two-verify.pdf", DocumentHash: strings.Repeat("ab", 32), FileSize: int64(len(out)),
			DocID: id, VerifyURL: "https://ca.eidmongolia.mn/verify/" + id, TrustURL: "https://eidmongolia.mn/trust",
			CAName: "eID Mongolia Issuing CA", TSAName: "eID Mongolia TSA (tsa.timeserver.mn)", Provider: "ca.eidmongolia.mn"}
		var err error
		if out, err = AppendVerifyPage(out, pd); err != nil {
			panic(err)
		}
	}
	return out
}

// fakeVerifyInput — two content pages; the last one carries a verify-looking page for another docId (verifyDocB) and
// a /verify/<docA>/1 link (a stamp-style URL): neither is the document's verify page, so it stays a content page.
func fakeVerifyInput(res string) []byte {
	return fxPDF(
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R 6 0 R] /Count 2 >>",
		"<< /Type /Page /Parent 2 0 R "+letter+" "+res+" /Contents 4 0 R >>",
		fxStream("", fxLines(72, 700, 14, 10, 3, "Page one body text")),
		fxHelvetica(),
		"<< /Type /Page /Parent 2 0 R "+letter+" "+res+" /Contents 7 0 R /Annots [8 0 R 9 0 R] >>",
		fxStream("", fxLines(72, 700, 14, 10, 3, "Page two body text")),
		"<< /Type /Annot /Subtype /Link /Rect [72 600 300 612] /Border [0 0 0] /A << /S /URI /URI (https://ca.eidmongolia.mn/verify/"+verifyDocB+") >> >>",
		"<< /Type /Annot /Subtype /Link /Rect [72 580 300 592] /Border [0 0 0] /A << /S /URI /URI (https://ca.eidmongolia.mn/verify/"+verifyDocA+"/1) >> >>",
	)
}

// verifyGen1Input — a content page and an eID verify page for verifyDocA whose page, Link annotation and URI action
// are generation 1 and 2 objects (PLACEMENT_SPEC §1a: every reference resolves with the generation it carries, every
// xref entry with the generation it records). Revision 1 is the content page alone with objects 6…8 free (6 and 7
// next generation 1, 8 next generation 2 — ISO 32000-1 §7.5.4, pyHanko strict xref); revision 2 adds the verify page
// as `6 1 obj`, its docId Link as `7 1 obj`, the Link's /A as `8 2 obj` (content 9 and the trust Link 10: generation 0).
func verifyGen1Input(res string) []byte {
	type obj struct {
		id, gen int
		body    string
	}
	var b bytes.Buffer
	write := func(objs []obj) map[int]int {
		offs := map[int]int{}
		for _, o := range objs {
			offs[o.id] = b.Len()
			fmt.Fprintf(&b, "%d %d obj\n%s\nendobj\n", o.id, o.gen, o.body)
		}
		return offs
	}
	b.WriteString("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
	r1 := []obj{
		{1, 0, "<< /Type /Catalog /Pages 2 0 R >>"},
		{2, 0, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
		{3, 0, "<< /Type /Page /Parent 2 0 R " + letter + " " + res + " /Contents 4 0 R >>"},
		{4, 0, fxStream("", fxLines(72, 700, 14, 10, 3, "Contract body text"))},
		{5, 0, fxHelvetica()},
	}
	offs := write(r1)
	x1 := b.Len()
	// Free list 0 → 6 → 7 → 8 → 0; the gen field of a free entry is the next generation of that number.
	b.WriteString("xref\n0 9\n0000000006 65535 f \n")
	for id := 1; id <= 5; id++ {
		fmt.Fprintf(&b, "%010d 00000 n \n", offs[id])
	}
	for _, f := range [][2]int{{7, 1}, {8, 1}, {0, 2}} {
		fmt.Fprintf(&b, "%010d %05d f \n", f[0], f[1])
	}
	fmt.Fprintf(&b, "trailer\n<< /Size 9 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", x1)
	r2 := []obj{
		{2, 0, "<< /Type /Pages /Kids [3 0 R 6 1 R] /Count 2 >>"},
		{6, 1, "<< /Type /Page /Parent 2 0 R " + letter + " " + res + " /Contents 9 0 R /Annots [7 1 R 10 0 R] >>"},
		{7, 1, "<< /Type /Annot /Subtype /Link /Rect [72 600 300 612] /Border [0 0 0] /A 8 2 R >>"},
		{8, 2, "<< /S /URI /URI (https://ca.eidmongolia.mn/verify/" + verifyDocA + ") >>"},
		{9, 0, fxStream("", fxLines(72, 700, 14, 10, 2, "eID Mongolia verification page"))},
		{10, 0, "<< /Type /Annot /Subtype /Link /Rect [72 580 300 592] /Border [0 0 0] /A << /S /URI /URI (https://eidmongolia.mn/trust) >> >>"},
	}
	offs = write(r2)
	x2 := b.Len()
	fmt.Fprintf(&b, "xref\n0 1\n0000000000 65535 f \n2 1\n%010d 00000 n \n6 5\n", offs[2])
	for _, o := range r2[1:] {
		fmt.Fprintf(&b, "%010d %05d n \n", offs[o.id], o.gen)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size 11 /Root 1 0 R /Prev %d >>\nstartxref\n%d\n%%%%EOF\n", x1, x2)
	return b.Bytes()
}

// placementInputs — synthetic inputs that exercise each scanner rule (placement/input).
func placementInputs() map[string][]byte {
	res := "/Resources << /Font << /F1 5 0 R >> >>"
	out := map[string][]byte{}

	// Text state: Tc, Tw (code 32), Tz, Ts, TL/T*, ', ", TJ adjustments, Tm (rotated), negative size; a footer under
	// the default spot.
	out["text-state.pdf"] = fxPage(letter+" "+res, strings.Join([]string{
		"BT /F1 12 Tf 72 700 Td 2 Tc 5 Tw (Spaced words here) Tj ET",
		"BT /F1 12 Tf 150 Tz 3 Ts 72 650 Td (Wide and raised) Tj ET",
		"BT /F1 10 Tf 14 TL 72 600 Td (first) Tj T* (second) ' 1 2 (third) \" ET",
		"BT /F1 11 Tf 72 500 Td [(Kern) -500 (ed) 2000 (back)] TJ ET",
		"BT /F1 10 Tf 0.7071 0.7071 -0.7071 0.7071 300 300 Tm (Rotated text line) Tj ET",
		"BT /F1 -10 Tf 72 200 Td (Negative size) Tj ET",
		"BT /F1 9 Tf 200 40 Td (Footer text that sits right under the default stamp position on the page) Tj ET",
	}, "\n"))

	// Fonts: Type0 Identity-H (/W both forms, /DW), Type0 with a predefined CMap, Type3, a missing font name, Tf before
	// any font; text at the bottom-right corner.
	out["fonts.pdf"] = fxPage(letter+" /Resources << /Font << /F1 5 0 R /T0 6 0 R /T1 8 0 R /T3 9 0 R >> >>", strings.Join([]string{
		"BT /T0 12 Tf 72 700 Td <0001000200030004000A> Tj ET",
		"BT /T1 12 Tf 72 650 Td <00410042> Tj ET",
		"BT /T3 12 Tf 72 600 Td (abc) Tj ET",
		"BT /Missing 12 Tf 72 550 Td (abc) Tj ET",
		"BT 72 500 Td (no Tf yet) Tj ET",
		"BT /T0 10 Tf 420 50 Td <00010002000300040005000600070008> Tj ET",
	}, "\n"),
		"<< /Type /Font /Subtype /Type0 /BaseFont /Helvetica /Encoding /Identity-H /DescendantFonts [7 0 R] >>",
		"<< /Type /Font /Subtype /CIDFontType2 /BaseFont /Helvetica /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> /DW 800 /W [1 [500 600] 3 5 700 1 [900]] >>",
		"<< /Type /Font /Subtype /Type0 /BaseFont /STSong-Light /Encoding /UniGB-UCS2-H /DescendantFonts [7 0 R] >>",
		"<< /Type /Font /Subtype /Type3 /FontBBox [0 0 1000 1000] /FontMatrix [0.001 0 0 0.001 0 0] /CharProcs << >> /Encoding << /Differences [] >> /FirstChar 97 /LastChar 99 /Widths [1 1 1] >>",
	)

	// Paths: strokes with width under a scaled CTM, curves c/v/y, closed s/b, white fills/strokes (skipped), a page
	// background (skipped), clip-only n, sh (ignored), a thin border under the bottom-left candidate.
	out["paths.pdf"] = fxPage(letter, strings.Join([]string{
		"0.9 g 0 0 612 792 re f",
		"0 g 1 1 1 rg 400 30 150 80 re f 0 0 0 0 k 380 20 50 50 re f 1 G 4 w 300 50 m 600 50 l S",
		"0 G 0 g q 2 0 0 2 0 0 cm 3 w 50 300 m 150 300 l S Q",
		"100 400 m 150 450 200 450 250 400 c 300 350 350 350 v 350 400 400 400 y S",
		"100 500 m 200 500 l 200 550 l s 300 500 m 400 500 l 400 550 l b",
		"10 10 50 50 re W n /Sh0 sh",
		"0.5 w 36 30 m 300 30 l S",
		"0 0 1 RG /DeviceRGB CS 1 1 1 SC 1 w 450 700 m 550 700 l S",
	}, "\n"))

	// XObjects: an image under the default spot via cm, a form with /Matrix holding text and a nested form, an inline
	// image whose data contains "EI" not followed by whitespace.
	img := fxStream("/Type /XObject /Subtype /Image /Width 1 /Height 1 /ColorSpace /DeviceGray /BitsPerComponent 8 ", "\x80")
	inner := fxStream("/Type /XObject /Subtype /Form /BBox [0 0 100 100] /Resources << /Font << /F1 5 0 R >> >> ", "BT /F1 10 Tf 0 0 Td (Inner form text) Tj ET")
	outer := fxStream("/Type /XObject /Subtype /Form /BBox [0 0 300 300] /Matrix [1 0 0 1 72 600] /Resources << /XObject << /In 8 0 R >> /Font << /F1 5 0 R >> >> ",
		"BT /F1 12 Tf 0 50 Td (Outer form text) Tj ET q 0.5 0 0 0.5 0 100 cm /In Do Q")
	out["xobjects.pdf"] = fxPage(letter+" /Resources << /Font << /F1 5 0 R >> /XObject << /Im0 6 0 R /Fm0 7 0 R /Fm1 9 0 R >> >>", strings.Join([]string{
		"q 200 0 0 64 380 30 cm /Im0 Do Q",
		"/Fm0 Do",
		"q 100 0 0 50 72 300 cm BI /W 4 /H 1 /CS /G /BPC 8 ID \x01EIx\x02 EI Q",
		"/Fm1 Do",
	}, "\n"), img, outer, inner,
		fxStream("/Type /XObject /Subtype /Form /BBox [0 0 10 10] ", "0 g 72 150 200 20 re f"))

	// Annotations: a visible signature widget at the default spot, a hidden annotation and a NoView one at the
	// bottom-left, a Popup, an invisible signature ([0 0 0 0]); the stamp goes to the bottom-left.
	out["annots.pdf"] = fxPDF(
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R "+letter+" /Contents 4 0 R /Annots [5 0 R 6 0 R 7 0 R 8 0 R 9 0 R 10 0 R] >>",
		fxStream("", ""),
		"<< /Type /Annot /Subtype /Widget /FT /Sig /Rect [340 36 560 100] /F 4 >>",
		"<< /Type /Annot /Subtype /Square /Rect [52 36 272 100] /F 2 >>",
		"<< /Type /Annot /Subtype /Square /Rect [60 40 200 90] /F 32 >>",
		"<< /Type /Annot /Subtype /Popup /Rect [40 30 300 120] >>",
		"<< /Type /Annot /Subtype /Widget /FT /Sig /Rect [0 0 0 0] /F 132 >>",
		"<< /Type /Annot /Subtype /Link /Rect [72 700 200 712] >>",
	)

	// Contents array of two FlateDecode streams (Name and Array filter forms), CropBox inside MediaBox, /Rotate 180.
	out["flate-rotate180.pdf"] = fxPDF(
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 /Rotate 180 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /CropBox [20 20 592 772] /Resources << /Font << /F1 7 0 R >> >> /Contents [4 0 R 5 0 R] >>",
		fxFlate("", "BT /F1 10 Tf 100 740 Td (Text near the user-space top"),
		strings.Replace(fxFlate("", ") Tj ET 0 g 400 700 150 40 re f"), "/Filter /FlateDecode", "/Filter [/FlateDecode]", 1),
		"<< >>",
		fxHelvetica(),
	)

	// /Rotate 270 page with a block where the visible bottom-right is.
	out["rotate270.pdf"] = fxPage(letter+" /Rotate 270 "+res, "0 g 40 300 60 100 re f")

	// Unsupported filter → unscanned.
	out["unscanned-filter.pdf"] = fxPDF(
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R "+letter+" /Contents 4 0 R >>",
		fxStream("/Filter /ASCIIHexDecode ", "3020302032303020323020726520660A>"),
	)

	// Form nesting deeper than 8 → unscanned.
	deep := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R " + letter + " /Resources << /XObject << /X 5 0 R >> >> /Contents 4 0 R >>",
		fxStream("", "/X Do"),
	}
	for i := range 9 {
		deep = append(deep, fxStream(fmt.Sprintf("/Type /XObject /Subtype /Form /BBox [0 0 1 1] /Resources << /XObject << /X %d 0 R >> >> ", 6+i), "/X Do"))
	}
	out["limit-depth.pdf"] = fxPDF(deep...)

	// q nesting deeper than 64 → unscanned.
	out["limit-save.pdf"] = fxPage(letter, strings.Repeat("q ", 65)+"0 g 10 10 10 10 re f")

	// Malformed tokens: stray ) ] >> } {, bad numbers (1.2.3 --5 1e5), comments, operators with wrong operands, Q
	// without q, an unterminated array swallowing the end.
	out["malformed.pdf"] = fxPage(letter+" "+res, strings.Join([]string{
		") ] >> } { % a comment re f\n",
		"Q Q 0 g 1.2.3 5 5 5 re f --5 1e5 10 10 re f",
		"+.5 -.5 5. 50 re f",
		"10 20 30 re f 1 2 3 4 5 6 7 re f",
		"<< /Dict [1 2 (3) <</N true>>] >> BDC 72 300 100 20 re f EMC",
		"BT /F1 10 Tf 72 100 Td (unbalanced \\) paren \\101 octal \\\r\nline) Tj <48 65 6C 6C 6F 2> Tj ET",
		"/Name#20With#41Hex 1 0 0 1 0 0 cm",
		"BT /F1 10 Tf 300 100 Td [(array never closed) -100 (more)",
	}, "\n"))

	// Many operators: within the limit, all boxes kept.
	var many strings.Builder
	for i := range 2000 {
		fmt.Fprintf(&many, "%d %d 2 2 re f\n", 36+(i%250)*2, 300+(i/250)*4)
	}
	out["many-ops.pdf"] = fxPage(letter, many.String())

	// zlib (§3.1): trailing bytes after the Adler-32 are ignored; truncated data, a missing Adler-32 or a wrong one →
	// unscanned (a decoder that does not detect truncation is not conformant).
	zpage := func(z string) []byte {
		return fxPDF("<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
			"<< /Type /Page /Parent 2 0 R "+letter+" /Contents 4 0 R >>", z)
	}
	zdata := "0 g 72 72 100 20 re f 300 40 200 30 re f"
	out["zlib-trailing.pdf"] = zpage(fxZlib("", zdata, -1, func(b []byte) []byte { return append(b, "garbage\x00\xff"...) }))
	out["zlib-truncated-data.pdf"] = zpage(fxZlib("", zdata, -1, func(b []byte) []byte { return b[:len(b)-12] }))
	out["zlib-no-adler.pdf"] = zpage(fxZlib("", zdata, -1, func(b []byte) []byte { return b[:len(b)-4] }))
	out["zlib-bad-adler.pdf"] = zpage(fxZlib("", zdata, -1, func(b []byte) []byte { b[len(b)-1] ^= 1; return b }))
	// FDICT (§3.1): dictionary id 1 (the Adler-32 of the empty dictionary) is accepted; any other id → unscanned.
	out["zlib-fdict-empty.pdf"] = zpage(fxZlib("", zdata, 1, nil))
	out["zlib-fdict-other.pdf"] = zpage(fxZlib("", zdata, 0x0A0B0C0D, nil))

	// Font cache (§3.4): two fonts written directly inside the page object share one cache entry (the containing
	// object) — /B is measured with /A's widths.
	narrow, wide := "<< /Type /Font /Subtype /Type1 /BaseFont /A /FirstChar 65 /Widths [100 100 100] >>",
		"<< /Type /Font /Subtype /Type1 /BaseFont /B /FirstChar 65 /Widths [900 900 900] >>"
	out["fonts-direct.pdf"] = fxPDF("<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R "+letter+" /Resources << /Font << /A "+narrow+" /B "+wide+" >> >> /Contents 4 0 R >>",
		fxStream("", "BT /A 10 Tf 72 700 Td (ABC) Tj ET\nBT /B 10 Tf 72 600 Td (ABC) Tj ET\nBT /B 10 Tf 360 40 Td (ABC) Tj ET"))

	// Huge reals (§2): float → int is saturating — /W range `0 1e20 100` assigns CIDs 0…65535 (Go amd64's plain
	// int() would give MinInt64 and assign nothing); /FirstChar 1e20 puts every code out of /Widths.
	out["int-saturate.pdf"] = fxPage(letter+" /Resources << /Font << /T0 6 0 R /S 8 0 R >> >>",
		"BT /T0 10 Tf 72 72 Td <00010002> Tj ET\nBT /S 10 Tf 72 200 Td (AB) Tj ET",
		"<< /Type /Font /Subtype /Type0 /BaseFont /X /Encoding /Identity-H /DescendantFonts [7 0 R] >>",
		"<< /Type /Font /Subtype /CIDFontType2 /BaseFont /X /DW 1000 /W [0 100000000000000000000.0 100 5 [1 2] -100000000000000000000.0 [3]] >>",
		"<< /Type /Font /Subtype /Type1 /BaseFont /Y /FirstChar 100000000000000000000.0 /Widths [50 50] /FontDescriptor << /MissingWidth 300 >> >>")
	return out
}

type placementVector struct {
	Name    string      `json:"name"`
	Input   string      `json:"input"` // relative to pades/testdata/golden
	Page    int         `json:"page"`  // 1-based
	Request [4]float64  `json:"request"`
	Expect  placeExpect `json:"expect"`
}

type placeExpect struct {
	Box    [4]int   `json:"box"`
	Rotate int      `json:"rotate"`
	Boxes  [][4]int `json:"boxes"` // null when unscanned
	X      int      `json:"x"`
	Y      int      `json:"y"`
	Status string   `json:"status"`
}

// placementVectorDefs — inputs × requests (pt). Golden inputs use the request of their pades golden case.
func placementVectorDefs() []placementVector {
	def := [4]float64{340, 36, 220, 64}
	v := []placementVector{
		{Name: "libreoffice-contract-p2", Input: "input/libreoffice-contract.pdf", Page: 2, Request: def},
		{Name: "libreoffice-contract-p1", Input: "input/libreoffice-contract.pdf", Page: 1, Request: def},
		{Name: "table-bottom", Input: "input/table-bottom.pdf", Page: 1, Request: def},
		{Name: "rotated90-footer", Input: "input/rotated90-footer.pdf", Page: 1, Request: [4]float64{536, 36, 220, 64}},
		{Name: "full-page", Input: "input/full-page.pdf", Page: 1, Request: def},
		{Name: "quartz-pdf13", Input: "input/quartz-pdf13.pdf", Page: 1, Request: def},
		{Name: "quartz-rotated90", Input: "input/quartz-rotated90.pdf", Page: 1, Request: [4]float64{36, 36, 220, 64}},
		{Name: "quartz-objstm", Input: "input/quartz-objstm.pdf", Page: 1, Request: def},
		{Name: "desktop-objstm", Input: "input/desktop-objstm.pdf", Page: 1, Request: def},
	}
	for _, n := range []string{"text-state", "fonts", "paths", "xobjects", "annots", "flate-rotate180", "rotate270",
		"unscanned-filter", "limit-depth", "limit-save", "malformed", "many-ops",
		"zlib-trailing", "zlib-truncated-data", "zlib-no-adler", "zlib-bad-adler", "zlib-fdict-empty", "zlib-fdict-other",
		"fonts-direct", "int-saturate"} {
		v = append(v, placementVector{Name: n, Input: "placement/input/" + n + ".pdf", Page: 1, Request: def})
	}
	return v
}

func runPlacementVector(t *testing.T, v placementVector) placeExpect {
	t.Helper()
	doc, err := os.ReadFile(filepath.Join(goldenRoot, v.Input)) // #nosec G304 -- тест
	if err != nil {
		t.Fatal(err)
	}
	inc, err := openIncremental(doc)
	if err != nil {
		t.Fatalf("%s: %v", v.Name, err)
	}
	page, ok := nthPage(inc.root().Key("Pages"), v.Page)
	if !ok {
		t.Fatalf("%s: page %d", v.Name, v.Page)
	}
	box, rot, err := pageGeometry(page)
	if err != nil {
		t.Fatalf("%s: %v", v.Name, err)
	}
	x, y, w, h := Round100(v.Request[0]), Round100(v.Request[1]), Round100(v.Request[2]), Round100(v.Request[3])
	got := placeExpect{Box: box, Rotate: rot, X: x, Y: y}
	occ, err := Occupancy(page, box)
	if err != nil {
		got.Status = string(PlaceUnscanned)
		return got
	}
	got.Boxes = occ
	px, py, free := PlaceVisible(box, rot, x, y, w, h, occ)
	switch {
	case !free:
		got.Status = string(PlaceOverlap)
	case px == x && py == y:
		got.Status = string(PlaceRequested)
	default:
		got.X, got.Y, got.Status = px, py, string(PlaceMoved)
	}
	return got
}

// TestPlacementVectors — occupancy boxes and the chosen position, box-for-box, against vectors.json.
func TestPlacementVectors(t *testing.T) {
	if *updatePlacement {
		writeFixtures(t, filepath.Join(goldenRoot, "input"), placementGoldenInputs())
		writeFixtures(t, filepath.Join(placementRoot, "input"), placementInputs())
	}
	path := filepath.Join(placementRoot, "vectors.json")
	var want []placementVector
	if !*updatePlacement {
		raw, err := os.ReadFile(path) // #nosec G304 -- тест
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &want); err != nil {
			t.Fatal(err)
		}
	}
	var got []placementVector
	for i, v := range placementVectorDefs() {
		v.Expect = runPlacementVector(t, v)
		got = append(got, v)
		if !*updatePlacement {
			if i >= len(want) || !reflect.DeepEqual(want[i], v) {
				t.Errorf("%s: placement vector mismatch\ngot  %+v", v.Name, v.Expect)
			}
		}
	}
	if *updatePlacement {
		out, _ := json.MarshalIndent(got, "", " ")
		// One box per line keeps the file reviewable.
		out = compactBoxes(out)
		if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil { // #nosec G306 -- тест
			t.Fatal(err)
		}
	} else if len(want) != len(got) {
		t.Errorf("vectors.json: %d vectors, want %d", len(want), len(got))
	}
}

// compactBoxes — rewrites MarshalIndent's one-number-per-line [4]int arrays as `[a, b, c, d]`.
func compactBoxes(b []byte) []byte {
	lines := strings.Split(string(b), "\n")
	var out []string
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		if strings.HasSuffix(l, "[") && i+5 < len(lines) && isIntLine(lines[i+1]) && isIntLine(lines[i+2]) &&
			isIntLine(lines[i+3]) && isIntLine(lines[i+4]) && strings.HasPrefix(strings.TrimSpace(lines[i+5]), "]") {
			n := func(s string) string { return strings.TrimSuffix(strings.TrimSpace(s), ",") }
			out = append(out, l+n(lines[i+1])+", "+n(lines[i+2])+", "+n(lines[i+3])+", "+n(lines[i+4])+strings.TrimSpace(lines[i+5]))
			i += 5
			continue
		}
		out = append(out, l)
	}
	return []byte(strings.Join(out, "\n"))
}

func isIntLine(s string) bool {
	s = strings.TrimSuffix(strings.TrimSpace(s), ",")
	if s == "" {
		return false
	}
	if s[0] == '-' {
		s = s[1:]
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

func writeFixtures(t *testing.T, dir string, files map[string][]byte) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil { // #nosec G306 -- тест
			t.Fatal(err)
		}
	}
}

// TestPlacementCandidates — the trial order on A4 with the portal's default request.
func TestPlacementCandidates(t *testing.T) {
	c := PlaceCandidates(59528, 84189, 34000, 3600, 22000, 6400)
	if c[0] != [2]int{34000, 3600} || c[1] != [2]int{3528, 3600} || c[2] != [2]int{34000, 4800} {
		t.Fatalf("order: %v", c[:3])
	}
	// right column k = 1…63 (3600 + 63·1200 + 6400 = 85600 > 80589 → k ≤ 59), then the left column.
	n := (84189 - 3600 - 3600 - 6400) / 1200
	if len(c) != 2+2*n || c[2+n] != [2]int{3528, 4800} {
		t.Fatalf("len %d (n %d), left column starts %v", len(c), n, c[2+n])
	}
	// A centred request: the mirrored column equals the requested one.
	if c := PlaceCandidates(1000, 3000, 400, 0, 200, 100); len(c) != 3 || c[1] != [2]int{400, 1200} {
		t.Fatalf("centred: %v", c)
	}
}

// FuzzOccupancy — the content-stream scanner never panics, loops or exceeds its limits on arbitrary content bytes.
func FuzzOccupancy(f *testing.F) {
	for _, b := range placementInputs() {
		if i := bytes.Index(b, []byte("stream\n")); i > 0 {
			if j := bytes.Index(b[i:], []byte("\nendstream")); j > 0 {
				f.Add(b[i+7 : i+j])
			}
		}
	}
	f.Add([]byte("BT /F1 12 Tf (abc) Tj ET q 1 0 0 1 0 0 cm 0 0 10 10 re f Q BI /W 1 ID x EI"))
	f.Fuzz(func(t *testing.T, content []byte) {
		doc := fxPage(letter+" /Resources << /Font << /F1 5 0 R >> /XObject << /X 6 0 R >> >>", string(content),
			fxStream("/Type /XObject /Subtype /Form /BBox [0 0 1 1] /Resources << /XObject << /X 6 0 R >> >> ", string(content)))
		inc, err := openIncremental(doc)
		if err != nil {
			return
		}
		page, ok := nthPage(inc.root().Key("Pages"), 1)
		if !ok {
			return
		}
		occ, err := Occupancy(page, [4]int{0, 0, 61200, 79200})
		if err == nil {
			PlaceVisible([4]int{0, 0, 61200, 79200}, 0, 34000, 3600, 22000, 6400, occ)
		}
	})
}

// TestSatInt — float → int is saturating on every platform (PLACEMENT_SPEC §2).
func TestSatInt(t *testing.T) {
	for in, want := range map[float64]int{
		0: 0, 1.9: 1, -1.9: -1, math.NaN(): 0, math.Inf(1): math.MaxInt64, math.Inf(-1): math.MinInt64,
		1e20: math.MaxInt64, -1e20: math.MinInt64, 9223372036854775807: math.MaxInt64, -9223372036854775808: math.MinInt64,
		9223372036854774784: 9223372036854774784, // the largest float64 below 2^63
	} {
		if got := SatInt(in); got != want {
			t.Errorf("SatInt(%v) = %d, want %d", in, got, want)
		}
	}
}

// TestDefaultStampPage — page 0 skips the document's own verify pages only (PLACEMENT_SPEC §1a).
func TestDefaultStampPage(t *testing.T) {
	uri := "https://ca.eidmongolia.mn/verify/" + verifyDocA
	res := "/Resources << /Font << /F1 5 0 R >> >>"
	one := fxPage(letter+" "+res, fxLines(72, 700, 14, 10, 1, "x"))
	for _, tc := range []struct {
		name    string
		doc     []byte
		uri     string
		page, n int
	}{
		{"no verify page", one, uri, 1, 1},
		{"one verify page", verifyPagesInput(one, verifyDocA), uri, 1, 2},
		{"two verify pages", verifyPagesInput(one, verifyDocA, verifyDocA), uri, 1, 3},
		{"other docId", verifyPagesInput(one, verifyDocB), uri, 2, 2},
		{"fake verify", fakeVerifyInput(res), uri, 2, 2},
		// Every page is a verify page (the single page links to the verify URL) → the last page.
		{"only verify pages", fxPage(letter+" "+res+" /Annots [6 0 R]", "",
			"<< /Type /Annot /Subtype /Link /Rect [0 0 1 1] /A << /S /URI /URI ("+uri+") >> >>"), uri, 1, 1},
		{"direct annotation", fxPage(letter+" "+res+" /Annots [<< /Subtype /Link /A << /S /URI /URI ("+uri+") >> >>]", ""), uri, 1, 1},
	} {
		page, n, err := DefaultStampPage(tc.doc, tc.uri)
		if err != nil || page != tc.page || n != tc.n {
			t.Errorf("%s: page %d n %d err %v, want %d %d", tc.name, page, n, err, tc.page, tc.n)
		}
	}
	// Two pages, both verify pages → the last (2).
	both := verifyPagesInput(fxPage(letter+" "+res+" /Annots [6 0 R]", "",
		"<< /Type /Annot /Subtype /Link /Rect [0 0 1 1] /A << /S /URI /URI ("+uri+") >> >>"), verifyDocA)
	if page, n, err := DefaultStampPage(both, uri); page != 2 || n != 2 || err != nil {
		t.Errorf("all verify: %d %d %v", page, n, err)
	}
}
