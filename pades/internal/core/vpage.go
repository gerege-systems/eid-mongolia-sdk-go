package core

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/digitorus/pdf"

	"github.com/gerege-systems/eid-mongolia-sdk-go/pades/assets"
	"github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/qr"
)

// Баталгаажуулалтын хуудас — PAGE_SPEC.md (pades-client/1). Минимал детерминист writer: бүх координат бүхэл pt, өнгө
// тогтмол мөр, stream шахалтгүй (фонтын asset-аас бусад), QR нь вектор тэгш өнцөгт. Native SDK бүр 1:1 давтана.
// CA-ийн fpdf/pdfcpu хуудастай төрх ойролцоо, байт-ижил биш.

// PageData — хуудасны агуулга (зурагчийн мэдээлэлгүй — тэр нь CMS-д).
type PageData struct {
	Brand        string // "eID Mongolia"
	FileName     string // NFC, цэвэрлэсэн
	DocumentHash string // хуудас нэмэхээс ӨМНӨХ оролтын SHA-256 (жижиг hex)
	FileSize     int64
	DocID        string
	VerifyURL    string
	TrustURL     string
	CAName       string
	TSAName      string
	Provider     string
	Lang         string // "mn" (анхдагч) | "en" — PAGE_SPEC.md §3a
}

// pageText — хуудасны тогтмол бичвэр (PAGE_SPEC.md §3a).
type pageText struct {
	title, subtitle, document, fileName, hashAlg, size, docHash, docID, verification string
	scan, scanHint, trust, provider                                                  string
}

var pageTexts = map[string]pageText{
	"mn": {
		title:        "-аар гарын үсэг зурсан баримт",
		subtitle:     "Гарын үсгүүд энэ PDF-д шингэсэн. Доорх холбоосоор эсвэл Adobe Acrobat-ын Signatures самбараар шалгана уу.",
		document:     "БАРИМТ",
		fileName:     "БАРИМТЫН НЭР",
		hashAlg:      "HASH АЛГОРИТМ",
		size:         "ХЭМЖЭЭ",
		docHash:      "БАРИМТЫН HASH",
		docID:        "БАРИМТЫН ID",
		verification: "ШАЛГАХ",
		scan:         "Гарын үсгийг шалгах",
		scanHint:     "QR кодыг утасны камераар уншуулах эсвэл холбоосыг нээнэ үү.",
		trust:        "Adobe Acrobat-д Монгол Улсын үндэсний Root CA-д итгэх заавар:",
		provider:     "Үйлчилгээ",
	},
	"en": {
		title:        " — Electronically signed document",
		subtitle:     "Signatures are embedded in this PDF. Verify them with the link below or in Adobe Acrobat's Signatures panel.",
		document:     "DOCUMENT",
		fileName:     "FILE NAME",
		hashAlg:      "HASH ALGORITHM",
		size:         "SIZE",
		docHash:      "DOCUMENT HASH",
		docID:        "DOCUMENT ID",
		verification: "VERIFICATION",
		scan:         "Scan to verify",
		scanHint:     "Scan this QR code with your phone camera to verify.",
		trust:        "Adobe Acrobat: trust the Mongolian National Root CA",
		provider:     "Provider",
	},
}

const (
	pageMediaBox = "[0 0 595.28 841.89]"
	pgLeft       = 42
	pgWidth      = 510
	pgCol2       = 297
	qrModule     = 2
	qrTextX      = 136
	fileNameMax  = 3

	colText   = "0.118 0.118 0.118"
	colMuted  = "0.431 0.431 0.431"
	colOK     = "0.086 0.541 0.31"
	colBanner = "0.863 0.961 0.902"
	colLine   = "0.863 0.863 0.863"
	colLink   = "0.118 0.431 0.863"

	// bannerPath — x 42…552, y 748…800, булан r = 6 (Bézier удирдах цэг 3.31).
	bannerPath = "48 800 m\n546 800 l\n549.31 800 552 797.31 552 794 c\n552 754 l\n552 750.69 549.31 748 546 748 c\n" +
		"48 748 l\n44.69 748 42 750.69 42 754 c\n42 794 l\n42 797.31 44.69 800 48 800 c\nh\nf"
)

// font id: 1 = NotoSans (Regular), 2 = NotoSans-Bold, 3 = Courier (стандарт 14, WinAnsi).
type pageWriter struct {
	ops      bytes.Buffer
	reg, bld *assets.Font
	links    [][5]any // x1 y1 x2 y2 url
}

func (w *pageWriter) op(s string, a ...any) {
	fmt.Fprintf(&w.ops, s, a...)
	w.ops.WriteByte('\n')
}

func (w *pageWriter) font(id int) *assets.Font {
	if id == 2 {
		return w.bld
	}
	return w.reg
}

// gids — тэмдэгт бүрийн glyph ID; фонтод байхгүй тэмдэгт → '?'.
func (w *pageWriter) gids(id int, s string) []uint16 {
	f := w.font(id)
	out := make([]uint16, 0, len(s))
	for _, r := range s {
		g, ok := f.GID[r]
		if !ok {
			g = f.GID['?']
		}
		out = append(out, g)
	}
	return out
}

// width1000 — мөрийн өргөн 1/1000 pt-ээр (size pt-д): Σ Width1000 × size. Courier: 600 × тэмдэгт.
func (w *pageWriter) width1000(id, size int, s string) int {
	if id == 3 {
		return 600 * utf8.RuneCountInString(s) * size
	}
	sum := 0
	for _, g := range w.gids(id, s) {
		sum += w.font(id).Width1000(g)
	}
	return sum * size
}

func (w *pageWriter) text(id, size, x, y int, color, s string) {
	var str string
	if id == 3 {
		str = "(" + pdfLiteral(s) + ")"
	} else {
		var b strings.Builder
		b.WriteByte('<')
		for _, g := range w.gids(id, s) {
			fmt.Fprintf(&b, "%04X", g)
		}
		b.WriteByte('>')
		str = b.String()
	}
	w.op("%s rg", color)
	w.op("BT /F%d %d Tf %d %d Td %s Tj ET", id, size, x, y, str)
}

// link — текстийн доорх URI annotation: [x, y−3, x+ceil(width), y+size].
func (w *pageWriter) link(id, size, x, y int, s string) {
	wd := (w.width1000(id, size, s) + 999) / 1000
	w.links = append(w.links, [5]any{x, y - 3, x + wd, y + size, s})
}

func (w *pageWriter) hline(y int) {
	w.op("%s RG", colLine)
	w.op("0.75 w %d %d m %d %d l S", pgLeft, y, pgLeft+pgWidth, y)
}

// wrap — PAGE_SPEC.md §Мөр таслах: U+0020-оор үг, greedy; үг ганцаараа багтахгүй бол тэмдэгтээр; ≤ maxLines, илүү
// бол сүүлийн мөрийг «…»-тэй богиносгоно.
func (w *pageWriter) wrap(id, size int, s string, maxW, maxLines int) []string {
	return w.wrapLimit(id, size, s, maxW*1000, maxLines)
}

// wrapLimit — wrap, өргөний хязгаар limit нь 1/1000 pt-ээр (харагдах гарын үсэгт: 1/100 pt × 10).
func (w *pageWriter) wrapLimit(id, size int, s string, limit, maxLines int) []string {
	fits := func(t string) bool { return w.width1000(id, size, t) <= limit }
	var lines []string
	cur := ""
	for _, word := range strings.Split(s, " ") {
		if word == "" {
			continue
		}
		cand := word
		if cur != "" {
			cand = cur + " " + word
		}
		if fits(cand) {
			cur = cand
			continue
		}
		if cur != "" {
			lines = append(lines, cur)
			cur = ""
		}
		for !fits(word) { // үг дангаараа урт → тэмдэгтээр
			r := []rune(word)
			n := 1
			for n < len(r) && fits(string(r[:n+1])) {
				n++
			}
			lines = append(lines, string(r[:n]))
			word = string(r[n:])
		}
		cur = word
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	if len(lines) > maxLines {
		last := []rune(lines[maxLines-1])
		for len(last) > 0 && !fits(string(last)+"…") {
			last = last[:len(last)-1]
		}
		lines = append(lines[:maxLines-1], string(last)+"…")
	}
	return lines
}

// HumanSize — PAGE_SPEC.md: < 1024 → "N B"; KB/MB/GB нэг аравтын оронтой, бүхэл арифметикээр .05 дээш тойруулна.
func HumanSize(b int64) string {
	switch {
	case b < 1<<10:
		return strconv.FormatInt(b, 10) + " B"
	case b < 1<<20:
		return tenths(b, 1<<10) + " KB"
	case b < 1<<30:
		return tenths(b, 1<<20) + " MB"
	}
	return tenths(b, 1<<30) + " GB"
}

func tenths(b, unit int64) string {
	t := (b*10 + unit/2) / unit
	return strconv.FormatInt(t/10, 10) + "." + strconv.FormatInt(t%10, 10)
}

// urlHost — "https://" / "http://"-ийг хасаад хоёр дахь '/' хүртэл (CA urlHost).
func urlHost(u string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	if i := strings.Index(s, "/"); i > 0 {
		if next := strings.Index(s[i+1:], "/"); next > 0 {
			return s[:i+1+next]
		}
	}
	return s
}

// pdfLiteral — ( ) \ -г escape (ASCII).
func pdfLiteral(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `(`, `\(`, `)`, `\)`)
	return r.Replace(s)
}

func asciiURL(u string) bool {
	for i := 0; i < len(u); i++ {
		if c := u[i]; c < 0x21 || c > 0x7e || c == '(' || c == ')' || c == '\\' {
			return false
		}
	}
	return u != ""
}

// pageContent — хуудасны content stream ба link-үүд.
func pageContent(p PageData, reg, bld *assets.Font) ([]byte, [][5]any, error) {
	if !asciiURL(p.VerifyURL) || p.TrustURL != "" && !asciiURL(p.TrustURL) {
		return nil, nil, errors.New("pades: URL ASCII биш")
	}
	m, err := qr.Encode([]byte(p.VerifyURL))
	if err != nil {
		return nil, nil, err
	}
	lang := p.Lang
	if lang == "" {
		lang = "mn"
	}
	tx, ok := pageTexts[lang]
	if !ok {
		return nil, nil, fmt.Errorf("pades: хуудасны хэл %q", p.Lang)
	}
	w := &pageWriter{reg: reg, bld: bld}
	// Banner
	w.op("%s rg", colBanner)
	w.op("%s", bannerPath)
	w.text(2, 13, 56, 778, colOK, p.Brand+tx.title)
	w.text(1, 9, 56, 760, colOK, tx.subtitle)
	// DOCUMENT
	y := 724
	w.hline(y)
	w.text(2, 11, pgLeft, y-17, colText, tx.document)
	y -= 34
	w.text(1, 8, pgLeft, y, colMuted, tx.fileName)
	y -= 14
	for i, line := range w.wrap(2, 10, p.FileName, pgWidth, fileNameMax) {
		if i > 0 {
			y -= 14
		}
		w.text(2, 10, pgLeft, y, colText, line)
	}
	y -= 20
	w.text(1, 8, pgLeft, y, colMuted, tx.hashAlg)
	w.text(1, 8, pgCol2, y, colMuted, tx.size)
	w.text(2, 10, pgLeft, y-14, colText, "SHA256")
	w.text(2, 10, pgCol2, y-14, colText, HumanSize(p.FileSize))
	y -= 34
	w.text(1, 8, pgLeft, y, colMuted, tx.docHash)
	w.text(3, 9, pgLeft, y-13, colText, p.DocumentHash)
	y -= 31
	w.text(1, 8, pgLeft, y, colMuted, tx.docID)
	w.text(3, 9, pgLeft, y-13, colText, p.DocID)
	y -= 35
	// VERIFICATION
	w.hline(y)
	w.text(2, 11, pgLeft, y-17, colText, tx.verification)
	y -= 35
	w.text(1, 9, pgLeft, y, colLink, p.VerifyURL)
	w.link(1, 9, pgLeft, y, p.VerifyURL)
	y -= 14
	// QR: дээд зүүн булан (42, y); мөр бүрийн хар модулийн тасралтгүй хэвтээ хэсэг = нэг тэгш өнцөгт.
	w.op("0 0 0 rg")
	n := len(m)
	for r := range n {
		for c := 0; c < n; {
			if !m[r][c] {
				c++
				continue
			}
			s := c
			for c < n && m[r][c] {
				c++
			}
			w.op("%d %d %d %d re", pgLeft+qrModule*s, y-qrModule*(r+1), qrModule*(c-s), qrModule)
		}
	}
	w.op("f")
	w.text(2, 11, qrTextX, y-14, colText, tx.scan)
	w.text(1, 9, qrTextX, y-29, colMuted, tx.scanHint)
	w.text(2, 9, qrTextX, y-43, colLink, urlHost(p.VerifyURL))
	if p.TrustURL != "" {
		w.text(1, 9, qrTextX, y-60, colMuted, tx.trust)
		w.text(2, 9, qrTextX, y-74, colLink, p.TrustURL)
		w.link(2, 9, qrTextX, y-74, p.TrustURL)
	}
	// Footer
	w.hline(71)
	w.text(1, 8, pgLeft, 58, colMuted, "CA: "+p.CAName+"  |  TSA: "+p.TSAName+"  |  "+tx.provider+": "+p.Provider)
	return w.ops.Bytes(), w.links, nil
}

// AppendVerifyPage — base-ийн ард баталгаажуулалтын хуудсыг INCREMENTAL UPDATE-аар нэмнэ (PAGE_SPEC.md §Объект):
// шинэ объектууд (хуудас, content, 2 Type0 фонт × 5 объект, Courier, link annotation-ууд) + /Pages үндсийн шинэ
// хувилбар (/Kids төгсгөлд, /Count + 1). Catalog өөрчлөгдөхгүй.
func AppendVerifyPage(base []byte, p PageData) ([]byte, error) {
	return InsertVerifyPage(base, p, false)
}

// InsertVerifyPage — AppendVerifyPage; first бол хуудас үндсэн /Pages-ийн /Kids-ийн ЭХЭНД орж баримтын 1-р хуудас
// болно (PAGE_SPEC.md §8a). Бусад бүх объект, дугаарлалт first-ээс үл хамаарна.
func InsertVerifyPage(base []byte, p PageData, first bool) (out []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, fmt.Errorf("%w: %v", ErrPDF, r)
		}
	}()
	reg, err := assets.Regular()
	if err != nil {
		return nil, err
	}
	bld, err := assets.Bold()
	if err != nil {
		return nil, err
	}
	content, links, err := pageContent(p, reg, bld)
	if err != nil {
		return nil, err
	}
	inc, err := openIncremental(base)
	if err != nil {
		return nil, err
	}
	root := inc.root()
	pages := root.Key("Pages")
	pp := pages.GetPtr()
	if pages.Kind() != pdf.Dict || pages.Key("Type").Name() != "Pages" || pp == root.GetPtr() || pp.GetID() == 0 {
		return nil, fmt.Errorf("%w: /Pages үндэс алга", ErrPDF)
	}
	count := pages.Key("Count").Int64()
	if count < 0 || pages.Key("Kids").Kind() != pdf.Array {
		return nil, fmt.Errorf("%w: /Pages /Kids /Count буруу", ErrPDF)
	}
	rp := root.GetPtr()
	if rp.GetGen() != 0 {
		return nil, fmt.Errorf("%w: Catalog-ийн үе 0 биш", ErrPDF)
	}
	// Дугаар: хуудас, content, F1 (Type0, CIDFont, FontDescriptor, FontFile2, ToUnicode), F2 (мөн), F3, link-үүд.
	pageID, contentID := inc.reserve(), inc.reserve()
	var fontIDs [2][5]uint32
	for i := range fontIDs {
		for j := range fontIDs[i] {
			fontIDs[i][j] = inc.reserve()
		}
	}
	courierID := inc.reserve()
	linkIDs := make([]uint32, len(links))
	for i := range linkIDs {
		linkIDs[i] = inc.reserve()
	}

	var pg bytes.Buffer
	fmt.Fprintf(&pg, "<< /Type /Page /Parent %d %d R /MediaBox %s /CropBox %s /Rotate 0 /Resources << /Font << /F1 %d 0 R /F2 %d 0 R /F3 %d 0 R >> >> /Contents %d 0 R",
		pp.GetID(), pp.GetGen(), pageMediaBox, pageMediaBox, fontIDs[0][0], fontIDs[1][0], courierID, contentID)
	if len(linkIDs) > 0 {
		pg.WriteString(" /Annots [")
		for i, id := range linkIDs {
			if i > 0 {
				pg.WriteByte(' ')
			}
			pg.WriteString(itoa(id) + " 0 R")
		}
		pg.WriteString("]")
	}
	pg.WriteString(" >>")
	inc.writeObject(pageID, pg.Bytes())
	inc.writeObject(contentID, streamObj("", content))
	for i, f := range []*assets.Font{reg, bld} {
		writeFont(inc, fontIDs[i], f)
	}
	inc.writeObject(courierID, []byte("<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>"))
	for i, l := range links {
		inc.writeObject(linkIDs[i], fmt.Appendf(nil, "<< /Type /Annot /Subtype /Link /Rect [%d %d %d %d] /Border [0 0 0] /A << /S /URI /URI (%s) >> >>",
			l[0], l[1], l[2], l[3], l[4]))
	}

	// /Pages үндэс: ижил дугаар, бусад түлхүүр хэвээр (CA AppendPage-тэй ижил).
	var pn bytes.Buffer
	pn.WriteString("<<")
	for _, key := range pages.Keys() {
		if key == "Kids" || key == "Count" {
			continue
		}
		pn.WriteString(" /" + escapeName(key) + " ")
		if err := serialize(&pn, pages.Key(key), pp.GetID(), 0); err != nil {
			return nil, fmt.Errorf("/Pages /%s: %w", key, err)
		}
	}
	kids := pages.Key("Kids")
	kp := kids.GetPtr()
	pn.WriteString(" /Kids [")
	if first { // [<хуудас> 0 R k1 k2 …] — элемент бүрийн өмнө зай
		pn.WriteString(itoa(pageID) + " 0 R")
		for i := range kids.Len() {
			pn.WriteByte(' ')
			if err := serialize(&pn, kids.Index(i), kp.GetID(), 0); err != nil {
				return nil, fmt.Errorf("/Pages /Kids: %w", err)
			}
		}
		fmt.Fprintf(&pn, "] /Count %d >>", count+1)
	} else { // [k1 k2 … <хуудас> 0 R] — элемент бүрийн ард зай
		for i := range kids.Len() {
			if err := serialize(&pn, kids.Index(i), kp.GetID(), 0); err != nil {
				return nil, fmt.Errorf("/Pages /Kids: %w", err)
			}
			pn.WriteByte(' ')
		}
		fmt.Fprintf(&pn, "%d 0 R] /Count %d >>", pageID, count+1)
	}
	inc.writeObjectGen(pp.GetID(), uint16(pp.GetGen()), pn.Bytes()) // #nosec G115 -- үе ≤ 65535
	return inc.finish(rp.GetID())
}

// streamObj — "<< /Length n[ extra] >>\nstream\n" + data + "\nendstream".
func streamObj(extra string, data []byte) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "<< /Length %d%s >>\nstream\n", len(data), extra)
	b.Write(data)
	b.WriteString("\nendstream")
	return b.Bytes()
}

// writeFont — Type0 (Identity-H) + CIDFontType2 + FontDescriptor + FontFile2 (asset, FlateDecode) + ToUnicode.
func writeFont(inc *incremental, ids [5]uint32, f *assets.Font) {
	for i, body := range fontBodies(ids, f) {
		inc.writeObject(ids[i], body)
	}
}

// fontBodies — writeFont-ийн 5 объектын бие (ids-ийн дарааллаар); verify хуудас ба харагдах гарын үсэгт ижил.
func fontBodies(ids [5]uint32, f *assets.Font) [5][]byte {
	var out [5][]byte
	out[0] = fmt.Appendf(nil, "<< /Type /Font /Subtype /Type0 /BaseFont /%s /Encoding /Identity-H /DescendantFonts [%d 0 R] /ToUnicode %d 0 R >>",
		f.PSName, ids[1], ids[4])
	var wa strings.Builder
	for g := range f.Advance {
		if g > 0 {
			wa.WriteByte(' ')
		}
		wa.WriteString(strconv.Itoa(f.Width1000(uint16(g)))) // #nosec G115 -- glyph тоо < 65536
	}
	out[1] = fmt.Appendf(nil, "<< /Type /Font /Subtype /CIDFontType2 /BaseFont /%s /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> /FontDescriptor %d 0 R /CIDToGIDMap /Identity /W [0 [%s]] >>",
		f.PSName, ids[2], wa.String())
	out[2] = fmt.Appendf(nil, "<< /Type /FontDescriptor /FontName /%s /Flags 32 /FontBBox [%d %d %d %d] /ItalicAngle 0 /Ascent %d /Descent %d /CapHeight %d /StemV 80 /FontFile2 %d 0 R >>",
		f.PSName, f.BBox[0], f.BBox[1], f.BBox[2], f.BBox[3], f.Ascent, f.Descent, f.CapHeight, ids[3])
	out[3] = streamObj(fmt.Sprintf(" /Length1 %d /Filter /FlateDecode", f.Length1), f.Stream)
	out[4] = streamObj("", toUnicode(f))
	return out
}

// toUnicode — glyph ID → Unicode (нэг glyph-д хамгийн бага code point), glyph ID-ээр эрэмбэлж 100-аар бүлэглэнэ.
func toUnicode(f *assets.Font) []byte {
	uni := make(map[uint16]rune)
	for r, g := range f.GID {
		if old, ok := uni[g]; !ok || r < old {
			uni[g] = r
		}
	}
	var pairs [][2]int
	for g := range len(f.Advance) {
		if r, ok := uni[uint16(g)]; ok { // #nosec G115
			pairs = append(pairs, [2]int{g, int(r)})
		}
	}
	var b strings.Builder
	b.WriteString("/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n" +
		"/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n/CMapName /Adobe-Identity-UCS def\n/CMapType 2 def\n" +
		"1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n")
	for i := 0; i < len(pairs); i += 100 {
		chunk := pairs[i:min(i+100, len(pairs))]
		fmt.Fprintf(&b, "%d beginbfchar\n", len(chunk))
		for _, p := range chunk {
			fmt.Fprintf(&b, "<%04X> <%04X>\n", p[0], p[1])
		}
		b.WriteString("endbfchar\n")
	}
	b.WriteString("endcmap\nCMapName currentdict /CMap defineresource pop\nend\nend")
	return []byte(b.String())
}
