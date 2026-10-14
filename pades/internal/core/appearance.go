package core

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"strconv"

	"github.com/digitorus/pdf"

	"github.com/gerege-systems/eid-mongolia-sdk-go/pades/assets"
	"github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/qr"
)

// Харагдах гарын үсэг — APPEARANCE_SPEC.md (pades-client/1). Widget нь сонгосон хуудсан дээр /Rect-тэй, /AP /N нь
// шахалтгүй form XObject (verify хуудасны фонт asset, өөрийн QR). Бүх урт/координат 1/100 pt-ийн БҮХЭЛ тоо (h100):
// бичихдээ Num100. Native SDK бүр 1:1 давтана; validator (internal/validate) ижил функцээр дахин үүсгэж тулгана.

// ErrAppearance — харагдах гарын үсгийн байршил/хэмжээ/хуудас буруу эсвэл бичвэр багтахгүй (REQUEST_INVALID).
var ErrAppearance = errors.New("pades: харагдах гарын үсэг")

// Visible — PrepareSignatureVisible-ийн оролт: байршил (харагдах хуудасны орон зайд, h100) ба бичвэр.
type Visible struct {
	Page       int // 1-ээс эхэлсэн, шийдэгдсэн (0 биш)
	X, Y, W, H int // h100; эх = CropBox (байхгүй бол MediaBox)-ийн /Rotate-ийн дараах харагдах зүүн доод булан
	Name       string
	Role       string
	Lang       string // "mn" | "en"
	Date       string // «YYYY-MM-DD HH:MM (+08)»
	URL        string // https://ca.eidmongolia.mn/verify/<docID>/<revIndex>
	// Tamper — ЗӨВХӨН validator-ийн халдлагын тест (pades багц хэзээ ч тавихгүй).
	Tamper *VisibleTamper
}

// VisibleTamper — харагдах revision-ийг бичихийн өмнө өөрчлөх тестийн hook (халдлагын хувилбар үүсгэх).
type VisibleTamper struct {
	// Body — объектын биеийг солино; role: "widget", "form", "F1.0"…"F1.4", "F2.0"…"F2.4".
	Body func(role string, body []byte) []byte
	// AnnotsPage — widget-ийг /P биш энэ хуудасны /Annots-д нэмнэ (1-ээс); −1 бол аль ч /Annots-д нэмэхгүй.
	AnnotsPage int
	// Extra — хуучин объектуудыг (дугаар → бие, үе 0) энэ revision-д дахин бичнэ.
	Extra map[uint32][]byte
}

// AppearanceParams — form XObject-ийн оролт (validator ч мөн үүгээр дахин үүсгэнэ).
type AppearanceParams struct {
	W, H   int // харагдах (эргүүлэлтийн дараах) өргөн, өндөр, h100; BBox = /Rect-ийн хэмжээ (90/270-д солигдоно)
	Rotate int // хуудасны /Rotate: 0 | 90 | 180 | 270
	Name   string
	Role   string
	Lang   string
	Date   string
	URL    string
}

// APPEARANCE_SPEC.md §3-ийн тогтмолууд (h100 = 1/100 pt).
const (
	apPad       = 400 // хүрээнээс QR/бичвэр хүртэл
	apGap       = 400 // QR ба бичвэрийн хооронд
	apMinModule = 100 // QR модулийн доод хэмжээ (1 pt)
	apMaxSize   = 11  // нэрийн фонтын хэмжээ (pt): 11 → 7
	apMinSize   = 7
	apBodyDelta = 2   // бусад мөр = нэрийн хэмжээ − 2
	apLeading   = 125 // мөрийн өндөр = size × 1.25 pt
	apDescent   = 25  // суурь шугам = мөрийн хайрцгийн доороос size × 0.25 pt
	apMaxLines  = 2   // нэр, үүрэг тус бүр ≤ 2 мөр (илүү бол «…»)
	// MaxAppearanceSide — өргөн/өндрийн дээд хэмжээ (14400 pt = PDF-ийн хуудасны дээд хязгаар), h100.
	MaxAppearanceSide = 1440000
)

// AppearanceLabels — 3 дахь мөр (APPEARANCE_SPEC.md §3).
var AppearanceLabels = map[string]string{
	"mn": "eID Mongolia-аар зурсан",
	"en": "Signed with eID Mongolia",
}

// Round100 — pt → h100: floor(v × 100 + 0.5) (IEEE-754 double; бүх хэлэнд ижил).
func Round100(v float64) int { return int(math.Floor(v*100 + 0.5)) }

// Num100 — h100 → PDF тоо: бүхэл бол «N», эс бөгөөс «N.d» / «N.dd» (төгсгөлийн тэггүй), сөрөгт «-».
func Num100(v int) string {
	sign := ""
	if v < 0 {
		sign, v = "-", -v
	}
	s := sign + strconv.Itoa(v/100)
	switch f := v % 100; {
	case f == 0:
	case f%10 == 0:
		s += "." + strconv.Itoa(f/10)
	default:
		s += fmt.Sprintf(".%02d", f)
	}
	return s
}

// apRotation — хуудасны /Rotate-ийн эсрэг (цагийн зүүний эсрэг) эргүүлэх content-ийн `cm` (0 бол "") ба BBox-ийн
// хэмжээ (хэрэглэгчийн орон зайд, /Rect-тэй ижил чиг). /Matrix-ийг ашиглахгүй — PDFKit эргүүлсэн /Matrix-тэй
// дүрслэлийг зурдаггүй (2026-10-15 шалгасан).
func apRotation(rot, w, h int) (cm string, bw, bh int, err error) {
	switch rot {
	case 0:
		return "", w, h, nil
	case 90:
		return "0 1 -1 0 " + Num100(h) + " 0 cm", h, w, nil
	case 180:
		return "-1 0 0 -1 " + Num100(w) + " " + Num100(h) + " cm", w, h, nil
	case 270:
		return "0 -1 1 0 0 " + Num100(w) + " cm", h, w, nil
	}
	return "", 0, 0, fmt.Errorf("%w: /Rotate %d", ErrAppearance, rot)
}

type apLine struct {
	font, size  int
	color, text string
}

// AppearanceContent — form XObject-ийн content stream (APPEARANCE_SPEC.md §3).
func AppearanceContent(p AppearanceParams, reg, bld *assets.Font) ([]byte, error) {
	label, ok := AppearanceLabels[p.Lang]
	if !ok {
		return nil, fmt.Errorf("%w: хэл %q", ErrAppearance, p.Lang)
	}
	if !asciiURL(p.URL) {
		return nil, fmt.Errorf("%w: URL ASCII биш", ErrAppearance)
	}
	if p.W <= 0 || p.H <= 0 || p.W > MaxAppearanceSide || p.H > MaxAppearanceSide {
		return nil, fmt.Errorf("%w: хэмжээ", ErrAppearance)
	}
	m, err := qr.Encode([]byte(p.URL))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAppearance, err)
	}
	n := len(m)
	mod := (p.H - 2*apPad) / n
	if mod < apMinModule {
		return nil, fmt.Errorf("%w: хэт жижиг (өндөр ≥ %s pt)", ErrAppearance, Num100(2*apPad+n*apMinModule))
	}
	tx := apPad + mod*n + apGap
	tw := p.W - tx - apPad
	w := &pageWriter{reg: reg, bld: bld}
	var lines []apLine
	for f := apMaxSize; f >= apMinSize && lines == nil && tw > 0; f-- {
		lines = apLayout(w, p, label, f, tw)
	}
	if lines == nil {
		return nil, fmt.Errorf("%w: хэт жижиг (бичвэр багтахгүй)", ErrAppearance)
	}
	total := 0
	for _, l := range lines {
		total += l.size * apLeading
	}
	cm, _, _, err := apRotation(p.Rotate, p.W, p.H)
	if err != nil {
		return nil, err
	}
	w.op("/EIDVerify <</URL (%s)>> BDC", p.URL)
	if cm != "" {
		w.op("q")
		w.op("%s", cm)
	}
	w.op("%s RG", colOK)
	w.op("1 w")
	w.op("0.5 0.5 %s %s re S", Num100(p.W-100), Num100(p.H-100))
	w.op("q %s 0 0 %s %s %s cm", Num100(mod), Num100(mod), Num100(apPad), Num100((p.H-mod*n)/2))
	w.op("0 0 0 rg")
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
			w.op("%d %d %d 1 re", s, n-1-r, c-s)
		}
	}
	w.op("f")
	w.op("Q")
	cursor := p.H - apPad - (p.H-2*apPad-total)/2
	for _, l := range lines {
		cursor -= l.size * apLeading
		w.op("%s rg", l.color)
		w.op("BT /F%d %d Tf %s %s Td %s Tj ET", l.font, l.size, Num100(tx), Num100(cursor+l.size*apDescent), w.glyphHex(l.font, l.text))
	}
	if cm != "" {
		w.op("Q")
	}
	w.op("EMC")
	return w.ops.Bytes(), nil
}

// apLayout — нэрийн фонт f (pt)-д мөрүүд: нэр (F2, f, ≤ 2 мөр), үүрэг (F1, f−2, ≤ 2 мөр), label, огноо (F1, f−2, нэг
// мөр). Аль нэг мөр өргөнд (tw) эсвэл нийт өндөр (H − 2·pad)-д багтахгүй бол nil.
func apLayout(w *pageWriter, p AppearanceParams, label string, f, tw int) []apLine {
	b := f - apBodyDelta
	limit := tw * 10 // h100 → 1/1000 pt
	var lines []apLine
	for _, t := range w.wrapLimit(2, f, p.Name, limit, apMaxLines) {
		lines = append(lines, apLine{2, f, colText, t})
	}
	if p.Role != "" {
		for _, t := range w.wrapLimit(1, b, p.Role, limit, apMaxLines) {
			lines = append(lines, apLine{1, b, colText, t})
		}
	}
	lines = append(lines, apLine{1, b, colOK, label}, apLine{1, b, colMuted, p.Date})
	total := 0
	for _, l := range lines {
		if l.text == "" || w.width1000(l.font, l.size, l.text) > limit {
			return nil
		}
		total += l.size * apLeading
	}
	if total > p.H-2*apPad {
		return nil
	}
	return lines
}

// AppearanceObjects — /AP /N form XObject ба түүний 2 фонт (11 объект): ids = [form, F1 ×5, F2 ×5] (F1 = NotoSans,
// F2 = NotoSans-Bold; объект бүр fontBodies-ийн дарааллаар). Буцаах нь объектын бие (ids-ийн дарааллаар).
func AppearanceObjects(p AppearanceParams, ids [11]uint32) ([][]byte, error) {
	reg, err := assets.Regular()
	if err != nil {
		return nil, err
	}
	bld, err := assets.Bold()
	if err != nil {
		return nil, err
	}
	_, bw, bh, err := apRotation(p.Rotate, p.W, p.H)
	if err != nil {
		return nil, err
	}
	content, err := AppearanceContent(p, reg, bld)
	if err != nil {
		return nil, err
	}
	out := make([][]byte, 0, len(ids))
	out = append(out, streamObj(fmt.Sprintf(" /Type /XObject /Subtype /Form /BBox [0 0 %s %s] /Resources << /Font << /F1 %d 0 R /F2 %d 0 R >> >>",
		Num100(bw), Num100(bh), ids[1], ids[6]), content))
	r := fontBodies([5]uint32(ids[1:6]), reg)
	b := fontBodies([5]uint32(ids[6:11]), bld)
	out = append(out, r[:]...)
	return append(out, b[:]...), nil
}

// VisibleWidget — харагдах гарын үсгийн талбар/widget-ийн бие (APPEARANCE_SPEC.md §2). rect — хэрэглэгчийн орон
// зайн [x1 y1 x2 y2] (h100).
func VisibleWidget(fieldName string, rect [4]int, pageID uint32, pageGen int, sigID, formID uint32) []byte {
	return fmt.Appendf(nil, "<<\n  /Type /Annot\n  /Subtype /Widget\n  /Rect [%s %s %s %s]\n  /P %d %d R\n  /F 4\n  /FT /Sig\n  /T (%s)\n  /V %d 0 R\n  /AP << /N %d 0 R >>\n>>",
		Num100(rect[0]), Num100(rect[1]), Num100(rect[2]), Num100(rect[3]), pageID, pageGen, fieldName, sigID, formID)
}

// VisibleRect — харагдах орон зайн (x, y, w, h) → хэрэглэгчийн орон зайн /Rect (APPEARANCE_SPEC.md §1). box —
// [llx lly urx ury] (хэвийн болгосон, h100), rot — 0/90/180/270. Тэгш өнцөгт хуудаснаас гарвал ErrAppearance.
func VisibleRect(box [4]int, rot, x, y, w, h int) ([4]int, error) {
	bw, bh := box[2]-box[0], box[3]-box[1]
	vw, vh := bw, bh
	if rot == 90 || rot == 270 {
		vw, vh = bh, bw
	}
	if x < 0 || y < 0 || w <= 0 || h <= 0 || x+w > vw || y+h > vh {
		return [4]int{}, fmt.Errorf("%w: тэгш өнцөгт хуудасны (CropBox) гадна", ErrAppearance)
	}
	// Харагдах (vx, vy) → хэрэглэгчийн (ux, uy).
	pt := func(vx, vy int) (int, int) {
		switch rot {
		case 90:
			return box[2] - vy, box[1] + vx
		case 180:
			return box[2] - vx, box[3] - vy
		case 270:
			return box[0] + vy, box[3] - vx
		}
		return box[0] + vx, box[1] + vy
	}
	x1, y1 := pt(x, y)
	x2, y2 := pt(x+w, y+h)
	return [4]int{min(x1, x2), min(y1, y2), max(x1, x2), max(y1, y2)}, nil
}

// pageGeometry — хуудасны (удамшсан) CropBox (байхгүй бол MediaBox) h100-аар хэвийн болгосон ба /Rotate (0–270).
func pageGeometry(page pdf.Value) (box [4]int, rot int, err error) {
	inh := func(key string) pdf.Value {
		v := page
		for range maxSerializeDepth {
			if x := v.Key(key); !x.IsNull() {
				return x
			}
			if v = v.Key("Parent"); v.Kind() != pdf.Dict {
				break
			}
		}
		return pdf.Value{}
	}
	b := inh("CropBox")
	if b.IsNull() {
		b = inh("MediaBox")
	}
	if b.Kind() != pdf.Array || b.Len() != 4 {
		return box, 0, fmt.Errorf("%w: хуудасны MediaBox алга", ErrAppearance)
	}
	var f [4]int
	for i := range 4 {
		e := b.Index(i)
		if e.Kind() != pdf.Integer && e.Kind() != pdf.Real {
			return box, 0, fmt.Errorf("%w: хуудасны хайрцаг буруу", ErrAppearance)
		}
		v := e.Float64()
		if math.IsNaN(v) || math.IsInf(v, 0) || math.Abs(v) > 1e7 {
			return box, 0, fmt.Errorf("%w: хуудасны хайрцаг буруу", ErrAppearance)
		}
		f[i] = Round100(v)
	}
	box = [4]int{min(f[0], f[2]), min(f[1], f[3]), max(f[0], f[2]), max(f[1], f[3])}
	if r := inh("Rotate"); !r.IsNull() {
		if r.Kind() != pdf.Integer || r.Int64()%90 != 0 {
			return box, 0, fmt.Errorf("%w: хуудасны /Rotate 90-ийн үржвэр биш", ErrAppearance)
		}
		rot = int((r.Int64()%360 + 360) % 360)
	}
	return box, rot, nil
}

// nthPage — /Pages модны n дэх (1-ээс) /Page (модны дарааллаар, гүн ≤ 32).
func nthPage(v pdf.Value, n int) (pdf.Value, bool) {
	var walk func(v pdf.Value, depth int) (pdf.Value, bool)
	walk = func(v pdf.Value, depth int) (pdf.Value, bool) {
		if depth > maxSerializeDepth {
			return pdf.Value{}, false
		}
		switch v.Key("Type").Name() {
		case "Page":
			n--
			return v, n == 0
		case "Pages":
			kids := v.Key("Kids")
			for i := range kids.Len() {
				if p, ok := walk(kids.Index(i), depth+1); ok {
					return p, true
				}
				if n <= 0 {
					break
				}
			}
		}
		return pdf.Value{}, false
	}
	if n < 1 {
		return pdf.Value{}, false
	}
	return walk(v, 0)
}

// PageCount — баримтын /Pages модны /Page объектын тоо (модыг тоолно, /Count-д итгэхгүй).
func PageCount(doc []byte) (n int, err error) {
	defer func() {
		if r := recover(); r != nil {
			n, err = 0, fmt.Errorf("%w: %v", ErrPDF, r)
		}
	}()
	inc, err := openIncremental(doc)
	if err != nil {
		return 0, err
	}
	var walk func(v pdf.Value, depth int)
	walk = func(v pdf.Value, depth int) {
		if depth > maxSerializeDepth || n > 1<<16 {
			return
		}
		switch v.Key("Type").Name() {
		case "Page":
			n++
		case "Pages":
			kids := v.Key("Kids")
			for i := range kids.Len() {
				walk(kids.Index(i), depth+1)
			}
		}
	}
	walk(inc.root().Key("Pages"), 0)
	return n, nil
}

// glyphHex — F1/F2 бичвэрийн `<GGGG…>` (PAGE_SPEC.md §2).
func (w *pageWriter) glyphHex(id int, s string) string {
	var b bytes.Buffer
	b.WriteByte('<')
	for _, g := range w.gids(id, s) {
		fmt.Fprintf(&b, "%04X", g)
	}
	b.WriteByte('>')
	return b.String()
}
