package core

import (
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"

	"github.com/digitorus/pdf"
)

// Occupancy scanner — PLACEMENT_SPEC.md §2–§4. A pure function of the page objects: it never renders, never loads a
// system font and uses only IEEE-754 double +, −, ×, ÷ (each product rounded on its own: the float64(...) conversions
// below stop the Go compiler from fusing a*b+c into an FMA, which other languages never do), floor and ceil.
// Every native SDK ports it 1:1; the vectors in pades/testdata/placement pin the exact box list.

// Limits (PLACEMENT_SPEC.md §5). Hitting any of them makes the page unscannable: the stamp stays where it was requested.
const (
	occMaxBytes    = 4 << 20 // decoded content bytes, page + every form execution
	occMaxOps      = 100_000 // operators executed, page + forms
	occMaxDepth    = 8       // form XObject nesting (page content = 0)
	occMaxSave     = 64      // q nesting per content stream
	occMaxOperands = 65_536  // operand objects pending at one operator (nested array elements count)
	occMaxNesting  = 32      // array / dictionary nesting in an operand
	occMaxAnnots   = 10_000  // /Annots entries
	occMaxWEntries = 65_536  // CIDFont /W: elements read (outer array, and each inner array)
	occMaxWAssign  = 262_144 // CIDFont /W: CID assignments attempted (assigned or not) before reading stops
	occMaxNumLen   = 32      // a longer numeric token is not a number
	occClamp       = 1e7     // box coordinates are clamped to ±occClamp pt before quantising
)

// errUnscannable — the page cannot be scanned within the rules (limit hit, unsupported filter, broken stream).
var errUnscannable = errors.New("pades: page content not scannable")

// Occupancy returns the occupied boxes of a page in default user space, h100 (1/100 pt), outward-rounded, in emission
// order (content stream order, then /Annots order). box is the page's normalised CropBox/MediaBox (h100), used only for
// the background-fill rule. Any error is errUnscannable (wrapped).
func Occupancy(page pdf.Value, box [4]int) (out [][4]int, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, fmt.Errorf("%w: %v", errUnscannable, r)
		}
	}()
	s := &occScanner{page: box, fonts: map[uint32]*occFont{}}
	content, err := s.pageContent(page.Key("Contents"))
	if err != nil {
		return nil, err
	}
	res := inherited(page, "Resources")
	if err := s.run(content, res, gstate{ctm: identity, lw: 1, th: 1, font: defaultFont}, 0); err != nil {
		return nil, err
	}
	if err := s.annots(page.Key("Annots")); err != nil {
		return nil, err
	}
	return s.boxes, nil
}

// inherited — a page attribute, following /Parent (depth ≤ 32).
func inherited(page pdf.Value, key string) pdf.Value {
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

type matrix [6]float64

var identity = matrix{1, 0, 0, 1, 0, 0}

// mul — m × n (row-vector convention, ISO 32000-1 §8.3.4), each term rounded separately, summed left to right.
func mul(m, n matrix) matrix {
	return matrix{
		float64(m[0]*n[0]) + float64(m[1]*n[2]),
		float64(m[0]*n[1]) + float64(m[1]*n[3]),
		float64(m[2]*n[0]) + float64(m[3]*n[2]),
		float64(m[2]*n[1]) + float64(m[3]*n[3]),
		float64(m[4]*n[0]) + float64(m[5]*n[2]) + n[4],
		float64(m[4]*n[1]) + float64(m[5]*n[3]) + n[5],
	}
}

// apply — (x, y) × m: x' = a·x + c·y + e, y' = b·x + d·y + f.
func (m matrix) apply(x, y float64) (float64, float64) {
	return float64(m[0]*x) + float64(m[2]*y) + m[4], float64(m[1]*x) + float64(m[3]*y) + m[5]
}

func (m matrix) finite() bool {
	for _, v := range m {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return false
		}
	}
	return true
}

// rect — a float bounding box being accumulated (device = default user space).
type rect struct{ x0, y0, x1, y1 float64 }

func pointRect(x, y float64) rect { return rect{x, y, x, y} }

func (r *rect) add(x, y float64) {
	r.x0, r.y0, r.x1, r.y1 = min(r.x0, x), min(r.y0, y), max(r.x1, x), max(r.y1, y)
}

// quantise — outward to h100 after clamping to ±occClamp pt: floor(min·100), ceil(max·100).
func quantise(r rect) ([4]int, error) {
	c := func(v float64) (float64, error) {
		if math.IsNaN(v) {
			return 0, fmt.Errorf("%w: NaN", errUnscannable)
		}
		return min(max(v, -occClamp), occClamp), nil
	}
	var v [4]float64
	var err error
	for i, x := range []float64{r.x0, r.y0, r.x1, r.y1} {
		if v[i], err = c(x); err != nil {
			return [4]int{}, err
		}
	}
	return [4]int{SatInt(math.Floor(v[0] * 100)), SatInt(math.Floor(v[1] * 100)), SatInt(math.Ceil(v[2] * 100)), SatInt(math.Ceil(v[3] * 100))}, nil
}

// SatInt — float64 → int, тэг рүү таслах, saturating (PLACEMENT_SPEC §2): NaN → 0, хүрээнээс гарсан / ±Inf →
// math.MinInt64 / math.MaxInt64. Go-гийн `int(f)` хүрээнээс гарсан утгад платформоос хамаардаг (amd64: MinInt64,
// arm64: saturating) тул шууд хэрэглэхгүй.
func SatInt(f float64) int {
	switch {
	case math.IsNaN(f):
		return 0
	case f >= 9223372036854775807: // 2^63 (float64-д яг дүрслэгдэнэ)
		return math.MaxInt64
	case f < -9223372036854775808:
		return math.MinInt64
	}
	return int(f)
}

// ── Fonts (PLACEMENT_SPEC.md §3.4) ──

const (
	fontSimple    = iota // 1-byte codes, /Widths
	fontIdentity         // Type0 + /Identity-H|V: 2-byte codes, /W + /DW
	fontComposite        // Type0, any other /Encoding: 1-byte codes, 1000
	fontDefault          // Type3, missing font, no Tf: 1-byte codes, 1000
)

type occFont struct {
	kind    int
	first   int
	widths  []float64 // simple: /Widths (non-number → NaN = not given)
	missing float64   // simple: FontDescriptor /MissingWidth if > 0, else 1000
	dw      float64   // identity: /DW, default 1000
	w       map[int]float64
}

var defaultFont = &occFont{kind: fontDefault}

func number(v pdf.Value) (float64, bool) {
	if k := v.Kind(); k == pdf.Integer || k == pdf.Real {
		return v.Float64(), true
	}
	return 0, false
}

func (s *occScanner) font(v pdf.Value) *occFont {
	if v.Kind() != pdf.Dict {
		return defaultFont
	}
	ptr := v.GetPtr()
	id := ptr.GetID()
	if f, ok := s.fonts[id]; ok && id != 0 {
		return f
	}
	f := loadFont(v)
	if id != 0 {
		s.fonts[id] = f
	}
	return f
}

func loadFont(v pdf.Value) *occFont {
	switch v.Key("Subtype").Name() {
	case "Type3":
		return defaultFont
	case "Type0":
		if enc := v.Key("Encoding"); enc.Kind() != pdf.Name || (enc.Name() != "Identity-H" && enc.Name() != "Identity-V") {
			return &occFont{kind: fontComposite}
		}
		f := &occFont{kind: fontIdentity, dw: 1000, w: map[int]float64{}}
		d := v.Key("DescendantFonts").Index(0)
		if dw, ok := number(d.Key("DW")); ok {
			f.dw = dw
		}
		w := d.Key("W")
		n := min(w.Len(), occMaxWEntries)
		budget := occMaxWAssign
		set := func(cid int, val float64) bool {
			if budget--; budget < 0 {
				return false
			}
			if _, ok := f.w[cid]; !ok && cid >= 0 && cid <= 0xFFFF {
				f.w[cid] = val
			}
			return true
		}
	read:
		for i := 0; i < n; {
			c0, ok := number(w.Index(i))
			if !ok || i+1 >= n {
				break
			}
			if arr := w.Index(i + 1); arr.Kind() == pdf.Array {
				for j := range min(arr.Len(), occMaxWEntries) {
					if x, ok := number(arr.Index(j)); ok && !set(SatInt(c0)+j, x) {
						break read
					}
				}
				i += 2
				continue
			}
			c1, ok1 := number(w.Index(i + 1))
			x, ok2 := number(w.Index(i + 2))
			if !ok1 || !ok2 || i+2 >= n {
				break
			}
			for c := max(SatInt(c0), 0); c <= SatInt(c1) && c <= 0xFFFF; c++ {
				if !set(c, x) {
					break read
				}
			}
			i += 3
		}
		return f
	}
	f := &occFont{kind: fontSimple, missing: 1000}
	if fc, ok := number(v.Key("FirstChar")); ok {
		f.first = SatInt(fc)
	}
	ws := v.Key("Widths")
	for i := range min(ws.Len(), 256) {
		x, ok := number(ws.Index(i))
		if !ok {
			x = math.NaN()
		}
		f.widths = append(f.widths, x)
	}
	if mw, ok := number(v.Key("FontDescriptor").Key("MissingWidth")); ok && mw > 0 {
		f.missing = mw
	}
	return f
}

// glyphs — a string's codes and their widths (glyph space, 1/1000 em) plus whether each code is the 1-byte code 32.
func (f *occFont) glyphs(b []byte, fn func(w0 float64, space bool)) {
	if f.kind == fontIdentity {
		for i := 0; i+1 < len(b); i += 2 {
			cid := int(b[i])<<8 | int(b[i+1])
			w, ok := f.w[cid]
			if !ok {
				w = f.dw
			}
			fn(w, false)
		}
		return
	}
	for _, c := range b {
		w := 1000.0
		if f.kind == fontSimple {
			w = f.missing
			if i := int(c) - f.first; i >= 0 && i < len(f.widths) && !math.IsNaN(f.widths[i]) {
				w = f.widths[i]
			}
		}
		fn(w, f.kind != fontComposite && c == ' ')
	}
}

// ── Content-stream lexer (PLACEMENT_SPEC.md §3.1) ──

const (
	tNum = iota
	tStr
	tName
	tArr
	tDict
	tOther // true/false/null, or any keyword inside an array/dictionary
)

type operand struct {
	kind int
	num  float64
	str  []byte
	name string
	arr  []operand
}

type lexer struct {
	b []byte
	i int
}

func isSpace(c byte) bool { return c == 0 || c == 9 || c == 10 || c == 12 || c == 13 || c == 32 }

func isDelim(c byte) bool {
	switch c {
	case '(', ')', '<', '>', '[', ']', '{', '}', '/', '%':
		return true
	}
	return false
}

// token kinds returned by next
const (
	lxEOF = iota
	lxObj
	lxKeyword
	lxArrEnd
	lxDictEnd
)

func (l *lexer) skipSpace() {
	for l.i < len(l.b) {
		c := l.b[l.i]
		switch {
		case isSpace(c):
			l.i++
		case c == '%':
			for l.i < len(l.b) && l.b[l.i] != '\r' && l.b[l.i] != '\n' {
				l.i++
			}
		default:
			return
		}
	}
}

func (l *lexer) regular() []byte {
	s := l.i
	for l.i < len(l.b) && !isSpace(l.b[l.i]) && !isDelim(l.b[l.i]) {
		l.i++
	}
	return l.b[s:l.i]
}

// isNumber — [+-]?(\d+(\.\d*)?|\.\d+), at most occMaxNumLen bytes.
func isNumber(t []byte) bool {
	if len(t) == 0 || len(t) > occMaxNumLen {
		return false
	}
	i := 0
	if t[0] == '+' || t[0] == '-' {
		i++
	}
	digits, dot := 0, false
	for ; i < len(t); i++ {
		switch c := t[i]; {
		case c >= '0' && c <= '9':
			digits++
		case c == '.' && !dot:
			dot = true
		default:
			return false
		}
	}
	return digits > 0
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// literal — after '(' : balanced parentheses, escapes; EOF ends the string.
func (l *lexer) literal() []byte {
	var out []byte
	depth := 1
	for l.i < len(l.b) {
		c := l.b[l.i]
		l.i++
		switch c {
		case '(':
			depth++
		case ')':
			if depth--; depth == 0 {
				return out
			}
		case '\\':
			if l.i >= len(l.b) {
				return out
			}
			e := l.b[l.i]
			l.i++
			switch e {
			case 'n':
				c = '\n'
			case 'r':
				c = '\r'
			case 't':
				c = '\t'
			case 'b':
				c = '\b'
			case 'f':
				c = '\f'
			case '\r':
				if l.i < len(l.b) && l.b[l.i] == '\n' {
					l.i++
				}
				continue
			case '\n':
				continue
			default:
				if e >= '0' && e <= '7' {
					v := int(e - '0')
					for k := 0; k < 2 && l.i < len(l.b) && l.b[l.i] >= '0' && l.b[l.i] <= '7'; k++ {
						v = v*8 + int(l.b[l.i]-'0')
						l.i++
					}
					c = byte(v)
				} else {
					c = e
				}
			}
		}
		out = append(out, c)
	}
	return out
}

// hexString — after '<' : hex digits, other bytes skipped, odd final nibble padded with 0; '>' or EOF ends it.
func (l *lexer) hexString() []byte {
	var out []byte
	hi, half := byte(0), false
	for l.i < len(l.b) {
		c := l.b[l.i]
		l.i++
		if c == '>' {
			break
		}
		v, ok := unhex(c)
		if !ok {
			continue
		}
		if half {
			out = append(out, hi<<4|v)
		} else {
			hi = v
		}
		half = !half
	}
	if half {
		out = append(out, hi<<4)
	}
	return out
}

// name — after '/' : regular bytes, #xx decoded.
func (l *lexer) name() string {
	t := l.regular()
	var out []byte
	for i := 0; i < len(t); i++ {
		if t[i] == '#' && i+2 < len(t) {
			if h, ok := unhex(t[i+1]); ok {
				if lo, ok := unhex(t[i+2]); ok {
					out = append(out, h<<4|lo)
					i += 2
					continue
				}
			}
		}
		out = append(out, t[i])
	}
	return string(out)
}

// next — one token. Keywords come back as lxKeyword with kw set; '{' '}' and stray ')' are skipped.
func (l *lexer) next() (int, operand, string) {
	for {
		l.skipSpace()
		if l.i >= len(l.b) {
			return lxEOF, operand{}, ""
		}
		c := l.b[l.i]
		switch c {
		case '(':
			l.i++
			return lxObj, operand{kind: tStr, str: l.literal()}, ""
		case '<':
			if l.i+1 < len(l.b) && l.b[l.i+1] == '<' {
				l.i += 2
				return lxObj, operand{kind: tDict}, "<<"
			}
			l.i++
			return lxObj, operand{kind: tStr, str: l.hexString()}, ""
		case '>':
			if l.i+1 < len(l.b) && l.b[l.i+1] == '>' {
				l.i += 2
				return lxDictEnd, operand{}, ""
			}
			l.i++
			continue
		case '[':
			l.i++
			return lxObj, operand{kind: tArr}, "["
		case ']':
			l.i++
			return lxArrEnd, operand{}, ""
		case '/':
			l.i++
			return lxObj, operand{kind: tName, name: l.name()}, ""
		case ')', '{', '}':
			l.i++
			continue
		}
		t := l.regular()
		if isNumber(t) {
			v, err := strconv.ParseFloat(string(t), 64)
			if err != nil { // unreachable for the grammar above; keep it a non-number
				return lxObj, operand{kind: tOther}, ""
			}
			return lxObj, operand{kind: tNum, num: v}, ""
		}
		switch string(t) {
		case "true", "false", "null":
			return lxObj, operand{kind: tOther}, ""
		}
		return lxKeyword, operand{}, string(t)
	}
}

// object — completes an array or dictionary opened by next (open = "[" or "<<"). Inside, every token is an element;
// EOF ends the content (eof = true). Nesting > occMaxNesting or too many elements → errUnscannable.
func (l *lexer) object(o operand, open string, depth int, count *int) (operand, bool, error) {
	if open == "" {
		return o, false, nil
	}
	if depth >= occMaxNesting {
		return o, false, fmt.Errorf("%w: nesting", errUnscannable)
	}
	for {
		k, e, kw := l.next()
		switch k {
		case lxEOF:
			return o, true, nil
		case lxArrEnd:
			if open == "[" {
				return o, false, nil
			}
			continue
		case lxDictEnd:
			if open == "<<" {
				return o, false, nil
			}
			continue
		case lxKeyword:
			e = operand{kind: tOther}
		case lxObj:
			var eof bool
			var err error
			if e, eof, err = l.object(e, kw, depth+1, count); err != nil || eof {
				return o, eof, err
			}
		}
		if *count++; *count > occMaxOperands {
			return o, false, fmt.Errorf("%w: operands", errUnscannable)
		}
		if open == "[" {
			o.arr = append(o.arr, e)
		}
	}
}

// ── Interpreter (PLACEMENT_SPEC.md §3.2–§3.6) ──

type gstate struct {
	ctm                    matrix
	lw                     float64
	fillWhite, strokeWhite bool
	tc, tw, th, tl, tfs    float64
	trise                  float64
	font                   *occFont
}

type subpath struct {
	sx, sy, cx, cy float64 // start and current point (device space)
	bbox           rect
	segs           []rect
}

type occScanner struct {
	page  [4]int
	bytes int
	ops   int
	boxes [][4]int
	fonts map[uint32]*occFont
}

func (s *occScanner) emit(r rect) error {
	q, err := quantise(r)
	if err != nil {
		return err
	}
	s.boxes = append(s.boxes, q)
	return nil
}

// stream — decoded bytes of a content/form stream: no filter, or exactly FlateDecode without parameters.
func (s *occScanner) stream(v pdf.Value) ([]byte, error) {
	if v.Kind() != pdf.Stream {
		return nil, fmt.Errorf("%w: not a stream", errUnscannable)
	}
	f, p := v.Key("Filter"), v.Key("DecodeParms")
	switch {
	case f.IsNull() && p.IsNull():
	case f.Kind() == pdf.Name && f.Name() == "FlateDecode" && p.IsNull():
	case f.Kind() == pdf.Array && f.Len() == 1 && f.Index(0).Kind() == pdf.Name && f.Index(0).Name() == "FlateDecode" &&
		(p.IsNull() || (p.Kind() == pdf.Array && p.Len() == 1 && p.Index(0).IsNull())):
	default:
		return nil, fmt.Errorf("%w: filter %v", errUnscannable, f)
	}
	rd := v.Reader()
	defer rd.Close()
	left := occMaxBytes - s.bytes
	b, err := io.ReadAll(io.LimitReader(rd, int64(left)+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errUnscannable, err)
	}
	if len(b) > left {
		return nil, fmt.Errorf("%w: content bytes", errUnscannable)
	}
	s.bytes += len(b)
	return b, nil
}

// pageContent — /Contents: absent → empty; a stream; or an array of streams joined with LF.
func (s *occScanner) pageContent(c pdf.Value) ([]byte, error) {
	switch c.Kind() {
	case pdf.Null:
		return nil, nil
	case pdf.Stream:
		return s.stream(c)
	case pdf.Array:
		var out []byte
		for i := range c.Len() {
			b, err := s.stream(c.Index(i))
			if err != nil {
				return nil, err
			}
			if i > 0 {
				out = append(out, '\n')
			}
			out = append(out, b...)
		}
		return out, nil
	}
	return nil, fmt.Errorf("%w: /Contents", errUnscannable)
}

// nums — the operands if they are exactly n numbers.
func nums(ops []operand, n int) ([]float64, bool) {
	if len(ops) != n {
		return nil, false
	}
	out := make([]float64, n)
	for i, o := range ops {
		if o.kind != tNum {
			return nil, false
		}
		out[i] = o.num
	}
	return out, true
}

// run — executes one content stream (page content or a form) from graphics state g, with its own operand stack,
// q stack, path and text matrices.
func (s *occScanner) run(content []byte, res pdf.Value, g gstate, depth int) error {
	l := &lexer{b: content}
	var stack []gstate
	var path []*subpath
	tm, tlm := identity, identity
	var ops []operand
	count := 0
	for {
		k, o, kw := l.next()
		switch k {
		case lxEOF:
			return nil
		case lxArrEnd, lxDictEnd:
			continue
		case lxObj:
			var eof bool
			var err error
			if o, eof, err = l.object(o, kw, 0, &count); err != nil {
				return err
			}
			if eof {
				return nil
			}
			if count++; count > occMaxOperands {
				return fmt.Errorf("%w: operands", errUnscannable)
			}
			ops = append(ops, o)
			continue
		}
		if s.ops++; s.ops > occMaxOps {
			return fmt.Errorf("%w: operators", errUnscannable)
		}
		args := ops
		ops, count = ops[:0], 0
		switch kw {
		case "q", "Q", "BT":
			if len(args) != 0 {
				break
			}
			switch kw {
			case "BT":
				tm, tlm = identity, identity
			case "Q":
				if n := len(stack); n > 0 {
					g, stack = stack[n-1], stack[:n-1]
				}
			case "q":
				if len(stack) >= occMaxSave {
					return fmt.Errorf("%w: q nesting", errUnscannable)
				}
				stack = append(stack, g)
			}
		case "cm":
			if v, ok := nums(args, 6); ok {
				if g.ctm = mul(matrix(v), g.ctm); !g.ctm.finite() {
					return fmt.Errorf("%w: CTM", errUnscannable)
				}
			}
		case "w":
			if v, ok := nums(args, 1); ok {
				g.lw = v[0]
			}
		case "g":
			if v, ok := nums(args, 1); ok {
				g.fillWhite = v[0] >= 1
			}
		case "G":
			if v, ok := nums(args, 1); ok {
				g.strokeWhite = v[0] >= 1
			}
		case "rg":
			if v, ok := nums(args, 3); ok {
				g.fillWhite = v[0] >= 1 && v[1] >= 1 && v[2] >= 1
			}
		case "RG":
			if v, ok := nums(args, 3); ok {
				g.strokeWhite = v[0] >= 1 && v[1] >= 1 && v[2] >= 1
			}
		case "k":
			if v, ok := nums(args, 4); ok {
				g.fillWhite = v[0] <= 0 && v[1] <= 0 && v[2] <= 0 && v[3] <= 0
			}
		case "K":
			if v, ok := nums(args, 4); ok {
				g.strokeWhite = v[0] <= 0 && v[1] <= 0 && v[2] <= 0 && v[3] <= 0
			}
		case "cs", "sc", "scn":
			g.fillWhite = false
		case "CS", "SC", "SCN":
			g.strokeWhite = false

		// ── Path construction (points transformed by the CTM when given) ──
		case "m":
			if v, ok := nums(args, 2); ok {
				x, y := g.ctm.apply(v[0], v[1])
				path = append(path, &subpath{sx: x, sy: y, cx: x, cy: y, bbox: pointRect(x, y)})
			}
		case "l", "c", "v", "y":
			n := map[string]int{"l": 2, "c": 6, "v": 4, "y": 4}[kw]
			v, ok := nums(args, n)
			if !ok || len(path) == 0 {
				break
			}
			sp := path[len(path)-1]
			seg := pointRect(sp.cx, sp.cy)
			for i := 0; i < n; i += 2 {
				x, y := g.ctm.apply(v[i], v[i+1])
				seg.add(x, y)
				sp.bbox.add(x, y)
				sp.cx, sp.cy = x, y
			}
			sp.segs = append(sp.segs, seg)
		case "h":
			if len(args) == 0 && len(path) > 0 {
				closePath(path[len(path)-1])
			}
		case "re":
			if v, ok := nums(args, 4); ok {
				x0, y0 := g.ctm.apply(v[0], v[1])
				x1, y1 := g.ctm.apply(v[0]+v[2], v[1])
				x2, y2 := g.ctm.apply(v[0]+v[2], v[1]+v[3])
				x3, y3 := g.ctm.apply(v[0], v[1]+v[3])
				sp := &subpath{sx: x0, sy: y0, cx: x0, cy: y0, bbox: pointRect(x0, y0)}
				for _, p := range [][2]float64{{x1, y1}, {x2, y2}, {x3, y3}} {
					seg := pointRect(sp.cx, sp.cy)
					seg.add(p[0], p[1])
					sp.segs = append(sp.segs, seg)
					sp.bbox.add(p[0], p[1])
					sp.cx, sp.cy = p[0], p[1]
				}
				closePath(sp)
				path = append(path, sp)
			}
		case "S", "s", "f", "F", "f*", "B", "B*", "b", "b*", "n":
			if len(args) != 0 {
				break
			}
			if (kw == "s" || kw == "b" || kw == "b*") && len(path) > 0 {
				closePath(path[len(path)-1])
			}
			fill := kw != "S" && kw != "s" && kw != "n"
			stroke := kw == "S" || kw == "s" || kw == "B" || kw == "B*" || kw == "b" || kw == "b*"
			if fill && !g.fillWhite {
				if err := s.fill(path); err != nil {
					return err
				}
			}
			if stroke && !g.strokeWhite {
				if err := s.stroke(path, g); err != nil {
					return err
				}
			}
			path = nil

		// ── Text ──
		case "Tc":
			if v, ok := nums(args, 1); ok {
				g.tc = v[0]
			}
		case "Tw":
			if v, ok := nums(args, 1); ok {
				g.tw = v[0]
			}
		case "Tz":
			if v, ok := nums(args, 1); ok {
				g.th = v[0] / 100
			}
		case "TL":
			if v, ok := nums(args, 1); ok {
				g.tl = v[0]
			}
		case "Ts":
			if v, ok := nums(args, 1); ok {
				g.trise = v[0]
			}
		case "Tf":
			if len(args) == 2 && args[0].kind == tName && args[1].kind == tNum {
				g.font, g.tfs = s.font(res.Key("Font").Key(args[0].name)), args[1].num
			}
		case "Td", "TD":
			if v, ok := nums(args, 2); ok {
				if kw == "TD" {
					g.tl = -v[1]
				}
				if tlm = mul(matrix{1, 0, 0, 1, v[0], v[1]}, tlm); !tlm.finite() {
					return fmt.Errorf("%w: text matrix", errUnscannable)
				}
				tm = tlm
			}
		case "T*":
			if len(args) == 0 {
				if tlm = mul(matrix{1, 0, 0, 1, 0, -g.tl}, tlm); !tlm.finite() {
					return fmt.Errorf("%w: text matrix", errUnscannable)
				}
				tm = tlm
			}
		case "Tm":
			if v, ok := nums(args, 6); ok {
				tm, tlm = matrix(v), matrix(v)
			}
		case "Tj", "'", "\"", "TJ":
			var items []operand
			switch {
			case kw == "Tj" && len(args) == 1 && args[0].kind == tStr, kw == "'" && len(args) == 1 && args[0].kind == tStr:
				items = args
			case kw == "\"" && len(args) == 3 && args[0].kind == tNum && args[1].kind == tNum && args[2].kind == tStr:
				g.tw, g.tc = args[0].num, args[1].num
				items = args[2:]
			case kw == "TJ" && len(args) == 1 && args[0].kind == tArr:
				items = args[0].arr
			default:
				continue
			}
			if kw == "'" || kw == "\"" {
				if tlm = mul(matrix{1, 0, 0, 1, 0, -g.tl}, tlm); !tlm.finite() {
					return fmt.Errorf("%w: text matrix", errUnscannable)
				}
				tm = tlm
			}
			var err error
			if tm, err = s.show(items, g, tm); err != nil {
				return err
			}
		case "Do":
			if len(args) != 1 || args[0].kind != tName {
				break
			}
			x := res.Key("XObject").Key(args[0].name)
			switch x.Key("Subtype").Name() {
			case "Image":
				if err := s.unitSquare(g.ctm); err != nil {
					return err
				}
			case "Form":
				if x.Kind() != pdf.Stream {
					break
				}
				if depth+1 > occMaxDepth {
					return fmt.Errorf("%w: form depth", errUnscannable)
				}
				fm := identity
				if m := x.Key("Matrix"); m.Kind() == pdf.Array && m.Len() == 6 {
					var v matrix
					ok := true
					for i := range 6 {
						v[i], ok = number(m.Index(i))
						if !ok {
							break
						}
					}
					if ok {
						fm = v
					}
				}
				ctm := mul(fm, g.ctm)
				if !ctm.finite() {
					return fmt.Errorf("%w: form matrix", errUnscannable)
				}
				fres := x.Key("Resources")
				if fres.Kind() != pdf.Dict {
					fres = res
				}
				b, err := s.stream(x)
				if err != nil {
					return err
				}
				fg := g
				fg.ctm = ctm
				if err := s.run(b, fres, fg, depth+1); err != nil {
					return err
				}
			}
		case "BI":
			if err := s.inlineImage(l, g.ctm); err != nil {
				return err
			}
		}
	}
}

func closePath(sp *subpath) {
	seg := pointRect(sp.cx, sp.cy)
	seg.add(sp.sx, sp.sy)
	sp.segs = append(sp.segs, seg)
	sp.cx, sp.cy = sp.sx, sp.sy
}

// fill — one box per subpath; a subpath box covering ≥ half of the page box is a background and is skipped.
func (s *occScanner) fill(path []*subpath) error {
	for _, sp := range path {
		q, err := quantise(sp.bbox)
		if err != nil {
			return err
		}
		// Area of the box clipped to the page box: ≤ page area, so exact in a double too (< 2^53).
		w, h := min(q[2], s.page[2])-max(q[0], s.page[0]), min(q[3], s.page[3])-max(q[1], s.page[1])
		if w > 0 && h > 0 && 2*int64(w)*int64(h) >= int64(s.page[2]-s.page[0])*int64(s.page[3]-s.page[1]) {
			continue
		}
		s.boxes = append(s.boxes, q)
	}
	return nil
}

// stroke — one box per segment, widened by half the line width mapped through the CTM (|a|+|c|, |b|+|d|).
func (s *occScanner) stroke(path []*subpath, g gstate) error {
	hw := math.Abs(g.lw) / 2
	ex := float64(hw*math.Abs(g.ctm[0])) + float64(hw*math.Abs(g.ctm[2]))
	ey := float64(hw*math.Abs(g.ctm[1])) + float64(hw*math.Abs(g.ctm[3]))
	for _, sp := range path {
		for _, r := range sp.segs {
			if err := s.emit(rect{r.x0 - ex, r.y0 - ey, r.x1 + ex, r.y1 + ey}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *occScanner) unitSquare(ctm matrix) error {
	x, y := ctm.apply(0, 0)
	r := pointRect(x, y)
	for _, p := range [][2]float64{{1, 0}, {0, 1}, {1, 1}} {
		x, y := ctm.apply(p[0], p[1])
		r.add(x, y)
	}
	return s.emit(r)
}

// show — one box per string/array operand: [min, max] of glyph extents in text space × [rise − 0.3·Tfs, rise + Tfs],
// through Tm then the CTM. Returns the advanced Tm.
func (s *occScanner) show(items []operand, g gstate, tm matrix) (matrix, error) {
	x := 0.0
	var ext *[2]float64
	for _, it := range items {
		switch it.kind {
		case tNum:
			x -= float64(float64(it.num/1000*g.tfs) * g.th)
		case tStr:
			g.font.glyphs(it.str, func(w0 float64, space bool) {
				gw := float64(float64(w0/1000*g.tfs) * g.th)
				lo, hi := min(x, x+gw), max(x, x+gw)
				if ext == nil {
					ext = &[2]float64{lo, hi}
				} else {
					ext[0], ext[1] = min(ext[0], lo), max(ext[1], hi)
				}
				adv := float64(w0/1000*g.tfs) + g.tc
				if space {
					adv += g.tw
				}
				x += float64(adv * g.th)
			})
		}
	}
	if ext != nil {
		ya, yb := g.trise+float64(g.tfs*-0.3), g.trise+g.tfs
		var r *rect
		for _, p := range [][2]float64{{ext[0], ya}, {ext[1], ya}, {ext[0], yb}, {ext[1], yb}} {
			tx, ty := tm.apply(p[0], p[1])
			dx, dy := g.ctm.apply(tx, ty)
			if r == nil {
				r = &rect{dx, dy, dx, dy}
			} else {
				r.add(dx, dy)
			}
		}
		if err := s.emit(*r); err != nil {
			return tm, err
		}
	}
	tm = mul(matrix{1, 0, 0, 1, x, 0}, tm)
	if !tm.finite() {
		return tm, fmt.Errorf("%w: text matrix", errUnscannable)
	}
	return tm, nil
}

// inlineImage — BI <key value>… ID <data> EI: data ends at the first "EI" preceded by a whitespace byte and followed by
// a whitespace byte or the end of the content. No EI → the content ends (no box).
func (s *occScanner) inlineImage(l *lexer, ctm matrix) error {
	count := 0
	for {
		k, o, kw := l.next()
		switch k {
		case lxEOF:
			return nil
		case lxObj:
			if _, eof, err := l.object(o, kw, 0, &count); err != nil || eof {
				return err
			}
			continue
		case lxKeyword:
			if kw != "ID" {
				continue
			}
		default:
			continue
		}
		break
	}
	if l.i < len(l.b) && isSpace(l.b[l.i]) {
		l.i++
	}
	for p := l.i; p+1 < len(l.b); p++ {
		if l.b[p] == 'E' && l.b[p+1] == 'I' && p > 0 && isSpace(l.b[p-1]) && (p+2 == len(l.b) || isSpace(l.b[p+2])) {
			l.i = p + 2
			return s.unitSquare(ctm)
		}
	}
	l.i = len(l.b)
	return nil
}

// annots — /Rect of every annotation except /Popup, hidden (/F bit 2) or NoView (/F bit 6) and zero-area rects.
func (s *occScanner) annots(a pdf.Value) error {
	if a.Kind() != pdf.Array {
		return nil
	}
	if a.Len() > occMaxAnnots {
		return fmt.Errorf("%w: annotations", errUnscannable)
	}
	for i := range a.Len() {
		an := a.Index(i)
		if an.Kind() != pdf.Dict || an.Key("Subtype").Name() == "Popup" {
			continue
		}
		if f := an.Key("F"); f.Kind() == pdf.Integer && f.Int64()&(2|32) != 0 {
			continue
		}
		r := an.Key("Rect")
		if r.Kind() != pdf.Array || r.Len() != 4 {
			continue
		}
		var v [4]float64
		ok := true
		for j := range 4 {
			if v[j], ok = number(r.Index(j)); !ok {
				break
			}
		}
		if !ok || v[0] == v[2] || v[1] == v[3] {
			continue
		}
		if err := s.emit(rect{min(v[0], v[2]), min(v[1], v[3]), max(v[0], v[2]), max(v[1], v[3])}); err != nil {
			return err
		}
	}
	return nil
}
