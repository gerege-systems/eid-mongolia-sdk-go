package validate

import (
	"bytes"
	"compress/zlib"
	"errors"
	"io"
	"maps"
	"strconv"
	"strings"
)

// Revision-ийн шинжилгээнд (revisions.go) зориулсан ХАТУУ PDF задлагч. digitorus/pdf нь ref-ийг
// автоматаар задалж, xref-ийн хувилбар тус бүрийг харуулдаггүй тул «гарын үсгийн дараа юу
// өөрчлөгдсөн»-ийг түүгээр тогтоох боломжгүй. Энэ задлагч нь зөвшөөрөгч биш, татгалзагч: ойлгоогүй
// зүйл бүр (давхар түлхүүр, танихгүй filter, хэт гүн бүтэц, /Encrypt, hybrid xref) алдаа болж,
// дуудагч нь алдааг «гарын үсгийн дараа өөрчлөгдсөн» гэж үзнэ (fail closed). Рекурс maxPDFDepth-ээр,
// нийт ажил pdfBudget-ээр хязгаарлагдана. Extract-тай адил ЗӨВХӨН worker дотор ажиллана.

const (
	maxPDFDepth     = 64        // шууд (ref биш) давхарлалтын гүн
	maxPDFNodes     = 1_000_000 // нэг баримтын бүх шинжилгээнд задлах утга + xref мөрийн нийт тоо
	maxPDFInflate   = 64 << 20  // задлах (FlateDecode) нийт байт
	maxXrefSections = 128       // xref гинжийн урт
	maxObjectNumber = 1 << 23   // PDF-ийн объектын дугаарын дээд хязгаар
)

var (
	errPDFSyntax = errors.New("validate: PDF бүтэц танигдсангүй")
	errPDFLimit  = errors.New("validate: PDF шинжилгээний хязгаар хэтэрлээ")
)

type (
	pdfRef  struct{ num, gen int }
	pdfName string
	pdfStr  string
	pdfArr  []any
	// pdfDict — null утгатай түлхүүр хадгалагдахгүй (PDF-д «байхгүй»-тэй ижил).
	pdfDict   map[string]any
	pdfStream struct {
		dict pdfDict
		data []byte // шахагдсан хэвээр (түүхий) байтууд
	}
)

// Бусад утга: nil (null), bool, int64, float64.

// pdfBudget — нэг баримтын бүх харагдац (revision бүрийн төлөв)-д хуваалцах нөөц ба задлалтын кэш.
// Харагдацууд нь нэг файлын эхний N байт тул ижил байрлал дахь объект бүгдэд ижил задарна: кэш нь
// revision-ийн тоогоор ажил (nodes, inflate) үржихээс сэргийлнэ.
type pdfBudget struct {
	nodes, inflate int
	objs           map[objKey]cachedObj
	stms           map[int]*objStm // ObjStm объектын байрлалаар
}

// objKey — idx < 0: off байрлал дахь шууд объект; эс бөгөөс off байрлалтай ObjStm-ийн idx дэх объект.
type objKey struct{ off, idx int }

type cachedObj struct {
	pdfIndirect
	end int // объектын төгсгөл: үүнээс богино харагдацад хэрэглэхгүй
}

func newPDFBudget() *pdfBudget {
	return &pdfBudget{nodes: maxPDFNodes, inflate: maxPDFInflate, objs: map[objKey]cachedObj{}, stms: map[int]*objStm{}}
}

func (b *pdfBudget) node() error {
	if b.nodes--; b.nodes < 0 {
		return errPDFLimit
	}
	return nil
}

type pdfParser struct {
	b      []byte
	pos    int
	budget *pdfBudget
	// strict — токенуудын хооронд зөвхөн isGapSpace (NUL, тайлбар үгүй). Гарын үсгийн мужийн ард
	// нэмэгдсэн объект, xref хэсгийг задлахад.
	strict bool
}

func isPDFSpace(c byte) bool {
	return c == 0 || c == '\t' || c == '\n' || c == '\f' || c == '\r' || c == ' '
}

func isPDFDelim(c byte) bool { return strings.IndexByte("()<>[]{}/%", c) >= 0 }

// isGapSpace — объект, xref хэсгүүдийн ХООРОНД зөвшөөрөгдөх зай. NUL болон тайлбар үгүй: xref-ийг
// файлаас хайж сэргээдэг viewer тэдгээрийн ард/дотор нуусан зүйлийг өөрөөр уншиж болно.
func isGapSpace(c byte) bool {
	return c == '\t' || c == '\n' || c == '\f' || c == '\r' || c == ' '
}

func allGapSpace(b []byte) bool {
	for _, c := range b {
		if !isGapSpace(c) {
			return false
		}
	}
	return true
}

func (p *pdfParser) skipGap() {
	for p.pos < len(p.b) && isGapSpace(p.b[p.pos]) {
		p.pos++
	}
}

func (p *pdfParser) skipSpace() {
	if p.strict {
		p.skipGap()
		return
	}
	for p.pos < len(p.b) && isPDFSpace(p.b[p.pos]) {
		p.pos++
	}
}

// skip — зай ба тайлбар (% … мөрийн төгсгөл). Хатуу горимд зөвхөн isGapSpace: NUL эсвэл % таарвал
// дараагийн токен задрахгүй (алдаа).
func (p *pdfParser) skip() {
	if p.strict {
		p.skipGap()
		return
	}
	for p.pos < len(p.b) {
		switch c := p.b[p.pos]; {
		case isPDFSpace(c):
			p.pos++
		case c == '%':
			for p.pos < len(p.b) && p.b[p.pos] != '\n' && p.b[p.pos] != '\r' {
				p.pos++
			}
		default:
			return
		}
	}
}

// keyword — яг k түлхүүр үг (ард нь зай/хязгаарлагч/төгсгөл) байвал уншина.
func (p *pdfParser) keyword(k string) bool {
	e := p.pos + len(k)
	if e > len(p.b) || string(p.b[p.pos:e]) != k {
		return false
	}
	if e < len(p.b) && !isPDFSpace(p.b[e]) && !isPDFDelim(p.b[e]) {
		return false
	}
	p.pos = e
	return true
}

func (p *pdfParser) uint() (int64, bool) {
	s := p.pos
	for p.pos < len(p.b) && p.b[p.pos] >= '0' && p.b[p.pos] <= '9' {
		p.pos++
	}
	if p.pos == s || p.pos-s > 18 {
		p.pos = s
		return 0, false
	}
	n, _ := strconv.ParseInt(string(p.b[s:p.pos]), 10, 64)
	return n, true
}

func (p *pdfParser) value(depth int) (any, error) {
	if depth > maxPDFDepth {
		return nil, errPDFSyntax
	}
	if err := p.budget.node(); err != nil {
		return nil, err
	}
	p.skip()
	if p.pos >= len(p.b) {
		return nil, errPDFSyntax
	}
	switch c := p.b[p.pos]; {
	case c == '/':
		p.pos++
		return p.name()
	case c == '(':
		p.pos++
		return p.literal()
	case c == '[':
		p.pos++
		arr := pdfArr{}
		for {
			p.skip()
			if p.pos < len(p.b) && p.b[p.pos] == ']' {
				p.pos++
				return arr, nil
			}
			v, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
		}
	case c == '<':
		if p.pos+1 < len(p.b) && p.b[p.pos+1] == '<' {
			p.pos += 2
			return p.dict(depth)
		}
		p.pos++
		return p.hex()
	case c >= '0' && c <= '9', c == '+', c == '-', c == '.':
		return p.number()
	case p.keyword("true"):
		return true, nil
	case p.keyword("false"):
		return false, nil
	case p.keyword("null"):
		return nil, nil
	}
	return nil, errPDFSyntax
}

func (p *pdfParser) dict(depth int) (any, error) {
	d := pdfDict{}
	for {
		p.skip()
		if p.pos+1 < len(p.b) && p.b[p.pos] == '>' && p.b[p.pos+1] == '>' {
			p.pos += 2
			maps.DeleteFunc(d, func(_ string, v any) bool { return v == nil })
			return d, nil
		}
		if p.pos >= len(p.b) || p.b[p.pos] != '/' {
			return nil, errPDFSyntax
		}
		p.pos++
		k, err := p.name()
		if err != nil {
			return nil, err
		}
		key := string(k.(pdfName))
		old, dup := d[key]
		v, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		// Давхар түлхүүрийг viewer бүр өөрөөр уншдаг (эхнийх/сүүлийнх) — утга нь зөрвөл хүлээн авахгүй.
		// Ижил утгатай давхардал хоёрдмол утгагүй (digitorus/pdfsign 1.5-аас доош хувилбартай баримтыг
		// давхар зурахдаа Catalog-т /Version-ийг хоёр бичдэг).
		if dup && !pdfEqual(old, v) {
			return nil, errPDFSyntax
		}
		d[key] = v
	}
}

func (p *pdfParser) name() (any, error) {
	var out []byte
	for p.pos < len(p.b) && !isPDFSpace(p.b[p.pos]) && !isPDFDelim(p.b[p.pos]) {
		c := p.b[p.pos]
		if c == '#' {
			if p.pos+2 >= len(p.b) {
				return nil, errPDFSyntax
			}
			v, err := strconv.ParseUint(string(p.b[p.pos+1:p.pos+3]), 16, 8)
			if err != nil {
				return nil, errPDFSyntax
			}
			c = byte(v)
			p.pos += 2
		}
		out = append(out, c)
		p.pos++
	}
	return pdfName(out), nil
}

func (p *pdfParser) literal() (any, error) {
	var out []byte
	for depth := 1; ; p.pos++ {
		if p.pos >= len(p.b) {
			return nil, errPDFSyntax
		}
		c := p.b[p.pos]
		switch c {
		case '(':
			depth++
		case ')':
			if depth--; depth == 0 {
				p.pos++
				return pdfStr(out), nil
			}
		case '\r': // мөрийн төгсгөл бүр \n гэж уншигдана
			if p.pos+1 < len(p.b) && p.b[p.pos+1] == '\n' {
				p.pos++
			}
			c = '\n'
		case '\\':
			if p.pos++; p.pos >= len(p.b) {
				return nil, errPDFSyntax
			}
			switch e := p.b[p.pos]; {
			case e == 'n':
				c = '\n'
			case e == 'r':
				c = '\r'
			case e == 't':
				c = '\t'
			case e == 'b':
				c = '\b'
			case e == 'f':
				c = '\f'
			case e == '\n':
				continue
			case e == '\r':
				if p.pos+1 < len(p.b) && p.b[p.pos+1] == '\n' {
					p.pos++
				}
				continue
			case e >= '0' && e <= '7':
				// \ddd: байтын арифметикаар (PDF-ийн дүрмээр дээд битийн илүүдэл хаягдана).
				c = 0
				for i := 0; i < 3 && p.pos < len(p.b) && p.b[p.pos] >= '0' && p.b[p.pos] <= '7'; i++ {
					c = c<<3 | (p.b[p.pos] - '0')
					p.pos++
				}
				p.pos--
			default:
				c = e
			}
		}
		out = append(out, c)
	}
}

func (p *pdfParser) hex() (any, error) {
	var digits []byte
	for ; ; p.pos++ {
		if p.pos >= len(p.b) {
			return nil, errPDFSyntax
		}
		c := p.b[p.pos]
		if c == '>' {
			p.pos++
			break
		}
		if !isPDFSpace(c) {
			digits = append(digits, c)
		}
	}
	if len(digits)%2 == 1 {
		digits = append(digits, '0')
	}
	out := make([]byte, len(digits)/2)
	for i := range out {
		v, err := strconv.ParseUint(string(digits[2*i:2*i+2]), 16, 8)
		if err != nil {
			return nil, errPDFSyntax
		}
		out[i] = byte(v)
	}
	return pdfStr(out), nil
}

// number — бүхэл/бодит тоо, эсвэл «n g R» заалт.
func (p *pdfParser) number() (any, error) {
	s := p.pos
	for p.pos < len(p.b) && strings.IndexByte("0123456789+-.", p.b[p.pos]) >= 0 {
		p.pos++
	}
	tok := string(p.b[s:p.pos])
	if p.pos < len(p.b) && !isPDFSpace(p.b[p.pos]) && !isPDFDelim(p.b[p.pos]) {
		return nil, errPDFSyntax
	}
	if strings.Contains(tok, ".") {
		f, err := strconv.ParseFloat(tok, 64)
		if err != nil {
			return nil, errPDFSyntax
		}
		return f, nil
	}
	n, err := strconv.ParseInt(tok, 10, 64)
	if err != nil {
		return nil, errPDFSyntax
	}
	if n >= 0 && tok[0] != '+' {
		save := p.pos
		p.skip()
		if g, ok := p.uint(); ok {
			p.skip()
			if p.keyword("R") {
				if n >= maxObjectNumber || g > 65535 {
					return nil, errPDFSyntax
				}
				return pdfRef{int(n), int(g)}, nil
			}
		}
		p.pos = save
	}
	return n, nil
}

type pdfIndirect struct {
	num, gen int
	val      any
}

// indirect — «n g obj … endobj». length нь шууд бус /Length-ийг тухайн харагдацад задална
// (nil бол шууд бус урттай stream алдаа).
func (p *pdfParser) indirect(length func(pdfRef) (int64, error)) (o pdfIndirect, err error) {
	p.skipSpace()
	n, ok1 := p.uint()
	p.skipSpace()
	g, ok2 := p.uint()
	p.skipSpace()
	if !ok1 || !ok2 || n >= maxObjectNumber || g > 65535 || !p.keyword("obj") {
		return o, errPDFSyntax
	}
	o.num, o.gen = int(n), int(g)
	if o.val, err = p.value(0); err != nil {
		return o, err
	}
	p.skip()
	if d, ok := o.val.(pdfDict); ok && p.keyword("stream") {
		if p.pos < len(p.b) && p.b[p.pos] == '\r' {
			p.pos++
		}
		if p.pos >= len(p.b) || p.b[p.pos] != '\n' {
			return o, errPDFSyntax
		}
		p.pos++
		var size int64
		switch l := d["Length"].(type) {
		case int64:
			size = l
		case pdfRef:
			if length == nil {
				return o, errPDFSyntax
			}
			if size, err = length(l); err != nil {
				return o, err
			}
		default:
			return o, errPDFSyntax
		}
		if size < 0 || size > int64(len(p.b)-p.pos) {
			return o, errPDFSyntax
		}
		o.val = pdfStream{dict: d, data: p.b[p.pos : p.pos+int(size)]}
		p.pos += int(size)
		p.skipSpace()
		if !p.keyword("endstream") {
			return o, errPDFSyntax
		}
		p.skip()
	}
	if !p.keyword("endobj") {
		return o, errPDFSyntax
	}
	return o, nil
}

// startxref — «startxref N %%EOF»; N-ийг буцаана.
func (p *pdfParser) startxref() (int, bool) {
	p.skipGap()
	if !p.keyword("startxref") {
		return 0, false
	}
	p.skipGap()
	n, ok := p.uint()
	p.skipGap()
	if !ok || n > int64(len(p.b)) || !bytes.HasPrefix(p.b[p.pos:], []byte("%%EOF")) {
		return 0, false
	}
	p.pos += len("%%EOF")
	return int(n), true
}

// decode — xref/object stream-ийн агуулга: filter-гүй эсвэл ганц FlateDecode (+ PNG predictor).
func (b *pdfBudget) decode(s pdfStream) ([]byte, error) {
	single := func(v any) (any, error) {
		a, ok := v.(pdfArr)
		switch {
		case !ok:
			return v, nil
		case len(a) == 0:
			return nil, nil
		case len(a) == 1:
			return a[0], nil
		}
		return nil, errPDFSyntax
	}
	filter, err := single(s.dict["Filter"])
	if err != nil {
		return nil, err
	}
	if filter == nil {
		return s.data, nil
	}
	if filter != pdfName("FlateDecode") {
		return nil, errPDFSyntax
	}
	zr, err := zlib.NewReader(bytes.NewReader(s.data))
	if err != nil {
		return nil, errPDFSyntax
	}
	out, err := io.ReadAll(io.LimitReader(zr, int64(b.inflate)+1))
	if err != nil {
		return nil, errPDFSyntax
	}
	if b.inflate -= len(out); b.inflate < 0 {
		return nil, errPDFLimit
	}
	parms, err := single(s.dict["DecodeParms"])
	if err != nil {
		return nil, err
	}
	if parms == nil {
		return out, nil
	}
	pd, ok := parms.(pdfDict)
	if !ok {
		return nil, errPDFSyntax
	}
	intOr := func(key string, def int64) int64 {
		switch v := pd[key].(type) {
		case nil:
			return def
		case int64:
			return v
		}
		return -1
	}
	pred, cols := intOr("Predictor", 1), intOr("Columns", 1)
	if pred == 1 {
		return out, nil
	}
	if pred < 10 || pred > 15 || cols < 1 || cols > 1<<16 || intOr("Colors", 1) != 1 || intOr("BitsPerComponent", 8) != 8 {
		return nil, errPDFSyntax
	}
	return unPNG(out, int(cols))
}

// unPNG — PNG мөрийн predictor-ийг буцаана (нэг байт = нэг пиксел).
func unPNG(in []byte, cols int) ([]byte, error) {
	if len(in)%(cols+1) != 0 {
		return nil, errPDFSyntax
	}
	out := make([]byte, 0, len(in)/(cols+1)*cols)
	prev := make([]byte, cols)
	for ; len(in) > 0; in = in[cols+1:] {
		row := in[1 : cols+1]
		cur := make([]byte, cols)
		for i, x := range row {
			var left, upLeft byte
			if i > 0 {
				left, upLeft = cur[i-1], prev[i-1]
			}
			up := prev[i]
			switch in[0] {
			case 0:
			case 1:
				x += left
			case 2:
				x += up
			case 3:
				x += left&up + (left^up)>>1 // ⌊(left+up)/2⌋, халихгүйгээр
			case 4:
				pa, pb, pc := absInt(int(up)-int(upLeft)), absInt(int(left)-int(upLeft)), absInt(int(left)+int(up)-2*int(upLeft))
				switch {
				case pa <= pb && pa <= pc:
					x += left
				case pb <= pc:
					x += up
				default:
					x += upLeft
				}
			default:
				return nil, errPDFSyntax
			}
			cur[i] = x
		}
		out = append(out, cur...)
		prev = cur
	}
	return out, nil
}

func absInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// pdfEqual — бүтцийн тэнцүү байдал. ref-ийг ДАГАХГҮЙ (дугаараар нь харьцуулна), stream-ийг толь +
// түүхий байтаар харьцуулна.
func pdfEqual(a, b any) bool {
	switch x := a.(type) {
	case nil:
		return b == nil
	// Тоо төрлөөрөө ч таарах ёстой (90 ≠ 90.0): бүхэл тоо шаарддаг түлхүүрт (/Rotate, /Count …) бодит
	// тоог viewer бүр өөрөөр (үл тоох / тайрах) уншдаг.
	case bool, pdfRef, pdfName, pdfStr, int64, float64:
		return a == b
	case pdfArr:
		y, ok := b.(pdfArr)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !pdfEqual(x[i], y[i]) {
				return false
			}
		}
		return true
	case pdfDict:
		y, ok := b.(pdfDict)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, v := range x {
			if w, has := y[k]; !has || !pdfEqual(v, w) {
				return false
			}
		}
		return true
	case pdfStream:
		y, ok := b.(pdfStream)
		return ok && bytes.Equal(x.data, y.data) && pdfEqual(x.dict, y.dict)
	}
	return false
}

// pdfRefs — утга доторх бүх ref (шууд давхарлалтаар; ref-ийг дагахгүй).
func pdfRefs(v any, f func(pdfRef)) {
	switch x := v.(type) {
	case pdfRef:
		f(x)
	case pdfArr:
		for _, e := range x {
			pdfRefs(e, f)
		}
	case pdfDict:
		for _, e := range x {
			pdfRefs(e, f)
		}
	case pdfStream:
		pdfRefs(x.dict, f)
	}
}

// ── Харагдац: баримтын нэг төлөв (эхний N байт) дахь xref гинж ба объектууд ──

const (
	entFree = iota + 1
	entUse
	entComp
)

// xrefEnt — entUse: off = байтын байрлал; entComp: off = ObjStm-ийн дугаар, idx = доторх дараалал.
type xrefEnt struct {
	kind          uint8
	off, gen, idx int
}

func (e xrefEnt) inUse() bool { return e.kind == entUse || e.kind == entComp }

// useEnt — «ашиглагдаж буй» (classic 'n' / xref stream type 1) мөр. Байрлал 0 нь файлын толгой (%PDF-) тул
// тэнд объект хэзээ ч байж чадахгүй: ийм мөр тодорхойлогдоогүй объект (ISO 32000-1 §7.3.10 — заалт нь null;
// pdf.js ч мөн байхгүйд тооцдог). macOS Quartz ашиглагдаагүй дугаарыг «0000000000 00000 n» гэж бичдэг.
// Чөлөөтэй (entFree) мөрөөр төлөөлүүлснээр revisions.go-ийн дүрмүүд шууд хамаарна: хожим тэр дугаарыг
// тодорхойлбол шинэ объект (зөвшөөрөгдсөн үүрэгтэй байх ёстой), суурьт түүн рүү заасан бол «сул» заалт →
// татгалзана; хожмын хэсэгт ашиглагдаж буй объектыг ийм мөрөөр «устгавал» чөлөөлөлт → татгалзана.
func useEnt(off, gen int) xrefEnt {
	if off == 0 {
		return xrefEnt{kind: entFree}
	}
	return xrefEnt{kind: entUse, off: off, gen: gen}
}

type xrefSection struct {
	off     int // гинжид (startxref, /Prev) бичигдсэн байрлал
	start   int // эхний зайг алгассан бодит эхлэл
	end     int // trailer толь / xref stream объектын төгсгөл
	trailer pdfDict
	ents    map[int]xrefEnt
}

type objStm struct {
	data  []byte
	nums  []int
	offs  []int
	first int
}

type pdfView struct {
	b        []byte
	budget   *pdfBudget
	sections []xrefSection // шинэ нь эхэндээ
	xref     map[int]xrefEnt
	trailer  pdfDict // хамгийн шинэ хэсгийнх
	objs     map[int]any
	inLength bool
	// usedLength — сүүлд задалсан объект шууд бус /Length ашигласан (харагдацаас хамаарна → кэшлэхгүй).
	usedLength bool
	refs       map[int][]int // graph()-ийн кэш
}

func (v *pdfView) parser(pos int) *pdfParser {
	return &pdfParser{b: v.b, pos: pos, budget: v.budget}
}

// openView — b-ийн сүүлийн startxref-ээс /Prev гинжийг дагаж xref-ийг нийлүүлнэ. startxref-ийн
// ард зөвхөн %%EOF ба зай байх ёстой.
func openView(b []byte, budget *pdfBudget) (*pdfView, error) {
	v := &pdfView{b: b, budget: budget, xref: map[int]xrefEnt{}, objs: map[int]any{}}
	tail := max(0, len(b)-1024)
	i := bytes.LastIndex(b[tail:], []byte("startxref"))
	if i < 0 {
		return nil, errPDFSyntax
	}
	p := v.parser(tail + i)
	off, ok := p.startxref()
	if !ok || !allGapSpace(b[p.pos:]) {
		return nil, errPDFSyntax
	}
	seen := map[int]bool{}
	for {
		if len(v.sections) == maxXrefSections || seen[off] || off >= len(b) {
			return nil, errPDFSyntax
		}
		seen[off] = true
		sec, err := v.section(off)
		if err != nil {
			return nil, err
		}
		v.sections = append(v.sections, sec)
		// /Encrypt: шифрлэгдсэн объектыг харьцуулж чадахгүй. /XRefStm (hybrid): viewer-ээс хамаарч
		// өөр объект харагдана.
		if sec.trailer["Encrypt"] != nil || sec.trailer["XRefStm"] != nil {
			return nil, errPDFSyntax
		}
		prev, has := sec.trailer["Prev"]
		if !has {
			break
		}
		n, ok := prev.(int64)
		if !ok || n < 0 || n >= int64(len(b)) {
			return nil, errPDFSyntax
		}
		off = int(n)
	}
	for _, sec := range v.sections {
		for num, e := range sec.ents {
			if _, newer := v.xref[num]; !newer {
				v.xref[num] = e
			}
		}
	}
	v.trailer = v.sections[0].trailer
	// /Size-аас дээш дугаартай объектыг viewer «байхгүй» гэж үздэг: гарын үсгийн дараа /Size-ийг
	// өсгөж нуусан объектыг ил гаргахаас сэргийлж, ийм мөртэй баримтыг хүлээн авахгүй.
	size, ok := v.trailer["Size"].(int64)
	if !ok {
		return nil, errPDFSyntax
	}
	for num, e := range v.xref {
		if e.inUse() && (int64(num) >= size || num == 0) {
			return nil, errPDFSyntax
		}
	}
	return v, nil
}

func (v *pdfView) section(off int) (xrefSection, error) {
	p := v.parser(off)
	p.skipGap()
	sec := xrefSection{off: off, start: p.pos, ents: map[int]xrefEnt{}}
	if p.pos >= len(p.b) || p.b[p.pos] != 'x' && (p.b[p.pos] < '0' || p.b[p.pos] > '9') {
		return sec, errPDFSyntax
	}
	set := func(num int64, e xrefEnt) error {
		if num >= maxObjectNumber {
			return errPDFSyntax
		}
		if _, dup := sec.ents[int(num)]; dup {
			return errPDFSyntax
		}
		sec.ents[int(num)] = e
		return v.budget.node()
	}
	if p.keyword("xref") {
		for {
			p.skipSpace()
			if p.keyword("trailer") {
				break
			}
			first, ok1 := p.uint()
			p.skipSpace()
			count, ok2 := p.uint()
			if !ok1 || !ok2 || first >= maxObjectNumber || count > maxObjectNumber {
				return sec, errPDFSyntax
			}
			p.skipGap()
			for i := int64(0); i < count; i++ {
				// Мөр бүр ЯГ 20 байт: «nnnnnnnnnn ggggg n» + хоёр байт мөрийн төгсгөл (SP LF, SP CR, CR LF).
				// Өөр хэлбэрийг viewer «засаж» уншдаг — засварын дүн нь бидний уншсантай зөрж болно.
				if p.pos+20 > len(p.b) {
					return sec, errPDFSyntax
				}
				row := p.b[p.pos : p.pos+20]
				o, err1 := strconv.ParseUint(string(row[:10]), 10, 63)
				g, err2 := strconv.ParseUint(string(row[11:16]), 10, 32)
				eol := string(row[18:])
				if err1 != nil || err2 != nil || row[10] != ' ' || row[16] != ' ' || eol != " \n" && eol != " \r" && eol != "\r\n" ||
					o > uint64(len(p.b)) || g > 65535 {
					return sec, errPDFSyntax
				}
				var e xrefEnt
				switch row[17] {
				case 'n':
					e = useEnt(int(o), int(g))
				case 'f':
					e = xrefEnt{kind: entFree}
				default:
					return sec, errPDFSyntax
				}
				p.pos += 20
				if err := set(first+i, e); err != nil {
					return sec, err
				}
			}
		}
		t, err := p.value(0)
		if err != nil {
			return sec, err
		}
		d, ok := t.(pdfDict)
		if !ok {
			return sec, errPDFSyntax
		}
		sec.trailer, sec.end = d, p.pos
		return sec, nil
	}
	o, err := p.indirect(nil)
	if err != nil {
		return sec, err
	}
	st, ok := o.val.(pdfStream)
	if !ok || st.dict["Type"] != pdfName("XRef") {
		return sec, errPDFSyntax
	}
	data, err := v.budget.decode(st)
	if err != nil {
		return sec, err
	}
	w, ok := st.dict["W"].(pdfArr)
	if !ok || len(w) != 3 {
		return sec, errPDFSyntax
	}
	var width [3]int
	for i, x := range w {
		n, ok := x.(int64)
		if !ok || n < 0 || n > 7 {
			return sec, errPDFSyntax
		}
		width[i] = int(n)
	}
	size, ok := st.dict["Size"].(int64)
	if !ok || size < 0 {
		return sec, errPDFSyntax
	}
	index := pdfArr{int64(0), size}
	if ix, has := st.dict["Index"]; has {
		if index, ok = ix.(pdfArr); !ok || len(index)%2 != 0 {
			return sec, errPDFSyntax
		}
	}
	row := width[0] + width[1] + width[2]
	if row == 0 {
		return sec, errPDFSyntax
	}
	field := func(n int) int {
		x := 0
		for _, c := range data[:n] {
			x = x<<8 | int(c)
		}
		data = data[n:]
		return x
	}
	for i := 0; i < len(index); i += 2 {
		first, ok1 := index[i].(int64)
		count, ok2 := index[i+1].(int64)
		if !ok1 || !ok2 || first < 0 || first >= maxObjectNumber || count < 0 || count > int64(len(data)/row) {
			return sec, errPDFSyntax
		}
		for j := int64(0); j < count; j++ {
			kind := 1
			if width[0] > 0 {
				kind = field(width[0])
			}
			f2, f3 := field(width[1]), field(width[2])
			var e xrefEnt
			switch kind {
			case 0:
				e = xrefEnt{kind: entFree}
			case 1:
				e = useEnt(f2, f3)
			case 2:
				e = xrefEnt{kind: entComp, off: f2, idx: f3}
			default:
				return sec, errPDFSyntax
			}
			if err := set(first+j, e); err != nil {
				return sec, err
			}
		}
	}
	if len(data) != 0 {
		return sec, errPDFSyntax
	}
	sec.trailer, sec.end = st.dict, p.pos
	return sec, nil
}

// get — ашиглагдаж буй num объектыг задална (толгойн дугаар/үе xref-тэй таарах ёстой).
func (v *pdfView) get(num int) (any, error) {
	if o, ok := v.objs[num]; ok {
		return o, nil
	}
	var val any
	switch e := v.xref[num]; e.kind {
	case entUse:
		if e.off >= len(v.b) {
			return nil, errPDFSyntax
		}
		key := objKey{e.off, -1}
		o, ok := v.budget.objs[key]
		if !ok || o.end > len(v.b) {
			p := v.parser(e.off)
			v.usedLength = false
			ind, err := p.indirect(v.length)
			if err != nil {
				return nil, err
			}
			o = cachedObj{ind, p.pos}
			if !v.usedLength {
				v.budget.objs[key] = o
			}
		}
		if o.num != num || o.gen != e.gen {
			return nil, errPDFSyntax
		}
		val = o.val
	case entComp:
		st, err := v.objStm(e.off)
		if err != nil {
			return nil, err
		}
		if e.idx >= len(st.nums) || st.nums[e.idx] != num || st.first+st.offs[e.idx] > len(st.data) {
			return nil, errPDFSyntax
		}
		key := objKey{v.xref[e.off].off, e.idx}
		o, ok := v.budget.objs[key]
		if !ok {
			p := &pdfParser{b: st.data, pos: st.first + st.offs[e.idx], budget: v.budget}
			if o.val, err = p.value(0); err != nil {
				return nil, err
			}
			v.budget.objs[key] = o
		}
		val = o.val
	default:
		return nil, errPDFSyntax
	}
	v.objs[num] = val
	return val, nil
}

// deref — ref-ийн заасан объект; ашиглагдаагүй дугаар бол null (PDF-ийн дүрэм), үе таарахгүй бол алдаа.
func (v *pdfView) deref(r pdfRef) (any, error) {
	e := v.xref[r.num]
	if !e.inUse() {
		return nil, nil
	}
	if e.kind == entUse && e.gen != r.gen || e.kind == entComp && r.gen != 0 {
		return nil, errPDFSyntax
	}
	return v.get(r.num)
}

// resolve — ref бол заасан объект, эс бөгөөс утга өөрөө.
func (v *pdfView) resolve(x any) (any, error) {
	if r, ok := x.(pdfRef); ok {
		return v.deref(r)
	}
	return x, nil
}

func (v *pdfView) length(r pdfRef) (int64, error) {
	if v.inLength {
		return 0, errPDFSyntax
	}
	v.inLength = true
	defer func() { v.inLength = false }()
	o, err := v.deref(r)
	if err != nil {
		return 0, err
	}
	n, ok := o.(int64)
	if !ok {
		return 0, errPDFSyntax
	}
	v.usedLength = true
	return n, nil
}

func (v *pdfView) objStm(num int) (*objStm, error) {
	if v.xref[num].kind != entUse {
		return nil, errPDFSyntax
	}
	o, err := v.get(num)
	if err != nil {
		return nil, err
	}
	off := v.xref[num].off
	if st, ok := v.budget.stms[off]; ok {
		return st, nil
	}
	s, ok := o.(pdfStream)
	n, ok1 := s.dict["N"].(int64)
	first, ok2 := s.dict["First"].(int64)
	// /Extends-ийг дэмжихгүй (гогцоо, давхар тодорхойлолт). /Length шууд байх ёстой: ObjStm нь
	// trailer-ээс «хүрэх» объект биш тул шууд бус уртыг нь хожим сольсон нь ялгаанд баригдахгүй.
	_, direct := s.dict["Length"].(int64)
	if !ok || !ok1 || !ok2 || !direct || s.dict["Type"] != pdfName("ObjStm") || s.dict["Extends"] != nil {
		return nil, errPDFSyntax
	}
	data, err := v.budget.decode(s)
	if err != nil {
		return nil, err
	}
	if n < 0 || n > int64(len(data)) || first < 0 || first > int64(len(data)) {
		return nil, errPDFSyntax
	}
	st := &objStm{data: data, first: int(first)}
	p := &pdfParser{b: data[:first], budget: v.budget}
	for i := int64(0); i < n; i++ {
		p.skipSpace()
		id, ok1 := p.uint()
		p.skipSpace()
		off, ok2 := p.uint()
		if !ok1 || !ok2 || id >= maxObjectNumber || off > int64(len(data)) || v.budget.node() != nil {
			return nil, errPDFSyntax
		}
		st.nums, st.offs = append(st.nums, int(id)), append(st.offs, int(off))
	}
	v.budget.stms[off] = st
	return st, nil
}

// graph — ашиглагдаж буй БҮХ объектыг задалж, объект бүрээс гарах ref-ийн дугааруудыг буцаана.
func (v *pdfView) graph() (map[int][]int, error) {
	if v.refs != nil {
		return v.refs, nil
	}
	refs := map[int][]int{}
	for num, e := range v.xref {
		if !e.inUse() {
			continue
		}
		o, err := v.get(num)
		if err != nil {
			return nil, err
		}
		var out []int
		pdfRefs(o, func(r pdfRef) { out = append(out, r.num) })
		refs[num] = out
	}
	v.refs = refs
	return refs, nil
}
