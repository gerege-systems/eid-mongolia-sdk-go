package validate

import (
	"bytes"
	"compress/zlib"
	"errors"
	"io"
	"strconv"
)

// CheckStructure — PDF-ийг рекурсив parser (digitorus/pdf)-т өгөхөөс ӨМНӨХ хямд урьдчилсан шалгалт. digitorus-ийн
// readObject/readArray/readDict нь давхарлалтын хязгааргүй рекурс тул ~2 MB `[[[[…` баримт goroutine-ийн stack-ийг
// (1 GB) дүүргэж `fatal error: stack overflow` өгдөг — recover() барихгүй, процесс бүхэлдээ унана.
//
// Арга: digitorus объектыг задалж эхэлдэг байж болох бүх цэгээс — файлын байт бүрийн `obj` ба `trailer` түлхүүр
// үгийн дараа (xref offset нь stream-ийн дотор заасан ч энэ байт тэнд бий), мөн /Type /ObjStm stream-ийн (FlateDecode,
// задалсан) толгойд заасан offset бүрээс — digitorus-ийн лексерийг (lex.go: хоосон зай, %-тайлбар, (…) мөр, <…> hex,
// /нэр #xx, << >> [ ]) давтаж, ЭХНИЙ объект дуусах хүртэл давхарлалтын гүнийг тоолно. Гүн > MaxNesting, нийт
// уншсан байт > nestScanFactor×len(doc)+1 MiB, задалсан ObjStm > maxObjStmBytes, эсвэл digitorus тайлж чадах
// боловч бид давтаагүй ObjStm (/DecodeParms, олон шүүлтүүр) бол ErrStructure (fail-closed). Шифрлэгдсэн баримтын ObjStm-ийг ч мөн
// адил шалгана (алгасахгүй): ciphertext нь zlib болж задрахгүй тул хууль ёсны баримтыг татгалзахгүй, харин /Encrypt-ийг
// түүхий байтаар (тайлбар, мөр, stream дотор) таних нь бүх ObjStm шалгалтыг унтраах тойруу зам байсан (2026-11-04).
//
// Энэ нь хамгаалалтын нэг давхарга — итгэлгүй PDF задлалыг бүхэлд нь аюулгүй болгохгүй (README «Итгэлгүй PDF»).
func CheckStructure(doc []byte) error {
	s := &nestScan{budget: nestScanFactor*len(doc) + 1<<20, inflateLeft: maxObjStmBytes}
	for _, kw := range [][]byte{[]byte("obj"), []byte("trailer")} {
		for i := 0; ; {
			j := bytes.Index(doc[i:], kw)
			if j < 0 {
				break
			}
			k := i + j
			at := k + len(kw)
			i = at
			// Токен `obj`/`trailer` нь хоёр талдаа зай/хязгаарлагчтай (`endobj`, `objx` — өөр түлхүүр үг).
			if k > 0 && !isPDFSpace(doc[k-1]) && !isPDFDelim(doc[k-1]) ||
				at < len(doc) && !isPDFSpace(doc[at]) && !isPDFDelim(doc[at]) {
				continue
			}
			s.fromTrailer = string(kw) == "trailer"
			if err := s.object(doc, at, true); err != nil {
				return err
			}
		}
	}
	if s.bigSize || s.sections > maxXrefSections || s.xrefEntries > maxXrefSize {
		return ErrStructure
	}
	return checkObjStmGraph(doc)
}

// MaxNesting — PDF объектын массив/толийн давхарлалтын дээд гүн. Жинхэнэ баримтад ~10-аас хэтрэхгүй; digitorus нэг
// түвшинд ~370 байт stack хэрэглэдэг тул 256 нь stack-д аюулгүй, хууль ёсны баримтад хангалттай нөөцтэй.
const MaxNesting = 256

const (
	nestScanFactor = 16       // нийт уншилтын төсөв = 16×len(doc) + 1 MiB (давхацсан объектоор квадрат ажил үүсгэхгүй)
	maxObjStmBytes = 32 << 20 // бүх ObjStm-ийн задалсан нийт хэмжээ (zip bomb)
	// maxXrefSize — trailer / xref stream-ийн /Size дээд хязгаар. digitorus нь /Size-аар xref хүснэгтийг шууд
	// make([]xref, Size) хуваарилж, Extract бүх мөрийг давтдаг тул 200 байтын баримтын /Size 10^10 нь 400 GB хуваарилалт
	// (Linux-д `fatal error: out of memory`) эсвэл хязгааргүй давталт болно. 10 MiB-ийн хууль ёсны баримтад хэдэн арван
	// мянгаас хэтрэхгүй.
	maxXrefSize = 1 << 21
	// maxObjStmWork — ObjStm-ийн гишүүн хайлтын ажлын дээд хэмжээ: Σ (толгойд уншсан «дугаар offset» хосын тоо ×
	// задалсан өгөгдлийн урт). gerege-systems/pdf (digitorus) нь ObjStm доторх объект бүрийг хайхдаа stream-ийг дахин
	// задалж толгойг эхнээс нь уншдаг (индексгүй) тул 100k гишүүнтэй ~1 MB ObjStm нь ~100 GB-ийн ажил болно. Хууль ёсны
	// баримтад ~100 гишүүн × ≤ 1 MB.
	maxObjStmWork = 1 << 30
)

// ErrStructure — PDF-ийн бүтэц хэт гүн давхарласан эсвэл хэт төвөгтэй (CheckStructure).
var ErrStructure = errors.New("PDF-ийн бүтэц хэт гүн давхарласан эсвэл хэт төвөгтэй")

type nestScan struct {
	budget      int
	inflateLeft int
	bigSize     bool // дээд түвшний /Size > maxXrefSize
	// fromTrailer — одоогийн дээд түвшний объект `trailer` түлхүүр үгийн араас (CheckStructure тавина).
	fromTrailer bool
	// sections — xref хэсгийн тоо: `trailer`-ийн араах толь + /Type /XRef толь (Prev гинж ≤ maxXrefSections; гинжийн
	// хэсэг бүр файлд байгаа тул энэ тоо гинжийн уртаас бага биш). xrefEntries — бүх xref stream-ийн мөрийн нийлбэр
	// (/Index-ийн тоонууд, /Index байхгүй бол /Size) ≤ maxXrefSize. objStmWork — maxObjStmWork-ийг үз.
	sections, xrefEntries, objStmWork int64
}

type nestTok int

const (
	tEOF nestTok = iota
	tErr         // digitorus энд panic хийнэ (recover барина) — задлал зогсоно
	tArr
	tArrEnd
	tDict
	tDictEnd
	tName
	tWord // тоо / түлхүүр үг
	tStr
)

type nestLex struct {
	b   []byte
	pos int
	val string // tName / tWord-ийн утга
}

// next — digitorus buffer.readToken-ийн давталт (зөвхөн бүтэц: мөр/hex-ийн агуулгыг буцаахгүй).
func (l *nestLex) next() nestTok {
	b := l.b
	for {
		for l.pos < len(b) && isPDFSpace(b[l.pos]) {
			l.pos++
		}
		if l.pos < len(b) && b[l.pos] == '%' {
			for l.pos < len(b) && b[l.pos] != '\r' && b[l.pos] != '\n' {
				l.pos++
			}
			continue
		}
		break
	}
	if l.pos >= len(b) {
		return tEOF
	}
	c := b[l.pos]
	l.pos++
	switch c {
	case '<':
		if l.pos < len(b) && b[l.pos] == '<' {
			l.pos++
			return tDict
		}
		for l.pos < len(b) && b[l.pos] != '>' {
			l.pos++
		}
		l.pos++
		return tStr
	case '(':
		for depth := 1; l.pos < len(b) && depth > 0; l.pos++ {
			switch b[l.pos] {
			case '(':
				depth++
			case ')':
				depth--
			case '\\':
				l.pos++
			}
		}
		return tStr
	case '[':
		return tArr
	case ']':
		return tArrEnd
	case '{', '}':
		l.val = string(c)
		return tWord
	case '/':
		var name []byte
		for l.pos < len(b) && !isPDFDelim(b[l.pos]) && !isPDFSpace(b[l.pos]) {
			if b[l.pos] == '#' && l.pos+2 < len(b) {
				if v, err := strconv.ParseUint(string(b[l.pos+1:l.pos+3]), 16, 8); err == nil {
					name = append(name, byte(v))
					l.pos += 3
					continue
				}
			}
			name = append(name, b[l.pos])
			l.pos++
		}
		l.val = string(name)
		return tName
	case '>':
		if l.pos < len(b) && b[l.pos] == '>' {
			l.pos++
			return tDictEnd
		}
		return tErr
	case ')':
		return tErr
	}
	start := l.pos - 1
	for l.pos < len(b) && !isPDFDelim(b[l.pos]) && !isPDFSpace(b[l.pos]) {
		l.pos++
	}
	l.val = string(b[start:l.pos])
	return tWord
}

func isInt(s string) bool {
	_, err := strconv.ParseInt(s, 10, 64)
	return err == nil
}

type nestFrame struct {
	dict      bool
	expectKey bool
	key       string // толийн одоогийн түлхүүр
}

// objStmInfo — дээд түвшний толийн /Type /Filter /DecodeParms /N /First.
type objStmInfo struct {
	typ, filter   string
	filters       int
	parms         bool
	indirect      bool // /Type /Filter /DecodeParms /N /First-ийн аль нэг нь лавлагаа (давтахгүй — fail-closed)
	first, nCount int64
	// xref stream (/Type /XRef): /W ба /Index массивын бүхэл утгууд (давхар түлхүүрийн сүүлийнх), бүхэл биш элемент
	// байвал *Bad (уншигч өөрөө алдаа өгнө — энд шийдэхгүй); /Size. length — шууд бүхэл /Length (-1 — байхгүй).
	w, index       []int64
	wBad, indexBad bool
	wSet, indexSet bool
	size           int64
	sizeSet        bool
	length         int64
}

// object — b[start:]-ээс digitorus readObject-ийн нэг объектыг (давхар `N G obj`-ийг оруулаад) гүнээр шалгана;
// allowStream бол дээд түвшний /Type /ObjStm толийн араас ирэх stream-ийг задалж шалгана.
func (s *nestScan) object(b []byte, start int, allowStream bool) error {
	l := &nestLex{b: b, pos: start}
	defer func() { s.budget -= l.pos - start }()
	var stack []nestFrame
	info := objStmInfo{length: -1}
	trailer := s.fromTrailer && allowStream
	s.fromTrailer = false
	for {
		if s.budget-(l.pos-start) < 0 {
			return ErrStructure
		}
		tok := l.next()
		top := len(stack) - 1
		if top >= 0 && stack[top].dict && stack[top].expectKey {
			switch tok {
			case tDictEnd:
				stack = stack[:top]
				if len(stack) == 0 {
					if trailer {
						s.sections++
					}
					if allowStream && !trailer && info.typ == "XRef" {
						if err := s.xrefStm(info); err != nil {
							return err
						}
					}
					if allowStream && (info.typ == "ObjStm" || info.typ == "XRef" || info.indirect) {
						return s.objStm(b, l, info)
					}
					return nil
				}
				stack[len(stack)-1].expectKey = stack[len(stack)-1].dict
				continue
			case tName:
				stack[top].key, stack[top].expectKey = l.val, false
				continue
			default:
				return nil // digitorus: non-name key → panic
			}
		}
		// Утга уншина.
		switch tok {
		case tEOF, tErr, tDictEnd:
			return nil
		case tArr, tDict:
			if len(stack) >= MaxNesting {
				return ErrStructure
			}
			if len(stack) == 1 && stack[0].dict && stack[0].key == "DecodeParms" {
				info.parms = true
			}
			if len(stack) == 1 && stack[0].dict && stack[0].key == "Filter" {
				info.filter, info.filters = "", 0 // digitorus: давхар түлхүүрийн сүүлийнх; массивын нэрсийг доор тоолно
			}
			if len(stack) == 1 && stack[0].dict && stack[0].key == "W" {
				info.w, info.wSet, info.wBad = nil, true, tok != tArr
			}
			if len(stack) == 1 && stack[0].dict && stack[0].key == "Index" {
				info.index, info.indexSet, info.indexBad = nil, true, tok != tArr
			}
			if len(stack) == 2 && stack[0].dict && (stack[0].key == "W" || stack[0].key == "Index") {
				if stack[0].key == "W" {
					info.wBad = true // массив доторх массив/толь — бүхэл биш
				} else {
					info.indexBad = true
				}
			}
			stack = append(stack, nestFrame{dict: tok == tDict, expectKey: tok == tDict})
			continue
		case tArrEnd:
			if top < 0 || stack[top].dict {
				return nil
			}
			stack = stack[:top]
		case tWord:
			if isInt(l.val) {
				save, saveVal := l.pos, l.val
				if l.next() == tWord && isInt(l.val) {
					if t3 := l.next(); t3 == tWord && l.val == "R" {
						if len(stack) == 1 && stack[0].dict {
							switch stack[0].key {
							case "Type", "Filter", "DecodeParms", "N", "First":
								info.indirect = true
							}
						}
						// /Filter [6 0 R] — digitorus Index()-ээр resolve хийж задална (DecodeParms-ийн гүн дэх лавлагаа,
						// жишээ нь /JBIG2Globals, хууль ёсны тул зөвхөн Filter).
						if len(stack) == 2 && stack[0].dict && stack[0].key == "Filter" {
							info.indirect = true
						}
						// /W, /Index-ийн лавлагаа (массив эсвэл элемент) — digitorus resolve хийхгүй, алдаа өгнө.
						if n := len(stack); (n == 1 || n == 2) && stack[0].dict {
							switch stack[0].key {
							case "W":
								info.wSet, info.wBad = true, true
							case "Index":
								info.indexSet, info.indexBad = true, true
							}
						}
						break // лавлагаа = нэг утга
					} else if t3 == tWord && l.val == "obj" {
						continue // давхар `N G obj` — дараагийн утга нь энэ объектын үргэлжлэл
					}
				}
				l.pos, l.val = save, saveVal
			}
			s.noteScalar(stack, &info, tok, l.val)
		case tName, tStr:
			s.noteScalar(stack, &info, tok, l.val)
		}
		// Нэг утга дууслаа.
		if len(stack) == 0 {
			return nil
		}
		if f := &stack[len(stack)-1]; f.dict {
			f.expectKey = true
		}
	}
}

// noteScalar — дээд түвшний толийн (ба /Filter массивын) энгийн утгыг тэмдэглэнэ.
func (s *nestScan) noteScalar(stack []nestFrame, info *objStmInfo, tok nestTok, val string) {
	switch {
	case len(stack) == 1 && stack[0].dict:
		switch stack[0].key {
		case "Type":
			if tok == tName {
				info.typ = val
			}
		case "Filter":
			if tok == tName {
				info.filter, info.filters = val, 1
			} else {
				info.filter, info.filters = "", 0 // null → digitorus шүүлтүүргүй (түүхийгээр) уншина; давхар түлхүүрийн сүүлийнх
			}
		case "DecodeParms":
			if !(tok == tWord && val == "null") {
				info.parms = true
			}
		case "N":
			info.nCount, _ = strconv.ParseInt(val, 10, 64)
		case "Size":
			n, err := strconv.ParseInt(val, 10, 64)
			if tok == tWord && err == nil && n > maxXrefSize {
				s.bigSize = true
			}
			info.size, info.sizeSet = n, tok == tWord && err == nil
		case "First":
			info.first, _ = strconv.ParseInt(val, 10, 64)
		case "Length":
			info.length = -1
			if n, err := strconv.ParseInt(val, 10, 64); tok == tWord && err == nil && n >= 0 {
				info.length = n
			}
		case "W":
			info.w, info.wSet, info.wBad = nil, true, true
		case "Index":
			info.index, info.indexSet, info.indexBad = nil, true, true
		}
	case len(stack) == 2 && stack[0].dict && stack[0].key == "Filter" && !stack[1].dict && tok == tName:
		info.filter = val
		info.filters++
	case len(stack) == 2 && stack[0].dict && !stack[1].dict && (stack[0].key == "W" || stack[0].key == "Index"):
		n, err := strconv.ParseInt(val, 10, 64)
		ok := tok == tWord && err == nil
		if stack[0].key == "W" {
			info.w, info.wBad = append(info.w, n), info.wBad || !ok
		} else {
			info.index, info.indexBad = append(info.index, n), info.indexBad || !ok
		}
	}
}

// objStm — `stream` түлхүүр үгийн араас FlateDecode өгөгдлийг (Length-ээс үл хамааран zlib өөрөө төгсөнө) задалж,
// толгойн offset бүрээс объектыг шалгана.
func (s *nestScan) objStm(b []byte, l *nestLex, info objStmInfo) error {
	if l.next() != tWord || l.val != "stream" {
		return nil
	}
	if info.indirect {
		return ErrStructure // stream-ийн /Type /Filter /N /First лавлагаагаар — хууль ёсны баримтад гардаггүй
	}
	if info.typ != "ObjStm" && info.typ != "XRef" {
		return nil
	}
	p := l.pos
	if p < len(b) && b[p] == '\r' {
		p++
	}
	if p < len(b) && b[p] == '\n' {
		p++
	}
	if info.typ == "XRef" {
		return s.xrefData(b[p:], info)
	}
	switch {
	case info.filters == 0:
		// Шахаагүй ObjStm — өгөгдөл нь файлын үлдсэн хэсэг (дээд хязгаар); ажлын тооцоонд шууд /Length (байвал).
		data := b[p:]
		pairs, err := s.objStmData(data, info)
		if err != nil {
			return err
		}
		n := int64(len(data))
		if info.length >= 0 {
			n = min(n, info.length)
		}
		return s.chargeObjStm(pairs, n)
	case info.filters > 1:
		return ErrStructure // digitorus [/FlateDecode /FlateDecode …]-г гинжлэн задалдаг — давтахгүй, fail-closed
	case info.filter != "FlateDecode":
		return nil // digitorus дэмжихгүй шүүлтүүр → panic (recover)
	case info.parms:
		return ErrStructure // predictor-тэй ObjStm-ийг давтахгүй — fail-closed
	}
	zr, err := zlib.NewReader(bytes.NewReader(b[p:]))
	if err != nil {
		return nil // digitorus мөн задалж чадахгүй
	}
	data, _ := io.ReadAll(io.LimitReader(zr, int64(s.inflateLeft)+1))
	if len(data) > s.inflateLeft {
		return ErrStructure
	}
	s.inflateLeft -= len(data)
	s.budget -= len(data)
	pairs, err := s.objStmData(data, info)
	if err != nil {
		return err
	}
	return s.chargeObjStm(pairs, int64(len(data)))
}

// chargeObjStm — нэг ObjStm-ийн гишүүн хайлтын ажил (хосын тоо × өгөгдлийн урт)-ыг maxObjStmWork-оос хасна.
func (s *nestScan) chargeObjStm(pairs, n int64) error {
	if pairs > 0 && n > 0 && pairs > (maxObjStmWork-s.objStmWork)/n {
		return ErrStructure
	}
	s.objStmWork += pairs * n
	return nil
}

// xrefStm — xref stream-ийн толь (/Type /XRef): хэсгийн тоо; /W-ийн элемент 0…8, мөрийн урт > 0; /Index-ийн хос бүр
// start, count ≥ 0, start+count ≤ maxXrefSize; бүх xref stream-ийн мөрийн нийлбэр (/Index байхгүй бол /Size) ≤
// maxXrefSize (CheckStructure төгсгөлд). Бүхэл биш / дутуу /W /Index-ийг уншигч өөрөө татгалзана — энд шийдэхгүй.
// digitorus: /W [0 0 0] + том /Index — хязгааргүй давталт; /W [1 0 0] + 64 MiB тэг — 64M мөр.
func (s *nestScan) xrefStm(info objStmInfo) error {
	s.sections++
	if info.wSet && !info.wBad && len(info.w) >= 3 {
		var row int64
		for _, w := range info.w {
			if w < 0 || w > 8 {
				return ErrStructure
			}
			row += w
		}
		if row == 0 {
			return ErrStructure
		}
	}
	switch {
	case info.indexSet && !info.indexBad && len(info.index)%2 == 0:
		for i := 0; i < len(info.index); i += 2 {
			start, n := info.index[i], info.index[i+1]
			if start < 0 || n < 0 || start > maxXrefSize || n > maxXrefSize-start {
				return ErrStructure
			}
			s.xrefEntries += n
		}
	case !info.indexSet && info.sizeSet && info.size >= 0:
		s.xrefEntries += min(info.size, maxXrefSize+1)
	}
	if s.xrefEntries > maxXrefSize {
		return ErrStructure
	}
	return nil
}

// xrefData — xref stream-ийн өгөгдөл: олон шүүлтүүр → ErrStructure (digitorus гинжлэн задалдаг); FlateDecode бол задалж
// (zlib өөрөө төгсөнө; predictor-ийг тооцохгүй — хэмжээ л) ObjStm-тэй хуваалцсан задлалтын төсвөөс хасна.
func (s *nestScan) xrefData(b []byte, info objStmInfo) error {
	switch {
	case info.filters == 0:
		return nil
	case info.filters > 1:
		return ErrStructure
	case info.filter != "FlateDecode":
		return nil
	}
	zr, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil
	}
	data, _ := io.ReadAll(io.LimitReader(zr, int64(s.inflateLeft)+1))
	if len(data) > s.inflateLeft {
		return ErrStructure
	}
	s.inflateLeft -= len(data)
	return nil
}

// objStmData — толгойн «дугаар offset» хос бүрийн объектыг шалгана. Offset-ийг digitorus-тэй яг ижлээр тооцно
// (read.go: `off, _ := b.readToken().(int64)`, `seekForward(first + off)`): бүхэл бус токен (`2.5`, `1e9`, `[`, `/N`,
// `(…)`, EOF) = 0, сөрөг offset ба /First, int64-ийн wrap хэвээр — өмнө нь эдгээрийг алгасдаг байсан тул бүхэл бус
// offset-оор `first`-ээс, сөрөгөөр толгойн дотроос уншигдах гүн объект шалгалтгүй үлдэж stack overflow өгдөг байв
// (2026-11-04). Өгөгдлийн төгсгөлөөс цаашхийг digitorus уншихгүй (EOF); сөрөг байрлал → ErrStructure.
//
// pairs — уншсан хосын тоо (эхний токен нь EOF биш давталт): гишүүн хайлтын ажлын тооцоонд (chargeObjStm).
func (s *nestScan) objStmData(data []byte, info objStmInfo) (pairs int64, err error) {
	l := &nestLex{b: data}
	firstDone := false // бүхэл бус offset олон байж болно — `first`-ийг нэг л удаа шалгана
	for i := int64(0); i < info.nCount; i++ {
		if l.next() == tEOF {
			break
		}
		pairs++
		var off int64 // бүхэл биш → 0 (хэт их бүхэлд digitorus panic хийнэ — 0 нь илүү шалгана)
		if l.next() == tWord {
			if v, err := strconv.ParseInt(l.val, 10, 64); err == nil {
				off = v
			}
		}
		at := info.first + off // int64 wrap — digitorus-тай ижил
		if at < 0 {
			// digitorus seekForward-ийн `b.offset-offset` дахин давж, дараагийн 4 KiB хэсгээс уншиж болно — шалгаж
			// чадахгүй байрлал, хууль ёсны баримтад гардаггүй (fail-closed).
			return pairs, ErrStructure
		}
		if at >= int64(len(data)) || at == info.first && firstDone {
			continue
		}
		firstDone = firstDone || at == info.first
		if s.budget < 0 {
			return pairs, ErrStructure
		}
		if err := s.object(data, int(at), false); err != nil {
			return pairs, err
		}
	}
	if s.budget < 0 {
		return pairs, ErrStructure
	}
	return pairs, nil
}
