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
// боловч бид давтаагүй ObjStm (/DecodeParms) бол ErrStructure (fail-closed). Шифрлэгдсэн баримтын ObjStm-ийг
// (ciphertext) алгасна — Extract/precheck нь шифрлэгдсэн баримтыг объект resolve хийхээс өмнө татгалздаг.
//
// Энэ нь хамгаалалтын нэг давхарга — итгэлгүй PDF задлалыг бүхэлд нь аюулгүй болгохгүй (README «Итгэлгүй PDF»).
func CheckStructure(doc []byte) error {
	s := &nestScan{budget: nestScanFactor*len(doc) + 1<<20, inflateLeft: maxObjStmBytes, encrypted: encryptRef.Match(doc)}
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
			if err := s.object(doc, at, true); err != nil {
				return err
			}
		}
	}
	if s.bigSize {
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
)

// ErrStructure — PDF-ийн бүтэц хэт гүн давхарласан эсвэл хэт төвөгтэй (CheckStructure).
var ErrStructure = errors.New("PDF-ийн бүтэц хэт гүн давхарласан эсвэл хэт төвөгтэй")

type nestScan struct {
	budget      int
	inflateLeft int
	encrypted   bool
	bigSize     bool // дээд түвшний /Size > maxXrefSize
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
}

// object — b[start:]-ээс digitorus readObject-ийн нэг объектыг (давхар `N G obj`-ийг оруулаад) гүнээр шалгана;
// allowStream бол дээд түвшний /Type /ObjStm толийн араас ирэх stream-ийг задалж шалгана.
func (s *nestScan) object(b []byte, start int, allowStream bool) error {
	l := &nestLex{b: b, pos: start}
	defer func() { s.budget -= l.pos - start }()
	var stack []nestFrame
	var info objStmInfo
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
					if allowStream && (info.typ == "ObjStm" || info.indirect) {
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
			}
		case "DecodeParms":
			if !(tok == tWord && val == "null") {
				info.parms = true
			}
		case "N":
			info.nCount, _ = strconv.ParseInt(val, 10, 64)
		case "Size":
			if n, err := strconv.ParseInt(val, 10, 64); tok == tWord && err == nil && n > maxXrefSize {
				s.bigSize = true
			}
		case "First":
			info.first, _ = strconv.ParseInt(val, 10, 64)
		}
	case len(stack) == 2 && stack[0].dict && stack[0].key == "Filter" && !stack[1].dict && tok == tName:
		info.filter = val
		info.filters++
	}
}

// objStm — `stream` түлхүүр үгийн араас FlateDecode өгөгдлийг (Length-ээс үл хамааран zlib өөрөө төгсөнө) задалж,
// толгойн offset бүрээс объектыг шалгана.
func (s *nestScan) objStm(b []byte, l *nestLex, info objStmInfo) error {
	if l.next() != tWord || l.val != "stream" || s.encrypted {
		return nil
	}
	if info.indirect {
		return ErrStructure // stream-ийн /Type /Filter /N /First лавлагаагаар — хууль ёсны баримтад гардаггүй
	}
	if info.typ != "ObjStm" {
		return nil
	}
	p := l.pos
	if p < len(b) && b[p] == '\r' {
		p++
	}
	if p < len(b) && b[p] == '\n' {
		p++
	}
	switch {
	case info.filters == 0:
		return s.objStmData(b[p:], info) // шахаагүй ObjStm — өгөгдөл нь файлын үлдсэн хэсэг (дээд хязгаар)
	case info.filters != 1 || info.filter != "FlateDecode":
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
	return s.objStmData(data, info)
}

func (s *nestScan) objStmData(data []byte, info objStmInfo) error {
	l := &nestLex{b: data}
	for i := int64(0); i < info.nCount; i++ {
		if l.next() == tEOF {
			break
		}
		if l.next() != tWord {
			continue
		}
		off, err := strconv.ParseInt(l.val, 10, 64)
		if err != nil || info.first < 0 || off < 0 || info.first+off >= int64(len(data)) {
			continue
		}
		if s.budget < 0 {
			return ErrStructure
		}
		if err := s.object(data, int(info.first+off), false); err != nil {
			return err
		}
	}
	if s.budget < 0 {
		return ErrStructure
	}
	return nil
}
