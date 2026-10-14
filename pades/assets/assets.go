// Package assets — verify хуудасны тогтмол asset (PAGE_SPEC.md): Noto Sans Regular/Bold-ийн урьдчилан subset хийсэн
// TrueType программ, zlib-ээр НЭГ УДАА шахсан байт (fonts/*.ttf.zlib). Native SDK бүр ЯГ ЭДГЭЭР байтыг FontFile2
// stream-д (/Filter /FlateDecode) бичнэ — runtime-д шахалт хийхгүй. Метрик (cmap, advance) нь fonts/*.metrics.json
// (TestMetricsJSON-оор TTF-ээс үүсгэж тулгана).
//
// Font: Noto Sans (The Noto Project Authors), SIL OFL 1.1 (fonts/OFL.txt). Subset: U+0020–007E, U+00A0–00FF,
// U+0400–04FF, U+2010–2027, U+2030–203A, U+20AE, U+2116 (ca-eidmongolia-mn pdfsign/fonts, 2026-10-07).
package assets

import (
	"bytes"
	"compress/zlib"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

var (
	//go:embed fonts/NotoSans-Regular.ttf.zlib
	regularZ []byte
	//go:embed fonts/NotoSans-Bold.ttf.zlib
	boldZ []byte
)

// Font — нэг фонтын PDF-д хэрэгтэй бүх зүйл.
type Font struct {
	PSName     string // /BaseFont, /FontName
	Stream     []byte // FontFile2 stream-ийн агуулга (zlib), тогтмол
	Length1    int    // задалсан TTF-ийн урт (/Length1)
	UnitsPerEm int
	Ascent     int // hhea.ascender
	Descent    int // hhea.descender (сөрөг)
	CapHeight  int // OS/2.sCapHeight
	BBox       [4]int
	GID        map[rune]uint16 // Unicode → glyph ID (cmap)
	Advance    []uint16        // glyph ID → advanceWidth (font units)
}

// Width1000 — glyph-ийн өргөн 1/1000 em-ээр: round(advance × 1000 / unitsPerEm), .5 дээш (бүхэл арифметик).
func (f *Font) Width1000(gid uint16) int {
	a := int(f.Advance[min(int(gid), len(f.Advance)-1)])
	return (a*1000*2 + f.UnitsPerEm) / (2 * f.UnitsPerEm)
}

var (
	once          sync.Once
	regular, bold *Font
	loadErr       error
)

func load() {
	if regular, loadErr = parse("NotoSans", regularZ); loadErr != nil {
		return
	}
	bold, loadErr = parse("NotoSans-Bold", boldZ)
}

// Regular / Bold — задалсан фонт (нэг удаа).
func Regular() (*Font, error) { once.Do(load); return regular, loadErr }

// Bold — дээрхийг үз.
func Bold() (*Font, error) { once.Do(load); return bold, loadErr }

func parse(name string, z []byte) (*Font, error) {
	zr, err := zlib.NewReader(bytes.NewReader(z))
	if err != nil {
		return nil, err
	}
	ttf, err := io.ReadAll(zr)
	if err != nil {
		return nil, err
	}
	tables := map[string][]byte{}
	if len(ttf) < 12 {
		return nil, errors.New("assets: TTF богино")
	}
	n := int(binary.BigEndian.Uint16(ttf[4:]))
	for i := range n {
		rec := ttf[12+16*i:]
		off, ln := binary.BigEndian.Uint32(rec[8:]), binary.BigEndian.Uint32(rec[12:])
		if uint64(off)+uint64(ln) > uint64(len(ttf)) {
			return nil, errors.New("assets: TTF хүснэгт хэтэрсэн")
		}
		tables[string(rec[:4])] = ttf[off : off+ln]
	}
	for _, t := range []string{"head", "hhea", "hmtx", "cmap", "OS/2", "maxp"} {
		if tables[t] == nil {
			return nil, fmt.Errorf("assets: %s хүснэгт алга", t)
		}
	}
	u16 := func(b []byte, o int) int { return int(binary.BigEndian.Uint16(b[o:])) }
	i16 := func(b []byte, o int) int { return int(int16(binary.BigEndian.Uint16(b[o:]))) }
	head, hhea, os2 := tables["head"], tables["hhea"], tables["OS/2"]
	f := &Font{PSName: name, Stream: z, Length1: len(ttf), UnitsPerEm: u16(head, 18),
		BBox:   [4]int{i16(head, 36), i16(head, 38), i16(head, 40), i16(head, 42)},
		Ascent: i16(hhea, 4), Descent: i16(hhea, 6), CapHeight: i16(os2, 88), GID: map[rune]uint16{}}
	numGlyphs, numH := u16(tables["maxp"], 4), u16(hhea, 34)
	hmtx := tables["hmtx"]
	f.Advance = make([]uint16, numGlyphs)
	for g := range numGlyphs {
		f.Advance[g] = uint16(u16(hmtx, 4*min(g, numH-1)))
	}
	cmap := tables["cmap"]
	var sub []byte
	for i := range u16(cmap, 2) {
		pid, eid, off := u16(cmap, 4+8*i), u16(cmap, 6+8*i), int(binary.BigEndian.Uint32(cmap[8+8*i:]))
		if pid == 3 && (eid == 1 || eid == 10) && (sub == nil || u16(cmap[off:], 0) == 12) {
			sub = cmap[off:]
		}
	}
	if sub == nil {
		return nil, errors.New("assets: Unicode cmap алга")
	}
	switch u16(sub, 0) {
	case 4:
		segX2 := u16(sub, 6)
		ends, starts, deltas, ranges := 14, 16+segX2, 16+2*segX2, 16+3*segX2
		for s := 0; s < segX2/2; s++ {
			end, start := u16(sub, ends+2*s), u16(sub, starts+2*s)
			delta, ro := u16(sub, deltas+2*s), u16(sub, ranges+2*s)
			for c := start; c <= end && c != 0xFFFF; c++ {
				var g int
				if ro == 0 {
					g = (c + delta) & 0xFFFF
				} else {
					idx := ranges + 2*s + ro + 2*(c-start)
					if g = u16(sub, idx); g != 0 {
						g = (g + delta) & 0xFFFF
					}
				}
				if g != 0 {
					f.GID[rune(c)] = uint16(g)
				}
			}
		}
	case 12:
		ng := int(binary.BigEndian.Uint32(sub[12:]))
		for i := range ng {
			grp := sub[16+12*i:]
			s, e, g := binary.BigEndian.Uint32(grp), binary.BigEndian.Uint32(grp[4:]), binary.BigEndian.Uint32(grp[8:])
			for c := s; c <= e; c++ {
				f.GID[rune(c)] = uint16(g + c - s)
			}
		}
	default:
		return nil, fmt.Errorf("assets: cmap формат %d", u16(sub, 0))
	}
	return f, nil
}
