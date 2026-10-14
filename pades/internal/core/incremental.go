// Package pades — иргэний өөрийн CMS-тэй PAdES baseline B-LT гарын үсгийг PDF-д incremental update-аар
// бичнэ (docs/PADES_SIGNING.md §4). Хоёр үе шат: Prepare (гарын үсгийн revision + тогтмол placeholder,
// signedAttrs → DTBS) → Finalize (CMS-ийг placeholder-т бичнэ) → AppendDSS (LTV өгөгдлийн revision).
//
// xref table / stream бичигч, Catalog хуулах логик нь github.com/digitorus/pdfsign/sign-ийн fork
// (BSD-2, LICENSE.digitorus) — манай validator-ийн нарийн profile (internal/validate/revisions.go) тэр
// хэлбэр дээр бичигдсэн тул хэлбэрийг хадгалсан. Ялгаа: SubFilter ETSI.CAdES.detached, /Name /Reason
// /Location /Prop_Build бичихгүй, signingTime attr үгүй, гарын үсгийг 2 үе шатаар (DTBS-ийг гаднаас —
// иргэний утас зурна), DSS revision, placeholder-ийн байрлалыг бичих үедээ мэднэ (тэг цуваа хайхгүй),
// AcroForm-ийн бусад бүх талбар/түлхүүрийг хадгална.
package core

import (
	"bytes"
	"cmp"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/digitorus/pdf"
)

// ErrPDF — оролтын PDF задарсангүй / дэмжигдээгүй бүтэцтэй (шифрлэгдсэн г.м.).
var ErrPDF = errors.New("pades: PDF задарсангүй эсвэл дэмжигдэхгүй бүтэцтэй")

type xrefEntry struct {
	id     uint32
	gen    uint16
	offset int64
}

// incremental — нэг incremental update (revision) бичигч. base-ийн байт хэзээ ч өөрчлөгдөхгүй: гаралт =
// base + "\n" + шинэ объектууд + xref + trailer.
type incremental struct {
	rdr     *pdf.Reader
	base    []byte
	out     bytes.Buffer
	nextID  uint32
	entries []xrefEntry
	stream  bool // base-ийн сүүлийн xref нь stream
}

// openIncremental — base-ийг задалж бичигч бэлдэнэ. digitorus/pdf хорлонтой оролтод panic хийдэг тул
// recover. AppendPage нь хэрэглэгчийн гарын үсэггүй оролтыг шууд өгнө (HasSignatureObjects-ийн адил задлагч);
// бусад дуудагч манай гаралт эсвэл нийтийн шалгагчаар (тусгаарлагдсан задлагч) шалгагдсан баримтыг өгнө.
func openIncremental(base []byte) (inc *incremental, err error) {
	defer func() {
		if r := recover(); r != nil {
			inc, err = nil, fmt.Errorf("%w: %v", ErrPDF, r)
		}
	}()
	rdr, err := pdf.NewReader(bytes.NewReader(base), int64(len(base)))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPDF, err)
	}
	if !rdr.Trailer().Key("Encrypt").IsNull() {
		return nil, fmt.Errorf("%w: шифрлэгдсэн PDF", ErrPDF)
	}
	if rdr.Trailer().Key("Root").Kind() != pdf.Dict {
		return nil, fmt.Errorf("%w: Catalog алга", ErrPDF)
	}
	inc = &incremental{rdr: rdr, base: base}
	switch rdr.XrefInformation.Type {
	case "table":
	case "stream":
		inc.stream = true
	default:
		return nil, fmt.Errorf("%w: xref төрөл %q", ErrPDF, rdr.XrefInformation.Type)
	}
	// Шинэ объектын дугаар: /Size болон ашиглагдсан хамгийн их дугаараас дээш (digitorus-ийн
	// getLastObjectIDFromXref-тэй адил хамгийн их дугаар + 1-ээс эхэлж болох ч /Size-аас доош бол
	// өмнөх revision-ийн бүртгэлгүй xref stream объекттой дугаар давхцахаас сэргийлнэ).
	maxID := uint32(0)
	for _, x := range rdr.Xref() {
		p := x.Ptr()
		if id := p.GetID(); id > maxID {
			maxID = id
		}
	}
	size := rdr.Trailer().Key("Size").Int64()
	if size <= 0 || size > 1<<23 {
		return nil, fmt.Errorf("%w: /Size буруу", ErrPDF)
	}
	// #nosec G115 -- дээрх шалгалтаар 0 < size ≤ 2^23
	inc.nextID = max(uint32(size), maxID+1)
	inc.out.Grow(len(base) + 64<<10)
	inc.out.Write(base)
	// File always needs an empty line after %%EOF (digitorus).
	inc.out.WriteByte('\n')
	return inc, nil
}

// reserve — дараагийн объектын дугаарыг захиална (бичихээс өмнө заалт хэрэгтэй үед).
func (inc *incremental) reserve() uint32 {
	id := inc.nextID
	inc.nextID++
	return id
}

// writeObject — id дугаартай шинэ объектыг бичиж xref-д бүртгэнэ; body-ийн эхлэх байрлалыг буцаана.
func (inc *incremental) writeObject(id uint32, body []byte) int64 {
	return inc.writeObjectGen(id, 0, body)
}

// writeObjectGen — base-ийн объектын шинэ хувилбар (ижил дугаар, үе) эсвэл шинэ объект.
func (inc *incremental) writeObjectGen(id uint32, gen uint16, body []byte) int64 {
	inc.out.WriteByte('\n')
	inc.entries = append(inc.entries, xrefEntry{id: id, gen: gen, offset: int64(inc.out.Len())})
	fmt.Fprintf(&inc.out, "%d %d obj\n", id, gen)
	start := int64(inc.out.Len())
	inc.out.Write(bytes.TrimSpace(body))
	inc.out.WriteString("\nendobj\n")
	return start
}

// addObject — шинэ дугаар авч бичнэ.
func (inc *incremental) addObject(body []byte) (uint32, int64) {
	id := inc.reserve()
	return id, inc.writeObject(id, body)
}

// finish — xref (base-тэй ижил төрөл) + trailer бичиж гаралтыг буцаана. root — шинэ Catalog.
func (inc *incremental) finish(root uint32) ([]byte, error) {
	if len(inc.entries) == 0 {
		return nil, errors.New("pades: шинэ объект алга")
	}
	inc.out.WriteByte('\n')
	xrefStart := int64(inc.out.Len())
	// Xref stream объект өөрийгөө Index-д бүртгэнэ (ISO 32000-1 §7.5.8.3; qpdf «xref entry for the xref stream
	// itself is missing»). Хамгийн их дугаар тул эрэмбэлсний дараа ч сүүлд орно.
	xid := uint32(0)
	if inc.stream {
		xid = inc.reserve()
		inc.entries = append(inc.entries, xrefEntry{id: xid, offset: xrefStart})
	}
	// Дугаараар эрэмбэлж дараалсан хэсгүүдэд (subsection) хуваана; нэг дугаар хоёр удаа бичигдэхгүй.
	slices.SortFunc(inc.entries, func(a, b xrefEntry) int { return cmp.Compare(a.id, b.id) })
	var runs [][2]int // [эхлэх индекс, тоо]
	for i, e := range inc.entries {
		if i > 0 && e.id == inc.entries[i-1].id {
			return nil, errors.New("pades: объектын дугаар давхардсан")
		}
		if i > 0 && e.id == inc.entries[i-1].id+1 {
			runs[len(runs)-1][1]++
			continue
		}
		runs = append(runs, [2]int{i, 1})
	}
	prev := inc.rdr.XrefInformation.StartPos
	tr := inc.rdr.Trailer()
	var trailerExtra bytes.Buffer
	if info := tr.Key("Info"); !info.IsNull() {
		p, tp := info.GetPtr(), tr.GetPtr()
		if p == tp { // шууд (direct) /Info — CA-ийн бичигч хаядаг байв; профайл pades-client/1 (P3) хуулна
			trailerExtra.WriteString(" /Info ")
			if err := serialize(&trailerExtra, info, tp.GetID(), 0); err != nil {
				return nil, fmt.Errorf("trailer /Info: %w", err)
			}
		} else {
			fmt.Fprintf(&trailerExtra, " /Info %d %d R", p.GetID(), p.GetGen())
		}
	}
	if id := tr.Key("ID"); id.Kind() == pdf.Array && id.Len() == 2 {
		fmt.Fprintf(&trailerExtra, " /ID [%s %s]", hexString(id.Index(0).RawString()), hexString(id.Index(1).RawString()))
	}
	if !inc.stream {
		// Classic xref: мөр бүр яг 20 байт (validator шалгадаг).
		inc.out.WriteString("xref\n")
		for _, r := range runs {
			fmt.Fprintf(&inc.out, "%d %d\n", inc.entries[r[0]].id, r[1])
			for _, e := range inc.entries[r[0] : r[0]+r[1]] {
				fmt.Fprintf(&inc.out, "%010d %05d n\r\n", e.offset, e.gen)
			}
		}
		fmt.Fprintf(&inc.out, "trailer\n<< /Size %d /Root %d 0 R%s /Prev %d >>\nstartxref\n%d\n%%%%EOF\n",
			inc.nextID, root, trailerExtra.String(), prev, xrefStart)
		return inc.out.Bytes(), nil
	}
	// Xref stream: мөр бүр (өөрийнх нь мөрийг оруулаад) [1 4 1]; /Size = xid + 1.
	var rows bytes.Buffer
	for _, e := range inc.entries {
		if e.offset > int64(^uint32(0)) {
			return nil, errors.New("pades: offset 4 байтад багтахгүй")
		}
		rows.WriteByte(1)
		var off [4]byte
		// #nosec G115 -- дээр шалгасан
		binary.BigEndian.PutUint32(off[:], uint32(e.offset))
		rows.Write(off[:])
		if e.gen > 0xff {
			return nil, errors.New("pades: үеийн дугаар 1 байтад багтахгүй")
		}
		rows.WriteByte(byte(e.gen))
	}
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	if _, err := zw.Write(rows.Bytes()); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	var index strings.Builder
	for i, r := range runs {
		if i > 0 {
			index.WriteByte(' ')
		}
		fmt.Fprintf(&index, "%d %d", inc.entries[r[0]].id, r[1])
	}
	// Объектыг шууд бичнэ (мөрийг нь дээр бүртгэсэн) — эхлэл нь xrefStart.
	fmt.Fprintf(&inc.out, "%d 0 obj\n<< /Type /XRef /Length %d /Filter /FlateDecode /W [1 4 1] /Prev %d /Size %d /Index [%s] /Root %d 0 R%s >>\nstream\n",
		xid, z.Len(), prev, inc.nextID, index.String(), root, trailerExtra.String())
	inc.out.Write(z.Bytes())
	fmt.Fprintf(&inc.out, "\nendstream\nendobj\nstartxref\n%d\n%%%%EOF\n", xrefStart)
	return inc.out.Bytes(), nil
}

// rootPtr — base-ийн Catalog-ийн заагч.
func (inc *incremental) root() pdf.Value { return inc.rdr.Trailer().Key("Root") }

// catalogCopy — Catalog-ийн skip-ээс бусад түлхүүрийг "/Key value\n" хэлбэрээр (digitorus createCatalog).
func (inc *incremental) catalogCopy(w io.Writer, skip ...string) error {
	root := inc.root()
	rp := root.GetPtr()
	for _, key := range root.Keys() {
		if key == "Type" || contains(skip, key) {
			continue
		}
		fmt.Fprintf(w, "  /%s ", escapeName(key))
		if err := serialize(w, root.Key(key), rp.GetID(), 0); err != nil {
			return fmt.Errorf("Catalog /%s: %w", key, err)
		}
		_, _ = io.WriteString(w, "\n")
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// itoa — uint32 → string.
func itoa(n uint32) string { return strconv.FormatUint(uint64(n), 10) }
