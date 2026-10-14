package core

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"

	"github.com/digitorus/pdf"
	pdfcpuapi "github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
)

// maxPageObjects — нэмэх хуудсаас хүрэх объектын дээд тоо (манай fpdf хуудас ~15).
const maxPageObjects = 256

// AppendPage — base-ийн ард pagePDF-ийн (манай fpdf-ийн нэг хуудастай гаралт) эхний хуудсыг INCREMENTAL
// UPDATE-аар нэмнэ: base-ийн байт яг prefix хэвээр, шинэ объектууд (хуудас, content, font, зураг, annotation)
// + /Pages-ийн үндэс зангилааны шинэ хувилбар (ижил дугаар, /Kids-ийн төгсгөлд шинэ хуудас, /Count + 1).
// Catalog өөрчлөгдөхгүй. Annotation бүр шууд бус объект (ISO 32000-1 Table 30: /Annots-ийн мөрүүд нь
// indirect reference). Хуучнаар pdfcpu merge нь баримтыг БҮТЭН дахин бичиж хэрэглэгчийн «заалтгүй»
// объектуудыг хаядаг байсан (сул заалт → Adobe «Document has been altered»).
func AppendPage(base, pagePDF []byte) (out []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, fmt.Errorf("%w: %v", ErrPDF, r)
		}
	}()
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

	ctx, err := pdfcpuapi.ReadContext(bytes.NewReader(pagePDF), pageConfig())
	if err != nil {
		return nil, fmt.Errorf("хуудас задлах: %w", err)
	}
	if err := ctx.EnsurePageCount(); err != nil {
		return nil, fmt.Errorf("хуудас задлах: %w", err)
	}
	pd, _, _, err := ctx.PageDict(1, false)
	if err != nil || pd == nil {
		return nil, fmt.Errorf("хуудас задлах: %v", err)
	}
	cp := &pageCopier{ctx: ctx, src: pagePDF, inc: inc, ids: map[int]uint32{}}
	pageID := inc.reserve()

	// ── хуудасны толь: /Parent → base-ийн /Pages; өвлөгдөх түлхүүрүүд fpdf-ийн /Pages-аас шууд (base-ийн
	// /Pages-ийн /Rotate /CropBox …-ийг өвлөхгүй) ──
	page := types.Dict{}
	for k, v := range pd {
		if k != "Parent" && k != "Annots" {
			page[k] = v
		}
	}
	parent, _ := ctx.DereferenceDict(pd["Parent"])
	for _, k := range []string{"MediaBox", "Resources", "CropBox", "Rotate"} {
		if _, ok := page[k]; !ok && parent != nil {
			if v, ok := parent[k]; ok {
				page[k] = v
			}
		}
	}
	if _, ok := page["Rotate"]; !ok {
		page["Rotate"] = types.Integer(0)
	}
	if _, ok := page["MediaBox"]; !ok {
		return nil, errors.New("pades: нэмэх хуудсанд /MediaBox алга")
	}
	if _, ok := page["CropBox"]; !ok {
		page["CropBox"] = page["MediaBox"]
	}
	var annots []uint32
	if a, err := ctx.DereferenceArray(pd["Annots"]); err == nil {
		for _, e := range a {
			switch v := e.(type) {
			case types.IndirectRef:
				annots = append(annots, cp.ref(int(v.ObjectNumber)))
			case types.Dict: // fpdf link annotation-ийг шууд бичдэг → шинэ объект
				id := inc.reserve()
				cp.direct = append(cp.direct, directObj{id: id, d: v})
				annots = append(annots, id)
			default:
				return nil, errors.New("pades: /Annots-ийн мөр толь биш")
			}
		}
	}
	var body bytes.Buffer
	if err := cp.write(&body, page, 0); err != nil {
		return nil, err
	}
	// "<< ... >>" → төгсгөлд /Parent /Annots нэмнэ.
	b := bytes.TrimSuffix(bytes.TrimSpace(body.Bytes()), []byte(">>"))
	body.Reset()
	body.Write(b)
	fmt.Fprintf(&body, " /Parent %d %d R", pp.GetID(), pp.GetGen())
	if len(annots) > 0 {
		body.WriteString(" /Annots [")
		for i, id := range annots {
			if i > 0 {
				body.WriteByte(' ')
			}
			body.WriteString(itoa(id) + " 0 R")
		}
		body.WriteString("]")
	}
	body.WriteString(" >>")
	inc.writeObject(pageID, body.Bytes())
	for _, d := range cp.direct {
		var ab bytes.Buffer
		if err := cp.write(&ab, d.d, 0); err != nil {
			return nil, err
		}
		inc.writeObject(d.id, ab.Bytes())
	}
	if err := cp.drain(); err != nil {
		return nil, err
	}

	// ── /Pages үндэс: ижил дугаар, бусад түлхүүр хэвээр ──
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
	for i := range kids.Len() {
		if err := serialize(&pn, kids.Index(i), kp.GetID(), 0); err != nil {
			return nil, fmt.Errorf("/Pages /Kids: %w", err)
		}
		pn.WriteByte(' ')
	}
	fmt.Fprintf(&pn, "%d 0 R] /Count %d >>", pageID, count+1)
	inc.writeObjectGen(pp.GetID(), uint16(pp.GetGen()), pn.Bytes())

	rp := root.GetPtr()
	if rp.GetGen() != 0 {
		return nil, fmt.Errorf("%w: Catalog-ийн үе 0 биш", ErrPDF)
	}
	return inc.finish(rp.GetID())
}

type directObj struct {
	id uint32
	d  types.Dict
}

// pageCopier — pdfcpu-ийн задалсан хуудасны объектуудыг шинэ дугаартайгаар base-ийн incremental-д хуулна.
type pageCopier struct {
	ctx    *model.Context
	src    []byte
	inc    *incremental
	ids    map[int]uint32 // эх дугаар → шинэ дугаар
	queue  []int
	direct []directObj
}

func (c *pageCopier) ref(n int) uint32 {
	if id, ok := c.ids[n]; ok {
		return id
	}
	id := c.inc.reserve()
	c.ids[n] = id
	c.queue = append(c.queue, n)
	return id
}

// drain — заагдсан объект бүрийг (шинэ дугаараар) бичнэ.
func (c *pageCopier) drain() error {
	for len(c.queue) > 0 {
		if len(c.ids) > maxPageObjects {
			return errors.New("pades: нэмэх хуудас хэт олон объекттой")
		}
		n := c.queue[0]
		c.queue = c.queue[1:]
		o, err := c.ctx.Dereference(types.IndirectRef{ObjectNumber: types.Integer(n)})
		if err != nil {
			return fmt.Errorf("хуудасны объект %d: %w", n, err)
		}
		var b bytes.Buffer
		if sd, ok := o.(types.StreamDict); ok {
			if sd.StreamLength == nil || sd.StreamOffset <= 0 || sd.StreamOffset+*sd.StreamLength > int64(len(c.src)) {
				return fmt.Errorf("хуудасны stream %d", n)
			}
			raw := c.src[sd.StreamOffset : sd.StreamOffset+*sd.StreamLength] // кодчилсон хэвээр
			d := types.Dict{}
			for k, v := range sd.Dict {
				d[k] = v
			}
			d["Length"] = types.Integer(len(raw))
			if err := c.write(&b, d, 0); err != nil {
				return err
			}
			b.WriteString("\nstream\n")
			b.Write(raw)
			b.WriteString("\nendstream")
		} else if err := c.write(&b, o, 0); err != nil {
			return err
		}
		c.inc.writeObject(c.ids[n], b.Bytes())
	}
	return nil
}

// write — pdfcpu объектыг PDF синтаксаар (заалтыг шинэ дугаараар) бичнэ.
func (c *pageCopier) write(w io.Writer, o types.Object, depth int) error {
	if depth > maxSerializeDepth {
		return errDepth
	}
	var err error
	switch v := o.(type) {
	case nil:
		_, err = io.WriteString(w, "null")
	case types.IndirectRef:
		_, err = fmt.Fprintf(w, "%d 0 R", c.ref(int(v.ObjectNumber)))
	case types.Dict:
		if _, err = io.WriteString(w, "<<"); err != nil {
			return err
		}
		for _, k := range slices.Sorted(maps.Keys(v)) {
			if _, err = io.WriteString(w, " /"+escapeName(k)+" "); err != nil {
				return err
			}
			if err = c.write(w, v[k], depth+1); err != nil {
				return err
			}
		}
		_, err = io.WriteString(w, " >>")
	case types.Array:
		if _, err = io.WriteString(w, "["); err != nil {
			return err
		}
		for i, e := range v {
			if i > 0 {
				if _, err = io.WriteString(w, " "); err != nil {
					return err
				}
			}
			if err = c.write(w, e, depth+1); err != nil {
				return err
			}
		}
		_, err = io.WriteString(w, "]")
	case types.Name:
		_, err = io.WriteString(w, "/"+escapeName(string(v)))
	case types.Integer:
		_, err = io.WriteString(w, strconv.Itoa(int(v)))
	case types.Float:
		_, err = io.WriteString(w, strconv.FormatFloat(float64(v), 'f', -1, 64))
	case types.Boolean:
		_, err = io.WriteString(w, strconv.FormatBool(bool(v)))
	case types.StringLiteral:
		raw, derr := types.Unescape(v.Value())
		if derr != nil {
			return derr
		}
		_, err = io.WriteString(w, hexString(string(raw)))
	case types.HexLiteral:
		_, err = io.WriteString(w, "<"+string(v)+">")
	default:
		return fmt.Errorf("pades: хуудасны объектын төрөл %T дэмжигдэхгүй", o)
	}
	return err
}

// pageConfig — pdfcpu-ийн анхдагч тохиргоо (model.newDefaultConfiguration, config.yml-тэй ижил утга) файлын системгүйгээр.
// SDK: model.NewDefaultConfiguration() нь хэрэглэгчийн config хавтсанд config.yml үүсгэдэг (mkdir) — js/WASM ба
// мобайл sandbox-д ажиллахгүй, мөн глобал model.ConfigPath-ийг өөрчлөхгүйн тулд энд шууд угсарна. Энэ кодод pdfcpu
// зөвхөн манай fpdf хуудсыг уншина (relaxed validation).
func pageConfig() *model.Configuration {
	return &model.Configuration{
		Version:                         model.VersionStr,
		CheckFileNameExt:                true,
		Reader15:                        true,
		DecodeAllStreams:                false,
		ValidationMode:                  model.ValidationRelaxed,
		ValidateLinks:                   false,
		Eol:                             types.EolLF,
		WriteObjectStream:               true,
		WriteXRefStream:                 true,
		EncryptUsingAES:                 true,
		EncryptKeyLength:                256,
		Permissions:                     model.PermissionsPrint,
		TimestampFormat:                 "2006-01-02 15:04",
		DateFormat:                      "2006-01-02",
		Optimize:                        true,
		OptimizeBeforeWriting:           true,
		OptimizeResourceDicts:           true,
		OptimizeDuplicateContentStreams: false,
		CreateBookmarks:                 true,
		NeedAppearances:                 false,
		Offline:                         true,
		Timeout:                         5,
		PreferredCertRevocationChecker:  model.CRL,
		FormFieldListMaxColWidth:        0,
	}
}
