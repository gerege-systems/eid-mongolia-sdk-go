package validate

import (
	"bytes"
	"fmt"
	"math"
	"regexp"
	"strconv"

	"github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/core"
)

// Харагдах гарын үсгийн own-signer хэлбэр (pades/APPEARANCE_SPEC.md §5 Validator). PAdES бичигчийн харагдах widget,
// /AP /N form XObject ба түүний 2 фонтыг (11 объект) гарын үсгийн өөрийн өгөгдлөөс (/Name, /M, claimedRole, revIndex,
// docID) core.AppearanceObjects-оор ДАХИН ҮҮСГЭЖ, задалсан объект бүрийг бүтцээр (pdfEqual: толь + stream-ийн түүхий
// байт) тулгана. Нэг ч байт (content stream, фонт, нөөцийн толь, /Matrix …) зөрвөл татгалзана.

// sigMeta — Extract-ийн шалгасан гарын үсгийн харагдах дүрслэлд хэрэгтэй өгөгдөл (объектын дугаараар).
type sigMeta struct {
	revIndex int    // ByteRange-ийн төгсгөлөөр эрэмбэлсэн дараалал (1-ээс) — PRECHECKS #6-ийн revIndex
	role     string // signer-attributes-v2-ийн ганц claimedRole ("" — байхгүй)
	roleOK   bool   // claimedRole 0 эсвэл яг 1 (хүчинтэй) — эс бөгөөс харагдах дүрслэл үүсгэх боломжгүй
}

const apVerifyPrefix = "https://ca.eidmongolia.mn/verify/"

var apURLRe = regexp.MustCompile(`^/EIDVerify <</URL \(https://ca\.eidmongolia\.mn/verify/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/([1-9][0-9]?)\)>> BDC\n`)

// ownVisible — own горимын харагдах widget d (объект widget): widget ба /AP-ийн 11 объект яг PAdES бичигчийнх.
func (c *classifier) ownVisible(d pdfDict, widget int) error {
	fail := errNotSignatureOnly
	if !onlyKeys(d, "Type", "Subtype", "Rect", "P", "F", "FT", "T", "V", "AP") {
		return fail
	}
	pr, ok1 := d["P"].(pdfRef)
	sr, ok2 := d["V"].(pdfRef)
	ap, ok3 := d["AP"].(pdfDict)
	t, ok4 := d["T"].(pdfStr)
	if !ok1 || !ok2 || !ok3 || !ok4 || !onlyKeys(ap, "N") || !c.pages[pr.num] {
		return fail
	}
	nr, ok := ap["N"].(pdfRef)
	if !ok {
		return fail
	}
	// Хуудасны хайрцаг ба эргэлт (удамшсан), /Rect (h100) нь хайрцаг дотор.
	box, rot, err := c.pageGeometry(pr.num)
	if err != nil {
		return err
	}
	ra, ok := d["Rect"].(pdfArr)
	if !ok || len(ra) != 4 {
		return fail
	}
	var rect [4]int
	for i, x := range ra {
		v, ok := pdfNumber(x)
		if !ok {
			return fail
		}
		rect[i] = core.Round100(v)
	}
	if rect[0] >= rect[2] || rect[1] >= rect[3] || rect[0] < box[0] || rect[1] < box[1] || rect[2] > box[2] || rect[3] > box[3] {
		return fail
	}
	w, h := rect[2]-rect[0], rect[3]-rect[1]
	if rot == 90 || rot == 270 {
		w, h = h, w
	}
	// Widget-ийн толь яг PAdES бичигчийнх (түлхүүр, утга, /F 4, /P, /AP << /N >>).
	if err := c.sameObject(widget, core.VisibleWidget(string(t), rect, uint32(pr.num), pr.gen, uint32(sr.num), uint32(nr.num))); err != nil { // #nosec G115 -- дугаар < 2^23
		return err
	}
	// Гарын үсгийн өгөгдөл: /Name, /M (+08'00'), claimedRole, revIndex.
	so, err := c.fin.deref(sr)
	if err != nil {
		return err
	}
	sd, ok := so.(pdfDict)
	meta, known := c.sigs[sr.num]
	if !ok || !known || !meta.roleOK {
		return fail
	}
	ns, ok := sd["Name"].(pdfStr)
	ms, ok2 := sd["M"].(pdfStr)
	if !ok || !ok2 {
		return fail
	}
	m := string(ms)
	if !ownDate(m) || m[16:] != "+08'00'" {
		return fail
	}
	date := m[2:6] + "-" + m[6:8] + "-" + m[8:10] + " " + m[10:12] + ":" + m[12:14] + " (+08)"
	// Объектын дугаарууд: form → /Resources /Font /F1 /F2 → Type0 (/DescendantFonts [CID], /ToUnicode) → CID
	// (/FontDescriptor) → FontDescriptor (/FontFile2).
	ids, sig, stamp, err := c.apIDs(nr)
	if err != nil {
		return err
	}
	fo, err := c.fin.get(int(ids[0]))
	if err != nil {
		return err
	}
	form, ok := fo.(pdfStream)
	if !ok {
		return fail
	}
	sm := apURLRe.FindSubmatch(form.data)
	if sm == nil || string(sm[2]) != strconv.Itoa(meta.revIndex) || c.docID != "" && string(sm[1]) != c.docID {
		return fail
	}
	url := apVerifyPrefix + string(sm[1]) + "/" + string(sm[2])
	// Зураг (APPEARANCE_SPEC.md §6.5): PDF-ээс уншсан өнгө/хэмжээ/alpha-аар дахин үүсгэнэ — объект бүрийн толь, content
	// stream-ийн байрлал (хэмжээнээс тооцсон) байт-ижил байх ёстой; AppearanceObjects нь alpha-г CheckPDFImage-ээр шалгана.
	p := core.AppearanceParams{W: w, H: h, Rotate: rot, Name: pdfTextString(ns), Role: meta.role, Date: date, URL: url,
		Sig: sig, Stamp: stamp}
	for _, lang := range []string{"mn", "en"} {
		p.Lang = lang
		bodies, err := core.AppearanceObjects(p, ids)
		if err != nil {
			return fail
		}
		match := true
		for i, b := range bodies {
			if c.sameObject(int(ids[i]), b) != nil {
				match = false
				break
			}
		}
		if match {
			return nil
		}
	}
	return fail
}

// apIDs — /AP /N-ээс объектын дугаарууд (core.AppearanceObjects-ийн дарааллаар: form, F1 ×5, F2 ×5, дараа нь
// /Resources /XObject-ийн /Sig, /Stamp тус бүрд base, /SMask) ба зургууд (PDF-ээс уншсан; nil = байхгүй); бүгд шинэ,
// үе 0, давхардалгүй.
func (c *classifier) apIDs(n pdfRef) (ids []uint32, sig, stamp *core.PDFImage, err error) {
	fail := errNotSignatureOnly
	refs := []pdfRef{n}
	get := func(r pdfRef) (pdfDict, error) {
		o, err := c.fin.deref(r)
		if err != nil {
			return nil, err
		}
		switch x := o.(type) {
		case pdfDict:
			return x, nil
		case pdfStream:
			return x.dict, nil
		}
		return nil, fail
	}
	form, err := get(n)
	if err != nil {
		return nil, nil, nil, err
	}
	res, _ := form["Resources"].(pdfDict)
	fonts, _ := res["Font"].(pdfDict)
	for _, key := range []string{"F1", "F2"} {
		t0, ok := fonts[key].(pdfRef)
		if !ok {
			return nil, nil, nil, fail
		}
		td, err := get(t0)
		if err != nil {
			return nil, nil, nil, err
		}
		desc, _ := td["DescendantFonts"].(pdfArr)
		tu, ok1 := td["ToUnicode"].(pdfRef)
		if len(desc) != 1 || !ok1 {
			return nil, nil, nil, fail
		}
		cid, ok := desc[0].(pdfRef)
		if !ok {
			return nil, nil, nil, fail
		}
		cd, err := get(cid)
		if err != nil {
			return nil, nil, nil, err
		}
		fd, ok := cd["FontDescriptor"].(pdfRef)
		if !ok {
			return nil, nil, nil, fail
		}
		fdd, err := get(fd)
		if err != nil {
			return nil, nil, nil, err
		}
		ff, ok := fdd["FontFile2"].(pdfRef)
		if !ok {
			return nil, nil, nil, fail
		}
		refs = append(refs, t0, cid, fd, ff, tu)
	}
	// Зураг: /XObject /Sig, /Stamp → base (1×1, 3 байт өнгө) → /SMask (W×H, alpha-ийн түүхий zlib). Толины бусад
	// түлхүүр/утгыг дахин үүсгэсэн объекттой тулгаж шалгана (sameObject).
	if x, has := res["XObject"]; has {
		xo, ok := x.(pdfDict)
		if !ok {
			return nil, nil, nil, fail
		}
		for _, key := range []string{"Sig", "Stamp"} {
			v, has := xo[key]
			if !has {
				continue
			}
			br, ok := v.(pdfRef)
			if !ok {
				return nil, nil, nil, fail
			}
			im, mr, err := c.apImage(br)
			if err != nil {
				return nil, nil, nil, err
			}
			refs = append(refs, br, mr)
			if key == "Sig" {
				sig = im
			} else {
				stamp = im
			}
		}
	}
	seen := map[int]bool{}
	ids = make([]uint32, len(refs))
	for i, r := range refs {
		if r.gen != 0 || !c.isNew[r.num] || seen[r.num] {
			return nil, nil, nil, fail
		}
		seen[r.num] = true
		ids[i] = uint32(r.num) // #nosec G115 -- дугаар < 2^23
	}
	return ids, sig, stamp, nil
}

// apImage — зургийн base XObject (br) ба түүний /SMask-аас core.PDFImage: өнгө = base stream-ийн 3 байт, W/H = mask-ийн
// /Width /Height (бүхэл), Alpha = mask stream-ийн түүхий байт. Хэлбэрийн бусад шалгалт — дахин үүсгэж тулгах.
func (c *classifier) apImage(br pdfRef) (*core.PDFImage, pdfRef, error) {
	fail := errNotSignatureOnly
	bo, err := c.fin.deref(br)
	if err != nil {
		return nil, pdfRef{}, err
	}
	base, ok := bo.(pdfStream)
	if !ok || len(base.data) != 3 {
		return nil, pdfRef{}, fail
	}
	mr, ok := base.dict["SMask"].(pdfRef)
	if !ok {
		return nil, pdfRef{}, fail
	}
	mo, err := c.fin.deref(mr)
	if err != nil {
		return nil, pdfRef{}, err
	}
	mask, ok := mo.(pdfStream)
	if !ok {
		return nil, pdfRef{}, fail
	}
	w, ok1 := mask.dict["Width"].(int64)
	h, ok2 := mask.dict["Height"].(int64)
	if !ok1 || !ok2 || w < 1 || h < 1 || w > core.MaxImageSide || h > core.MaxImageSide {
		return nil, pdfRef{}, fail
	}
	return &core.PDFImage{W: int(w), H: int(h), Color: [3]int{int(base.data[0]), int(base.data[1]), int(base.data[2])},
		Alpha: mask.data}, mr, nil
}

// sameObject — num объект нь body-г (PAdES бичигчийн бие) задалсантай бүтцээрээ (толь + stream-ийн байт) тэнцүү.
func (c *classifier) sameObject(num int, body []byte) error {
	src := fmt.Appendf(nil, "%d 0 obj\n%s\nendobj\n", num, bytes.TrimSpace(body))
	p := &pdfParser{b: src, budget: c.fin.budget}
	want, err := p.indirect(nil)
	if err != nil {
		return err
	}
	got, err := c.fin.get(num)
	if err != nil {
		return err
	}
	if !pdfEqual(got, want.val) {
		return errNotSignatureOnly
	}
	return nil
}

// pageGeometry — хуудасны (/Parent-ээр удамшсан) CropBox (байхгүй бол MediaBox), h100-аар хэвийн болгосон, ба /Rotate.
func (c *classifier) pageGeometry(num int) (box [4]int, rot int, err error) {
	fail := errNotSignatureOnly
	inh := func(key string) (any, error) {
		var cur any = pdfRef{num: num}
		for range 32 {
			r, ok := cur.(pdfRef)
			if !ok {
				return nil, nil
			}
			o, err := c.fin.get(r.num)
			if err != nil {
				return nil, err
			}
			d, ok := o.(pdfDict)
			if !ok {
				return nil, fail
			}
			if v, has := d[key]; has {
				return c.fin.resolve(v)
			}
			cur = d["Parent"]
		}
		return nil, fail
	}
	b, err := inh("CropBox")
	if err != nil {
		return box, 0, err
	}
	if b == nil {
		if b, err = inh("MediaBox"); err != nil {
			return box, 0, err
		}
	}
	arr, ok := b.(pdfArr)
	if !ok || len(arr) != 4 {
		return box, 0, fail
	}
	var f [4]int
	for i, x := range arr {
		v, ok := pdfNumber(x)
		if !ok {
			return box, 0, fail
		}
		f[i] = core.Round100(v)
	}
	box = [4]int{min(f[0], f[2]), min(f[1], f[3]), max(f[0], f[2]), max(f[1], f[3])}
	r, err := inh("Rotate")
	if err != nil {
		return box, 0, err
	}
	if r != nil {
		n, ok := r.(int64)
		if !ok || n%90 != 0 {
			return box, 0, fail
		}
		rot = int((n%360 + 360) % 360)
	}
	return box, rot, nil
}

// pdfNumber — бүхэл эсвэл бодит тоо (|v| ≤ 1e7).
func pdfNumber(x any) (float64, bool) {
	var v float64
	switch n := x.(type) {
	case int64:
		v = float64(n)
	case float64:
		v = n
	default:
		return 0, false
	}
	return v, !math.IsNaN(v) && math.Abs(v) <= 1e7
}
