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
	ids, err := c.apIDs(nr)
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
	p := core.AppearanceParams{W: w, H: h, Rotate: rot, Name: pdfTextString(ns), Role: meta.role, Date: date, URL: url}
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

// apIDs — /AP /N-ээс 11 объектын дугаар (core.AppearanceObjects-ийн дарааллаар); бүгд шинэ, үе 0, давхардалгүй.
func (c *classifier) apIDs(n pdfRef) ([11]uint32, error) {
	var ids [11]uint32
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
		return ids, err
	}
	res, _ := form["Resources"].(pdfDict)
	fonts, _ := res["Font"].(pdfDict)
	for _, key := range []string{"F1", "F2"} {
		t0, ok := fonts[key].(pdfRef)
		if !ok {
			return ids, fail
		}
		td, err := get(t0)
		if err != nil {
			return ids, err
		}
		desc, _ := td["DescendantFonts"].(pdfArr)
		tu, ok1 := td["ToUnicode"].(pdfRef)
		if len(desc) != 1 || !ok1 {
			return ids, fail
		}
		cid, ok := desc[0].(pdfRef)
		if !ok {
			return ids, fail
		}
		cd, err := get(cid)
		if err != nil {
			return ids, err
		}
		fd, ok := cd["FontDescriptor"].(pdfRef)
		if !ok {
			return ids, fail
		}
		fdd, err := get(fd)
		if err != nil {
			return ids, err
		}
		ff, ok := fdd["FontFile2"].(pdfRef)
		if !ok {
			return ids, fail
		}
		refs = append(refs, t0, cid, fd, ff, tu)
	}
	seen := map[int]bool{}
	for i, r := range refs {
		if r.gen != 0 || !c.isNew[r.num] || seen[r.num] {
			return ids, fail
		}
		seen[r.num] = true
		ids[i] = uint32(r.num) // #nosec G115 -- дугаар < 2^23
	}
	return ids, nil
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
