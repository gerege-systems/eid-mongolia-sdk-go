package validate

import (
	"bytes"
	"reflect"

	"github.com/digitorus/pdf"
)

// checkObjStmGraph — digitorus Reader.resolve нь ObjStm доторх объектыг уншихдаа агуулагч stream-ийг (мөн толгойн
// /Length /Filter /DecodeParms /N /First /Extends лавлагааг) рекурсээр resolve хийдэг, мөчлөгийн хамгаалалтгүй.
// Тиймээс ~8 KB баримт (xref stream-д объект өөрийгөө, эсвэл өөр ObjStm доторх объектыг агуулагч гэж заасан; /Length
// нь өөрийн ObjStm дотор) `fatal error: stack overflow` өгч процессыг унагана (FuzzValidatePDF олсон), /Extends
// мөчлөг — төгсгөлгүй давталт. ISO 32000-1 §7.5.7-оор stream (ObjStm өөрөө) ба ObjStm-ийн /Length-ийн утга ObjStm
// дотор байж болохгүй тул хууль ёсны баримтад эдгээр гардаггүй — fail-closed (ErrStructure):
//   - агуулагч stream нь өөрөө ObjStm доторх объект;
//   - агуулагч (ба /Extends-ээр холбогдсон) stream-ийн толгойн аль нэг лавлагаа ObjStm доторх объект руу заасан;
//   - /Extends мөчлөг эсвэл maxObjStmChain-аас урт гинж.
//
// Үүний дараа ObjStm доторх объектын resolve нь агуулагч (энгийн объект) + толгойн энгийн объектуудаар хязгаарлагдана.
// digitorus xref-ийн талбаруудыг (inStream, stream, ptr) экспортлодоггүй тул reflect-ээр (зөвхөн унших) авна —
// go.mod-д pin хийсэн хувилбарын бүтэц; талбар олдохгүй бол (хувилбар солигдсон) fail-closed.
func checkObjStmGraph(doc []byte) (err error) {
	defer func() {
		if recover() != nil {
			err = nil // digitorus энд panic хийдэг баримтыг дуудагч өөрөө PDF_INVALID болгоно
		}
	}()
	r, err := pdf.NewReader(bytes.NewReader(doc), int64(len(doc)))
	if err != nil {
		return nil
	}
	xr := reflect.ValueOf(r.Xref())
	if xr.Len() == 0 {
		return nil
	}
	if e := xr.Index(0); !e.FieldByName("inStream").IsValid() || !e.FieldByName("stream").IsValid() || !e.FieldByName("ptr").IsValid() {
		return ErrStructure
	}
	// registered(p) — xref[p.id].ptr == p (digitorus үүнээс өөр бол null буцаадаг).
	registered := func(p ref) bool { return int(p.id) < xr.Len() && refOf(xr.Index(int(p.id)).FieldByName("ptr")) == p }
	inStream := func(p ref) bool { return registered(p) && xr.Index(int(p.id)).FieldByName("inStream").Bool() }
	containers := map[ref]bool{}
	for i := 0; i < xr.Len(); i++ {
		e := xr.Index(i)
		if !e.FieldByName("inStream").Bool() {
			continue
		}
		s := refOf(e.FieldByName("stream"))
		if inStream(s) {
			return ErrStructure
		}
		containers[s] = true
	}
	for c := range containers {
		seen := map[ref]bool{}
		for p := c; registered(p); {
			if seen[p] || len(seen) > maxObjStmChain {
				return ErrStructure
			}
			seen[p] = true
			v := resolveEntry(r, int(p.id))
			if v.Kind() != pdf.Stream {
				break
			}
			hdr := reflect.ValueOf(v.RawData()).FieldByName("hdr")
			if !hdr.IsValid() || hdr.Kind() != reflect.Map {
				return ErrStructure
			}
			bad := false
			walkRefs(hdr, 0, func(x ref) { bad = bad || inStream(x) })
			if bad {
				return ErrStructure
			}
			ext := hdr.MapIndex(reflect.ValueOf("Extends").Convert(hdr.Type().Key()))
			if !ext.IsValid() || ext.Elem().Kind() != reflect.Struct || ext.Elem().Type().Name() != "objptr" {
				break
			}
			p = refOf(ext.Elem())
		}
	}
	return nil
}

// resolveEntry — xref[i]-ийн объект (Ptr() нь pointer method тул хаягтай элементээс).
func resolveEntry(r *pdf.Reader, i int) pdf.Value {
	xs := r.Xref()
	p := xs[i].Ptr()
	return r.Resolve(p, p)
}

// maxObjStmChain — /Extends гинжийн дээд урт (хууль ёсны баримтад 1–2).
const maxObjStmChain = 64

type ref struct {
	id  uint32
	gen uint16
}

// refOf — digitorus objptr{id, gen}-ийн reflect утгаас.
func refOf(v reflect.Value) ref {
	return ref{id: uint32(v.FieldByName("id").Uint()), gen: uint16(v.FieldByName("gen").Uint())}
}

// walkRefs — digitorus-ийн задалсан утга (dict / array / objptr) доторх бүх лавлагаа.
func walkRefs(v reflect.Value, depth int, fn func(ref)) {
	if depth > MaxNesting {
		return
	}
	switch v.Kind() {
	case reflect.Interface:
		if !v.IsNil() {
			walkRefs(v.Elem(), depth, fn)
		}
	case reflect.Map:
		it := v.MapRange()
		for it.Next() {
			walkRefs(it.Value(), depth+1, fn)
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			walkRefs(v.Index(i), depth+1, fn)
		}
	case reflect.Struct:
		if v.Type().Name() == "objptr" {
			fn(refOf(v))
		}
	}
}
