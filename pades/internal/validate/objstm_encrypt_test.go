package validate

import (
	"bytes"
	"compress/zlib"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// zipBombStream — "4 0 " толгой + maxObjStmBytes-ээс их хоосон зай; задлахад ~33 MiB, шахсан нь ~33 KB.
var zipBombStream = sync.OnceValue(func() []byte {
	var z bytes.Buffer
	zw, _ := zlib.NewWriterLevel(&z, zlib.BestCompression)
	_, _ = zw.Write([]byte("4 0 "))
	_, _ = zw.Write(bytes.Repeat([]byte{' '}, maxObjStmBytes+1<<20))
	_ = zw.Close()
	return z.Bytes()
})

// zipBombObjStmPDF — сонгодог xref-тэй PDF: obj 3 нь zip bomb FlateDecode ObjStm. inject нь толгойн дараа (xref-д
// бүртгэлгүй) бичигдэх дурын текст, trailerExtra нь trailer-ийн толинд нэмэгдэнэ.
func zipBombObjStmPDF(inject, trailerExtra string) []byte {
	bomb := zipBombStream()
	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n" + inject + "\n")
	offs := []int{b.Len()}
	b.WriteString("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
	offs = append(offs, b.Len())
	b.WriteString("2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n")
	offs = append(offs, b.Len())
	fmt.Fprintf(&b, "3 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode /Length %d >>\nstream\n", len(bomb))
	b.Write(bomb)
	b.WriteString("\nendstream\nendobj\n")
	x := b.Len()
	fmt.Fprintf(&b, "xref\n0 4\n0000000000 65535 f \n")
	for _, o := range offs {
		fmt.Fprintf(&b, "%010d 00000 n \n", o)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size 4 /Root 1 0 R %s>>\nstartxref\n%d\n%%%%EOF\n", trailerExtra, x)
	return b.Bytes()
}

// TestCheckStructureZipBombIgnoresFakeEncrypt — /Encrypt-ийг түүхий байтын regex-ээр таньж ObjStm-ийн шалгалтыг
// бүхэлд нь унтраадаг байсан (2026-11-04 review): `% /Encrypt <<` тайлбар нэмэхэд zip bomb ObjStm (~33 KB → 33 MiB)
// CheckStructure-ийг давж digitorus руу ордог байв. Одоо ObjStm-ийг шифрлэлтээс үл хамааран шалгана — trailer-т
// жинхэнээсээ /Encrypt зарласан баримтын bomb ч татгалзагдана.
func TestCheckStructureZipBombIgnoresFakeEncrypt(t *testing.T) {
	const id = "<abababababababababababababababab>"
	o := "<" + strings.Repeat("55", 32) + ">"
	u := "<" + strings.Repeat("66", 32) + ">"
	for name, doc := range map[string][]byte{
		"шифрлэлтгүй":                 zipBombObjStmPDF("", ""),
		"%-тайлбарт `/Encrypt <<`":    zipBombObjStmPDF("% /Encrypt <<", ""),
		"%-тайлбарт `/Encrypt N 0 R`": zipBombObjStmPDF("% /Encrypt 9 0 R", ""),
		"мөр дотор":                   zipBombObjStmPDF("5 0 obj\n(/Encrypt <<)\nendobj", ""),
		"stream өгөгдөл дотор":        zipBombObjStmPDF("5 0 obj\n<< /Length 11 >>\nstream\n/Encrypt <<\nendstream\nendobj", ""),
		"trailer-ийн жинхэнэ /Encrypt": zipBombObjStmPDF("",
			"/ID ["+id+" "+id+"] /Encrypt << /Filter /Standard /V 2 /R 3 /Length 128 /O "+o+" /U "+u+" /P -4 >> "),
	} {
		t.Run(name, func(t *testing.T) {
			if err := CheckStructure(doc); !errors.Is(err, ErrStructure) {
				t.Fatalf("CheckStructure: %v, want ErrStructure", err)
			}
			if _, err := Extract(doc); !errors.Is(err, ErrStructure) {
				t.Fatalf("Extract: %v, want ErrStructure", err)
			}
		})
	}
}

// FuzzCheckStructure — CheckStructure panic хийхгүй, төсвөөс хэтэрсэн ажил хийхгүй (go test -fuzz=FuzzCheckStructure).
func FuzzCheckStructure(f *testing.F) {
	// zip bomb-ийг seed болгохгүй (exec бүр 32 MiB задална) — жижиг FlateDecode ObjStm + хуурамч /Encrypt.
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	_, _ = zw.Write([]byte("5 0 6 9 [[[1]]] << /A [(x) <0a> /N#41] >>"))
	_ = zw.Close()
	f.Add([]byte(fmt.Sprintf("%%PDF-1.7\n%% /Encrypt <<\n4 0 obj\n<< /Type /ObjStm /N 2 /First 8 /Filter /FlateDecode /Length %d >>\nstream\n%s\nendstream\nendobj\ntrailer\n<< /Size 7 /Encrypt 9 0 R >>\n", z.Len(), z.Bytes())))
	f.Add([]byte("%PDF-1.7\n% /Encrypt <<\n1 0 obj\n<< /Type /ObjStm /N 1 /First 4 >>\nstream\n5 0 [[[\nendstream\nendobj\n"))
	files, _ := filepath.Glob(filepath.Join("..", "..", "testdata", "encrypted-objstm", "*.pdf"))
	for _, p := range files {
		if b, err := os.ReadFile(p); err == nil { // #nosec G304 -- тест
			f.Add(b)
		}
	}
	f.Fuzz(func(t *testing.T, doc []byte) {
		_ = CheckStructure(doc)
	})
}

// objStmXrefPDF — xref stream-тэй PDF: obj 3 нь ObjStm 4 дотор (толгойн нэмэлт hdr, түүхий stream өгөгдөл data) —
// digitorus obj 3-ийг resolve хийхдээ ObjStm-ийг задална.
func objStmXrefPDF(hdr string, data []byte) []byte {
	var b bytes.Buffer
	offs := map[int]int{}
	b.WriteString("%PDF-1.7\n")
	offs[1] = b.Len()
	b.WriteString("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
	offs[2] = b.Len()
	b.WriteString("2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n")
	offs[4] = b.Len()
	fmt.Fprintf(&b, "4 0 obj\n<< /Type /ObjStm /N 1 /First 4 %s /Length %d >>\nstream\n", hdr, len(data))
	b.Write(data)
	b.WriteString("\nendstream\nendobj\n")
	offs[5] = b.Len()
	var xr bytes.Buffer
	for i := 0; i <= 5; i++ {
		switch {
		case i == 3:
			xr.Write([]byte{2, 0, 0, 0, 4, 0, 0})
		case offs[i] != 0:
			o := offs[i]
			xr.Write([]byte{1, byte(o >> 24), byte(o >> 16), byte(o >> 8), byte(o), 0, 0})
		default:
			xr.Write([]byte{0, 0, 0, 0, 0, 0xff, 0xff})
		}
	}
	fmt.Fprintf(&b, "5 0 obj\n<< /Type /XRef /Size 6 /W [1 4 2] /Root 1 0 R /Length %d >>\nstream\n", xr.Len())
	b.Write(xr.Bytes())
	fmt.Fprintf(&b, "\nendstream\nendobj\nstartxref\n%d\n%%%%EOF\n", offs[5])
	return b.Bytes()
}

func deflate(b []byte) []byte {
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	_, _ = zw.Write(b)
	_ = zw.Close()
	return z.Bytes()
}

// TestCheckStructureObjStmFilterMismatch — scanner ба digitorus /Filter-ийг өөрөөр уншдаг байсан (2026-11-04 review):
// `[/FlateDecode /FlateDecode]`-г digitorus гинжлэн задалдаг ч scanner «дэмжихгүй» гэж алгасдаг; давхар түлхүүрт
// (`/Filter /FlateDecode /Filter null`) digitorus сүүлийнхийг (түүхий) уншдаг ч scanner FlateDecode гэж zlib-ээр
// задлах гэж бүтэлгүйтээд алгасдаг байв — 1.6 KB → 1.69 GB, эсвэл ObjStm доторх `[[[…` stack overflow.
func TestCheckStructureObjStmFilterMismatch(t *testing.T) {
	deep := append([]byte("3 0 "), bytes.Repeat([]byte{'['}, MaxNesting+10)...)
	for name, tc := range map[string]struct {
		hdr  string
		data []byte
		bad  bool
	}{
		"хууль ёсны [/FlateDecode]":           {"/Filter [/FlateDecode]", deflate([]byte("3 0 << >>")), false},
		"хууль ёсны шүүлтүүргүй":              {"", []byte("3 0 << >>"), false},
		"[/FlateDecode] гүн":                  {"/Filter [/FlateDecode]", deflate(deep), true},
		"[/FlateDecode /FlateDecode]":         {"/Filter [/FlateDecode /FlateDecode]", deflate(deflate([]byte("3 0 << >>"))), true},
		"давхар түлхүүр /FlateDecode → null":  {"/Filter /FlateDecode /Filter null", deep, true},
		"давхар түлхүүр /FlateDecode → []":    {"/Filter /FlateDecode /Filter []", deep, true},
		"давхар түлхүүр [] → /FlateDecode":    {"/Filter [] /Filter /FlateDecode", deflate(deep), true},
		"давхар түлхүүр /ASCIIHex → [] (гүн)": {"/Filter /ASCIIHexDecode /Filter []", deep, true},
		"[6 0 R] (лавлагаа массив дотор)":     {"/Filter [6 0 R]", deflate(deep), true},
		"[/FlateDecode 6 0 R]":                {"/Filter [/FlateDecode 6 0 R]", deflate(deflate(deep)), true},
	} {
		t.Run(name, func(t *testing.T) {
			doc := objStmXrefPDF(tc.hdr, tc.data)
			err := CheckStructure(doc)
			if tc.bad != errors.Is(err, ErrStructure) || !tc.bad && err != nil {
				t.Fatalf("CheckStructure: %v (bad=%v)", err, tc.bad)
			}
			if !tc.bad {
				if _, err := Extract(doc); !errors.Is(err, ErrNoSignature) {
					t.Fatalf("Extract: %v", err)
				}
			}
		})
	}
}
