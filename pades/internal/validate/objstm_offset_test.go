package validate

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"runtime/debug"
	"strings"
	"testing"
)

// objStmOffsetPDF — obj 3 нь ObjStm 4 (FlateDecode) дотор; толгой hdr ба өгөгдөл body, /First = len(hdr) (first == -1
// бол). pad > 0 бол толгойн дараа ийм урт тайлбар (CheckStructure-ийн төсөв 16×len(doc)-ийг өсгөнө; xref offset зөв).
func objStmOffsetPDF(n int, first int64, hdr, body string, pad int) []byte {
	if first == -1 {
		first = int64(len(hdr))
	}
	data := deflate([]byte(hdr + body))
	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n")
	if pad > 0 {
		b.WriteString("%" + strings.Repeat("x", pad) + "\n")
	}
	offs := map[int]int{1: b.Len()}
	b.WriteString("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
	offs[2] = b.Len()
	b.WriteString("2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n")
	offs[4] = b.Len()
	fmt.Fprintf(&b, "4 0 obj\n<< /Type /ObjStm /N %d /First %d /Filter /FlateDecode /Length %d >>\nstream\n", n, first, len(data))
	b.Write(data)
	b.WriteString("\nendstream\nendobj\n")
	offs[5] = b.Len()
	var xr bytes.Buffer
	for i := 0; i <= 5; i++ {
		switch o := offs[i]; {
		case i == 3:
			xr.Write([]byte{2, 0, 0, 0, 4, 0, 0})
		case o != 0:
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

// TestCheckStructureObjStmOffsetSemantics — digitorus ObjStm-ийн толгойн offset-ийг `readToken().(int64)`-ээр уншдаг:
// бүхэл бус токен = 0, сөрөг ба int64 wrap хэвээр (`seekForward(first+off)`). Scanner эдгээрийг алгасдаг байсан тул
// `3 2.5`, `3 -K`-аар заасан гүн объект шалгалтгүй үлдэж, digitorus-ийн рекурс `fatal error: stack overflow` өгдөг
// байв (2026-11-04, TS SDK 0.40.2-ийн review-ээс). Хэт их offset (wrap → сөрөг) scanner-ийг panic хийлгэдэг байв.
func TestCheckStructureObjStmOffsetSemantics(t *testing.T) {
	deep := strings.Repeat("[", MaxNesting+10)
	wrapOff := fmt.Sprint(int64(math.MinInt64) + 23) // first = MinInt64: first+off wrap → 23 = len("3 " + off + " ")
	for name, tc := range map[string]struct {
		n     int
		first int64
		hdr   string
		body  string
		bad   bool
	}{
		"хууль ёсны":                     {1, -1, "3 0 ", "<< >>", false},
		"хууль ёсны, /N хэт их":          {5, -1, "3 0 ", "<< /A [1 2 -3] /B (x) /C 4.5 >>", false},
		"бүтэн offset 0 → гүн":           {1, -1, "3 0 ", deep, true},
		"бутархай offset (2.5)":          {1, -1, "3 2.5 ", deep, true},
		"бутархай offset (0.0)":          {1, -1, "3 0.0 ", deep, true},
		"1e9 (түлхүүр үг)":               {1, -1, "3 1e9 ", deep, true},
		"offset [":                       {1, -1, "3 [ ", deep, true},
		"offset /N":                      {1, -1, "3 /N ", deep, true},
		"offset (x)":                     {1, -1, "3 (x) ", deep, true},
		"offset <00>":                    {1, -1, "3 <00> ", deep, true},
		"offset true":                    {1, -1, "3 true ", deep, true},
		"offset int64-ээс их":            {1, -1, "3 99999999999999999999 ", deep, true},
		"сөрөг offset → толгойн дотор":   {1, -1, fmt.Sprintf("3 -%d %s ", len(deep)+1, deep), "null", true},
		"сөрөг /First":                   {1, -6, "3 10 " + deep, "", true},
		"int64 wrap → өгөгдөл":           {1, math.MinInt64, "3 " + wrapOff + " ", deep, true},
		"бутархай offset, хоёр дахь хос": {2, -1, "5 0 3 2.5 ", deep, true},
	} {
		t.Run(name, func(t *testing.T) {
			doc := objStmOffsetPDF(tc.n, tc.first, tc.hdr, tc.body, 0)
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
	// first+off < 0 (int64 wrap орно): digitorus seekForward дахин давж өөр хэсгээс уншиж болох тул ErrStructure;
	// өмнө нь scanner сөрөг индексээр panic хийдэг, эсвэл алгасдаг байв.
	for _, tc := range []struct {
		first int64
		off   string
	}{{10, "9223372036854775807"}, {10, "-9223372036854775808"}, {-9223372036854775807, "0"}, {-5, "1"}} {
		doc := objStmOffsetPDF(1, tc.first, "3 "+tc.off+" ", deep, 0)
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("first %d offset %s: CheckStructure panic: %v", tc.first, tc.off, r)
				}
			}()
			if err := CheckStructure(doc); !errors.Is(err, ErrStructure) {
				t.Fatalf("first %d offset %s: %v, want ErrStructure", tc.first, tc.off, err)
			}
		}()
	}
}

// TestExtractDeepObjStmNoStackOverflow — scanner давхарлалт гэж тоолдоггүй `1 0 obj 1 0 obj …` гинж (бүтэн offset) ObjStm
// дотор: scanner нэвтрүүлнэ (доор шалгана — тест задлагч хүртэл очно), gerege-systems/pdf v0.1.4-ийн гүний хязгаар panic
// (recover) болгоно. v0.1.3-д 1 GB stack дүүрч процесс унадаг байв; stack-ийн хязгаар 64 MiB (worker-тэй ижил) тул
// регресс бол тест процесс унана.
func TestExtractDeepObjStmNoStackOverflow(t *testing.T) {
	defer debug.SetMaxStack(debug.SetMaxStack(64 << 20))
	const n = 400_000
	// Төсөв (16×len(doc)+1 MiB) задалсан өгөгдөл + гинжийн уншилтыг (~2×3.2 MB) багтаахаар тайлбараар дүүргэнэ.
	doc := objStmOffsetPDF(1, -1, "3 0 ", strings.Repeat("1 0 obj ", n)+"null", 600_000)
	if err := CheckStructure(doc); err != nil {
		t.Fatalf("CheckStructure: %v — тест задлагч хүртэл очих ёстой", err)
	}
	if sigs, err := Extract(doc); err == nil || len(sigs) != 0 {
		t.Fatalf("Extract: %d, %v — алдаа хүлээсэн", len(sigs), err)
	}
}
