package validate

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"
)

// lexLoopPDF — нэг объекттой classic xref PDF; objStm бол объект 1 нь шахаагүй ObjStm, объект 2 түүний дотор.
func lexLoopPDF(body string, objStm bool) []byte { return lexLoopPDFN(body, objStm, 1, "2 0 ") }

// lexLoopPDFN — lexLoopPDF, ObjStm-ийн /N ба толгойг (hdr) өгнө.
func lexLoopPDFN(body string, objStm bool, n int, hdr string) []byte {
	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n")
	obj := body
	if objStm {
		obj = fmt.Sprintf("<</Type/ObjStm/N %d/First %d/Length %d>>\nstream\n%s%s\nendstream", n, len(hdr), len(hdr)+len(body), hdr, body)
	}
	off := b.Len()
	fmt.Fprintf(&b, "1 0 obj\n%s\nendobj\n", obj)
	x := b.Len()
	if !objStm {
		fmt.Fprintf(&b, "xref\n0 2\n0000000000 65535 f \n%010d 00000 n \ntrailer\n<</Size 2>>\nstartxref\n%d\n%%%%EOF\n", off, x)
		return b.Bytes()
	}
	// xref stream (W [1 4 2]): 0 free, 1 → off, 2 → ObjStm 1 index 0.
	rows := []byte{0, 0, 0, 0, 0, 0, 0, 1, byte(off >> 24), byte(off >> 16), byte(off >> 8), byte(off), 0, 0, 2, 0, 0, 0, 1, 0, 0}
	fmt.Fprintf(&b, "3 0 obj\n<</Type/XRef/W[1 4 2]/Index[0 3]/Size 3/Length %d>>\nstream\n", len(rows))
	b.Write(rows)
	fmt.Fprintf(&b, "\nendstream\nendobj\nstartxref\n%d\n%%%%EOF\n", x)
	return b.Bytes()
}

// digitorus/pdf v0.1.2-ийн lexer нь массив дотор `endobj` (мөн ObjStm-ийн төгсгөлд хаагдаагүй массив/мөр)
// таарвал ахихгүй мөнхийн давталтад орж санах ойг хязгааргүй өсгөдөг байв (craftzbay/pdf v0.1.3-eid.1 засвар).
// Extract нь эдгээрийг ErrNotPDF болгож хурдан татгалзах ёстой; регресс бол тест гацахын оронд унана.
func TestExtractRejectsUnterminatedObjectsPromptly(t *testing.T) {
	cases := map[string][]byte{
		"endobj массивт":           lexLoopPDF("[1", false),
		"endobj давхар массивт":    lexLoopPDF("<</K[[/A", false),
		"ObjStm хаагдаагүй массив": lexLoopPDF("[1", true),
		"ObjStm хаагдаагүй мөр":    lexLoopPDF("(abc", true),
		"ObjStm хаагдаагүй hex":    lexLoopPDF("<0a", true),
		"ObjStm /N хэт их":         lexLoopPDFN("1", true, 2_000_000_000, "5 0 "),
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			done := make(chan error, 1)
			go func() {
				_, err := Extract(doc)
				done <- err
			}()
			select {
			case err := <-done:
				if !errors.Is(err, ErrNotPDF) {
					t.Fatalf("хүлээсэн ErrNotPDF, авсан %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Extract буцсангүй (lexer мөнхийн давталт)")
			}
		})
	}
}
