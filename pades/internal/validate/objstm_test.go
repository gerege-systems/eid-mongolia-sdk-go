package validate

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

// xrefStreamPDF — xref stream-тэй жижиг PDF: obj 1 Catalog (/X 3 0 R), obj 2 xref stream (/Size size, W [1 2 1]),
// obj 3 = ObjStm 4-ийн 0-р объект (row3 өгвөл түүгээр солино), obj 4 — ObjStm (/Length length4; row4 өгвөл xref-ийн
// мөрийг солино).
func xrefStreamPDF(size, length4 string, row3, row4 []byte) []byte {
	var b bytes.Buffer
	b.WriteString("%PDF-1.5\n%" + string(bytes.Repeat([]byte("x"), 300)) + "\n")
	off1 := b.Len()
	b.WriteString("1 0 obj\n<< /Type /Catalog /X 3 0 R >>\nendobj\n")
	off4 := b.Len()
	fmt.Fprintf(&b, "4 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Length %s >>\nstream\n3 0 << >>\nendstream\nendobj\n", length4)
	off2 := b.Len()
	row := func(t byte, f2 int, f3 byte) []byte { return []byte{t, byte(f2 >> 8), byte(f2), f3} }
	if row3 == nil {
		row3 = row(2, 4, 0)
	}
	if row4 == nil {
		row4 = row(1, off4, 0)
	}
	rows := bytes.Join([][]byte{row(0, 0, 0xff), row(1, off1, 0), row(1, off2, 0), row3, row4}, nil)
	fmt.Fprintf(&b, "2 0 obj\n<< /Type /XRef /Size %s /W [1 2 1] /Index [0 5] /Root 1 0 R /Length %d >>\nstream\n", size, len(rows))
	b.Write(rows)
	fmt.Fprintf(&b, "\nendstream\nendobj\nstartxref\n%d\n%%%%EOF\n", off2)
	return b.Bytes()
}

// TestCheckStructureObjStmGraph — digitorus resolve-ийн мөчлөг (FuzzValidatePDF олсон `fatal error: stack overflow`)
// ба /Size-ийн хуваарилалт ErrStructure; хууль ёсны ObjStm хэвээр задарна.
func TestCheckStructureObjStmGraph(t *testing.T) {
	inStm := func(container byte) []byte { return []byte{2, 0, container, 0} }
	for _, tc := range []struct {
		name string
		doc  []byte
		bad  bool
	}{
		{"ObjStm-д obj 3 (хууль ёсны)", xrefStreamPDF("5", "9", nil, nil), false},
		{"/Size maxXrefSize", xrefStreamPDF(fmt.Sprint(maxXrefSize), "9", nil, nil), false},
		{"obj 3 өөрийнхөө агуулагч", xrefStreamPDF("5", "9", inStm(3), nil), true},
		{"ObjStm 4 нь ObjStm 3 дотор (харилцан)", xrefStreamPDF("5", "9", nil, inStm(3)), true},
		{"ObjStm-ийн /Length өөрийн ObjStm дотор", xrefStreamPDF("5", "3 0 R", nil, nil), true},
		{"/Size 10^10", xrefStreamPDF("10000000000", "9", nil, nil), true},
	} {
		err := CheckStructure(tc.doc)
		if tc.bad != errors.Is(err, ErrStructure) || !tc.bad && err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
		if !tc.bad {
			if _, err := Extract(tc.doc); !errors.Is(err, ErrNoSignature) {
				t.Errorf("%s: Extract %v", tc.name, err)
			}
		}
	}
}
