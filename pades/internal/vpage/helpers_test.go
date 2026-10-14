package vpage

import (
	"bytes"
	"testing"

	"github.com/go-pdf/fpdf"
)

func minimalPDF(t *testing.T) []byte {
	t.Helper()
	op := fpdf.New("P", "mm", "A4", "")
	op.AddPage()
	op.SetFont("Helvetica", "", 12)
	op.Cell(40, 10, "Edge test content")
	var b bytes.Buffer
	if err := op.Output(&b); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
