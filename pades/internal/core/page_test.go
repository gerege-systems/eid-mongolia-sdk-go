package core

import (
	"bytes"
	"testing"
	"time"

	"github.com/digitorus/pdf"
	"github.com/go-pdf/fpdf"
	pdfcpuapi "github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

// linkPage — fpdf-ийн нэг хуудас (UTF-8 бус font, link annotation-тэй — fpdf /Annots-д шууд толь бичдэг).
func linkPage(t *testing.T) []byte {
	t.Helper()
	d := fpdf.New("P", "mm", "A4", "")
	d.AddPage()
	d.SetFont("Helvetica", "", 12)
	d.CellFormat(80, 10, "verify", "", 1, "L", false, 0, "https://ca.eidmongolia.mn/verify/x")
	var b bytes.Buffer
	if err := d.Output(&b); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// xrefStreamPDF — base-ийг pdfcpu-ээр xref stream + ObjStm хэлбэрт хувиргана.
func xrefStreamPDF(t *testing.T, in []byte) []byte {
	t.Helper()
	conf := model.NewDefaultConfiguration()
	conf.WriteXRefStream, conf.WriteObjectStream = true, true
	var b bytes.Buffer
	if err := pdfcpuapi.Optimize(bytes.NewReader(in), &b, conf); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// Хуудас incremental update-аар нэмэгдэнэ: эх байт prefix, 2 хуудас, annotation бүр шууд бус, дараа нь гарын
// үсгийн widget хуудасны /Annots-д орно.
func TestAppendPageIncremental(t *testing.T) {
	for name, base := range map[string][]byte{"classic": basePDF(t, true), "xref stream": xrefStreamPDF(t, basePDF(t, true))} {
		t.Run(name, func(t *testing.T) {
			out, err := AppendPage(base, linkPage(t))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.HasPrefix(out, base) {
				t.Fatal("эх баримт prefix биш")
			}
			rdr, err := pdf.NewReader(bytes.NewReader(out), int64(len(out)))
			if err != nil {
				t.Fatal(err)
			}
			if wantStream := name == "xref stream"; (rdr.XrefInformation.Type == "stream") != wantStream {
				t.Fatalf("xref төрөл %q", rdr.XrefInformation.Type)
			}
			pages := rdr.Trailer().Key("Root").Key("Pages")
			if pages.Key("Count").Int64() != 2 || pages.Key("Kids").Len() != 2 {
				t.Fatalf("хуудас %d", pages.Key("Count").Int64())
			}
			p2 := pages.Key("Kids").Index(1)
			if p2.Key("Parent").GetPtr() != pages.GetPtr() || p2.Key("MediaBox").Len() != 4 || p2.Key("Resources").Kind() != pdf.Dict {
				t.Fatal("шинэ хуудасны /Parent /MediaBox /Resources")
			}
			annots := p2.Key("Annots")
			if annots.Len() != 1 || annots.Index(0).GetPtr() == p2.GetPtr() || annots.Index(0).Key("Subtype").Name() != "Link" {
				t.Fatal("link annotation шууд бус объект биш")
			}

			prep, err := PrepareSignature(out, time.Now(), "ALICE BOLD")
			if err != nil {
				t.Fatal(err)
			}
			rdr, err = pdf.NewReader(bytes.NewReader(prep.PDF), int64(len(prep.PDF)))
			if err != nil {
				t.Fatal(err)
			}
			root := rdr.Trailer().Key("Root")
			p1 := root.Key("Pages").Key("Kids").Index(0)
			pa := p1.Key("Annots")
			if pa.Len() != 1 || pa.Index(0).Key("FT").Name() != "Sig" || pa.Index(0).GetPtr() != root.Key("AcroForm").Key("Fields").Index(0).GetPtr() {
				t.Fatal("widget эхний хуудасны /Annots-д алга")
			}
			if v := root.Key("AcroForm").Key("Fields").Index(0).Key("V").Key("Name").Text(); v != "ALICE BOLD" {
				t.Fatalf("/Name %q", v)
			}
		})
	}
}
