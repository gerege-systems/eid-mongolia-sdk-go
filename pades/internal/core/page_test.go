package core

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/pdf"

	"github.com/gerege-systems/eid-mongolia-sdk-go/pades/assets"

	pdfcpuapi "github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

// testPageData — PAGE_SPEC-ийн жишээ өгөгдөл.
func testPageData() PageData {
	return PageData{Brand: "eID Mongolia", FileName: "Гэрээ Өө Үү.pdf", DocumentHash: strings.Repeat("ab", 32), FileSize: 12345,
		DocID: "6f0c2b9e-3a1d-4c55-9b7e-0a1b2c3d4e5f", VerifyURL: "https://ca.eidmongolia.mn/verify/6f0c2b9e-3a1d-4c55-9b7e-0a1b2c3d4e5f",
		TrustURL: "https://eidmongolia.mn/trust", CAName: "eID Mongolia Issuing CA", TSAName: "eID Mongolia TSA (tsa.timeserver.mn)",
		Provider: "ca.eidmongolia.mn"}
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
			out, err := AppendVerifyPage(base, testPageData())
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
			if annots.Len() != 2 || annots.Index(0).GetPtr() == p2.GetPtr() || annots.Index(0).Key("Subtype").Name() != "Link" {
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

// TestPageTextsFit — хоёр хэлний тогтмол бичвэр фонтод бүрэн (glyph) ба мөрөндөө багтана (PAGE_SPEC.md §3a).
func TestPageTextsFit(t *testing.T) {
	reg, _ := assets.Regular()
	bld, _ := assets.Bold()
	w := &pageWriter{reg: reg, bld: bld}
	for lang, tx := range pageTexts {
		for _, c := range []struct {
			id, size, max int
			s             string
		}{{2, 13, 496, "eID Mongolia" + tx.title}, {1, 9, 496, tx.subtitle}, {2, 11, 416, tx.scan}, {1, 9, 416, tx.scanHint},
			{1, 9, 416, tx.trust}, {2, 11, 510, tx.document}, {2, 11, 510, tx.verification}} {
			if got := w.width1000(c.id, c.size, c.s); got > c.max*1000 {
				t.Errorf("%s: %q өргөн %d > %d", lang, c.s, got/1000, c.max)
			}
			for _, r := range c.s {
				if _, ok := w.font(c.id).GID[r]; !ok {
					t.Errorf("%s: glyph алга %q", lang, r)
				}
			}
		}
	}
}
