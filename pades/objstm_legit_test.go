package pades

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/validate"
)

// TestObjStmLegitAccepted — PRECHECKS #2b (ObjStm мөчлөг / /Size) хууль ёсны ObjStm + xref stream-тэй баримтыг хуурамчаар
// татгалзахгүй. testdata/objstm/ (qpdf 12.4.2 `--object-streams=generate`):
//   - qpdf-chrome.pdf — Chrome 155 (Skia/PDF) «Save as PDF»-ийн гаралт;
//   - qpdf-linearized.pdf — golden/input/quartz-rotated90.pdf, `--linearize` нэмсэн (hint stream + хоёр xref stream);
//   - signed-qpdf-*.pdf — гарын үсэгтэй golden/input/stamped.pdf (pdfcpu) ба validate/input/qualified-phone.pdf (macOS).
//     Бүтнээр дахин бичсэн тул гарын үсэг хүчингүй — зөвхөн CheckStructure-ийг шалгана.
//
// Мөн бодит ObjStm-тэй golden/input/quartz-objstm.pdf, desktop-objstm.pdf. Гарын үсэггүй бүх баримтад ValidatePDF →
// PDF_NO_SIGNATURE (PDF_INVALID биш), Prepare амжилттай.
func TestObjStmLegitAccepted(t *testing.T) {
	p := loadOrCreatePKI(t)
	files, err := filepath.Glob(filepath.Join("testdata", "objstm", "*.pdf"))
	if err != nil || len(files) < 4 {
		t.Fatalf("%v %v", files, err)
	}
	files = append(files, filepath.Join(goldenDir, "input", "quartz-objstm.pdf"), filepath.Join(goldenDir, "input", "desktop-objstm.pdf"))
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			doc, err := os.ReadFile(f) // #nosec G304 -- тест
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(doc, []byte("/ObjStm")) || !bytes.Contains(doc, []byte("/XRef")) {
				t.Fatal("ObjStm / xref stream алга — тестийн өгөгдөл буруу")
			}
			if err := validate.CheckStructure(doc); err != nil {
				t.Fatalf("CheckStructure: %v", err)
			}
			if strings.HasPrefix(filepath.Base(f), "signed-") {
				return
			}
			if _, err := ValidatePDF(context.Background(), doc, ValidateOptions{Offline: true}); ErrorCode(err) != CodePDFNoSignature {
				t.Fatalf("ValidatePDF: %v", err)
			}
			if _, err := Prepare(doc, testOpts(p, p.citizen.cert)); err != nil {
				t.Fatalf("Prepare: %v", err)
			}
		})
	}
}
