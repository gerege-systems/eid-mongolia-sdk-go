package pades

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzValidatePDF — дайсагнасан PDF: ValidatePDF (offline: CheckStructure → Extract → validate) ба Verify нь ямар ч
// оролтод panic / stack overflow / hang-гүйгээр Report эсвэл *Error буцаана. Seed = репогийн бүх тестийн PDF
// (golden, validate v4 — deep-nesting орно, CA корпус). `go test` seed-үүдийг энгийн unit-ээр ажиллуулна; CI-ийн
// `fuzz` job нь `-fuzztime=30s` mutation хийнэ.
func FuzzValidatePDF(f *testing.F) {
	for _, root := range []string{"testdata", filepath.Join("internal", "validate", "testdata"), filepath.Join("internal", "core", "testdata")} {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".pdf") {
				return err
			}
			b, err := os.ReadFile(path) // #nosec G304 -- тест
			if err != nil {
				return err
			}
			f.Add(b)
			return nil
		})
		if err != nil {
			f.Fatal(err)
		}
	}
	f.Add([]byte{})
	f.Add([]byte("%PDF-1.7\n%%EOF\n"))
	f.Add([]byte("%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n"))
	f.Fuzz(func(t *testing.T, doc []byte) {
		rep, err := ValidatePDF(context.Background(), doc, ValidateOptions{Offline: true})
		if err == nil && rep == nil {
			t.Fatal("ValidatePDF: nil Report, nil алдаа")
		}
		if err != nil && ErrorCode(err) == "" {
			t.Fatalf("ValidatePDF: *Error биш алдаа: %v", err)
		}
		if rep, err := Verify(doc, VerifyOptions{}); err == nil && rep == nil {
			t.Fatal("Verify: nil Report, nil алдаа")
		}
	})
}
