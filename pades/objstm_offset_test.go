package pades

import (
	"fmt"
	"testing"
)

// TestObjStmHugeOffsetNoPanic — ObjStm-ийн толгойн offset /First-тэй нийлээд int64-ээс давж (wrap → сөрөг) CheckStructure
// индекс сөрөг болж panic хийдэг байв; Prepare/SuggestPlacement-д recover байхгүй тул RP-ийн goroutine унана (v0.22.1).
func TestObjStmHugeOffsetNoPanic(t *testing.T) {
	for _, off := range []string{"9223372036854775807", "-9223372036854775808"} {
		data := "3 " + off + " [[["
		doc := []byte(fmt.Sprintf("%%PDF-1.7\n4 0 obj\n<< /Type /ObjStm /N 1 /First 10 /Length %d >>\nstream\n%s\nendstream\nendobj\n", len(data), data))
		t.Run(off, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic: %v", r)
				}
			}()
			_, _ = Prepare(doc, PrepareOptions{})
			_, _ = SuggestPlacement(doc, Appearance{})
		})
	}
}
