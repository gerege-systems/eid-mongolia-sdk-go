package validate

import (
	"context"
	"os"
	"testing"

	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

// isolated — CA-д тусгаарлагдсан дэд процесс (worker.go); клиент талд (mobile/wasm) дэд процесс боломжгүй тул
// процесс доторх Extract (panic-ийг extractWith өөрөө барина).
func isolated(t *testing.T) func(context.Context, []byte) ([]RawSignature, error) {
	t.Helper()
	return func(_ context.Context, d []byte) ([]RawSignature, error) { return Extract(d) }
}

// TestMain — тест дэх pdfcpu MergeRaw (CA-ийн хуучин stamp-ийн суурь) config.yml бичихгүй (js/wasm-д FS алга).
func TestMain(m *testing.M) {
	model.ConfigPath = "disable"
	os.Exit(m.Run())
}
