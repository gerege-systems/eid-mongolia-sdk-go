package validate

import (
	"context"
	"testing"
)

// isolated — CA-д тусгаарлагдсан дэд процесс (worker.go); клиент талд (mobile/wasm) дэд процесс боломжгүй тул
// процесс доторх Extract (panic-ийг extractWith өөрөө барина).
func isolated(t *testing.T) func(context.Context, []byte) ([]RawSignature, error) {
	t.Helper()
	return func(_ context.Context, d []byte) ([]RawSignature, error) { return Extract(d) }
}
