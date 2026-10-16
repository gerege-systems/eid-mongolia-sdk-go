package pades

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// flakyLTV — TSA-аас бусад (OCSP/CRL) хүсэлтийг fails > 0 үед 503-аар унагана; LTV retry-ийн хүлээлт бүр fails-ийг
// нэгээр бууруулна (sleepFn-оор). TS SDK 0.18.3-ийн pades-golden LTV retry тесттэй ижил хувилбар.
type flakyLTV struct {
	next  http.RoundTripper
	fails int
}

func (f *flakyLTV) RoundTrip(r *http.Request) (*http.Response, error) {
	if f.fails > 0 && !strings.HasPrefix(r.URL.Host, "tsa.") {
		return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}, Request: r}, nil
	}
	return f.next.RoundTrip(r)
}

// ltvGolden — эхний алдаагүй, файлаас оролттой golden тохиолдол + түүний хүлээгдэх утга.
func ltvGolden(t *testing.T) (*goldenPKI, *replayTransport, goldenCase, []byte, goldenExpect) {
	t.Helper()
	p := loadOrCreatePKI(t)
	raw, err := os.ReadFile(filepath.Join(goldenDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m goldenManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	rt := &replayTransport{t: t, m: &m, live: p.liveResponder(t), record: map[string][]byte{}}
	want := map[string]goldenExpect{}
	for _, c := range m.Cases {
		want[c.Name] = c.Expect
	}
	for _, c := range goldenCases() {
		if strings.HasPrefix(c.Input, "case:") || want[c.Name].Error != "" || want[c.Name].OutSHA256 == "" {
			continue
		}
		in, err := os.ReadFile(filepath.Join(goldenDir, c.Input)) // #nosec G304 -- тест
		if err != nil {
			t.Fatal(err)
		}
		return p, rt, c, in, want[c.Name]
	}
	t.Fatal("тохиолдол алга")
	return nil, nil, goldenCase{}, nil, goldenExpect{}
}

func withSleeps(t *testing.T, f *flakyLTV, sleeps *[]time.Duration) {
	t.Helper()
	orig := sleepFn
	sleepFn = func(ctx context.Context, d time.Duration) error {
		*sleeps = append(*sleeps, d)
		if f.fails > 0 {
			f.fails--
		}
		return ctx.Err()
	}
	t.Cleanup(func() { sleepFn = orig })
}

func intp(n int) *int { return &n }

func TestCompleteLTVRetry(t *testing.T) {
	p, rt, c, in, want := ltvGolden(t)

	// 2 унаад 3 дахь нь амжвал гаралт golden-той байт-ижил; хүлээлт ~1 с, ~3 с (+0–25%).
	f := &flakyLTV{next: rt, fails: 2}
	var sleeps []time.Duration
	withSleeps(t, f, &sleeps)
	got, _, err := runGoldenWith(context.Background(), t, p, f, c, in, nil)
	if err != nil || got.OutSHA256 != want.OutSHA256 {
		t.Fatalf("%v: %s ≠ %s", err, got.OutSHA256, want.OutSHA256)
	}
	if len(sleeps) != 2 || sleeps[0] < time.Second || sleeps[0] > 1250*time.Millisecond ||
		sleeps[1] < 3*time.Second || sleeps[1] > 3750*time.Millisecond {
		t.Fatalf("backoff %v", sleeps)
	}

	// 3-уулаа унавал LTV_UNAVAILABLE (retryable).
	f.fails, sleeps = 100, nil
	_, _, err = runGoldenWith(context.Background(), t, p, f, c, in, nil)
	var pe *Error
	if ErrorCode(err) != CodeLTVUnavailable || !errors.As(err, &pe) || len(sleeps) != 2 {
		t.Fatalf("%v %v", err, sleeps)
	}

	// LTVRetries 0 — давтахгүй.
	f.fails, sleeps = 100, nil
	if _, _, err = runGoldenWith(context.Background(), t, p, f, c, in, intp(0)); ErrorCode(err) != CodeLTVUnavailable || len(sleeps) != 0 {
		t.Fatalf("0: %v %v", err, sleeps)
	}

	// 0–10-аас гадуур → REQUEST_INVALID.
	for _, n := range []int{-1, 11} {
		if _, _, err = runGoldenWith(context.Background(), t, p, rt, c, in, intp(n)); ErrorCode(err) != CodeRequestInvalid {
			t.Fatalf("%d: %v", n, err)
		}
	}

	// ctx цуцлалт хүлээлтийн үеэр — дахин оролдохгүй, context.Canceled-ийг боож буцаана.
	ctx, cancel := context.WithCancel(context.Background())
	f.fails, sleeps = 100, nil
	orig := sleepFn
	sleepFn = func(ctx context.Context, d time.Duration) error {
		sleeps = append(sleeps, d)
		cancel()
		return ctx.Err()
	}
	defer func() { sleepFn = orig }()
	if _, _, err = runGoldenWith(ctx, t, p, f, c, in, nil); ErrorCode(err) != CodeLTVUnavailable || !errors.Is(err, context.Canceled) || len(sleeps) != 1 {
		t.Fatalf("cancel: %v %v", err, sleeps)
	}
}
