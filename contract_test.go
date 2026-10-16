//go:build contract

// Гэрээний тест — сүлжээ шаарддаг тул энгийн `go test`-д орохгүй: `go test -tags contract ./...`.
// SDK-ийн дууддаг RP-API зам бүр (routes.go) live /.well-known/eid-ийн endpoints-д байх ёстой; discovery-д байгаа ч
// SDK хамраагүй замуудыг WARN болгон хэвлэнэ (fail биш).
package eid

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

const eidDiscoveryURL = "https://rp.eidmongolia.mn/.well-known/eid"

var (
	endpointRe    = regexp.MustCompile(`^(GET|POST|PUT|PATCH|DELETE)\s+(https?://\S+)`)
	placeholderRe = regexp.MustCompile(`\{[^}]*\}`)
)

// normRoute — "METHOD /path/{}" (query хасаж, {param} нэрийг үл тооно).
func normRoute(method, path string) string {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	return method + " " + placeholderRe.ReplaceAllString(path, "{}")
}

type discoveredEndpoint struct{ method, url string }

// collectEndpoints — endpoints мод доторх "METHOD URL …" мөр бүрийг цуглуулна (тайлбартай мөр ч орно).
func collectEndpoints(v any, out *[]discoveredEndpoint) {
	switch t := v.(type) {
	case map[string]any:
		for _, x := range t {
			collectEndpoints(x, out)
		}
	case string:
		if m := endpointRe.FindStringSubmatch(t); m != nil {
			*out = append(*out, discoveredEndpoint{m[1], m[2]})
		}
	}
}

// warn — stderr-д; GitHub Actions дээр нэг нэгдсэн ::warning:: annotation.
func warn(title string, lines []string) {
	for _, l := range lines {
		fmt.Fprintf(os.Stderr, "WARN: %s: %s\n", title, l)
	}
	if len(lines) > 0 && os.Getenv("GITHUB_ACTIONS") == "true" {
		fmt.Printf("::warning title=%s::%s\n", title, strings.Join(lines, "%0A"))
	}
}

func fetchJSON(t *testing.T, url string, out any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatalf("GET %s: JSON: %v", url, err)
	}
}

func TestContractRPRoutes(t *testing.T) {
	var d struct {
		RPAPIBase string         `json:"rp_api_base"`
		Endpoints map[string]any `json:"endpoints"`
	}
	fetchJSON(t, eidDiscoveryURL, &d)

	if d.RPAPIBase != DefaultBaseURL {
		t.Errorf("rp_api_base = %q, SDK DefaultBaseURL = %q", d.RPAPIBase, DefaultBaseURL)
	}

	var eps []discoveredEndpoint
	collectEndpoints(d.Endpoints, &eps)
	if len(eps) == 0 {
		t.Fatal("discovery endpoints хоосон / танигдаагүй")
	}
	// rp_api_base доорх замуудыг SDK-ийн замтай тулгана; бусад хост (ca. public г.м.) зөвхөн WARN-д.
	rpKey := func(e discoveredEndpoint) (string, bool) {
		p, ok := strings.CutPrefix(e.url, d.RPAPIBase+"/")
		return normRoute(e.method, "/"+p), ok
	}
	rp := map[string]bool{}
	for _, e := range eps {
		if k, ok := rpKey(e); ok {
			rp[k] = true
		}
	}

	covered := map[string]bool{}
	for _, r := range rpRoutes {
		k := normRoute(r.method, r.path)
		covered[k] = true
		if !rp[k] {
			t.Errorf("SDK зам discovery-д алга: %s %s", r.method, r.path)
		}
	}

	// CA-ийн гэрээнд (код + docs) байгаа ч discovery-д жагсаагдаагүй замууд — WARN; discovery-д орсон бол rpRoutes руу
	// шилжүүлэх сануулга (WARN).
	var undiscovered, nowDiscovered []string
	for _, r := range rpRoutesUndiscovered {
		k := normRoute(r.method, r.path)
		covered[k] = true
		if rp[k] {
			nowDiscovered = append(nowDiscovered, r.method+" "+r.path)
		} else {
			undiscovered = append(undiscovered, r.method+" "+r.path)
		}
	}
	warn("SDK зам CA-д бий ч discovery-д алга", undiscovered)
	warn("discovery-д орсон — rpRoutesUndiscovered-оос rpRoutes руу шилжүүл", nowDiscovered)

	var uncovered []string
	for _, e := range eps {
		if k, ok := rpKey(e); !ok || !covered[k] {
			uncovered = append(uncovered, e.method+" "+e.url)
		}
	}
	sort.Strings(uncovered)
	warn("discovery-д байгаа ч SDK хамраагүй", uncovered)
	t.Logf("SDK %d зам тулгав (+%d discovery-гүй); discovery-д SDK хамраагүй %d (WARN)", len(rpRoutes), len(rpRoutesUndiscovered), len(uncovered))
}

// TestContractPDFSignaturesBody — discovery-ийн endpoints.pdf.signatures-ийн биеийн талбарууд ({a, b?, …}) нь
// PDFSignatureRegistration-ийн JSON түлхүүрүүдтэй ЯГ тэнцүү (CA DisallowUnknownFields — илүү талбар 400, дутуу нь
// SDK шинэ талбарыг дамжуулж чадахгүй).
func TestContractPDFSignaturesBody(t *testing.T) {
	var d struct {
		Endpoints struct {
			PDF map[string]string `json:"pdf"`
		} `json:"endpoints"`
	}
	fetchJSON(t, eidDiscoveryURL, &d)
	desc := d.Endpoints.PDF["signatures"]
	i, j := strings.IndexByte(desc, '{'), strings.IndexByte(desc, '}')
	if i < 0 || j < i {
		t.Fatalf("endpoints.pdf.signatures-д бие алга: %q", desc)
	}
	var want []string
	for _, f := range strings.Split(desc[i+1:j], ",") {
		want = append(want, strings.TrimSuffix(strings.TrimSpace(f), "?"))
	}
	var got []string
	rt := reflect.TypeOf(PDFSignatureRegistration{})
	for k := range rt.NumField() {
		if name := strings.Split(rt.Field(k).Tag.Get("json"), ",")[0]; name != "-" { // SDK-ийн дотоод (PriorSignatures)
			got = append(got, name)
		}
	}
	sort.Strings(want)
	sort.Strings(got)
	if strings.Join(want, ",") != strings.Join(got, ",") {
		t.Fatalf("POST /pdf/signatures бие зөрөв:\ndiscovery %v\nSDK       %v", want, got)
	}
}

// TestContractShare — discovery-ийн endpoints.share-ийн multipart талбарууд ({file, filename?, to (1–5), …}) нь
// shareFormFields-тэй ЯГ тэнцүү (CA үл мэдэгдэх талбарыг 400-аар татгалздаг), share блок ShareInfo-д задарна.
func TestContractShare(t *testing.T) {
	var d struct {
		RPAPIBase string         `json:"rp_api_base"`
		Endpoints map[string]any `json:"endpoints"`
		Share     *ShareInfo     `json:"share"`
	}
	fetchJSON(t, eidDiscoveryURL, &d)
	desc, _ := d.Endpoints["share"].(string)
	if !strings.HasPrefix(desc, "POST "+d.RPAPIBase+routeShare.path+" ") {
		t.Fatalf("endpoints.share: %q", desc)
	}
	i, j := strings.IndexByte(desc, '{'), strings.IndexByte(desc, '}')
	if i < 0 || j < i {
		t.Fatalf("endpoints.share-д талбар алга: %q", desc)
	}
	var want []string
	for _, f := range strings.Split(desc[i+1:j], ",") {
		f = strings.TrimSpace(f)
		if k := strings.IndexByte(f, ' '); k >= 0 { // "to (1–5)"
			f = f[:k]
		}
		want = append(want, strings.TrimSuffix(f, "?"))
	}
	got := append([]string(nil), shareFormFields...)
	sort.Strings(want)
	sort.Strings(got)
	if strings.Join(want, ",") != strings.Join(got, ",") {
		t.Fatalf("POST /share талбар зөрөв:\ndiscovery %v\nSDK       %v", want, got)
	}
	s := d.Share
	if s == nil {
		t.Fatal("discovery-д share блок алга")
	}
	if s.Endpoint != d.RPAPIBase+routeShare.path || s.MaxFileBytes <= 0 || s.MaxRecipients <= 0 || len(s.Formats) == 0 ||
		s.Quota.PerRPHour <= 0 || s.Quota.PerRPDay <= 0 || s.Quota.PerRecipientDay <= 0 {
		t.Fatalf("share блок: %+v", s)
	}
	t.Logf("share.enabled=%v maxFileBytes=%d maxRecipients=%d quota=%+v", s.Enabled, s.MaxFileBytes, s.MaxRecipients, s.Quota)
}

// TestContractTokenCertificate — discovery-ийн tokenCertificate блок TokenCertInfo-д задарч, issue/result нь
// routes.go-тэй таарна; scopeLockedOnRenewal (CA !373) true.
func TestContractTokenCertificate(t *testing.T) {
	var d struct {
		RPAPIBase        string         `json:"rp_api_base"`
		TokenCertificate *TokenCertInfo `json:"tokenCertificate"`
	}
	fetchJSON(t, eidDiscoveryURL, &d)
	i := d.TokenCertificate
	if i == nil {
		t.Fatal("discovery-д tokenCertificate блок алга")
	}
	if i.Issue != d.RPAPIBase+routeTokenCertificate.path || i.Result != d.RPAPIBase+routeTokenCertificateResult.path ||
		!i.ScopeLockedOnRenewal {
		t.Fatalf("tokenCertificate блок: %+v", i)
	}
}

// TestContractPDFRegisterErrorCodes — discovery-ийн pdfSigning.registerErrorCodes == PDFRegisterErrorCodes (олонлогоор).
// CA-д талбар гарахаас өмнө skip + WARN (гарсны дараа тулгалт заавал). TS SDK-ийн contract тесттэй ижил.
func TestContractPDFRegisterErrorCodes(t *testing.T) {
	var d struct {
		PDFSigning struct {
			RegisterErrorCodes *[]string `json:"registerErrorCodes"`
		} `json:"pdfSigning"`
	}
	fetchJSON(t, eidDiscoveryURL, &d)
	if d.PDFSigning.RegisterErrorCodes == nil {
		warn("pdfSigning.registerErrorCodes discovery-д алга", []string{"CA-д нэмэгдсэний дараа тулгалт идэвхжинэ"})
		t.Skip("pdfSigning.registerErrorCodes алга")
	}
	set := func(xs []string) string {
		m := map[string]bool{}
		for _, x := range xs {
			m[x] = true
		}
		var out []string
		for x := range m {
			out = append(out, x)
		}
		sort.Strings(out)
		return strings.Join(out, ",")
	}
	if got, want := set(*d.PDFSigning.RegisterErrorCodes), set(PDFRegisterErrorCodes[:]); got != want {
		t.Fatalf("CA ↔ SDK кодын олонлог зөрсөн:\nCA  %s\nSDK %s", got, want)
	}
}
