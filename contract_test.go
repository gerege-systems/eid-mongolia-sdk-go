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

	var uncovered []string
	for _, e := range eps {
		if k, ok := rpKey(e); !ok || !covered[k] {
			uncovered = append(uncovered, e.method+" "+e.url)
		}
	}
	sort.Strings(uncovered)
	warn("discovery-д байгаа ч SDK хамраагүй", uncovered)
	t.Logf("SDK %d зам тулгав; discovery-д SDK хамраагүй %d (WARN)", len(rpRoutes), len(uncovered))
}
