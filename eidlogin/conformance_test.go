package eidlogin

// ../testdata/conformance/eidlogin/scenarios.json (eidlogin/1) — Handler-ийг гараар бичигдсэн HTTP сценариор
// ажиллуулна. Формат ба matcher-ууд: ../testdata/conformance/README.md §eidlogin. TS createEidLogin ижил файлыг
// ажиллуулна.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	eid "github.com/gerege-systems/eid-mongolia-sdk-go"
)

type confRule struct {
	Method             string  `json:"method"`
	Path               string  `json:"path"`
	PathPrefix         string  `json:"pathPrefix"`
	Status             int     `json:"status"`
	ContentType        string  `json:"contentType"`
	Body               any     `json:"body"`
	BodyText           *string `json:"bodyText"`
	ExpiresAtInSeconds int     `json:"expiresAtInSeconds"`
}

type confStep struct {
	Repeat   int            `json:"repeat"`
	Upstream []confRule     `json:"upstream"`
	Request  confReq        `json:"request"`
	Expect   map[string]any `json:"expect"`
}

type confReq struct {
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	Headers    map[string]string `json:"headers"`
	JSON       any               `json:"json"`
	Text       *string           `json:"text"`
	CookieFrom *int              `json:"cookieFrom"`
	IP         string            `json:"ip"`
}

type confScenario struct {
	Name          string            `json:"name"`
	Config        map[string]any    `json:"config"`
	Upstream      []confRule        `json:"upstream"`
	Steps         []confStep        `json:"steps"`
	Events        *[]map[string]any `json:"events"`
	RateLimitKeys *[]string         `json:"rateLimitKeys"`
}

type confResult struct {
	status  int
	json    map[string]any
	header  http.Header
	cookies map[string]string // eid_login cookie: "" key = value, бусад = attribute
}

const confClientIPHeader = "X-Conformance-Client-IP"

func TestConformanceScenarios(t *testing.T) {
	b, err := os.ReadFile("../testdata/conformance/eidlogin/scenarios.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Config    map[string]any `json:"config"`
		Upstream  []confRule     `json:"upstream"`
		Scenarios []confScenario `json:"scenarios"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	for _, sc := range f.Scenarios {
		t.Run(sc.Name, func(t *testing.T) { runConfScenario(t, f.Config, f.Upstream, sc) })
	}
}

func runConfScenario(t *testing.T, base map[string]any, baseUp []confRule, sc confScenario) {
	cfg := map[string]any{}
	for k, v := range base {
		cfg[k] = v
	}
	for k, v := range sc.Config {
		cfg[k] = v
	}
	cs := func(k string) string { s, _ := cfg[k].(string); return s }
	cn := func(k string) float64 { n, _ := cfg[k].(float64); return n }

	var mu sync.Mutex
	rules := append(append([]confRule{}, sc.Upstream...), baseUp...)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		for _, ru := range rules {
			if ru.Method != r.Method || (ru.Path != "" && ru.Path != r.URL.Path) || (ru.PathPrefix != "" && !strings.HasPrefix(r.URL.Path, ru.PathPrefix)) {
				continue
			}
			ct := ru.ContentType
			if ct == "" {
				ct = "application/json"
			}
			w.Header().Set("Content-Type", ct)
			var body []byte
			if ru.BodyText != nil {
				body = []byte(*ru.BodyText)
			} else {
				m, _ := ru.Body.(map[string]any)
				if ru.ExpiresAtInSeconds > 0 {
					m2 := map[string]any{}
					for k, v := range m {
						m2[k] = v
					}
					m2["expiresAt"] = time.Now().Add(time.Duration(ru.ExpiresAtInSeconds) * time.Second).UTC().Format(time.RFC3339)
					m = m2
				}
				body, _ = json.Marshal(m)
			}
			w.WriteHeader(ru.Status)
			_, _ = w.Write(body)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"error":"not found"}`)
	}))
	defer srv.Close()

	client, err := eid.NewClient(eid.Config{BaseURL: srv.URL, Credentials: eid.Credentials{RPUUID: cs("rpUUID"), RPName: cs("rpName"),
		APISecret: cs("apiSecret")}})
	if err != nil {
		t.Fatal(err)
	}
	type ev struct {
		kind EventKind
		sid  string
		meta map[string]any
	}
	var events []ev
	var keys []string
	c := Config{
		Client: client,
		OnSuccess: func(http.ResponseWriter, *http.Request, *Identity) (*Success, error) {
			return &Success{Redirect: "/dashboard"}, nil
		},
		CallbackURL:       cs("callbackUrl"),
		SuccessRedirect:   cs("successRedirect"),
		FailureRedirect:   cs("failureRedirect"),
		TTL:               time.Duration(cn("ttlSeconds")) * time.Second,
		Poll:              time.Duration(cn("pollMs")) * time.Millisecond,
		PushFloor:         time.Duration(cn("pushFloorMs")) * time.Millisecond,
		DisablePushFloor:  cn("pushFloorMs") == 0,
		CookieName:        cs("cookieName"),
		DisableRevocation: cs("revocation") == "disabled",
		DisableDecoy:      cfg["decoy"] == false,
		ClientIP:          func(r *http.Request) string { return r.Header.Get(confClientIPHeader) },
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		OnEvent: func(_ context.Context, kind EventKind, sid string, meta map[string]any) {
			events = append(events, ev{kind, sid, meta})
		},
	}
	if cfg["recordRateLimitKeys"] == true {
		c.RateLimit = func(_ context.Context, key string) bool { keys = append(keys, key); return true }
	}
	h, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	h.sleep = func(context.Context, time.Duration) {}

	results := make([]confResult, len(sc.Steps))
	for i, st := range sc.Steps {
		if len(st.Upstream) > 0 {
			mu.Lock()
			rules = append(append([]confRule{}, st.Upstream...), rules...)
			mu.Unlock()
		}
		n := max(st.Repeat, 1)
		for range n {
			var body io.Reader
			ctype := ""
			if st.Request.JSON != nil {
				b, _ := json.Marshal(st.Request.JSON)
				body, ctype = bytes.NewReader(b), "application/json"
			} else if st.Request.Text != nil {
				body = strings.NewReader(*st.Request.Text)
			}
			r := httptest.NewRequest(st.Request.Method, "https://rp.conformance.test"+st.Request.Path, body)
			if ctype != "" {
				r.Header.Set("Content-Type", ctype)
			}
			for k, v := range st.Request.Headers {
				r.Header.Set(k, v)
			}
			if st.Request.IP != "" {
				r.Header.Set(confClientIPHeader, st.Request.IP)
			}
			if st.Request.CookieFrom != nil {
				if v, ok := results[*st.Request.CookieFrom].cookies[""]; ok {
					r.Header.Set("Cookie", cs("cookieName")+"="+v)
				}
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			res := confResult{status: w.Code, header: w.Header()}
			if strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
				_ = json.Unmarshal(w.Body.Bytes(), &res.json)
			}
			for _, setc := range w.Header().Values("Set-Cookie") {
				if strings.HasPrefix(setc, cs("cookieName")+"=") {
					res.cookies = parseConfCookie(setc)
				}
			}
			results[i] = res
			if err := confCheckStep(st.Expect, res, results); err != nil {
				t.Fatalf("алхам %d: %v (status %d, json %v, Set-Cookie %v)", i, err, res.status, res.json, w.Header().Values("Set-Cookie"))
			}
		}
	}
	if sc.Events != nil {
		if len(events) != len(*sc.Events) {
			t.Fatalf("events %d ≠ %d: %+v", len(events), len(*sc.Events), events)
		}
		for i, want := range *sc.Events {
			got := events[i]
			if string(got.kind) != want["kind"] {
				t.Fatalf("event %d: %s ≠ %v", i, got.kind, want["kind"])
			}
			if ws, ok := want["sessionId"]; ok {
				var gs any = got.sid
				if got.sid == "" {
					gs = nil
				}
				if err := confMatch(ws, gs, results); err != nil {
					t.Fatalf("event %d sessionId: %v", i, err)
				}
			}
			if wm, ok := want["meta"]; ok {
				if err := confMatch(wm, confNorm(got.meta), results); err != nil {
					t.Fatalf("event %d meta: %v (%v)", i, err, got.meta)
				}
			}
		}
	}
	if sc.RateLimitKeys != nil && !slices.Equal(keys, *sc.RateLimitKeys) {
		t.Fatalf("rate limit keys %q ≠ %q", keys, *sc.RateLimitKeys)
	}
}

func confNorm(v any) any {
	b, _ := json.Marshal(v)
	var out any
	_ = json.Unmarshal(b, &out)
	return out
}

func parseConfCookie(sc string) map[string]string {
	out := map[string]string{}
	for i, part := range strings.Split(sc, ";") {
		part = strings.TrimSpace(part)
		k, v, has := strings.Cut(part, "=")
		if i == 0 {
			out[""] = v
			continue
		}
		if !has {
			v = "true"
		}
		out[strings.ToLower(k)] = v
	}
	return out
}

func confKeys(m map[string]any) []string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return k
}

func confCheckStep(e map[string]any, res confResult, all []confResult) error {
	if s, ok := e["status"].(float64); ok && int(s) != res.status {
		return fmt.Errorf("status %d ≠ %v", res.status, s)
	}
	if ks, ok := e["jsonKeys"].([]any); ok {
		var want []string
		for _, k := range ks {
			want = append(want, k.(string))
		}
		sort.Strings(want)
		if !slices.Equal(confKeys(res.json), want) {
			return fmt.Errorf("json keys %v ≠ %v", confKeys(res.json), want)
		}
	}
	if i, ok := e["sameKeysAs"].(float64); ok && !slices.Equal(confKeys(res.json), confKeys(all[int(i)].json)) {
		return fmt.Errorf("json keys %v ≠ алхам %d-ийн %v", confKeys(res.json), int(i), confKeys(all[int(i)].json))
	}
	if j, ok := e["json"]; ok {
		if err := confMatch(j, confNorm(res.json), all); err != nil {
			return fmt.Errorf("json: %w", err)
		}
	}
	if l, ok := e["location"]; ok {
		if err := confMatch(l, res.header.Get("Location"), all); err != nil {
			return fmt.Errorf("location: %w", err)
		}
	}
	if hs, ok := e["headers"].(map[string]any); ok {
		for k, v := range hs {
			if got := res.header.Get(k); got != v {
				return fmt.Errorf("header %s %q ≠ %q", k, got, v)
			}
		}
	}
	if e["noSetCookie"] == true && res.cookies != nil {
		return fmt.Errorf("Set-Cookie байх ёсгүй")
	}
	if sc, ok := e["setCookie"].(map[string]any); ok {
		if res.cookies == nil {
			return fmt.Errorf("Set-Cookie алга")
		}
		if sc["cleared"] == true && (res.cookies[""] != "" || res.cookies["max-age"] != "0") {
			return fmt.Errorf("cookie цэвэрлэгдээгүй: %v", res.cookies)
		}
		if v, ok := sc["value"]; ok {
			if err := confMatch(v, res.cookies[""], all); err != nil {
				return fmt.Errorf("cookie value: %w", err)
			}
		}
		if attrs, ok := sc["attributes"].(map[string]any); ok {
			for k, v := range attrs {
				got, has := res.cookies[strings.ToLower(k)]
				if v == true {
					if !has {
						return fmt.Errorf("cookie %s алга", k)
					}
					continue
				}
				if err := confMatch(v, got, all); err != nil {
					return fmt.Errorf("cookie %s: %w", k, err)
				}
			}
		}
	}
	return nil
}

// confMatch — want (README §eidlogin matcher-ууд) ба got.
func confMatch(want, got any, all []confResult) error {
	if m, ok := want.(map[string]any); ok {
		if re, ok := m["$re"].(string); ok {
			if s := confStr(got); !regexp.MustCompile(re).MatchString(s) {
				return fmt.Errorf("%q ≁ /%s/", s, re)
			}
			return nil
		}
		if rg, ok := m["$range"].([]any); ok {
			n, ok := got.(float64)
			if !ok || n < rg[0].(float64) || n > rg[1].(float64) {
				return fmt.Errorf("%v ∉ %v", got, rg)
			}
			return nil
		}
		if ref, ok := m["$sameAs"].(string); ok {
			parts := strings.SplitN(ref, ".", 3)
			var idx int
			if _, err := fmt.Sscan(parts[0], &idx); err != nil {
				return err
			}
			src := confNorm(all[idx].json).(map[string]any)[parts[2]]
			if confStr(src) != confStr(got) {
				return fmt.Errorf("%v ≠ %s (%v)", got, ref, src)
			}
			return nil
		}
		gm, ok := got.(map[string]any)
		if !ok {
			return fmt.Errorf("объект хүлээсэн: %v", got)
		}
		for k, w := range m {
			if err := confMatch(w, gm[k], all); err != nil {
				return fmt.Errorf("%s: %w", k, err)
			}
		}
		return nil
	}
	if want == nil {
		if got != nil {
			return fmt.Errorf("null хүлээсэн: %v", got)
		}
		return nil
	}
	if fmt.Sprint(want) != fmt.Sprint(got) || (want == true) != (got == true) {
		return fmt.Errorf("%v ≠ %v", got, want)
	}
	return nil
}

func confStr(v any) string {
	if f, ok := v.(float64); ok {
		return fmt.Sprint(int64(f))
	}
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}
