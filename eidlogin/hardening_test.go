package eidlogin

// rp-conformance/2 хатуужуулалтын unit тест (Java SDK 0.2.0 EidLogin.ipKey / windowLimiter-тэй ижил утгууд).
// HTTP протоколын түвшинг ../testdata/conformance/eidlogin/scenarios.json (eidlogin/2) шалгана.

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIPKey(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.7":                   "203.0.113.7",
		"2001:db8:1:2::1":               "2001:db8:1:2::/64",
		"2001:DB8:0001:0002:ffff::7":    "2001:db8:1:2::/64",
		"[2001:db8:1:3::1]":             "2001:db8:1:3::/64",
		"fe80::1%eth0":                  "fe80:0:0:0::/64",
		"::1":                           "0:0:0:0::/64",
		"::ffff:203.0.113.7":            "203.0.113.7",
		"[::ffff:cb00:7107]":            "203.0.113.7",
		"1.2.3.4:5678":                  "1.2.3.4:5678",
		"not:an:ip":                     "not:an:ip",
		"2001:db8:aaaa:bbbb:cccc::dddd": "2001:db8:aaaa:bbbb::/64",
	} {
		if got := ipKey(in); got != want {
			t.Errorf("ipKey(%q) = %q ≠ %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"": "unknown", "  ": "unknown", " 203.0.113.7 ": "203.0.113.7"} {
		if got := startKey(in); got != want {
			t.Errorf("startKey(%q) = %q ≠ %q", in, got, want)
		}
	}
}

func TestWindowLimiterOverflowBucket(t *testing.T) {
	allow := windowLimiter(2, time.Minute, 2)
	ctx := context.Background()
	steps := []struct {
		key  string
		want bool
	}{
		{"start:a", true}, {"start:b", true}, // хүснэгт дүүрэв
		{"start:c", true}, {"start:d", true}, {"start:e", false}, // overflow bucket (2)
		{"start:a", true}, {"start:a", false}, // байгаа тоолуур хэвээр
		{"start:b", true}, {"start:b", false},
	}
	for i, s := range steps {
		if got := allow(ctx, s.key); got != s.want {
			t.Fatalf("алхам %d %s: %v ≠ %v", i, s.key, got, s.want)
		}
	}
}

func TestDefaultCookieNameAndDuplicates(t *testing.T) {
	for _, c := range []struct {
		cfg  Config
		want string
	}{
		{Config{CookiePath: "/"}, "__Host-eid_login"},
		{Config{CookiePath: "/", InsecureCookie: true}, "eid_login"},
		{Config{CookiePath: "/", CookieDomain: "rp.example.test"}, "eid_login"},
		{Config{CookiePath: "/auth"}, "eid_login"},
	} {
		if got := defaultCookieName(c.cfg); got != c.want {
			t.Errorf("%+v: %s ≠ %s", c.cfg, got, c.want)
		}
	}
	for header, ok := range map[string]bool{
		"a=1; __Host-eid_login=x.y":                       true,
		"__Host-eid_login=x.y; __Host-eid_login=z":        false,
		"__Host-eid_login=x.y; __Host-eid_login=\"\xff\"": false, // утга нь net/http-д хүчингүй ч тоологдоно
		"eid_login=x.y": false,
	} {
		r := httptest.NewRequest("GET", "/auth/eid/status", nil)
		r.Header.Set("Cookie", header)
		if v, got := singleCookie(r, "__Host-eid_login"); got != ok || (ok && v != "x.y") {
			t.Errorf("%q: %q %v ≠ %v", header, v, got, ok)
		}
	}
	r := httptest.NewRequest("GET", "/auth/eid/status", nil)
	r.Header.Add("Cookie", "__Host-eid_login=x.y")
	r.Header.Add("Cookie", "__Host-eid_login=z")
	if _, ok := singleCookie(r, "__Host-eid_login"); ok {
		t.Error("хоёр Cookie header-т тарьсан cookie тоологдсонгүй")
	}
}
