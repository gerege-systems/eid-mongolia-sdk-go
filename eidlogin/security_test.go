package eidlogin

import (
	"context"
	"crypto/x509"
	"errors"
	"maps"
	"regexp"
	"slices"
	"testing"
	"time"

	eid "github.com/gerege-systems/eid-mongolia-sdk-go"
)

func (f *fakeEID) setRefuse(v string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refuse = v
}

func (f *fakeEID) otherPolled() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.polledOther
}

var vcRe = regexp.MustCompile(`^[0-9]{5}$`)

// G1: eID дугаарыг татгалзсан push нь бодит push-тэй ижил хэлбэр, ижил доод хугацаа, PENDING → EXPIRED.
func TestPushDecoyIndistinguishable(t *testing.T) {
	e := setup(t, nil)
	real := e.do(t, "POST", "/auth/eid/start", `{"mode":"push","idCode":"УБ12345678"}`, nil)
	e.fake.setRefuse("json400")
	decoy := e.do(t, "POST", "/auth/eid/start", `{"mode":"push","idCode":"УБ87654321"}`, nil)
	if real.code != 200 || decoy.code != 200 {
		t.Fatalf("status: real %d decoy %d %v", real.code, decoy.code, decoy.body)
	}
	if !slices.Equal(slices.Sorted(maps.Keys(real.body)), slices.Sorted(maps.Keys(decoy.body))) {
		t.Fatalf("талбарууд зөрүүтэй: %v ≠ %v", real.body, decoy.body)
	}
	if decoy.body["mode"] != "push" || decoy.body["expiresIn"] != real.body["expiresIn"] || !vcRe.MatchString(decoy.body["vc"].(string)) {
		t.Fatalf("decoy: %v", decoy.body)
	}
	// Хоёулаа ижил доод хугацаанд (хуурмаг цаг: эхлэл = одоо → бүтэн 1 с хүлээнэ).
	if !slices.Equal(e.sleeps, []time.Duration{time.Second, time.Second}) {
		t.Fatalf("floor: %v", e.sleeps)
	}
	rc, dc := loginCookie(t, real.header), loginCookie(t, decoy.header)
	if !uuidRe.MatchString(dc[len("eid_login=") : 36+len("eid_login=")]) {
		t.Fatalf("decoy sessionId UUID биш: %s", dc)
	}
	// Status: хоёулаа PENDING, ижил талбарууд; decoy eID-ээс асуухгүй, Poll-ын хугацаанд барина.
	e.sleeps = nil
	rp := e.do(t, "GET", "/auth/eid/status", "", map[string]string{"Cookie": rc})
	dp := e.do(t, "GET", "/auth/eid/status", "", map[string]string{"Cookie": dc})
	if rp.body["state"] != "PENDING" || dp.body["state"] != "PENDING" ||
		!slices.Equal(slices.Sorted(maps.Keys(rp.body)), slices.Sorted(maps.Keys(dp.body))) || dp.body["vc"] != decoy.body["vc"] {
		t.Fatalf("pending: real %v decoy %v", rp.body, dp.body)
	}
	if !slices.Equal(e.sleeps, []time.Duration{time.Second}) || e.fake.otherPolled() {
		t.Fatalf("decoy poll: sleeps %v, eID асуусан %v", e.sleeps, e.fake.otherPolled())
	}
	// TTL-ийн дараа EXPIRED (бодиттой ижил зам — store-ийн хугацаа).
	tx, _ := e.h.cfg.Store.Get(context.Background(), dc[len("eid_login="):36+len("eid_login=")])
	if tx == nil || !tx.Decoy {
		t.Fatalf("decoy tx: %+v", tx)
	}
	tx.ExpiresAt = time.Now().Add(-time.Second)
	_ = e.h.cfg.Store.Set(context.Background(), tx, time.Minute)
	if x := e.do(t, "GET", "/auth/eid/status", "", map[string]string{"Cookie": dc}); x.body["state"] != "EXPIRED" {
		t.Fatalf("expired: %v", x.body)
	}
	// Аудит: хоёулаа push_sent, decoy нь зөвхөн meta-д.
	if len(e.events) != 2 || e.events[0].kind != EventPushSent || e.events[0].meta["decoy"] != false ||
		e.events[1].kind != EventPushSent || e.events[1].meta["decoy"] != true {
		t.Fatalf("events: %+v", e.events)
	}
	if k := e.events[0].meta["pushKey"].(string); len(k) != 32 || k == e.events[1].meta["pushKey"] {
		t.Fatalf("pushKey: %v", e.events)
	}
	for _, ev := range e.events {
		for _, v := range ev.meta {
			if s, _ := v.(string); s == "УБ12345678" || s == "УБ87654321" {
				t.Fatalf("meta-д регистр: %v", ev.meta)
			}
		}
	}
}

// Тасалдал (5xx, proxy-ийн JSON бус 4xx, 401) — decoy биш, 502 (порталтай ижил); floor хэвээр.
func TestPushOutageNotDecoy(t *testing.T) {
	for _, mode := range []string{"500", "proxy400", "401"} {
		e := setup(t, nil)
		e.fake.setRefuse(mode)
		r := e.do(t, "POST", "/auth/eid/start", `{"mode":"push","idCode":"УБ12345678"}`, nil)
		if r.code != 502 || r.body["error"] != "eid_unavailable" || len(e.events) != 0 {
			t.Fatalf("%s: %d %v %v", mode, r.code, r.body, e.events)
		}
		if !slices.Equal(e.sleeps, []time.Duration{time.Second}) {
			t.Fatalf("%s floor: %v", mode, e.sleeps)
		}
	}
}

func TestDecoyAndFloorOptOut(t *testing.T) {
	e := setup(t, func(c *Config) { c.DisableDecoy, c.DisablePushFloor = true, true })
	e.fake.setRefuse("json400")
	if r := e.do(t, "POST", "/auth/eid/start", `{"mode":"push","idCode":"УБ12345678"}`, nil); r.code != 502 {
		t.Fatalf("DisableDecoy: %d", r.code)
	}
	if len(e.sleeps) != 0 {
		t.Fatalf("DisablePushFloor: %v", e.sleeps)
	}
	e2 := setup(t, func(c *Config) { c.PushFloor = 3 * time.Second })
	e2.do(t, "POST", "/auth/eid/start", `{"mode":"qr"}`, nil)
	e2.do(t, "POST", "/auth/eid/start", `{"mode":"push","idCode":"УБ12345678"}`, nil)
	if !slices.Equal(e2.sleeps, []time.Duration{3 * time.Second}) {
		t.Fatalf("PushFloor (зөвхөн push): %v", e2.sleeps)
	}
}

// Хязгаар decoy-д ч үйлчилнэ; push_limited event.
func TestDecoyRateLimited(t *testing.T) {
	e := setup(t, nil)
	e.fake.setRefuse("json400")
	for range 3 {
		if r := e.do(t, "POST", "/auth/eid/start", `{"mode":"push","idCode":"УБ12345678"}`, nil); r.code != 200 {
			t.Fatalf("%d", r.code)
		}
	}
	if r := e.do(t, "POST", "/auth/eid/start", `{"mode":"push","idCode":"УБ12345678"}`, nil); r.code != 429 {
		t.Fatalf("decoy хязгааргүй: %d", r.code)
	}
	if k := e.kinds(); !slices.Equal(k, []EventKind{EventPushSent, EventPushSent, EventPushSent, EventPushLimited}) {
		t.Fatalf("events %v", k)
	}
}

// G2: цуцлагдсан гэрчилгээ → FAILED VALIDATION (500 биш), OnSuccess дуудагдахгүй.
func TestRevocation(t *testing.T) {
	cases := []struct {
		name   string
		mod    func(*Config)
		state  string
		reason string
		rev    eid.RevocationStatus
	}{
		{"revoked", func(c *Config) {
			c.Revocation = func(context.Context, *x509.Certificate, *x509.Certificate) (eid.RevocationStatus, error) {
				return eid.RevocationRevoked, nil
			}
		}, "FAILED", "revoked", ""},
		{"checker error", func(c *Config) {
			c.Revocation = func(context.Context, *x509.Certificate, *x509.Certificate) (eid.RevocationStatus, error) {
				return "", errors.New("boom")
			}
		}, "FAILED", "revocation_unavailable", ""},
		{"hard-fail unknown", func(c *Config) { c.RevocationMode = eid.RevocationHardFail }, "FAILED", "revocation_unavailable", ""},
		// Анхдагч: AIA OCSP; тестийн гэрчилгээнд AIA алга → хариугүй → soft-fail зөвшөөрнө.
		{"default soft", nil, "OK", "", eid.RevocationUnchecked},
		{"good", func(c *Config) {
			c.Revocation = func(context.Context, *x509.Certificate, *x509.Certificate) (eid.RevocationStatus, error) {
				return eid.RevocationGood, nil
			}
		}, "OK", "", eid.RevocationGood},
		{"disabled", func(c *Config) { c.DisableRevocation = true }, "OK", "", eid.RevocationSkipped},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := setup(t, tc.mod)
			s := e.do(t, "POST", "/auth/eid/start", `{"mode":"qr"}`, nil)
			e.fake.set("OK", "QR", "")
			r := e.do(t, "GET", "/auth/eid/status", "", map[string]string{"Cookie": loginCookie(t, s.header)})
			if r.code != 200 || r.body["state"] != tc.state {
				t.Fatalf("%d %v", r.code, r.body)
			}
			last := e.events[len(e.events)-1]
			if tc.state == "FAILED" {
				if r.body["error"] != "VALIDATION" || len(e.ids) != 0 || last.kind != EventUnverified || last.meta["reason"] != tc.reason {
					t.Fatalf("%v ids=%d %+v", r.body, len(e.ids), last)
				}
				return
			}
			if len(e.ids) != 1 || e.ids[0].Revocation != tc.rev || last.kind != EventSuccess || last.meta["revocation"] != string(tc.rev) {
				t.Fatalf("ids %+v event %+v", e.ids, last)
			}
		})
	}
}

// G3: refused / failed / expired / unverified / flow_refused.
func TestEvents(t *testing.T) {
	e := setup(t, nil)
	for _, end := range []string{"USER_REFUSED", "WRONG_VC", "TIMEOUT"} {
		e.fake.set("", "", "")
		s := e.do(t, "POST", "/auth/eid/start", `{"mode":"qr"}`, nil)
		e.fake.set(end, "QR", "")
		e.do(t, "GET", "/auth/eid/status", "", map[string]string{"Cookie": loginCookie(t, s.header)})
	}
	if k := e.kinds(); !slices.Equal(k, []EventKind{EventRefused, EventFailed, EventExpired}) {
		t.Fatalf("%v", k)
	}
	if e.events[1].meta["endResult"] != "WRONG_VC" || e.events[0].sid != sid {
		t.Fatalf("%+v", e.events)
	}

	e = setup(t, nil)
	s := e.do(t, "POST", "/auth/eid/start", `{"mode":"qr"}`, nil)
	e.fake.mu.Lock()
	e.fake.tamper = true
	e.fake.mu.Unlock()
	e.fake.set("OK", "QR", "")
	e.do(t, "GET", "/auth/eid/status", "", map[string]string{"Cookie": loginCookie(t, s.header)})
	if len(e.events) != 1 || e.events[0].kind != EventUnverified || e.events[0].meta["reason"] != "validation" {
		t.Fatalf("%+v", e.events)
	}

	e = setup(t, nil)
	w := e.do(t, "GET", "/auth/eid/start?mode=web2app", "", nil)
	e.do(t, "GET", "/auth/eid/callback?sessionId=other&userChallengeVerifier=x", "", map[string]string{"Cookie": loginCookie(t, w.header)})
	if len(e.events) != 1 || e.events[0].kind != EventFlowRefused || e.events[0].meta["reason"] != "unbound" {
		t.Fatalf("%+v", e.events)
	}
}

// Хариугүй бодит push (CA TIMEOUT) нь decoy-той ижил EXPIRED-ээр төгсөнө (FAILED/TIMEOUT биш).
func TestPushTimeoutLooksLikeDecoy(t *testing.T) {
	e := setup(t, nil)
	s := e.do(t, "POST", "/auth/eid/start", `{"mode":"push","idCode":"УБ12345678"}`, nil)
	e.fake.set("TIMEOUT", "", "")
	r := e.do(t, "GET", "/auth/eid/status", "", map[string]string{"Cookie": loginCookie(t, s.header)})
	if len(r.body) != 1 || r.body["state"] != "EXPIRED" {
		t.Fatalf("push TIMEOUT: %v", r.body)
	}
	if k := e.kinds(); !slices.Equal(k, []EventKind{EventPushSent, EventExpired}) {
		t.Fatalf("events %v", k)
	}
}
