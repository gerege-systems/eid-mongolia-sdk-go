package eid

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// testdata/devicelink_golden.json — ca-eidmongolia-mn server/internal/crypto/testdata/devicelink_golden.json-ийн
// ЗАСВАРГҮЙ хуулбар (TS SDK test/fixtures-тэй байт-ижил). Сервер, iOS, Android, TS, Go бүгд байт-ижил гаргана.
type goldenFile struct {
	Vectors []struct {
		Name  string `json:"name"`
		Input struct {
			DeviceLinkBase      string `json:"deviceLinkBase"`
			SchemeName          string `json:"schemeName"`
			SessionSecret       string `json:"sessionSecret"`
			DeviceLinkType      string `json:"deviceLinkType"`
			ElapsedSeconds      *int64 `json:"elapsedSeconds"`
			SessionToken        string `json:"sessionToken"`
			SessionType         string `json:"sessionType"`
			Lang                string `json:"lang"`
			RPChallengeOrDigest string `json:"rpChallengeOrDigest"`
			RelyingPartyName    string `json:"relyingPartyName"`
			BrokeredRpName      string `json:"brokeredRpName"`
			Interactions        string `json:"interactions"`
			InitialCallbackURL  string `json:"initialCallbackUrl"`
		} `json:"input"`
		AuthCode   string `json:"authCode"`
		DeviceLink string `json:"deviceLink"`
	} `json:"vectors"`
	Invalid []struct {
		Name string `json:"name"`
		Link string `json:"link"`
	} `json:"invalid"`
}

var receivedAt = time.UnixMilli(1_790_000_000_123)

func loadGolden(t *testing.T) goldenFile {
	t.Helper()
	b, err := os.ReadFile("testdata/devicelink_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var g goldenFile
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	return g
}

func goldenInput(g goldenFile, name string, extra time.Duration) DeviceLinkInput {
	for _, v := range g.Vectors {
		if v.Name != name {
			continue
		}
		i := v.Input
		in := DeviceLinkInput{
			DeviceLinkBase: i.DeviceLinkBase, DeviceLinkType: DeviceLinkType(i.DeviceLinkType),
			SessionToken: i.SessionToken, SessionSecret: i.SessionSecret, SessionType: DeviceLinkSessionType(i.SessionType),
			Lang: i.Lang, ReceivedAt: receivedAt, RelyingPartyName: i.RelyingPartyName, Interactions: i.Interactions,
			InitialCallbackURL: i.InitialCallbackURL, SchemeName: i.SchemeName, BrokeredRpName: i.BrokeredRpName,
		}
		var e int64
		if i.ElapsedSeconds != nil {
			e = *i.ElapsedSeconds
		}
		in.Now = receivedAt.Add(time.Duration(e)*time.Second + extra)
		switch in.SessionType {
		case SessionAuth:
			in.RPChallenge = i.RPChallengeOrDigest
		case SessionSign:
			in.Digest = i.RPChallengeOrDigest
		}
		return in
	}
	panic("golden вектор алга: " + name)
}

func TestBuildDeviceLink_Golden(t *testing.T) {
	g := loadGolden(t)
	if len(g.Vectors) != 15 {
		t.Fatalf("вектор %d", len(g.Vectors))
	}
	produced := map[string]bool{}
	for _, v := range g.Vectors {
		for _, extra := range []time.Duration{0, 999 * time.Millisecond} { // floor
			got, err := BuildDeviceLink(goldenInput(g, v.Name, extra))
			if err != nil {
				t.Fatalf("%s: %v", v.Name, err)
			}
			if got != v.DeviceLink {
				t.Fatalf("%s (+%v)\n got %s\nwant %s", v.Name, extra, got, v.DeviceLink)
			}
			produced[got] = true
		}
		if !strings.HasSuffix(v.DeviceLink, "&authCode="+v.AuthCode) {
			t.Fatal(v.Name)
		}
	}
	for _, bad := range g.Invalid {
		if produced[bad.Link] {
			t.Fatalf("invalid холбоос гарав: %s", bad.Name)
		}
	}
}

func TestBuildDeviceLink_CallbackOnlyForSameDevice(t *testing.T) {
	g := loadGolden(t)
	qr := goldenInput(g, "eid-qr-auth-e0", 0)
	want, _ := BuildDeviceLink(qr)
	qr.InitialCallbackURL = ""
	if got, _ := BuildDeviceLink(qr); got != want {
		t.Fatal("QR-д callback authCode-д орсон")
	}
	w := goldenInput(g, "eid-web2app-auth", 0)
	want, _ = BuildDeviceLink(w)
	w.InitialCallbackURL = "https://rp.example.mn/other"
	if got, _ := BuildDeviceLink(w); got == want {
		t.Fatal("Web2App-д callback authCode-д ороогүй")
	}
}

func TestBuildDeviceLink_Elapsed(t *testing.T) {
	g := loadGolden(t)
	e := func(in DeviceLinkInput) string {
		l, err := BuildDeviceLink(in)
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(l)
		return u.Query().Get("elapsedSeconds")
	}
	qr := goldenInput(g, "eid-qr-auth-e7", 0)
	qr.Now = receivedAt.Add(7999 * time.Millisecond)
	if got := e(qr); got != "7" {
		t.Fatal(got)
	}
	qr.Now = receivedAt.Add(-3 * time.Second)
	if got := e(qr); got != "0" {
		t.Fatal(got)
	}
}

func TestBuildDeviceLink_Invalid(t *testing.T) {
	g := loadGolden(t)
	qr := goldenInput(g, "eid-qr-auth-e0", 0)
	w := goldenInput(g, "eid-web2app-auth", 0)
	mod := func(base DeviceLinkInput, f func(*DeviceLinkInput)) DeviceLinkInput { f(&base); return base }
	cases := map[string]DeviceLinkInput{
		"http base":           mod(qr, func(i *DeviceLinkInput) { i.DeviceLinkBase = "http://ca.eidmongolia.mn/dl" }),
		"scheme base":         mod(qr, func(i *DeviceLinkInput) { i.DeviceLinkBase = "eidmongolia://approve" }),
		"base query":          mod(qr, func(i *DeviceLinkInput) { i.DeviceLinkBase = "https://ca.eidmongolia.mn/dl?x=1" }),
		"base empty":          mod(qr, func(i *DeviceLinkInput) { i.DeviceLinkBase = "" }),
		"type":                mod(qr, func(i *DeviceLinkInput) { i.DeviceLinkType = "Notification" }),
		"sessionType":         mod(qr, func(i *DeviceLinkInput) { i.SessionType = "login" }),
		"token &":             mod(qr, func(i *DeviceLinkInput) { i.SessionToken = "abc&vc=1" }),
		"token empty":         mod(qr, func(i *DeviceLinkInput) { i.SessionToken = "" }),
		"lang 2":              mod(qr, func(i *DeviceLinkInput) { i.Lang = "mn" }),
		"lang upper":          mod(qr, func(i *DeviceLinkInput) { i.Lang = "MON" }),
		"secret url":          mod(qr, func(i *DeviceLinkInput) { i.SessionSecret = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8" }),
		"secret empty":        mod(qr, func(i *DeviceLinkInput) { i.SessionSecret = "" }),
		"auth no challenge":   mod(qr, func(i *DeviceLinkInput) { i.RPChallenge = "" }),
		"sign no digest":      mod(qr, func(i *DeviceLinkInput) { i.SessionType = SessionSign; i.RPChallenge = "" }),
		"cert challenge":      mod(qr, func(i *DeviceLinkInput) { i.SessionType = SessionCert }),
		"QR no receivedAt":    mod(qr, func(i *DeviceLinkInput) { i.ReceivedAt = time.Time{} }),
		"Web2App no callback": mod(w, func(i *DeviceLinkInput) { i.InitialCallbackURL = "" }),
		"App2App no callback": mod(w, func(i *DeviceLinkInput) { i.DeviceLinkType = LinkApp2App; i.InitialCallbackURL = "" }),
	}
	for name, in := range cases {
		_, err := BuildDeviceLink(in)
		var de *DeviceLinkError
		if !errors.As(err, &de) {
			t.Errorf("%s: DeviceLinkError хүлээв, авсан %v", name, err)
		}
	}
}

func TestTickQRDeviceLink(t *testing.T) {
	g := loadGolden(t)
	in := goldenInput(g, "eid-qr-auth-e0", 0)
	in.ReceivedAt = time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	var links []string
	done := make(chan error, 1)
	go func() {
		done <- TickQRDeviceLink(ctx, in, 5*time.Millisecond, func(l string) {
			mu.Lock()
			links = append(links, l)
			mu.Unlock()
		})
	}()
	time.Sleep(40 * time.Millisecond)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	mu.Lock()
	n := len(links)
	mu.Unlock()
	if n < 3 || !strings.Contains(links[0], "deviceLinkType=QR&elapsedSeconds=0&") {
		t.Fatalf("ticks %d %v", n, links)
	}
	in.SessionSecret = ""
	var de *DeviceLinkError
	if err := TickQRDeviceLink(context.Background(), in, 0, func(string) {}); !errors.As(err, &de) {
		t.Fatal(err)
	}
}
