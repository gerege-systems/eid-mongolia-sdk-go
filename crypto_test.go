package eid

import (
	"encoding/base64"
	"strings"
	"testing"
)

// smartIDVector — Smart-ID RP-API v3 docs (signature_protocols.html)-ийн албан ёсны вектор. CA сервер
// (acsp_test.go), iOS, Android, TS SDK бүгд ЭНЭ digest-ийг гаргана.
var smartIDVector = ACSPV2Params{
	ServerRandom:        "MTlop6EXCrQ6FOErcKjxUhbV",
	RPChallenge:         "GYS+yoah6emAcVDNIajwSs6UB/M95XrDxMzXBUkwQJ9YFDipXXzGpPc7raWcuc2+TEoRc7WvIZ/7dU/iRXenYg==",
	UserChallenge:       "GnsWXXEjTCKR89fj9uo5u5ReBZ9JR7_pezLAI5jMS00",
	RelyingPartyName:    "DEMO",
	BrokeredRpName:      "Example RP",
	Interactions:        "W3sidHlwZSI6ImNvbmZpcm1hdGlvbk1lc3NhZ2UiLCJkaXNwbGF5VGV4dDIwMCI6IkxvbmdlciBkZXNjcmlwdGlvbiBvZiB0aGUgdHJhbnNhY3Rpb24gY29udGV4dCJ9LHsidHlwZSI6ImRpc3BsYXlUZXh0QW5kUElOIiwiZGlzcGxheVRleHQ2MCI6IlNob3J0IGRlc2NyaXB0aW9uIG9mIHRoZSB0cmFuc2FjdGlvbiBjb250ZXh0In1d",
	InteractionTypeUsed: "confirmationMessage",
	InitialCallbackURL:  "https://rp.example.com/callback-url?value=RrKjjT4aggzu27YBddX1bQ",
	FlowType:            "Web2App",
}

func TestACSPV2_SmartIDVector(t *testing.T) {
	d, err := ACSPV2Digest(smartIDVector, SHA512)
	if err != nil {
		t.Fatal(err)
	}
	const want = "pKOjbNl/5Fy8NfrFqsj6pSn8W8O+Ik8rM33QSsbyD3J9qDJvEm90SboUciuY4wHGWa0Pnq8BgT3NJKmJiUDfKg=="
	if got := base64.StdEncoding.EncodeToString(d); got != want {
		t.Fatalf("digest\n got %s\nwant %s", got, want)
	}
	p := smartIDVector
	p.BrokeredRpName, p.InitialCallbackURL = "", ""
	s := string(BuildACSPV2Payload(p))
	if !strings.HasPrefix(s, "smart-id|ACSP_V2|MTlop6EXCrQ6FOErcKjxUhbV|") || !strings.Contains(s, "|REVNTw==||") ||
		!strings.HasSuffix(s, "|confirmationMessage||Web2App") {
		t.Fatalf("хоосон талбарын тусгаарлагч алдагдав: %s", s)
	}
	if _, err := ACSPV2Digest(smartIDVector, "MD5"); err == nil {
		t.Fatal("MD5 зөвшөөрөгдөв")
	}
}

func TestInteractionsToBase64_SmartIDVector(t *testing.T) {
	got, err := InteractionsToBase64([]Interaction{
		{Type: "confirmationMessage", DisplayText200: "Longer description of the transaction context"},
		{Type: "displayTextAndPIN", DisplayText60: "Short description of the transaction context"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != smartIDVector.Interactions {
		t.Fatalf("interactions base64\n got %s\nwant %s", got, smartIDVector.Interactions)
	}
	// JSON.stringify-тай ижил: HTML escape хийхгүй, кирилл UTF-8 хэвээр.
	got, _ = InteractionsToBase64([]Interaction{{Type: "displayTextAndPIN", DisplayText60: "Банк <А&Б>"}})
	raw, _ := base64.StdEncoding.DecodeString(got)
	if string(raw) != `[{"type":"displayTextAndPIN","displayText60":"Банк <А&Б>"}]` {
		t.Fatalf("JSON: %s", raw)
	}
}

func TestSHA256Base64AndChallenge(t *testing.T) {
	if got := SHA256Base64([]byte("abc")); got != "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=" {
		t.Fatal(got)
	}
	c, err := RandomChallenge(0)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := base64.StdEncoding.DecodeString(c); len(b) != 64 {
		t.Fatalf("challenge %d байт", len(b))
	}
	if c2, _ := RandomChallenge(0); c2 == c {
		t.Fatal("challenge давтагдав")
	}
}

func TestInteractionsToBase64_LineSeparators(t *testing.T) {
	got, _ := InteractionsToBase64([]Interaction{{Type: "x", DisplayText60: "a\u2028b\u2029c \\u2028 \\\u2028"}})
	raw, _ := base64.StdEncoding.DecodeString(got)
	// JSON.stringify: U+2028/2029 түүхийгээр, «\» → «\\»
	if want := "[{\"type\":\"x\",\"displayText60\":\"a\u2028b\u2029c \\\\u2028 \\\\\u2028\"}]"; string(raw) != want {
		t.Fatalf("\n got %s\nwant %s", raw, want)
	}
}
