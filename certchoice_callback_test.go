package eid

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestCertificateChoiceDeviceLink_Callback(t *testing.T) {
	c, rc := server(t, jsonReply(200, dlReply))
	ctx := context.Background()

	s, err := c.Sign.CertificateChoiceDeviceLink(ctx, &CertChoiceOptions{CallbackURL: " https://rp.example.mn/auth/eid/callback?value=abc "})
	if err != nil {
		t.Fatal(err)
	}
	req, body := rc.last()
	m := bodyMap(t, body)
	if req.URL.Path != "/signature/certificate-choice/device-link/anonymous" ||
		m["initialCallbackUrl"] != "https://rp.example.mn/auth/eid/callback?value=abc" ||
		keys(m) != "certificateLevel,initialCallbackUrl,relyingPartyName,relyingPartyUUID" && keys(m) != "initialCallbackUrl,relyingPartyName,relyingPartyUUID" {
		t.Fatal(req.URL.Path, m)
	}
	if s.CallbackURL != "https://rp.example.mn/auth/eid/callback?value=abc" || s.SessionType != SessionCert {
		t.Fatal(s)
	}

	// callback-гүй: талбар явахгүй.
	if _, err = c.Sign.CertificateChoiceDeviceLink(ctx, nil); err != nil {
		t.Fatal(err)
	}
	_, body = rc.last()
	if _, ok := bodyMap(t, body)["initialCallbackUrl"]; ok {
		t.Fatalf("callback-гүй хүсэлтэд initialCallbackUrl: %s", body)
	}
}

func TestCertificateChoiceByEtsi_NoCallback(t *testing.T) {
	c, rc := server(t, jsonReply(200, `{"sessionID":"s1","vc":{"type":"alphaNumeric5","value":"54321"}}`))
	if _, err := c.Sign.CertificateChoiceByEtsi(context.Background(), "PNOMN-1", &CertChoiceOptions{CallbackURL: "https://rp.example.mn/cb"}); err != nil {
		t.Fatal(err)
	}
	_, body := rc.last()
	if _, ok := bodyMap(t, body)["initialCallbackUrl"]; ok {
		t.Fatalf("notification cert-choice initialCallbackUrl илгээв: %s", body)
	}
}

func TestCertChoiceLinkInput_Callback(t *testing.T) {
	c, _ := server(t, jsonReply(200, dlReply))
	ctx := context.Background()
	const cb = "https://rp.example.mn/auth/eid/callback?value=abc"

	with, err := c.Sign.CertificateChoiceDeviceLink(ctx, &CertChoiceOptions{CallbackURL: cb})
	if err != nil {
		t.Fatal(err)
	}
	for _, lt := range []DeviceLinkType{LinkWeb2App, LinkApp2App} {
		l, err := BuildDeviceLink(with.LinkInput(lt, "mon"))
		if err != nil {
			t.Fatalf("%s: %v", lt, err)
		}
		u, _ := url.Parse(l)
		if u.Query().Get("sessionType") != "cert" || u.Query().Get("deviceLinkType") != string(lt) {
			t.Fatal(l)
		}
	}

	without, err := c.Sign.CertificateChoiceDeviceLink(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var de *DeviceLinkError
	if _, err := BuildDeviceLink(without.LinkInput(LinkWeb2App, "mon")); err == nil || !errors.As(err, &de) {
		t.Fatalf("callback-гүй Web2App DeviceLinkError хүлээв: %v", err)
	}

	// QR: authCode callback-ээс хамаарахгүй.
	now := with.ReceivedAt.Add(3 * time.Second)
	a, b := with.LinkInput(LinkQR, "mon"), without.LinkInput(LinkQR, "mon")
	a.Now, b.Now, b.ReceivedAt = now, now, a.ReceivedAt
	la, err1 := BuildDeviceLink(a)
	lb, err2 := BuildDeviceLink(b)
	if err1 != nil || err2 != nil || la != lb {
		t.Fatal("QR authCode callback-ээс хамаарсан", err1, err2)
	}
	if strings.Contains(la, "callback") {
		t.Fatal(la)
	}
}

func TestSessionSecretDigest(t *testing.T) {
	const secret = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	const want = "Yw3NKWbEM2aRElRIu7JbT_QSpJxzLbLIq8G4WBvXEN0"
	got, err := SessionSecretDigest(secret)
	if err != nil || got != want {
		t.Fatal(got, err)
	}
	// base64url fallback (ижил байт).
	if g, err := SessionSecretDigest("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"); err != nil || g != want {
		t.Fatal(g, err)
	}
	if !VerifySessionSecretDigest(want, secret) {
		t.Fatal("зөв digest false")
	}
	for name, d := range map[string]string{"өөр": "Yw3NKWbEM2aRElRIu7JbT_QSpJxzLbLIq8G4WBvXEN1", "хоосон": "", "богино": want[:10]} {
		if VerifySessionSecretDigest(d, secret) {
			t.Fatal(name)
		}
	}
	if VerifySessionSecretDigest(want, "") || VerifySessionSecretDigest(want, "***") {
		t.Fatal("буруу secret true")
	}
	if _, err := SessionSecretDigest("***"); err == nil {
		t.Fatal("буруу secret алдаагүй")
	}
}
