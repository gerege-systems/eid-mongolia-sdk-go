package eid

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

// CA !357 (2026-10-14): session start-ын expiresAt (RFC 3339) ба 409 NO_SIGNING_CERTIFICATE / 409
// CERT_CHOICE_INVALID / 400 REQUEST_INVALID.
func TestSessionStartCAExpiresAt(t *testing.T) {
	const exp = "2026-10-14T14:10:00Z"
	want, _ := time.Parse(time.RFC3339, exp)
	c, _ := server(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "device-link") {
			jsonReply(200, strings.TrimSuffix(dlReply, "}")+`,"expiresAt":"`+exp+`"}`)(w, r)
			return
		}
		jsonReply(200, `{"sessionID":"s1","vc":{"type":"alphaNumeric5","value":"54321"},"expiresAt":"`+exp+`"}`)(w, r)
	})
	ctx := context.Background()
	ix := []Interaction{{Type: "displayTextAndPIN", DisplayText60: "x"}}
	n, err := c.Sign.DigestByEtsi(ctx, "PNOMN-1", SHA256Base64(nil), ix, nil)
	if err != nil || !n.ExpiresAt.Equal(want) {
		t.Fatal("sign push", n, err)
	}
	d, err := c.Sign.DeviceLinkByEtsi(ctx, "PNOMN-1", SHA256Base64(nil), ix, nil)
	if err != nil || !d.ExpiresAt.Equal(want) {
		t.Fatal("sign device-link", d, err)
	}
	cc, err := c.Sign.CertificateChoiceByEtsi(ctx, "PNOMN-1", nil)
	if err != nil || !cc.ExpiresAt.Equal(want) {
		t.Fatal("cert-choice", cc, err)
	}
	a, err := c.Auth.NotificationByEtsi(ctx, "PNOMN-1", ix, nil)
	if err != nil || !a.ExpiresAt.Equal(want) {
		t.Fatal("auth push", a, err)
	}
	ad, err := c.Auth.DeviceLinkAnonymous(ctx, ix, nil)
	if err != nil || !ad.ExpiresAt.Equal(want) {
		t.Fatal("auth device-link", ad, err)
	}
}

func TestSessionStartExpiresAtFallback(t *testing.T) {
	c, _ := server(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "device-link") {
			jsonReply(200, dlReply)(w, r)
			return
		}
		jsonReply(200, `{"sessionID":"s1","vc":{"type":"alphaNumeric5","value":"54321"},"expiresAt":"маргааш"}`)(w, r)
	})
	ctx := context.Background()
	ix := []Interaction{{Type: "displayTextAndPIN", DisplayText60: "x"}}
	n, err := c.Sign.DigestByEtsi(ctx, "PNOMN-1", SHA256Base64(nil), ix, nil)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(n.ExpiresAt); d < DefaultSignSessionTTL-5*time.Second || d > DefaultSignSessionTTL {
		t.Fatal("тооцоолол", d)
	}
	ad, err := c.Auth.DeviceLinkAnonymous(ctx, ix, nil)
	if err != nil || !ad.ExpiresAt.IsZero() {
		t.Fatal("auth талбаргүй → тэг", ad.ExpiresAt, err)
	}
}

func TestSessionStartTypedErrors(t *testing.T) {
	for _, tc := range []struct {
		status int
		code   string
		target error
	}{
		{409, CodeNoSigningCertificate, ErrNoSigningCertificate},
		{409, CodeCertChoiceInvalid, ErrCertChoiceInvalid},
		{400, CodeRequestInvalid, ErrRequestInvalid},
	} {
		c, _ := server(t, jsonReply(tc.status, `{"error":"x","code":"`+tc.code+`"}`))
		_, err := c.Sign.DigestByEtsi(context.Background(), "PNOMN-1", SHA256Base64(nil), nil, nil)
		if !errors.Is(err, tc.target) {
			t.Fatalf("%s: errors.Is false: %v", tc.code, err)
		}
		var ae *APIError
		if !errors.As(err, &ae) || ae.Status != tc.status || ae.Code != tc.code {
			t.Fatalf("%s: %+v", tc.code, ae)
		}
		for _, other := range []error{ErrNoSigningCertificate, ErrCertChoiceInvalid, ErrRequestInvalid} {
			if other != tc.target && errors.Is(err, other) {
				t.Fatalf("%s нь %v биш", tc.code, other)
			}
		}
	}
}
