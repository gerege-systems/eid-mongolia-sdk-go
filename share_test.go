package eid

import (
	"context"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

// POST /share (CA docs/SHARE_EMAIL.md, main 0329ef95) ба /certificates-ийн issuedAt/revokedAt/revocationReason.

var testPDF = []byte("%PDF-1.7\n…")

func shareClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := NewClient(Config{BaseURL: srv.URL, Credentials: Credentials{RPUUID: "u", RPName: "n", APISecret: "rp_sk_x"},
		Trust: TrustConfig{AllowUntrusted: true}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type sharePart struct {
	name, filename, ctype, value string
}

func readShareParts(t *testing.T, r *http.Request) []sharePart {
	t.Helper()
	mt, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/form-data" {
		t.Fatalf("Content-Type %q", r.Header.Get("Content-Type"))
	}
	mr := multipart.NewReader(r.Body, params["boundary"])
	var out []sharePart
	for {
		p, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(p)
		out = append(out, sharePart{p.FormName(), p.FileName(), p.Header.Get("Content-Type"), string(b)})
	}
}

func TestShareRequestAndResult(t *testing.T) {
	var parts []sharePart
	c := shareClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/share" || r.Header.Get("Authorization") != "Bearer rp_sk_x" {
			t.Errorf("%s %s %q", r.Method, r.URL.Path, r.Header.Get("Authorization"))
		}
		parts = readShareParts(t, r)
		_, _ = io.WriteString(w, `{"sent":2,"sha256":"ab","signatures":1,"docID":"d-1"}`)
	})
	res, err := c.Share(context.Background(), ShareRequest{File: testPDF, Filename: "гэрээ.pdf", To: []string{"a@x.mn", "b@x.mn"},
		Subject: "Гэрээ", Message: "Зурна уу", Lang: "en"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Sent != 2 || res.SHA256 != "ab" || res.Signatures != 1 || res.DocID != "d-1" || len(res.Raw) == 0 {
		t.Fatalf("%+v", res)
	}
	want := []sharePart{
		{name: "to", value: "a@x.mn"}, {name: "to", value: "b@x.mn"},
		{name: "subject", value: "Гэрээ"}, {name: "message", value: "Зурна уу"}, {name: "lang", value: "en"},
		{name: "filename", value: "гэрээ.pdf"},
		{name: "file", filename: "document.pdf", ctype: "application/pdf", value: string(testPDF)},
	}
	for i := range want[:6] {
		want[i].ctype = parts[i].ctype // текст талбарын Content-Type-ийг үл тооно
	}
	if !reflect.DeepEqual(parts, want) {
		t.Fatalf("parts:\n%+v\nwant\n%+v", parts, want)
	}
	for _, p := range parts {
		found := false
		for _, f := range shareFormFields {
			found = found || p.name == f
		}
		if !found {
			t.Fatalf("гэрээнд байхгүй талбар %q", p.name)
		}
	}
}

func TestShareOptionalFieldsOmitted(t *testing.T) {
	c := shareClient(t, func(w http.ResponseWriter, r *http.Request) {
		parts := readShareParts(t, r)
		if len(parts) != 2 || parts[0].name != "to" || parts[1].name != "file" || parts[1].filename != "document.pdf" {
			t.Errorf("%+v", parts)
		}
		_, _ = io.WriteString(w, `{"sent":1,"sha256":"cd","signatures":2}`)
	})
	res, err := c.Share(context.Background(), ShareRequest{File: testPDF, To: []string{"a@x.mn"}})
	if err != nil || res.DocID != "" {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestShareErrors(t *testing.T) {
	cases := []struct {
		status int
		body   string
		header string
		check  func(t *testing.T, se *ShareError)
	}{
		{422, `{"error":"…","code":"FILE_NOT_SIGNED","reason":"untrusted"}`, "", func(t *testing.T, se *ShareError) {
			if se.Code != CodeFileNotSigned || se.Reason != ShareReasonUntrusted {
				t.Fatalf("%+v", se)
			}
		}},
		{502, `{"error":"…","code":"MAIL_FAILED","sent":1,"failed":1,"recipients":["sent","failed"]}`, "", func(t *testing.T, se *ShareError) {
			if se.Code != CodeMailFailed || se.Sent != 1 || se.Failed != 1 ||
				!reflect.DeepEqual(se.Recipients, []string{ShareRecipientSent, ShareRecipientFailed}) || se.Retryable() {
				t.Fatalf("%+v", se)
			}
		}},
		{429, `{"error":"…","code":"RATE_LIMITED"}`, "30", func(t *testing.T, se *ShareError) {
			if se.RetryAfter != 30*time.Second || !se.Retryable() {
				t.Fatalf("%+v", se)
			}
		}},
		{503, `{"error":"…","code":"VALIDATOR_BUSY"}`, "30", func(t *testing.T, se *ShareError) {
			if se.Code != CodeValidatorBusy || !se.Retryable() {
				t.Fatalf("%+v", se)
			}
		}},
		{503, `{"error":"…","code":"SHARE_DISABLED"}`, "", func(t *testing.T, se *ShareError) {
			if se.Code != CodeShareDisabled || se.Retryable() {
				t.Fatalf("%+v", se)
			}
		}},
		{400, `{"error":"…","code":"REQUEST_INVALID"}`, "", func(t *testing.T, se *ShareError) {
			if !errors.Is(se, ErrRequestInvalid) {
				t.Fatal("errors.Is(ErrRequestInvalid)")
			}
		}},
		{413, `<html>nginx</html>`, "", func(t *testing.T, se *ShareError) {
			if se.Code != "" || se.Status != 413 {
				t.Fatalf("%+v", se)
			}
		}},
	}
	for _, tc := range cases {
		c := shareClient(t, func(w http.ResponseWriter, r *http.Request) {
			if tc.header != "" {
				w.Header().Set("Retry-After", tc.header)
			}
			w.WriteHeader(tc.status)
			_, _ = io.WriteString(w, tc.body)
		})
		_, err := c.Share(context.Background(), ShareRequest{File: testPDF, To: []string{"a@x.mn"}})
		var se *ShareError
		if !errors.As(err, &se) {
			t.Fatalf("%d: %T %v", tc.status, err, err)
		}
		var ae *APIError
		if !errors.As(err, &ae) || ae.Status != tc.status {
			t.Fatalf("%d: errors.As(*APIError)", tc.status)
		}
		if !strings.HasPrefix(se.Error(), "eid: share ") {
			t.Fatalf("Error() = %q", se.Error())
		}
		tc.check(t, se)
	}
}

func TestShareAuthErrors(t *testing.T) {
	for status, check := range map[int]func(error) bool{
		401: func(e error) bool { var x *AuthenticationError; return errors.As(e, &x) },
		403: func(e error) bool { var x *ForbiddenError; return errors.As(e, &x) },
	} {
		c := shareClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			_, _ = io.WriteString(w, `{"error":"…"}`)
		})
		_, err := c.Share(context.Background(), ShareRequest{File: testPDF, To: []string{"a@x.mn"}})
		var se *ShareError
		if !check(err) || errors.As(err, &se) {
			t.Fatalf("%d: %T", status, err)
		}
	}
}

func TestShareInfo(t *testing.T) {
	c := shareClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/eid" {
			t.Errorf("path %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"share":{"enabled":false,"endpoint":"https://rp.eidmongolia.mn/share",
			"formats":[{"extension":".pdf","mime":"application/pdf","name":"pdf"}],"languages":["mn","en"],
			"maxFileBytes":3080192,"maxFilenameChars":120,"maxMessageChars":1000,"maxRecipients":5,"maxSubjectChars":150,
			"permission":"SIGN","quota":{"perRPDay":200,"perRPHour":30,"perRecipientDay":10},"requiresValidSignature":true}}`)
	})
	s, err := c.ShareInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if s.Enabled || s.MaxFileBytes != 3080192 || s.MaxRecipients != 5 || s.Quota != (ShareQuota{30, 200, 10}) ||
		len(s.Formats) != 1 || s.Formats[0].Extension != ".pdf" || !s.RequiresValidSignature || len(s.Raw) == 0 {
		t.Fatalf("%+v", s)
	}

	old := shareClient(t, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, `{}`) })
	s, err = old.ShareInfo(context.Background())
	if err != nil || s.Enabled {
		t.Fatalf("%+v %v", s, err)
	}
}

func TestPersonCertificateRevocationFields(t *testing.T) {
	c := shareClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"personEtsi":"PNOMN-1","counts":{"revoked":1,"suspended":1,"total":2},"certificates":[
			{"type":"SIGN","status":"REVOKED","issuedAt":"2026-01-02T03:04:05+08:00","revokedAt":"2026-02-01T00:00:00+08:00","revocationReason":"keyCompromise"},
			{"type":"SIGN","status":"SUSPENDED","issuedAt":"2025-01-02T03:04:05+08:00","revocationReason":"superseded"}]}`)
	})
	pc, err := c.Person.Certificates(context.Background(), "PNOMN-1")
	if err != nil {
		t.Fatal(err)
	}
	a, b := pc.Certificates[0], pc.Certificates[1]
	if a.IssuedAt == nil || a.IssuedAt.Year() != 2026 || a.RevokedAt == nil || a.RevokedAt.Month() != time.February ||
		a.RevocationReason != "keyCompromise" {
		t.Fatalf("%+v", a)
	}
	if b.RevokedAt != nil || b.RevocationReason != "superseded" || b.IssuedAt == nil {
		t.Fatalf("%+v", b)
	}
}
