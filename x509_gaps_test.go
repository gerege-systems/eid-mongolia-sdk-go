package eid

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResponseSizeLimits(t *testing.T) {
	ctx := context.Background()
	// JSON > 4 MiB → *ResponseTooLargeError (таслаж задлахгүй).
	big := `{"personEtsi":"PNOMN-1","pad":"` + strings.Repeat("a", maxJSONBody) + `"}`
	c, _ := server(t, jsonReply(200, big))
	_, err := c.Organization.GetRepresentations(ctx, "PNOMN-1")
	var tl *ResponseTooLargeError
	if !errors.As(err, &tl) || tl.Limit != maxJSONBody || strings.Contains(tl.Error(), "PNOMN-1") {
		t.Fatalf("ResponseTooLargeError хүлээв: %v", err)
	}
	// Яг хязгаар хүртэл — зөвшөөрнө.
	exact := `{"personEtsi":"PNOMN-1","pad":"` + strings.Repeat("a", maxJSONBody-len(`{"personEtsi":"PNOMN-1","pad":""}`)) + `"}`
	c, _ = server(t, jsonReply(200, exact))
	if _, err := c.Organization.GetRepresentations(ctx, "PNOMN-1"); err != nil {
		t.Fatal(err)
	}

	// PDF: Config.PDFMaxBytes.
	pdf := bytes.Repeat([]byte{'x'}, 2048)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(pdf) }))
	t.Cleanup(srv.Close)
	mk := func(max int64) *Client {
		cl, err := NewClient(Config{BaseURL: srv.URL, Credentials: creds, PDFMaxBytes: max, Trust: TrustConfig{AllowUntrusted: true}})
		if err != nil {
			t.Fatal(err)
		}
		return cl
	}
	if _, err := mk(1024).PDF.Document(ctx, "s"); !errors.As(err, &tl) || tl.Limit != 1024 {
		t.Fatalf("PDFMaxBytes: %v", err)
	}
	if _, err := mk(1024).PDF.TokenDocument(ctx, "s"); !errors.As(err, &tl) {
		t.Fatalf("TokenDocument PDFMaxBytes: %v", err)
	}
	if b, err := mk(2048).PDF.Document(ctx, "s"); err != nil || len(b) != 2048 {
		t.Fatal(len(b), err)
	}
	if b, err := mk(0).PDF.Document(ctx, "s"); err != nil || len(b) != 2048 { // анхдагч 64 MiB
		t.Fatal(len(b), err)
	}
}

func TestRepresentationsRaw(t *testing.T) {
	c, _ := server(t, jsonReply(200, `{"personEtsi":"PNOMN-1","representations":[{"orgEtsi":"NTRMN-1"}],"future":{"x":1}}`))
	r, err := c.Organization.GetRepresentations(context.Background(), "PNOMN-1")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(r.Raw, &m); err != nil || string(m["future"]) != `{"x":1}` || len(r.Representations) != 1 {
		t.Fatalf("Raw: %s %v", r.Raw, err)
	}
}

func TestPDFToken(t *testing.T) {
	ctx := context.Background()
	hashToSign := sha256.Sum256([]byte("dtbs"))
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var gotReq map[string]any
	var gotPDF []byte
	var gotFinalize map[string]string
	c, rc := server(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/pdf/token/prepare":
			if err := r.ParseMultipartForm(1 << 20); err != nil {
				t.Error(err)
			}
			_ = json.Unmarshal([]byte(r.FormValue("request")), &gotReq)
			f, _, _ := r.FormFile("pdf")
			gotPDF, _ = io.ReadAll(f)
			_, _ = io.WriteString(w, `{"signingID":"11111111-1111-4111-8111-111111111111","docID":"d","hashToSign":"`+
				base64.StdEncoding.EncodeToString(hashToSign[:])+`","hashAlgorithm":"SHA-256","signatureAlgorithm":"ecdsa-with-SHA256",`+
				`"signatureFormat":"RAW_RS","expiresAt":"2026-10-14T12:10:00+08:00"}`)
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/finalize"):
			_ = json.NewDecoder(r.Body).Decode(&gotFinalize)
			_, _ = io.WriteString(w, `{"docID":"d","documentStatus":"READY","outSha256":"`+hex.EncodeToString(make([]byte, 32))+`","size":3}`)
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/document"):
			_, _ = io.WriteString(w, "PDF")
		default:
			w.WriteHeader(404)
		}
	})
	_, cert := tokenKeys(t, "PNOMN-12345678")
	s, err := c.PDF.TokenPrepare(ctx, PDFTokenPrepareInput{
		PDF: []byte("%PDF-1.7"), FileName: "гэрээ.pdf", SignerEtsi: "PNOMN-12345678", Certificate: cert.cert.Raw, OnBehalfOf: "NTRMN-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if s.SigningID == "" || !bytes.Equal(s.HashToSign, hashToSign[:]) || s.SignatureFormat != "RAW_RS" || s.ExpiresAt.IsZero() || len(s.Raw) == 0 {
		t.Fatalf("%+v", s)
	}
	if gotReq["relyingPartyUUID"] != creds.RPUUID || gotReq["certificate"] != base64.StdEncoding.EncodeToString(cert.cert.Raw) ||
		gotReq["fileName"] != "гэрээ.pdf" || gotReq["onBehalfOf"] != "NTRMN-1" || gotReq["signer"].(map[string]any)["etsi"] != "PNOMN-12345678" ||
		string(gotPDF) != "%PDF-1.7" {
		t.Fatalf("request: %v %q", gotReq, gotPDF)
	}
	if _, ok := gotReq["docID"]; ok {
		t.Fatal("хоосон docID илгээгдэв")
	}
	// Токен r||s (64 байт) — DER биш.
	rr, ss, _ := ecdsa.Sign(rand.Reader, ek, s.HashToSign)
	sig := append(rr.FillBytes(make([]byte, 32)), ss.FillBytes(make([]byte, 32))...)
	blk, err := c.PDF.TokenFinalize(ctx, s.SigningID, sig)
	if err != nil || blk.DocumentStatus != PDFReady {
		t.Fatal(blk, err)
	}
	if gotFinalize["signature"] != base64.StdEncoding.EncodeToString(sig) || len(gotFinalize) != 1 {
		t.Fatal(gotFinalize)
	}
	req, _ := rc.last()
	if req.URL.Path != "/pdf/token/11111111-1111-4111-8111-111111111111/finalize" || req.Header.Get("Content-Type") != "application/json" {
		t.Fatal(req.URL.Path)
	}
	if _, err := c.PDF.TokenFinalize(ctx, s.SigningID, sig[:63]); err == nil {
		t.Fatal("63 байт зөвшөөрөгдөв")
	}
	if b, err := c.PDF.TokenDocument(ctx, s.SigningID); err != nil || string(b) != "PDF" {
		t.Fatal(string(b), err)
	}
	if _, err := c.PDF.TokenPrepare(ctx, PDFTokenPrepareInput{PDF: []byte("%PDF")}); err == nil {
		t.Fatal("дутуу оролт зөвшөөрөгдөв")
	}
	// hashToSign 32 байт биш → ValidationError.
	c2, _ := server(t, jsonReply(200, `{"signingID":"x","hashToSign":"AAAA"}`))
	_, err = c2.PDF.TokenPrepare(ctx, PDFTokenPrepareInput{PDF: []byte("%PDF"), FileName: "a.pdf", SignerEtsi: "PNOMN-1", Certificate: []byte{1}})
	wantInvalid(t, err, "hashToSign")
}
