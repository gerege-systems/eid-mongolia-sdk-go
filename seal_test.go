package eid

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"testing"
	"time"
)

// caSealRequest — CA server/internal/dto.SealRequest (JSON tag-ууд ЯГ ижил; CA DisallowUnknownFields).
type caSealRequest struct {
	RelyingPartyUUID string `json:"relyingPartyUUID,omitempty"`
	RelyingPartyName string `json:"relyingPartyName,omitempty"`
	Digest           string `json:"digest"`
	HashType         string `json:"hashType,omitempty"`
}

func sealTestCert(t *testing.T, ku x509.KeyUsage) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(4242), Subject: pkix.Name{CommonName: "Gerege Systems LLC", Organization: []string{"Gerege Systems LLC"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: ku}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, der
}

// sealReply — CA dto.SealResponse-ийн хэлбэрээр (signature/cert блок нь session status-тай ижил) хариулна.
func sealReply(t *testing.T, key *ecdsa.PrivateKey, certDER []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		var req caSealRequest
		if err := dec.Decode(&req); err != nil {
			w.WriteHeader(400)
			_, _ = fmt.Fprintf(w, `{"code":"REQUEST_INVALID","message":%q}`, err.Error())
			return
		}
		digest, _ := base64.StdEncoding.DecodeString(req.Digest)
		sig, err := ecdsa.SignASN1(rand.Reader, key, digest)
		if err != nil {
			t.Error(err)
		}
		_, _ = fmt.Fprintf(w, `{"orgEtsi":"NTRMN-6235972","signature":{"value":%q,"signatureAlgorithm":"ecdsa-with-SHA256"},`+
			`"cert":{"value":%q,"certificateLevel":"QUALIFIED"},"sealedAt":"2026-11-09T04:05:06Z"}`,
			base64.StdEncoding.EncodeToString(sig), base64.StdEncoding.EncodeToString(certDER))
	}
}

func TestSeal_RequestAndVerify(t *testing.T) {
	key, certDER := sealTestCert(t, x509.KeyUsageContentCommitment)
	c, rc := server(t, sealReply(t, key, certDER))
	d := sha256.Sum256([]byte("doc"))
	r, err := c.Seal.Seal(context.Background(), "NTRMN-6235972", d[:], "")
	if err != nil {
		t.Fatal(err)
	}
	req, body := rc.last()
	if req.Method != http.MethodPost || req.URL.Path != "/seal/NTRMN-6235972" || req.Header.Get("Authorization") != "Bearer "+creds.APISecret {
		t.Fatal(req.Method, req.URL.Path)
	}
	var got map[string]any
	_ = json.Unmarshal(body, &got)
	if len(got) != 2 || got["hashType"] != "SHA256" || got["digest"] != base64.StdEncoding.EncodeToString(d[:]) {
		t.Fatalf("body %s", body)
	}
	if r.OrgEtsi != "NTRMN-6235972" || !bytes.Equal(r.Certificate, certDER) || r.CertificateLevel != LevelQualified ||
		r.SignatureAlgorithm != "ecdsa-with-SHA256" || !r.SealedAt.Equal(time.Date(2026, 11, 9, 4, 5, 6, 0, time.UTC)) || len(r.Raw) == 0 {
		t.Fatalf("%+v", r)
	}
	if !ecdsa.VerifyASN1(&key.PublicKey, d[:], r.Signature) {
		t.Fatal("signature")
	}
}

func TestSeal_HashTypes(t *testing.T) {
	key, certDER := sealTestCert(t, x509.KeyUsageContentCommitment)
	c, rc := server(t, sealReply(t, key, certDER))
	for _, tc := range []struct {
		h    HashAlgorithm
		n    int
		wire string
	}{{SHA384, 48, "SHA384"}, {SHA512, 64, "SHA512"}} {
		if _, err := c.Seal.Seal(context.Background(), "NTRMN-6235972", make([]byte, tc.n), tc.h); err != nil {
			t.Fatal(tc.h, err)
		}
		_, body := rc.last()
		if !bytes.Contains(body, []byte(`"hashType":"`+tc.wire+`"`)) {
			t.Fatalf("%s", body)
		}
	}
	// Урт таарахгүй → сервер рүү явахгүй.
	n := len(rc.reqs)
	if _, err := c.Seal.Seal(context.Background(), "NTRMN-6235972", make([]byte, 32), SHA384); err == nil || len(rc.reqs) != n {
		t.Fatal("length mismatch accepted", err)
	}
}

func TestSeal_Rejects(t *testing.T) {
	d := sha256.Sum256([]byte("doc"))
	_, certDER := sealTestCert(t, x509.KeyUsageContentCommitment)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var ve *ValidationError

	c, _ := server(t, sealReply(t, other, certDER))
	if _, err := c.Seal.Seal(context.Background(), "NTRMN-6235972", d[:], SHA256); !errors.As(err, &ve) {
		t.Fatalf("wrong key: %v", err)
	}
	signKey, signDER := sealTestCert(t, x509.KeyUsageContentCommitment|x509.KeyUsageDigitalSignature)
	c, _ = server(t, sealReply(t, signKey, signDER))
	if _, err := c.Seal.Seal(context.Background(), "NTRMN-6235972", d[:], SHA256); !errors.As(err, &ve) {
		t.Fatalf("non-seal cert: %v", err)
	}
	c, _ = server(t, jsonReply(200, `{"orgEtsi":"NTRMN-6235972","signature":null,"cert":null}`))
	if _, err := c.Seal.Seal(context.Background(), "NTRMN-6235972", d[:], SHA256); !errors.As(err, &ve) {
		t.Fatalf("empty: %v", err)
	}
	c, _ = server(t, jsonReply(403, `{"code":"FORBIDDEN","message":"RP-д энэ байгууллагын SEAL permission алга"}`))
	var fe *ForbiddenError
	if _, err := c.Seal.Seal(context.Background(), "NTRMN-6235972", d[:], SHA256); !errors.As(err, &fe) {
		t.Fatalf("403: %v", err)
	}
	c, _ = server(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(429)
		_, _ = w.Write([]byte(`{"code":"RATE_LIMITED","message":"хэт олон хүсэлт"}`))
	})
	var ae *APIError
	if _, err := c.Seal.Seal(context.Background(), "NTRMN-6235972", d[:], SHA256); !errors.As(err, &ae) || !ae.Retryable() || ae.RetryAfter != 7*time.Second {
		t.Fatalf("429: %v", err)
	}
}

func TestSeal_Certificate(t *testing.T) {
	_, certDER := sealTestCert(t, x509.KeyUsageContentCommitment)
	// CA dto.SealCertificateResponse.
	c, rc := server(t, jsonReply(200, fmt.Sprintf(`{"orgEtsi":"NTRMN-6235972","certificate":%q,"serialNumber":"4242",`+
		`"subjectDn":"CN=Gerege Systems LLC","issuerDn":"CN=eID Mongolia Organization Issuing CA","notBefore":"2026-11-01T00:00:00Z",`+
		`"notAfter":"2029-11-01T00:00:00Z","certificateLevel":"QUALIFIED"}`, base64.StdEncoding.EncodeToString(certDER))))
	sc, err := c.Seal.Certificate(context.Background(), "NTRMN-6235972")
	if err != nil || !bytes.Equal(sc.Certificate, certDER) || sc.SerialNumber != "4242" || sc.CertificateLevel != LevelQualified || sc.NotAfter.Year() != 2029 {
		t.Fatal(err, sc)
	}
	if req, _ := rc.last(); req.Method != http.MethodGet || req.URL.Path != "/seal/certificate/NTRMN-6235972" {
		t.Fatal(req.Method, req.URL.Path)
	}
	c, _ = server(t, jsonReply(404, `{"code":"NOT_FOUND","message":"seal тохируулаагүй"}`))
	if _, err := c.Seal.Certificate(context.Background(), "NTRMN-6235972"); err == nil {
		t.Fatal("404 accepted")
	}
}

func TestIsSealCertificate(t *testing.T) {
	_, seal := sealTestCert(t, x509.KeyUsageContentCommitment)
	_, sign := sealTestCert(t, x509.KeyUsageContentCommitment|x509.KeyUsageDigitalSignature)
	a, _ := x509.ParseCertificate(seal)
	b, _ := x509.ParseCertificate(sign)
	if !IsSealCertificate(a) || IsSealCertificate(b) || IsSealCertificate(nil) {
		t.Fatal()
	}
}
