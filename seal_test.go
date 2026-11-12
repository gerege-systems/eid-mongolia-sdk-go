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
	"sync"
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
	n := rc.count()
	if _, err := c.Seal.Seal(context.Background(), "NTRMN-6235972", make([]byte, 32), SHA384); err == nil || rc.count() != n {
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

// ── Тамганы гэрчилгээний олголт (CA !483): POST → 202 PENDING, GET …/requests/{id} → ISSUED/REJECTED/EXPIRED/FAILED ──

const sealReqID = "5f0c2b1e-7a40-4c11-9a51-2f6e0d3c9b11"

// sealReqBody — CA dto.SealCertificateRequestResponse (бичлэг); extra нь `,"key":…` хэлбэрийн нэмэлт талбарууд.
func sealReqBody(status, extra string) string {
	return `{"requestId":"` + sealReqID + `","orgEtsi":"NTRMN-6235972","status":"` + status +
		`","createdAt":"2026-11-09T05:00:00Z","expiresAt":"2026-11-09T05:07:00Z"` + extra + `}`
}

func sealIssuedBody(certDER []byte) string {
	return sealReqBody("ISSUED", fmt.Sprintf(`,"decidedAt":"2026-11-09T05:01:00Z","certificate":{"orgEtsi":"NTRMN-6235972",`+
		`"certificate":%q,"serialNumber":"88002","subjectDn":"CN=Gerege Systems LLC","issuerDn":"CN=eID Mongolia Organization Issuing CA",`+
		`"notBefore":"2026-11-09T05:01:00Z","notAfter":"2029-11-09T05:01:00Z","certificateLevel":"QUALIFIED"}`, base64.StdEncoding.EncodeToString(certDER)))
}

func (r *rec) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.reqs)
}

type sealStep struct {
	status int
	body   string
	header map[string]string
}

// sealSeq — дарааллаар хариулна (сүүлийнхийг давтана).
func sealSeq(steps ...sealStep) http.HandlerFunc {
	var mu sync.Mutex
	i := 0
	return func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		s := steps[min(i, len(steps)-1)]
		i++
		mu.Unlock()
		for k, v := range s.header {
			w.Header().Set(k, v)
		}
		w.WriteHeader(s.status)
		_, _ = w.Write([]byte(s.body))
	}
}

func TestSeal_RequestCertificate(t *testing.T) {
	c, rc := server(t, jsonReply(202, sealReqBody("PENDING", `,"approvers":2`)))
	r, err := c.Seal.RequestCertificate(context.Background(), "NTRMN-6235972")
	if err != nil {
		t.Fatal(err)
	}
	req, _ := rc.last()
	if req.Method != http.MethodPost || req.URL.Path != "/seal/certificate/NTRMN-6235972" || req.Header.Get("Authorization") != "Bearer "+creds.APISecret {
		t.Fatal(req.Method, req.URL.Path)
	}
	if r.RequestID != sealReqID || r.Status != SealRequestPending || r.Approvers != 2 || r.ExpiresAt.Minute() != 7 || r.Certificate != nil {
		t.Fatalf("%+v", r)
	}
}

func TestSeal_CertificateRequestIssued(t *testing.T) {
	_, certDER := sealTestCert(t, x509.KeyUsageContentCommitment)
	c, rc := server(t, jsonReply(200, sealIssuedBody(certDER)))
	r, err := c.Seal.CertificateRequest(context.Background(), "NTRMN-6235972", sealReqID)
	if err != nil {
		t.Fatal(err)
	}
	if req, _ := rc.last(); req.Method != http.MethodGet || req.URL.Path != "/seal/certificate/NTRMN-6235972/requests/"+sealReqID {
		t.Fatal(req.Method, req.URL.Path)
	}
	if r.Status != SealRequestIssued || r.DecidedAt == nil || r.Certificate == nil || !bytes.Equal(r.Certificate.Certificate, certDER) ||
		r.Certificate.SerialNumber != "88002" || r.Certificate.CertificateLevel != LevelQualified {
		t.Fatalf("%+v", r)
	}
	// ISSUED боловч certificate-гүй, эсвэл requestId-гүй → *ValidationError.
	for _, body := range []string{sealReqBody("ISSUED", ""), `{"status":"PENDING"}`} {
		c, _ := server(t, jsonReply(200, body))
		var ve *ValidationError
		if _, err := c.Seal.CertificateRequest(context.Background(), "NTRMN-6235972", sealReqID); !errors.As(err, &ve) {
			t.Fatalf("%s: %v", body, err)
		}
	}
}

func TestSeal_WaitForCertificate(t *testing.T) {
	_, certDER := sealTestCert(t, x509.KeyUsageContentCommitment)
	c, rc := server(t, sealSeq(
		sealStep{status: 200, body: sealReqBody("PENDING", "")},
		sealStep{status: 200, body: sealReqBody("APPROVED", `,"decidedAt":"2026-11-09T05:01:00Z"`)},
		sealStep{status: 200, body: sealIssuedBody(certDER)},
	))
	sc, err := c.Seal.WaitForCertificate(context.Background(), "NTRMN-6235972", sealReqID, &SealWaitOptions{Interval: time.Millisecond})
	if err != nil || !bytes.Equal(sc.Certificate, certDER) || sc.NotAfter.Year() != 2029 {
		t.Fatal(err, sc)
	}
	if n := rc.count(); n != 3 {
		t.Fatalf("poll %d", n)
	}
}

func TestSeal_WaitForCertificateTerminal(t *testing.T) {
	for _, tc := range []struct {
		status  SealRequestStatus
		extra   string
		failure string
	}{
		{SealRequestRejected, `,"decidedAt":"2026-11-09T05:01:00Z"`, ""},
		{SealRequestExpired, `,"failure":"EXPIRED"`, "EXPIRED"},
		{SealRequestFailed, `,"decidedAt":"2026-11-09T05:01:00Z","failure":"SEAL_ISSUANCE_FAILED"`, "SEAL_ISSUANCE_FAILED"},
	} {
		c, rc := server(t, sealSeq(sealStep{status: 200, body: sealReqBody("PENDING", "")}, sealStep{status: 200, body: sealReqBody(string(tc.status), tc.extra)}))
		_, err := c.Seal.WaitForCertificate(context.Background(), "NTRMN-6235972", sealReqID, &SealWaitOptions{Interval: time.Millisecond})
		var se *SealRequestError
		if !errors.As(err, &se) || se.Outcome != tc.status || se.RequestID != sealReqID || se.Failure != tc.failure {
			t.Fatalf("%s: %v", tc.status, err)
		}
		if n := rc.count(); n != 2 {
			t.Fatalf("%s: poll %d", tc.status, n)
		}
	}
}

func TestSeal_WaitForCertificateTimeoutAndCancel(t *testing.T) {
	c, _ := server(t, jsonReply(200, sealReqBody("PENDING", "")))
	_, err := c.Seal.WaitForCertificate(context.Background(), "NTRMN-6235972", sealReqID, &SealWaitOptions{Interval: 5 * time.Millisecond, Timeout: 30 * time.Millisecond})
	var se *SealRequestError
	if !errors.As(err, &se) || se.Outcome != SealRequestTimeout || se.Failure != "" {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := c.Seal.WaitForCertificate(ctx, "NTRMN-6235972", sealReqID, &SealWaitOptions{Interval: 10 * time.Second}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}

func TestSeal_WaitForCertificateRetryAfter(t *testing.T) {
	_, certDER := sealTestCert(t, x509.KeyUsageContentCommitment)
	c, rc := server(t, sealSeq(
		sealStep{status: 429, body: `{"error":"хэт олон","code":"RATE_LIMITED"}`, header: map[string]string{"Retry-After": "1"}},
		sealStep{status: 200, body: sealIssuedBody(certDER)},
	))
	t0 := time.Now()
	sc, err := c.Seal.WaitForCertificate(context.Background(), "NTRMN-6235972", sealReqID, &SealWaitOptions{Interval: time.Millisecond})
	if err != nil || !bytes.Equal(sc.Certificate, certDER) {
		t.Fatal(err)
	}
	if time.Since(t0) < 950*time.Millisecond || rc.count() != 2 {
		t.Fatalf("Retry-After дагаагүй: %v, %d", time.Since(t0), rc.count())
	}
	// 404 SEAL_REQUEST_NOT_FOUND — давтахгүй, шууд.
	c, rc = server(t, jsonReply(404, `{"error":"олдсонгүй","code":"SEAL_REQUEST_NOT_FOUND"}`))
	_, err = c.Seal.WaitForCertificate(context.Background(), "NTRMN-6235972", sealReqID, &SealWaitOptions{Interval: time.Millisecond})
	var ae *APIError
	if !errors.Is(err, ErrSealRequestNotFound) || !errors.As(err, &ae) || ae.Status != 404 || rc.count() != 1 {
		t.Fatal(err)
	}
}

func TestSeal_RequestCertificateErrors(t *testing.T) {
	ctx := context.Background()
	c, _ := server(t, jsonReply(409, `{"error":"ADMIN алга","code":"SEAL_APPROVER_UNAVAILABLE"}`))
	_, err := c.Seal.RequestCertificate(ctx, "NTRMN-6235972")
	var ae *APIError
	if !errors.Is(err, ErrSealApproverUnavailable) || !errors.As(err, &ae) || ae.Status != 409 || ae.Retryable() {
		t.Fatal(err)
	}
	c, _ = server(t, jsonReply(409, `{"error":"байгууллага ACTIVE биш"}`))
	if _, err := c.Seal.RequestCertificate(ctx, "NTRMN-6235972"); errors.Is(err, ErrSealApproverUnavailable) || !errors.As(err, &ae) || ae.Status != 409 {
		t.Fatal(err)
	}
	c, _ = server(t, jsonReply(403, `{"error":"SEAL эрхгүй","code":"PERMISSION_DENIED"}`))
	var fe *ForbiddenError
	if _, err := c.Seal.RequestCertificate(ctx, "NTRMN-6235972"); !errors.As(err, &fe) {
		t.Fatal(err)
	}
	c, _ = server(t, sealSeq(sealStep{status: 429, body: `{"error":"хэт олон","code":"RATE_LIMITED"}`, header: map[string]string{"Retry-After": "3600"}}))
	if _, err := c.Seal.RequestCertificate(ctx, "NTRMN-6235972"); !errors.As(err, &ae) || ae.Status != 429 || !ae.Retryable() || ae.RetryAfter != time.Hour {
		t.Fatal(err)
	}
}

// Тамганы 409 бүр тогтвортой code-той (CA 2026-11-12; статус хэвээр); GET /seal/certificate идэвхтэй гэрчилгээгүй бол 409.
func TestSeal_ConflictCodes(t *testing.T) {
	ctx := context.Background()
	d := sha256.Sum256([]byte("doc"))
	all := []struct {
		code     string
		sentinel error
		onGet    bool // GET /seal/certificate-д ч ирнэ
	}{
		{CodeOrgNotActive, ErrOrgNotActive, false},
		{CodeSealNotIssued, ErrSealNotIssued, true},
		{CodeSealCertRevoked, ErrSealCertRevoked, true},
		{CodeSealKeyUnavailable, ErrSealKeyUnavailable, false},
		{CodeSealCertExpired, ErrSealCertExpired, true},
		{CodeSealCertNotYetValid, ErrSealCertNotYetValid, true},
	}
	check := func(what string, err error, i int, rc *rec) {
		t.Helper()
		var ae *APIError
		if !errors.As(err, &ae) || ae.Status != 409 || ae.Code != all[i].code || ae.Retryable() || rc.count() != 1 {
			t.Fatalf("%s %s: %v (%d хүсэлт)", what, all[i].code, err, rc.count())
		}
		for j, o := range all {
			if errors.Is(err, o.sentinel) != (i == j) {
				t.Fatalf("%s %s: errors.Is(%v) = %v", what, all[i].code, o.sentinel, i != j)
			}
		}
		if errors.Is(err, ErrSealApproverUnavailable) || errors.Is(err, ErrSealServiceDisabled) || errors.Is(err, ErrSealRequestNotFound) {
			t.Fatalf("%s %s: өөр sentinel таарсан", what, all[i].code)
		}
	}
	for i, tc := range all {
		body := fmt.Sprintf(`{"error":"тамгалах боломжгүй","code":%q}`, tc.code)
		c, rc := server(t, jsonReply(409, body))
		_, err := c.Seal.Seal(ctx, "NTRMN-6235972", d[:], SHA256)
		check("Seal", err, i, rc)
		if tc.onGet {
			c, rc = server(t, jsonReply(409, body))
			_, err = c.Seal.Certificate(ctx, "NTRMN-6235972")
			check("Certificate", err, i, rc)
		}
	}
	c, rc := server(t, jsonReply(409, `{"error":"байгууллага ACTIVE биш","code":"ORG_NOT_ACTIVE"}`))
	_, err := c.Seal.RequestCertificate(ctx, "NTRMN-6235972")
	check("RequestCertificate", err, 0, rc)

	// code-гүй / танигдаагүй 409 — *APIError хэвээр, sentinel таарахгүй.
	for _, body := range []string{`{"error":"байгууллага ACTIVE биш"}`, `{"error":"x","code":"SEAL_SOMETHING_NEW"}`} {
		c, _ := server(t, jsonReply(409, body))
		_, err := c.Seal.Seal(ctx, "NTRMN-6235972", d[:], SHA256)
		var ae *APIError
		if !errors.As(err, &ae) || ae.Status != 409 {
			t.Fatalf("%s: %v", body, err)
		}
		for _, o := range all {
			if errors.Is(err, o.sentinel) {
				t.Fatalf("%s: %v таарсан", body, o.sentinel)
			}
		}
	}

	// 403: RP-д SEAL эрхгүй (байгууллага зөвшөөрөөгүй / эрх хасагдсан) — *ForbiddenError; OnBehalfOf-ийн 403 ORG_NOT_ACTIVE
	// нь ErrOrgNotActive-тэй таарна, бусад sentinel-тэй үгүй.
	var fe *ForbiddenError
	c, _ = server(t, jsonReply(403, `{"error":"SEAL эрхгүй","code":"PERMISSION_DENIED"}`))
	if _, err := c.Seal.Seal(ctx, "NTRMN-6235972", d[:], SHA256); !errors.As(err, &fe) || fe.Code != "PERMISSION_DENIED" || errors.Is(err, ErrOrgNotActive) {
		t.Fatalf("403: %v", err)
	}
	c, _ = server(t, jsonReply(403, `{"error":"идэвхгүй","code":"ORG_NOT_ACTIVE"}`))
	if _, err := c.Seal.Seal(ctx, "NTRMN-6235972", d[:], SHA256); !errors.As(err, &fe) || !errors.Is(err, ErrOrgNotActive) || errors.Is(err, ErrSealNotIssued) {
		t.Fatalf("403 ORG_NOT_ACTIVE: %v", err)
	}

	want := []string{"ORG_NOT_ACTIVE", "SEAL_NOT_ISSUED", "SEAL_CERT_REVOKED", "SEAL_KEY_UNAVAILABLE", "SEAL_CERT_EXPIRED",
		"SEAL_CERT_NOT_YET_VALID", "SEAL_APPROVER_UNAVAILABLE", "SEAL_REQUEST_NOT_FOUND", "SEAL_SERVICE_DISABLED"}
	if fmt.Sprint(SealErrorCodes) != fmt.Sprint(want) {
		t.Fatalf("SealErrorCodes = %v", SealErrorCodes)
	}
}

// 503 SEAL_SERVICE_DISABLED (CA 2026-11-12): оператор олголт / тамгалалтыг унтраасан — Retry-After-гүй, давтахгүй.
func TestSeal_ServiceDisabled(t *testing.T) {
	ctx := context.Background()
	d := sha256.Sum256([]byte("doc"))
	var ae *APIError

	c, rc := server(t, jsonReply(503, `{"error":"тамганы гэрчилгээ олгох үйлчилгээ түр унтраалттай байна","code":"SEAL_SERVICE_DISABLED","service":"issuance"}`))
	_, err := c.Seal.RequestCertificate(ctx, "NTRMN-6235972")
	if !errors.Is(err, ErrSealServiceDisabled) || !errors.As(err, &ae) || ae.Status != 503 || ae.Code != CodeSealServiceDisabled ||
		ae.Service != SealServiceIssuance || ae.RetryAfter != 0 || ae.Retryable() || rc.count() != 1 {
		t.Fatalf("issuance: %v", err)
	}
	if errors.Is(err, ErrSealApproverUnavailable) || errors.Is(err, ErrSealRequestNotFound) {
		t.Fatalf("issuance: өөр sentinel таарсан: %v", err)
	}

	c, rc = server(t, jsonReply(503, `{"error":"the sealing service is currently disabled","code":"SEAL_SERVICE_DISABLED","service":"sealing"}`))
	_, err = c.Seal.Seal(ctx, "NTRMN-6235972", d[:], SHA256)
	if !errors.Is(err, ErrSealServiceDisabled) || !errors.As(err, &ae) || ae.Status != 503 || ae.Service != SealServiceSealing ||
		ae.Retryable() || rc.count() != 1 {
		t.Fatalf("sealing: %v", err)
	}

	// Урд талын proxy Retry-After нэмсэн ч давтахгүй: Retryable() false, WaitForCertificate нэг л хүсэлт.
	disabled := sealStep{status: 503, body: `{"error":"x","code":"SEAL_SERVICE_DISABLED","service":"issuance"}`, header: map[string]string{"Retry-After": "1"}}
	c, rc = server(t, sealSeq(disabled))
	_, err = c.Seal.WaitForCertificate(ctx, "NTRMN-6235972", sealReqID, &SealWaitOptions{Interval: time.Millisecond})
	if !errors.Is(err, ErrSealServiceDisabled) || !errors.As(err, &ae) || ae.Retryable() || rc.count() != 1 {
		t.Fatalf("wait 503: %v (%d хүсэлт)", err, rc.count())
	}

	// Батлагдсан ч олголт унтраалттай байсан хүсэлт: FAILED + failure → *SealRequestError, errors.Is таарна.
	c, rc = server(t, sealSeq(sealStep{status: 200, body: sealReqBody("FAILED", `,"decidedAt":"2026-11-12T05:01:00Z","failure":"SEAL_SERVICE_DISABLED"`)}))
	_, err = c.Seal.WaitForCertificate(ctx, "NTRMN-6235972", sealReqID, &SealWaitOptions{Interval: time.Millisecond})
	var se *SealRequestError
	if !errors.As(err, &se) || se.Outcome != SealRequestFailed || se.Failure != CodeSealServiceDisabled ||
		!errors.Is(err, ErrSealServiceDisabled) || rc.count() != 1 {
		t.Fatalf("wait FAILED: %v", err)
	}
	if errors.Is(&SealRequestError{Outcome: SealRequestFailed, Failure: "SEAL_ISSUANCE_FAILED"}, ErrSealServiceDisabled) {
		t.Fatal("өөр failure ErrSealServiceDisabled-тэй таарсан")
	}
}

// Бусад 503 хэвээр: код/Retry-After-аар Retryable, ErrSealServiceDisabled биш, Service хоосон.
func TestSeal_Other503Unchanged(t *testing.T) {
	ctx := context.Background()
	d := sha256.Sum256([]byte("doc"))
	var ae *APIError
	for _, tc := range []struct {
		step      sealStep
		retryable bool
	}{
		{sealStep{status: 503, body: `{"error":"state store","code":"STATE_UNAVAILABLE"}`, header: map[string]string{"Retry-After": "5"}}, true},
		{sealStep{status: 503, body: `<html>upstream</html>`, header: map[string]string{"Retry-After": "2"}}, true},
		{sealStep{status: 503, body: `{"error":"түр алдаа"}`}, false},
		{sealStep{status: 503, body: `{"error":"x","code":"OTHER","service":7}`}, false},
	} {
		c, _ := server(t, sealSeq(tc.step))
		_, err := c.Seal.Seal(ctx, "NTRMN-6235972", d[:], SHA256)
		if !errors.As(err, &ae) || ae.Status != 503 || ae.Retryable() != tc.retryable || ae.Service != "" || errors.Is(err, ErrSealServiceDisabled) {
			t.Fatalf("%s: %v", tc.step.body, err)
		}
	}
	// WaitForCertificate: 503 + Retry-After-ийг дагаж үргэлжилнэ.
	_, certDER := sealTestCert(t, x509.KeyUsageContentCommitment)
	c, rc := server(t, sealSeq(
		sealStep{status: 503, body: `{"error":"state store","code":"STATE_UNAVAILABLE"}`, header: map[string]string{"Retry-After": "1"}},
		sealStep{status: 200, body: sealIssuedBody(certDER)},
	))
	sc, err := c.Seal.WaitForCertificate(ctx, "NTRMN-6235972", sealReqID, &SealWaitOptions{Interval: time.Millisecond})
	if err != nil || !bytes.Equal(sc.Certificate, certDER) || rc.count() != 2 {
		t.Fatalf("wait 503 retry: %v (%d хүсэлт)", err, rc.count())
	}
}
