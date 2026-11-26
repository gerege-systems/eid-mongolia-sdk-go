package eid

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// caSealRegisterRequest — CA server/internal/dto SealRegisterRequest-ийн хуулбар (ca-eidmongolia-mn main 70c0e09c,
// PR #78). CA handler DisallowUnknownFields-ээр задалдаг тул SDK-ийн бие яг эдгээр түлхүүртэй байх ёстой.
type caSealRegisterRequest struct {
	DocID               string   `json:"docID"`
	RevIndex            int      `json:"revIndex"`
	CMS                 string   `json:"cms"`
	FileName            string   `json:"fileName,omitempty"`
	InSHA256            string   `json:"inSha256"`
	SigRevSHA256        string   `json:"sigRevSha256"`
	OutSHA256           string   `json:"outSha256"`
	PriorCMSSHA256      []string `json:"priorCmsSha256,omitempty"`
	PriorRevisionSHA256 []string `json:"priorRevisionSha256,omitempty"`
}

// caSealRequestV158 — CA dto.SealRequest (V158: + docId, revIndex).
type caSealRequestV158 struct {
	RelyingPartyUUID string `json:"relyingPartyUUID,omitempty"`
	RelyingPartyName string `json:"relyingPartyName,omitempty"`
	Digest           string `json:"digest"`
	HashType         string `json:"hashType,omitempty"`
	DocID            string `json:"docId,omitempty"`
	RevIndex         int    `json:"revIndex,omitempty"`
}

const (
	testSealOrg   = "NTRMN-6235972"
	testSealDocID = "3f0c2a8e-6b1d-4c55-9a77-000000000002"
)

func h64(c byte) string { return strings.Repeat(string(c), 64) }

func testSealReg() SealRegistration {
	return SealRegistration{DocID: testSealDocID, RevIndex: 1, CMS: []byte{0x30, 1}, FileName: "Нэхэмжлэх.pdf",
		InSHA256: h64('a'), SigRevSHA256: h64('b'), OutSHA256: h64('c')}
}

const sealRegisteredJSON = `{"docID":"` + testSealDocID + `","revIndex":1,"registeredAt":"2026-11-25T12:00:00+08:00","verifyUrl":"https://ca.eidmongolia.mn/verify/` + testSealDocID + `"}`

func TestRegisterSealedPDF(t *testing.T) {
	var got caSealRegisterRequest
	status := http.StatusCreated
	c, rc := server(t, func(w http.ResponseWriter, r *http.Request) {
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&got); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"bad","code":"REQUEST_INVALID"}`))
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(sealRegisteredJSON))
	})
	out, err := c.Seal.RegisterSealedPDF(context.Background(), " "+testSealOrg+" ", testSealReg())
	if err != nil {
		t.Fatal(err)
	}
	req, body := rc.last()
	if req.Method != http.MethodPost || req.URL.Path != "/seal/"+testSealOrg+"/registrations" ||
		req.Header.Get("Authorization") != "Bearer "+creds.APISecret {
		t.Fatalf("%s %s", req.Method, req.URL.Path)
	}
	if got.CMS != "MAE=" || got.DocID != testSealDocID || got.RevIndex != 1 || got.FileName != "Нэхэмжлэх.pdf" ||
		got.InSHA256 != h64('a') || got.SigRevSHA256 != h64('b') || got.OutSHA256 != h64('c') {
		t.Fatalf("%+v", got)
	}
	for _, k := range []string{"medium", "sessionID", "pageSha256", "onBehalfOf", "signerEtsi", "priorCmsSha256", "PriorSignatures"} {
		if strings.Contains(string(body), `"`+k+`"`) {
			t.Errorf("%s илгээх ёсгүй: %s", k, body)
		}
	}
	if !out.Created || out.DocID != testSealDocID || out.RevIndex != 1 || out.VerifyURL == "" || out.RegisteredAt == "" {
		t.Fatalf("%+v", out)
	}
	// fileName заавал биш — хоосон бол илгээхгүй.
	noName := testSealReg()
	noName.FileName = ""
	status = http.StatusOK
	out, err = c.Seal.RegisterSealedPDF(context.Background(), testSealOrg, noName)
	if _, body = rc.last(); err != nil || out.Created || strings.Contains(string(body), "fileName") {
		t.Fatalf("200 давталт / fileName-гүй: %v %+v %s", err, out, body)
	}
}

// TestRegisterSealedPDFValidate — CA TestRegisterSealWindowReservationDuplicate-ийн «Хэлбэр → 400 REQUEST_INVALID»
// векторууд (pades_seal_register_test.go) + orgEtsi (orgEtsiRe): SDK сүлжээнд гаргахгүй (*ValidationError).
func TestRegisterSealedPDFValidate(t *testing.T) {
	c, rc := server(t, jsonReply(http.StatusCreated, sealRegisteredJSON))
	for name, mod := range map[string]func(*SealRegistration){
		"docID":       func(r *SealRegistration) { r.DocID = strings.ToUpper(r.DocID) },
		"revIndex 0":  func(r *SealRegistration) { r.RevIndex = 0 },
		"revIndex 17": func(r *SealRegistration) { r.RevIndex = 17 },
		"prior тоо":   func(r *SealRegistration) { r.PriorCMSSHA256 = []string{h64('d')} },
		"prior дутуу": func(r *SealRegistration) { r.RevIndex = 2 },
		"prior hex":   func(r *SealRegistration) { r.RevIndex, r.PriorRevisionSHA256 = 2, []string{"x"} },
		"out":         func(r *SealRegistration) { r.OutSHA256 = "x" },
		"in том үсэг": func(r *SealRegistration) { r.InSHA256 = strings.ToUpper(h64('a')) },
		"sigRev":      func(r *SealRegistration) { r.SigRevSHA256 = "" },
		"fileName":    func(r *SealRegistration) { r.FileName = strings.Repeat("а", 121) },
		"cms хоосон":  func(r *SealRegistration) { r.CMS = nil },
		"cms хэт том": func(r *SealRegistration) { r.CMS = make([]byte, 28673) },
	} {
		r := testSealReg()
		mod(&r)
		var ve *ValidationError
		if _, err := c.Seal.RegisterSealedPDF(context.Background(), testSealOrg, r); !errors.As(err, &ve) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, org := range []string{"", "PNOMN-1", "NTRMN-", "NTRMN-ab_c"} {
		var ve *ValidationError
		if _, err := c.Seal.RegisterSealedPDF(context.Background(), org, testSealReg()); !errors.As(err, &ve) {
			t.Errorf("orgEtsi %q: %v", org, err)
		}
	}
	if n := rc.count(); n != 0 {
		t.Fatalf("хэлбэрийн алдаа сүлжээнд гарав: %d", n)
	}
	// Хил: 120 тэмдэгт, 28 672 байт, prior revision + CMS холимог.
	ok := testSealReg()
	ok.FileName, ok.CMS = strings.Repeat("а", 120), make([]byte, 28672)
	ok.RevIndex, ok.PriorCMSSHA256, ok.PriorRevisionSHA256 = 3, []string{h64('d')}, []string{h64('e')}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
}

// TestRegisterSealedPDFErrors — SealRegisterErrorCodes-ийн код бүр CA-ийн HTTP статусаар → *APIError.Code (429/503 —
// Retryable, RetryAfter); 403 code-гүй → *ForbiddenError.
func TestRegisterSealedPDFErrors(t *testing.T) {
	status := map[string]int{
		CodeRequestTooLarge: 413, CodeRequestInvalid: 400, CodeRateLimited: 429, CodeStateUnavailable: 503,
		CodeCMSInvalid: 400, CodeSignerMismatch: 409, CodeSignerCertInvalid: 409, CodeSignatureInvalid: 400,
		CodeSealNotFound: 409, CodeSealDocMismatch: 409, CodeTimestampInvalid: 400, CodeDocIDReserved: 409,
		CodeDocIDConflict: 409, CodePriorMismatch: 409, CodeRegistryConflict: 409,
	}
	if len(status) != len(SealRegisterErrorCodes) {
		t.Fatalf("тест %d код, SDK %d", len(status), len(SealRegisterErrorCodes))
	}
	for _, code := range SealRegisterErrorCodes {
		st, ok := status[code]
		if !ok {
			t.Fatalf("%s: статус алга", code)
		}
		h := func(w http.ResponseWriter, _ *http.Request) {
			if st == 429 || st == 503 {
				w.Header().Set("Retry-After", "600")
			}
			w.WriteHeader(st)
			_, _ = fmt.Fprintf(w, `{"error":"x","code":%q}`, code)
		}
		c, _ := server(t, h)
		_, err := c.Seal.RegisterSealedPDF(context.Background(), testSealOrg, testSealReg())
		var ae *APIError
		if !errors.As(err, &ae) || ae.Code != code || ae.Status != st {
			t.Errorf("%s: %v", code, err)
			continue
		}
		if retry := st == 429 || st == 503; ae.Retryable() != retry || retry && ae.RetryAfter != 600*time.Second {
			t.Errorf("%s: Retryable %v RetryAfter %v", code, ae.Retryable(), ae.RetryAfter)
		}
	}
	c, _ := server(t, jsonReply(http.StatusForbidden, `{"error":"SEAL эрхгүй"}`))
	var fe *ForbiddenError
	if _, err := c.Seal.RegisterSealedPDF(context.Background(), testSealOrg, testSealReg()); !errors.As(err, &fe) {
		t.Fatalf("403: %v", err)
	}
	c, _ = server(t, jsonReply(http.StatusNotImplemented, `{"error":"тамганы бүртгэл тохируулаагүй"}`))
	var ae *APIError
	if _, err := c.Seal.RegisterSealedPDF(context.Background(), testSealOrg, testSealReg()); !errors.As(err, &ae) || ae.Status != 501 {
		t.Fatalf("501: %v", err)
	}
}

// TestRegisterSealedPDFPriorMismatch — CA-ийн гинжийн дүрэм (persistence.CheckChain) тамганд ч ижил: өмнөх мөр горим A
// бол 409 PRIOR_MISMATCH → RegisterSignature-тэй ижил хослолоор дахин.
func TestRegisterSealedPDFPriorMismatch(t *testing.T) {
	reg := testSealReg()
	reg.RevIndex = 3
	reg.PriorCMSSHA256 = []string{h64('1'), h64('2')}
	reg.PriorSignatures = []PDFPriorSignature{{CMSSHA256: h64('1'), RevisionSHA256: h64('3')}, {CMSSHA256: h64('2'), RevisionSHA256: h64('4')}}
	try := func(r SealRegistration, wantCMS, wantRev, code string) (*SealRegistered, int, error) {
		calls := 0
		c, _ := server(t, func(w http.ResponseWriter, req *http.Request) {
			calls++
			var got caSealRegisterRequest
			dec := json.NewDecoder(req.Body)
			dec.DisallowUnknownFields()
			if err := dec.Decode(&got); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"bad","code":"REQUEST_INVALID"}`))
				return
			}
			if strings.Join(got.PriorCMSSHA256, ",") == wantCMS && strings.Join(got.PriorRevisionSHA256, ",") == wantRev {
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(sealRegisteredJSON))
				return
			}
			w.WriteHeader(http.StatusConflict)
			_, _ = fmt.Fprintf(w, `{"error":"x","code":%q}`, code)
		})
		out, err := c.Seal.RegisterSealedPDF(context.Background(), testSealOrg, r)
		return out, calls, err
	}
	if out, n, err := try(reg, h64('2'), h64('3'), CodePriorMismatch); err != nil || !out.Created || n != 2 {
		t.Fatalf("эхний мөр горим A: %v %+v %d", err, out, n)
	}
	var ae *APIError
	if _, n, err := try(reg, "-", "-", CodePriorMismatch); !errors.As(err, &ae) || ae.Code != CodePriorMismatch || n != 4 {
		t.Fatalf("таарахгүй: %v %d", err, n)
	}
	if _, n, err := try(reg, "-", "-", CodeSealNotFound); !errors.As(err, &ae) || ae.Code != CodeSealNotFound || n != 1 {
		t.Fatalf("өөр алдаа шууд: %v %d", err, n)
	}
	manual := reg
	manual.PriorCMSSHA256, manual.PriorRevisionSHA256 = []string{h64('2')}, []string{h64('3')}
	if _, n, err := try(manual, "-", "-", CodePriorMismatch); err == nil || n != 1 {
		t.Fatalf("гараар ангилсан: %v %d", err, n)
	}
}

// TestSealRegisterErrorCodes — CA memory.SealRegisterErrorCodes (main 70c0e09c)-тэй ЯГ ижил дараалал, давхардалгүй.
func TestSealRegisterErrorCodes(t *testing.T) {
	want := []string{"REQUEST_TOO_LARGE", "REQUEST_INVALID", "RATE_LIMITED", "STATE_UNAVAILABLE",
		"CMS_INVALID", "SIGNER_MISMATCH", "SIGNER_CERT_INVALID", "SIGNATURE_INVALID",
		"SEAL_NOT_FOUND", "SEAL_DOC_MISMATCH", "TIMESTAMP_INVALID",
		"DOC_ID_RESERVED", "DOC_ID_CONFLICT", "PRIOR_MISMATCH", "REGISTRY_CONFLICT"}
	if strings.Join(SealRegisterErrorCodes, ",") != strings.Join(want, ",") {
		t.Fatalf("SealRegisterErrorCodes = %v", SealRegisterErrorCodes)
	}
}

// TestSealForDocument — POST /seal/{orgEtsi}-д {digest, hashType SHA256, docId, revIndex} (CA dto.SealRequest V158);
// Seal нь нөөцгүй (хуучин бие хэвээр); буруу нөөцийг (CA TestSealReservationValidation-ийн векторууд) сүлжээнд гаргахгүй.
func TestSealForDocument(t *testing.T) {
	key, certDER := sealTestCert(t, x509.KeyUsageContentCommitment)
	var got caSealRequestV158
	c, rc := server(t, func(w http.ResponseWriter, r *http.Request) {
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&got); err != nil {
			w.WriteHeader(400)
			return
		}
		digest, _ := base64.StdEncoding.DecodeString(got.Digest)
		sig, _ := ecdsa.SignASN1(rand.Reader, key, digest)
		_, _ = fmt.Fprintf(w, `{"orgEtsi":%q,"signature":{"value":%q,"signatureAlgorithm":"ecdsa-with-SHA256"},`+
			`"cert":{"value":%q,"certificateLevel":"QUALIFIED"},"sealedAt":"2026-11-25T04:05:06Z"}`, testSealOrg,
			base64.StdEncoding.EncodeToString(sig), base64.StdEncoding.EncodeToString(certDER))
	})
	d := sha256.Sum256([]byte("dtbs"))
	if _, err := c.Seal.SealForDocument(context.Background(), testSealOrg, d[:], testSealDocID, 2); err != nil {
		t.Fatal(err)
	}
	req, body := rc.last()
	if req.URL.Path != "/seal/"+testSealOrg || got.DocID != testSealDocID || got.RevIndex != 2 || got.HashType != "SHA256" ||
		got.Digest != base64.StdEncoding.EncodeToString(d[:]) {
		t.Fatalf("%s %s", req.URL.Path, body)
	}
	if _, err := c.Seal.Seal(context.Background(), testSealOrg, d[:], SHA256); err != nil {
		t.Fatal(err)
	}
	if _, body = rc.last(); strings.Contains(string(body), "docId") || strings.Contains(string(body), "revIndex") {
		t.Fatalf("Seal нөөц илгээх ёсгүй: %s", body)
	}
	n := rc.count()
	d384 := make([]byte, 48)
	for name, f := range map[string]func() error{
		"docId том үсэг": func() error {
			_, err := c.Seal.SealForDocument(context.Background(), testSealOrg, d[:], strings.ToUpper(testSealDocID), 1)
			return err
		},
		"revIndex 0": func() error {
			_, err := c.Seal.SealForDocument(context.Background(), testSealOrg, d[:], testSealDocID, 0)
			return err
		},
		"revIndex 17": func() error {
			_, err := c.Seal.SealForDocument(context.Background(), testSealOrg, d[:], testSealDocID, 17)
			return err
		},
		"docId-гүй": func() error {
			_, err := c.Seal.SealForDocument(context.Background(), testSealOrg, d[:], "", 2)
			return err
		},
		"SHA-384 урт": func() error {
			_, err := c.Seal.SealForDocument(context.Background(), testSealOrg, d384, testSealDocID, 1)
			return err
		},
	} {
		var ve *ValidationError
		if err := f(); !errors.As(err, &ve) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if rc.count() != n {
		t.Fatal("буруу нөөц сүлжээнд гарав")
	}
}
