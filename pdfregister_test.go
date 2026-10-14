package eid

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// caRegisterRequest — CA server/internal/dto PDFSignatureRegisterRequest-ийн хуулбар (ca-eidmongolia-mn main,
// 2026-10-14). CA handler DisallowUnknownFields-ээр задалдаг тул SDK-ийн бие яг эдгээр түлхүүртэй байх ёстой.
type caRegisterRequest struct {
	DocID               string   `json:"docID"`
	RevIndex            int      `json:"revIndex"`
	Medium              string   `json:"medium"`
	SessionID           string   `json:"sessionID,omitempty"`
	CMS                 string   `json:"cms"`
	FileName            string   `json:"fileName"`
	InSHA256            string   `json:"inSha256"`
	PageSHA256          string   `json:"pageSha256,omitempty"`
	SigRevSHA256        string   `json:"sigRevSha256"`
	OutSHA256           string   `json:"outSha256"`
	PriorCMSSHA256      []string `json:"priorCmsSha256,omitempty"`
	PriorRevisionSHA256 []string `json:"priorRevisionSha256,omitempty"`
	OnBehalfOf          string   `json:"onBehalfOf,omitempty"`
	SignerEtsi          string   `json:"signerEtsi,omitempty"`
}

func TestRegisterSignature(t *testing.T) {
	var got caRegisterRequest
	c, rc := server(t, func(w http.ResponseWriter, r *http.Request) {
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&got); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"bad","code":"REQUEST_INVALID"}`))
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"docID":"d","revIndex":1,"registeredAt":"2026-10-14T12:00:00+08:00","verifyUrl":"https://ca.eidmongolia.mn/verify/d"}`))
	})
	reg := PDFSignatureRegistration{DocID: "d", RevIndex: 1, Medium: PDFMediumPhone, SessionID: "s", CMS: []byte{0x30, 1},
		FileName: "a.pdf", InSHA256: "in", PageSHA256: "pg", SigRevSHA256: "sr", OutSHA256: "out", SignerEtsi: "PNOMN-1"}
	out, err := c.PDF.RegisterSignature(context.Background(), reg)
	if err != nil {
		t.Fatal(err)
	}
	req, body := rc.last()
	if req.Method != http.MethodPost || req.URL.Path != "/pdf/signatures" || out.VerifyURL == "" || got.CMS != "MAE=" || got.SignerEtsi != "PNOMN-1" {
		t.Fatalf("%s %s %+v %+v", req.Method, req.URL.Path, out, got)
	}
	if !out.Created {
		t.Fatal("201 → Created")
	}
	if bytes.Contains(body, []byte("hasPage")) {
		t.Fatal("hasPage илгээх ёсгүй (CA DisallowUnknownFields)")
	}
	for name, mut := range map[string]func(*PDFSignatureRegistration){
		"medium":     func(r *PDFSignatureRegistration) { r.Medium = "x" },
		"session":    func(r *PDFSignatureRegistration) { r.SessionID = "" },
		"page rev 1": func(r *PDFSignatureRegistration) { r.PageSHA256 = "" },
		"cms":        func(r *PDFSignatureRegistration) { r.CMS = nil },
	} {
		bad := reg
		mut(&bad)
		if _, err := c.PDF.RegisterSignature(context.Background(), bad); err == nil {
			t.Errorf("%s: алдаа хүлээв", name)
		}
	}
	// CA-ийн алдаа → *APIError.Code.
	c2, _ := server(t, jsonReply(http.StatusConflict, `{"error":"x","code":"SIGNER_MISMATCH"}`))
	_, err = c2.PDF.RegisterSignature(context.Background(), reg)
	var ae *APIError
	if !errors.As(err, &ae) || ae.Code != "SIGNER_MISMATCH" {
		t.Fatalf("%v", err)
	}
}

func TestRegisterSignatureReplayAndPriorMismatch(t *testing.T) {
	ctx := context.Background()
	c, _ := server(t, jsonReply(http.StatusOK, `{"docID":"d","revIndex":1,"registeredAt":"x","verifyUrl":"v"}`))
	reg := PDFSignatureRegistration{DocID: "d", RevIndex: 1, Medium: PDFMediumToken, CMS: []byte{0x30, 1}, FileName: "a.pdf",
		InSHA256: "in", PageSHA256: "pg", SigRevSHA256: "sr", OutSHA256: "out"}
	out, err := c.PDF.RegisterSignature(ctx, reg)
	if err != nil || out.Created {
		t.Fatalf("200 давталт → Created false: %v %+v", err, out)
	}

	// Горим A-ийн өмнөх мөр: CA зөвхөн want хослолыг хүлээн авна.
	reg3 := reg
	reg3.RevIndex, reg3.PageSHA256 = 3, ""
	reg3.PriorCMSSHA256 = []string{"c1", "c2"}
	reg3.PriorSignatures = []PDFPriorSignature{{CMSSHA256: "c1", RevisionSHA256: "v1"}, {CMSSHA256: "c2", RevisionSHA256: "v2"}}
	try := func(wantCMS, wantRev string, code string) (*PDFSignatureRegistered, int, error) {
		calls := 0
		c, _ := server(t, func(w http.ResponseWriter, r *http.Request) {
			calls++
			var got caRegisterRequest
			dec := json.NewDecoder(r.Body)
			dec.DisallowUnknownFields() // PriorSignatures CA руу очихгүй
			if err := dec.Decode(&got); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"bad","code":"REQUEST_INVALID"}`))
				return
			}
			if strings.Join(got.PriorCMSSHA256, ",") == wantCMS && strings.Join(got.PriorRevisionSHA256, ",") == wantRev {
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"docID":"d","revIndex":3,"registeredAt":"x","verifyUrl":"v"}`))
				return
			}
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":"x","code":"` + code + `"}`))
		})
		out, err := c.PDF.RegisterSignature(ctx, reg3)
		return out, calls, err
	}
	if out, n, err := try("c2", "v1", "PRIOR_MISMATCH"); err != nil || !out.Created || n != 2 {
		t.Fatalf("эхний мөр горим A: %v %+v %d", err, out, n)
	}
	if out, n, err := try("c1", "v2", "PRIOR_MISMATCH"); err != nil || n != 4 {
		t.Fatalf("хоёр дахь мөр горим A (бүх хослол): %v %+v %d", err, out, n)
	}
	var ae *APIError
	if _, n, err := try("-", "-", "PRIOR_MISMATCH"); !errors.As(err, &ae) || ae.Code != "PRIOR_MISMATCH" || n != 4 {
		t.Fatalf("таарахгүй: %v %d", err, n)
	}
	if _, n, err := try("-", "-", "REGISTRY_CONFLICT"); !errors.As(err, &ae) || ae.Code != "REGISTRY_CONFLICT" || n != 1 {
		t.Fatalf("өөр алдаа шууд: %v %d", err, n)
	}
	// Гараар ангилсан → оролдохгүй.
	reg3.PriorCMSSHA256, reg3.PriorRevisionSHA256 = []string{"c2"}, []string{"v2"}
	if _, n, err := try("-", "-", "PRIOR_MISMATCH"); err == nil || n != 1 {
		t.Fatalf("гараар: %v %d", err, n)
	}
}

func TestPriorSplits(t *testing.T) {
	got := priorSplits(2)
	want := [][]bool{{true, false}, {true, true}, {false, true}}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for i := range want {
		for j := range want[i] {
			if got[i][j] != want[i][j] {
				t.Fatalf("%v", got)
			}
		}
	}
	if n := len(priorSplits(6)); n != 6 {
		t.Fatalf("n > 4: зөвхөн эхний k (%d)", n)
	}
}
