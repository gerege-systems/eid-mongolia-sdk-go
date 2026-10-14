package eid

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
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
