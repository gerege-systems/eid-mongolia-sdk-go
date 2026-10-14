package pades

import (
	"encoding/json"
	"errors"
	"strings"
)

// ProfileVersion — PDF/CMS профайлын хувилбар (docs/PADES_CLIENT_SIDE.md §7 «pades-client/1»). Профайл өөрчлөгдвөл
// нэмэгдэж golden vector шинэчлэгдэнэ.
const ProfileVersion = "pades-client/1"

// CompletedMeta — Completed-ийн binding-д (mobile/capi/wasm) дамжих JSON хэсэг (PDF-ээс бусад).
type CompletedMeta struct {
	DocID          string   `json:"docId"`
	OutSHA256      string   `json:"outSha256"`
	InSHA256       string   `json:"inSha256"`
	HasPage        bool     `json:"hasPage"`
	PageSHA256     string   `json:"pageSha256,omitempty"`
	RevIndex       int      `json:"revIndex"`
	SigRevSHA256   string   `json:"sigRevSha256"`
	PriorCMSSHA256 []string `json:"priorCmsSha256"`
	SignerCert     []byte   `json:"signerCert"`    // base64
	CMS            []byte   `json:"cms,omitempty"` // base64 (capi)
}

// Meta — c-ийн JSON хэсэг; withCMS бол CMS-ийг оруулна.
func (c *Completed) Meta(withCMS bool) CompletedMeta {
	m := CompletedMeta{DocID: c.DocID, OutSHA256: c.OutSHA256, InSHA256: c.InSHA256, HasPage: c.HasPage,
		PageSHA256: c.PageSHA256, RevIndex: c.RevIndex, SigRevSHA256: c.SigRevSHA256,
		PriorCMSSHA256: c.PriorCMSSHA256, SignerCert: c.SignerCert}
	if m.PriorCMSSHA256 == nil {
		m.PriorCMSSHA256 = []string{}
	}
	if withCMS {
		m.CMS = c.CMS
	}
	return m
}

// ErrorJSON — binding-ийн алдааны JSON {"code","message"} (pades.Error биш бол code = "INTERNAL").
func ErrorJSON(err error) string {
	out := struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}{Code: "INTERNAL", Message: err.Error()}
	var e *Error
	if errors.As(err, &e) {
		out.Code, out.Message = e.Code, e.Message
		if e.Err != nil {
			out.Message += ": " + e.Err.Error()
		}
	}
	b, _ := json.Marshal(out)
	return string(b)
}

// ParsePrepareOptions / ParseCompleteOptions / ParseVerifyOptions — binding-ийн options JSON (lowerCamelCase;
// []byte нь base64, цаг RFC 3339). Үл мэдэгдэх түлхүүр → REQUEST_INVALID.
func ParsePrepareOptions(s string) (PrepareOptions, error) {
	var o PrepareOptions
	return o, parseJSON(s, &o)
}

// ParseCompleteOptions — дээрхийг үз. HTTPClient/Now нь JSON-оор дамжихгүй.
func ParseCompleteOptions(s string) (CompleteOptions, error) {
	var o CompleteOptions
	return o, parseJSON(s, &o)
}

// ParseVerifyOptions — дээрхийг үз.
func ParseVerifyOptions(s string) (VerifyOptions, error) {
	var o VerifyOptions
	return o, parseJSON(s, &o)
}

func parseJSON(s string, v any) error {
	if s == "" {
		return nil
	}
	dec := json.NewDecoder(stringsReader(s))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return newErr(CodeRequestInvalid, "options JSON", err)
	}
	return nil
}

func stringsReader(s string) *strings.Reader { return strings.NewReader(s) }
