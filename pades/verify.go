package pades

import (
	"bytes"
	"context"
	"strings"
	"time"

	"github.com/digitorus/pdf"

	"github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/validate"
)

// Report — CA-ийн нийтийн шалгагчийн (/v3/validate/pdf) тайлантай ижил JSON хэлбэр.
type (
	Report          = validate.PDFReport
	SignatureReport = validate.SignatureReport
	CertInfo        = validate.CertInfo
	TimestampInfo   = validate.TimestampInfo
	LTVInfo         = validate.LTVInfo
	Indication      = validate.Indication
)

// Indication-ийн утгууд.
const (
	Valid         = validate.Valid
	Invalid       = validate.Invalid
	Indeterminate = validate.Indeterminate
)

// VerifyOptions — Verify-ийн тохиргоо.
type VerifyOptions struct {
	// Roots — итгэлийн тулгуур DER; хоосон бол Mongolian National Root CA.
	Roots [][]byte `json:"roots,omitempty"`
	// Intermediates — нэмэлт завсрын CA DER (шигтгэсэн 02–05-аас гадна).
	Intermediates [][]byte `json:"intermediates,omitempty"`
	// Issuers — eID-ийн олгогч гэж үзэх нэмэлт CA DER (шигтгэсэн 04/05-аас гадна; тест).
	Issuers [][]byte `json:"issuers,omitempty"`
	// Time — шалгах цаг (цагийн тэмдэггүй гарын үсэгт); тэг бол одоо.
	Time time.Time `json:"time,omitempty"`
}

// Verify — ValidatePDF-ийн сүлжээгүй хэлбэр (Offline: true): цуцлалтыг зөвхөн баримтын DSS-ийн OCSP/CRL-ээс.
//
// Deprecated: ValidatePDF (онлайн OCSP/CRL, ctx) ашиглана уу.
func Verify(doc []byte, o VerifyOptions) (*Report, error) {
	rep, err := ValidatePDF(context.Background(), doc, ValidateOptions{Roots: o.Roots, Intermediates: o.Intermediates,
		Issuers: o.Issuers, Time: o.Time, Offline: true})
	if ErrorCode(err) == CodePDFNoSignature {
		return &Report{Indication: Valid, Signatures: []SignatureReport{}}, nil // v0.6.0 хүртэлх зан
	}
	if ErrorCode(err) == CodePDFTooManySignatures {
		err.(*Error).Code = CodePDFInvalid // v0.6.0 хүртэлх зан
	}
	return rep, err
}

// docIDFromPage — баталгаажуулалтын хуудасны холбоос (`<pageVerifyURL><uuid>`)-оос docID; олдохгүй бол "".
func docIDFromPage(doc []byte) (id string) {
	defer func() {
		if recover() != nil {
			id = ""
		}
	}()
	r, err := pdf.NewReader(bytes.NewReader(doc), int64(len(doc)))
	if err != nil {
		return ""
	}
	for _, x := range r.Xref() {
		v := r.Resolve(x.Ptr(), x.Ptr())
		if v.Kind() != pdf.Dict || v.Key("Subtype").Name() != "Link" {
			continue
		}
		u := v.Key("A").Key("URI").RawString()
		if rest, ok := strings.CutPrefix(u, pageVerifyURL); ok && uuidRe.MatchString(rest) {
			return rest
		}
	}
	return ""
}
