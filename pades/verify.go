package pades

import (
	"bytes"
	"context"
	"errors"
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

// Verify — PDF доторх бүх гарын үсгийг CA-ийн нийтийн шалгагчийн кодоор (hardened revision profile) шалгана.
// Сүлжээ рүү гарахгүй: цуцлалтыг баримтын DSS-ийн OCSP/CRL-ээс (CA өөрийн бүртгэлээс уншдаг).
func Verify(doc []byte, o VerifyOptions) (*Report, error) {
	if len(doc) > MaxOutputBytes {
		return nil, newErr(CodePDFTooLarge, "PDF 10 MiB-аас их", nil)
	}
	roots, err := parseRoots(o.Roots)
	if err != nil {
		return nil, newErr(CodeRequestInvalid, "roots", err)
	}
	inter, err := parseDERs(o.Intermediates)
	if err != nil {
		return nil, newErr(CodeRequestInvalid, "intermediates", err)
	}
	issuers, err := parseDERs(o.Issuers)
	if err != nil {
		return nil, newErr(CodeRequestInvalid, "issuers", err)
	}
	raws, err := validate.Extract(doc)
	switch {
	case errors.Is(err, validate.ErrNoSignature):
		return &Report{Indication: Valid, Signatures: []SignatureReport{}}, nil
	case err != nil:
		return nil, newErr(CodePDFInvalid, "PDF задарсангүй", err)
	}
	var now func() time.Time
	if !o.Time.IsZero() {
		t := o.Time
		now = func() time.Time { return t }
	}
	v := newValidator(roots, inter, issuers, now, raws)
	rep, err := v.ValidatePDF(context.Background(), doc)
	if err != nil {
		return nil, newErr(CodePDFInvalid, "шалгаж чадсангүй", err)
	}
	return rep, nil
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
