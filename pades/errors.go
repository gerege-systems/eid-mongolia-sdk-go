package pades

import (
	"errors"
	"fmt"
)

// Алдааны тогтмол кодууд (binding-ууд JSON {code,message}-ээр дамжуулна). Утга нь өөрчлөгдөхгүй.
const (
	CodePDFInvalid               = "PDF_INVALID"
	CodePDFEncrypted             = "PDF_ENCRYPTED"
	CodePDFLocked                = "PDF_LOCKED" // DocMDP P=1 certification гарын үсэгтэй
	CodePDFTooLarge              = "PDF_TOO_LARGE"
	CodePDFTooManySignatures     = "PDF_TOO_MANY_SIGNATURES"
	CodePDFPriorSignatureInvalid = "PDF_PRIOR_SIGNATURE_INVALID"
	CodePDFForeignSignature      = "PDF_FOREIGN_SIGNATURE" // өмнөх гарын үсэг eID-ийн хүчинтэй B-LT биш
	CodeSignerInvalid            = "SIGNER_INVALID"
	CodeRequestInvalid           = "REQUEST_INVALID"
	CodeSignatureInvalid         = "SIGNATURE_INVALID"
	CodeTSAUnavailable           = "TSA_UNAVAILABLE"
	CodeLTVUnavailable           = "LTV_UNAVAILABLE"
	CodeSelfValidationFailed     = "SELF_VALIDATION_FAILED"
	CodePlaceholderOverflow      = "PLACEHOLDER_OVERFLOW"
	CodeStateInvalid             = "STATE_INVALID"
)

// Error — pades-ийн бүх алдаа. Code нь дээрх тогтмолуудын нэг; Err нь шалтгаан (байвал).
type Error struct {
	Code    string
	Message string
	Err     error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("pades: %s: %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("pades: %s: %s", e.Code, e.Message)
}

func (e *Error) Unwrap() error { return e.Err }

// ErrorCode — err-ийн Code (pades.Error биш бол "").
func ErrorCode(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func newErr(code, msg string, cause error) *Error {
	return &Error{Code: code, Message: msg, Err: cause}
}

// ProfileVersion — PDF/CMS профайлын хувилбар (pades/PROFILE.md). Профайл өөрчлөгдвөл нэмэгдэж golden шинэчлэгдэнэ;
// native SDK бүр ижил хувилбарын golden-ийг байт-ижил давтана.
const ProfileVersion = "pades-client/1"
