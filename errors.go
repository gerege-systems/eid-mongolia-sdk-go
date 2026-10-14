package eid

import "fmt"

// SDK-ийн төрөлжсөн алдаанууд. RP backend эдгээрийг errors.As-аар ялган барьж хэрэглэгчид зөв мессеж/үйлдэл
// сонгоно (ж: *AuthenticationError → тохиргооны алдаа, *SessionFailedError{USER_REFUSED} → дахин оролд,
// *ValidationError → хариунд ИТГЭХГҮЙ).

// AuthenticationError — HTTP 401: API secret буруу эсвэл байхгүй. Тохиргооны (RP secret) алдаа.
type AuthenticationError struct{}

func (*AuthenticationError) Error() string {
	return "eid: API secret буруу эсвэл байхгүй (401)"
}

// ForbiddenError — HTTP 403: IP allowlist/mTLS зөвшөөрөөгүй, RP-д эрх алга, эсвэл OnBehalfOf-ийн төлөөлөл
// татгалзсан. Сервер {"error","code"} буцаасан бол Code (ж: CodeRepresentationDenied) — салааллыг үүгээр хийнэ.
type ForbiddenError struct {
	// Code — серверийн тогтвортой алдааны код; байхгүй (JSON биш, proxy) бол "".
	Code string
	// Message — серверийн "error" текст (логт; хэрэглэгчид шууд харуулахгүй).
	Message string
}

func (e *ForbiddenError) Error() string {
	if e.Message == "" {
		return "eid: IP allowlist эсвэл mTLS зөвшөөрөөгүй (403)"
	}
	if e.Code != "" {
		return fmt.Sprintf("eid: RP-API 403 %s: %s", e.Code, e.Message)
	}
	return "eid: RP-API 403: " + e.Message
}

// APIError — RP-API-аас ирсэн бусад HTTP алдаа (4xx/5xx).
type APIError struct {
	Status int
	// Body — хариуны бие (64 KiB хүртэл таслагдсан).
	Body string
	// Code — серверийн {"error","code"}-ийн code (ж: CodeOrgNotFound); байхгүй бол "".
	Code string
}

func (e *APIError) Error() string { return fmt.Sprintf("eid: RP-API %d: %s", e.Status, e.Body) }

// NetworkError — сүлжээ/timeout: upstream хариу өгсөнгүй. Unwrap нь эх алдааг (context.DeadlineExceeded г.м.) буцаана.
type NetworkError struct {
	// Op — "GET /session/…" эсвэл URL.
	Op string
	// Timeout — хүсэлт хугацаа хэтэрсэн (context deadline / client timeout).
	Timeout bool
	Err     error
}

func (e *NetworkError) Error() string {
	if e.Timeout {
		return "eid: хүсэлт хугацаа хэтэрлээ: " + e.Op
	}
	return fmt.Sprintf("eid: сүлжээний алдаа (%s): %v", e.Op, e.Err)
}

func (e *NetworkError) Unwrap() error { return e.Err }

// SessionFailedError — session амжилтгүй дууссан (endResult ≠ OK): TIMEOUT, USER_REFUSED*, DOCUMENT_UNUSABLE г.м.
// EndResult-оор салгаж RP UI-д тохирох мессеж харуулна.
type SessionFailedError struct {
	EndResult string
}

func (e *SessionFailedError) Error() string { return "eid: session амжилтгүй: " + e.EndResult }

// ValidationError — хариуны баталгаажуулалт бүтэлгүйтсэн: гэрчилгээний гинж итгэлцэлгүй, гарын үсэг
// challenge/digest-тэй таарсангүй, certLevel хүрэлцээгүй г.м. ЭНЭ алдаа гарвал хариунд ИТГЭХГҮЙ
// (хуурамч/proxy хийгдсэн байж болзошгүй).
type ValidationError struct {
	Reason string
}

func (e *ValidationError) Error() string { return "eid: баталгаажуулалт: " + e.Reason }

// DeviceLinkError — device link угсрах боломжгүй: deviceLinkBase https биш, token/lang/secret хэлбэр буруу, эсвэл
// төрөлд хэрэгтэй талбар дутуу. Session-ийг дахин эхлүүлнэ; холбоосыг таахгүй.
type DeviceLinkError struct {
	Reason string
}

func (e *DeviceLinkError) Error() string { return "eid: BuildDeviceLink: " + e.Reason }

// Байгууллагын нэрийн өмнөөс (OnBehalfOf) урсгалын татгалзлын кодууд — ForbiddenError.Code / APIError.Code-д ирнэ.
const (
	// CodeRepresentationDenied — 403: идэвхтэй төлөөлөгч биш.
	CodeRepresentationDenied = "REPRESENTATION_DENIED"
	// CodeRepresentationPending — 403: PIN2-оор баталгаажуулаагүй (MANAGER).
	CodeRepresentationPending = "REPRESENTATION_PENDING"
	// CodeRepresentationExpired — 403: хугацааны гадна.
	CodeRepresentationExpired = "REPRESENTATION_EXPIRED"
	// CodeOrgNotActive — 403: байгууллага eID-д идэвхгүй.
	CodeOrgNotActive = "ORG_NOT_ACTIVE"
	// CodeSignerUnidentified — 403: anonymous session.
	CodeSignerUnidentified = "SIGNER_UNIDENTIFIED"
	// CodeOrgNotFound — 404: байгууллага олдсонгүй.
	CodeOrgNotFound = "ORG_NOT_FOUND"
	// CodeRepresentationRevoked — 403 (PDF баримт татахад): prepare-ээс хойш эрх хасагдсан, баримт үүсээгүй.
	CodeRepresentationRevoked = "REPRESENTATION_REVOKED"
)

// OnBehalfErrorCodes — OnBehalfOf урсгалын бүх татгалзлын код.
var OnBehalfErrorCodes = []string{
	CodeRepresentationDenied,
	CodeRepresentationPending,
	CodeRepresentationExpired,
	CodeOrgNotActive,
	CodeSignerUnidentified,
	CodeOrgNotFound,
	CodeRepresentationRevoked,
}

func invalid(format string, a ...any) error {
	return &ValidationError{Reason: fmt.Sprintf(format, a...)}
}
