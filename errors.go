package eid

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// SDK-ийн төрөлжсөн алдаанууд. RP backend эдгээрийг errors.As-аар ялган барьж хэрэглэгчид зөв мессеж/үйлдэл
// сонгоно (ж: *AuthenticationError → тохиргооны алдаа, *SessionFailedError{USER_REFUSED} → дахин оролд,
// *ValidationError → хариунд ИТГЭХГҮЙ).

// AuthenticationError — HTTP 401: API secret буруу эсвэл байхгүй. Тохиргооны (RP secret) алдаа.
//
// CA-ийн өөрийн 401 нь JSON {"error"[,"code"]} — Message (ба байвал Code) бөглөгдөнө; JSON биш (proxy / nginx) бол
// хоёул "" — үүгээр CA-ийн 401-ийг урд талын proxy-ийнхоос ялгана.
type AuthenticationError struct {
	// Code — серверийн {"code"}; JSON биш (proxy) бол "".
	Code string
	// Message — серверийн {"error"} текст (логт).
	Message string
	// Body — хариуны бие (64 KiB хүртэл таслагдсан).
	Body string
	// Header — хариуны header-ууд.
	Header http.Header
}

func (e *AuthenticationError) Error() string {
	if e.Code != "" {
		return "eid: API secret буруу эсвэл байхгүй (401 " + e.Code + ")"
	}
	return "eid: API secret буруу эсвэл байхгүй (401)"
}

// ForbiddenError — HTTP 403: IP allowlist/mTLS зөвшөөрөөгүй, RP-д эрх алга, эсвэл OnBehalfOf-ийн төлөөлөл
// татгалзсан. Сервер {"error","code"} буцаасан бол Code (ж: CodeRepresentationDenied) — салааллыг үүгээр хийнэ.
type ForbiddenError struct {
	// Code — серверийн тогтвортой алдааны код; байхгүй (JSON биш, proxy) бол "".
	Code string
	// Message — серверийн "error" текст (логт; хэрэглэгчид шууд харуулахгүй).
	Message string
	// RetryAfter — хариуны Retry-After (секунд эсвэл HTTP-огноо задалсан); байхгүй/буруу бол 0.
	RetryAfter time.Duration
	// Header — хариуны header-ууд.
	Header http.Header
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
	// RetryAfter — хариуны Retry-After (секунд эсвэл HTTP-огноо задалсан); байхгүй/буруу бол 0. CA түр алдаанд
	// (429 PDF_PREPARE_BUSY / RATE_LIMITED, 503 DOCUMENT_PENDING / TSA_UNAVAILABLE / LTV_UNAVAILABLE г.м.) тавина.
	RetryAfter time.Duration
	// Header — хариуны header-ууд.
	Header http.Header
}

func (e *APIError) Error() string { return fmt.Sprintf("eid: RP-API %d: %s", e.Status, e.Body) }

// Retryable — CA-ийн түр алдаа (RetryableCodes-ийн нэг, эсвэл 429/503 + Retry-After): RetryAfter-ийн дараа ижил
// хүсэлтийг давтаж болно (prepared state хэвээр).
func (e *APIError) Retryable() bool {
	for _, c := range RetryableCodes {
		if e.Code == c {
			return true
		}
	}
	return (e.Status == http.StatusTooManyRequests || e.Status == http.StatusServiceUnavailable) && e.RetryAfter > 0
}

// CA-ийн түр (давтаж болох) алдааны кодууд — APIError.Code. docs: PADES_SIGNING §3.1/§3.4, TOKEN_CERT, TOKEN_AUTH.
const (
	// CodePDFPrepareBusy — 429: зэрэг prepare-ийн хязгаар (RP 10, нийт 50); Retry-After: 5.
	CodePDFPrepareBusy = "PDF_PREPARE_BUSY"
	// CodeDocumentPending — 503 (PDF баримт татахад): угсралт 30с-д дуусаагүй; Retry-After: 5.
	CodeDocumentPending = "DOCUMENT_PENDING"
	// CodeTSAUnavailable — 503: TSA хүрэхгүй/тохируулаагүй; Retry-After: 30 (document).
	CodeTSAUnavailable = "TSA_UNAVAILABLE"
	// CodeLTVUnavailable — 503: CRL/OCSP (LTV) өгөгдөл хүчингүй/шалгагдахгүй; Retry-After: 60.
	CodeLTVUnavailable = "LTV_UNAVAILABLE"
	// CodeRateLimited — 429 (токен, токеноор нэвтрэлт): хүсэлтийн хязгаар; Retry-After.
	CodeRateLimited = "RATE_LIMITED"
	// CodeStateUnavailable — 503 (токен): state store түр хүрэхгүй; Retry-After.
	CodeStateUnavailable = "STATE_UNAVAILABLE"
	// CodeIssuancePending — 503 (токены гэрчилгээний үр дүн): олгогдож байна; Retry-After: 5.
	CodeIssuancePending = "ISSUANCE_PENDING"
)

// RetryableCodes — APIError.Retryable-ийн танидаг түр алдааны кодууд.
var RetryableCodes = []string{
	CodePDFPrepareBusy, CodeDocumentPending, CodeTSAUnavailable, CodeLTVUnavailable,
	CodeRateLimited, CodeStateUnavailable, CodeIssuancePending,
}

// parseRetryAfter — RFC 9110 §10.2.3: delay-seconds эсвэл HTTP-date (now-оос хойшхи хугацаа). Буруу/өнгөрсөн → 0.
func parseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		if n <= 0 || n > int64(24*time.Hour/time.Second) {
			return 0
		}
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil && t.After(now) {
		return t.Sub(now)
	}
	return 0
}

// NetworkError — сүлжээ/timeout: upstream хариу өгсөнгүй. Unwrap нь эх алдааг (context.DeadlineExceeded г.м.) буцаана.
//
// Op ба Err-д хувь хүний таних тэмдэг ОРОХГҮЙ: замын /etsi/{…} ба /document/{…} хэсэг "…" болно, *url.Error (бүтэн
// URL-тай) нь доторх шалтгаанаараа солигдоно — алдааг шууд лог руу бичиж болно.
type NetworkError struct {
	// Op — "GET /session/…" (таних тэмдэг хасагдсан зам).
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

// identifierInPath — замын хувь хүн/төхөөрөмжийн таних тэмдэг (PNOMN-…, РД, documentNumber).
var identifierInPath = regexp.MustCompile(`/(etsi|document)/[^/?#\s]+`)

// maskPath — алдаа/логт орох зам: /etsi/{…}, /document/{…} → "…", query хасагдана.
func maskPath(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	return identifierInPath.ReplaceAllString(p, "/$1/…")
}

func invalid(format string, a ...any) error {
	return &ValidationError{Reason: fmt.Sprintf(format, a...)}
}
