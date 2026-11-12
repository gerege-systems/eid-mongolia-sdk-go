package eid

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// SealService — байгууллагын цахим тамга (e-Seal): байгууллагын HSM дэх түлхүүрээр digest тамгална. Интерактив биш
// (иргэн, PIN, апп оролцохгүй) — хариу шууд (session-гүй). RP-д тухайн байгууллагын `SEAL:<orgEtsi>` эрх хэрэгтэй (үгүй бол
// *ForbiddenError, 403). Хэт олон хүсэлтэд CA 429 буцаана — *APIError.Retryable() / RetryAfter-ийн дараа дахин.
//
// PDF-ийг тамгалах бол pades.SealPDF (PAdES-BASELINE-LT, RFC 3161 timestamp заавал).
//
// Тамганы гэрчилгээ олгох (CA !483, 2026-11-09): RequestCertificate → 202 PENDING хүсэлт; байгууллагын ADMIN eID аппаараа
// PIN2-оор батална; CertificateRequest / WaitForCertificate-ээр ISSUED (гэрчилгээтэй) / REJECTED / EXPIRED / FAILED хүртэл
// асууна.
//
// Үйлчилгээний унтраалга (CA 2026-11-12): eID-ийн оператор тамганы гэрчилгээний олголт ба тамгалалтыг тус тусад нь
// платформ даяар унтрааж болно — RequestCertificate / Seal нь 503 ErrSealServiceDisabled (*APIError, Service =
// SealServiceIssuance | SealServiceSealing; Retry-After-гүй, Retryable() false) буцаана: автоматаар давтахгүй. Certificate
// ба CertificateRequest (тэгэхээр WaitForCertificate-ийн асуулга) хэзээ ч унтардаггүй.
type SealService struct {
	h *httpDoer
}

// SealCertificate — GET /seal/certificate/{orgEtsi}-ийн хариу (CA dto.SealCertificateResponse). CertificateLevel нь
// ГЭРЧИЛГЭЭНЭЭС өөрөөс нь (QcSSCD байвал QSCD, үгүй бол QUALIFIED) — CA-ийн одоогийн түлхүүрийн тохиргооноос биш.
type SealCertificate struct {
	OrgEtsi          string           `json:"orgEtsi"`
	Certificate      []byte           `json:"certificate"` // DER (JSON-д base64)
	SerialNumber     string           `json:"serialNumber"`
	SubjectDN        string           `json:"subjectDn"`
	IssuerDN         string           `json:"issuerDn"`
	NotBefore        time.Time        `json:"notBefore"`
	NotAfter         time.Time        `json:"notAfter"`
	CertificateLevel CertificateLevel `json:"certificateLevel"`
}

// SealResult — POST /seal/{orgEtsi}-ийн хариу (CA dto.SealResponse): ECDSA гарын үсэг (DER) ба тамганы гэрчилгээ.
type SealResult struct {
	OrgEtsi string
	// Signature — digest дээрх ECDSA гарын үсэг (ASN.1 DER).
	Signature []byte
	// SignatureAlgorithm — ж: ecdsa-with-SHA256 (digest-ийн hash-аас).
	SignatureAlgorithm string
	// Certificate — тамгалсан гэрчилгээ (DER).
	Certificate []byte
	// CertificateLevel — тамгалсан гэрчилгээний өөрийнх нь түвшин (QcSSCD байвал QSCD, үгүй бол QUALIFIED).
	CertificateLevel CertificateLevel
	SealedAt         time.Time
	// Raw — серверийн түүхий JSON.
	Raw json.RawMessage
}

// SealRequestStatus — тамганы гэрчилгээний хүсэлтийн төлөв (CA dto.SealCertificateRequestResponse.status).
type SealRequestStatus string

const (
	SealRequestPending  SealRequestStatus = "PENDING"
	SealRequestApproved SealRequestStatus = "APPROVED" // батлагдсан, гэрчилгээ олгогдож байна
	SealRequestIssued   SealRequestStatus = "ISSUED"   // Certificate бөглөгдсөн
	SealRequestRejected SealRequestStatus = "REJECTED"
	SealRequestExpired  SealRequestStatus = "EXPIRED"
	SealRequestFailed   SealRequestStatus = "FAILED" // Failure: SEAL_ISSUANCE_FAILED | PUSH_FAILED | SEAL_SERVICE_DISABLED
)

// SealCertificateRequest — POST /seal/certificate/{orgEtsi} (202) ба GET /seal/certificate/{orgEtsi}/requests/{requestId}-ийн
// хариу (CA dto.SealCertificateRequestResponse).
type SealCertificateRequest struct {
	RequestID string            `json:"requestId"`
	OrgEtsi   string            `json:"orgEtsi"`
	Status    SealRequestStatus `json:"status"`
	CreatedAt time.Time         `json:"createdAt"`
	// ExpiresAt — батлах хугацааны төгсгөл (дараа нь EXPIRED).
	ExpiresAt time.Time  `json:"expiresAt"`
	DecidedAt *time.Time `json:"decidedAt,omitempty"`
	// Approvers — PIN2 push илгээсэн ADMIN-ийн тоо (шинэ/PENDING хариунд).
	Approvers int `json:"approvers,omitempty"`
	// Failure — FAILED/EXPIRED үеийн машин код: EXPIRED | SEAL_ISSUANCE_FAILED | PUSH_FAILED | SEAL_SERVICE_DISABLED
	// (CodeSealServiceDisabled — ADMIN баталсан ч олголт унтраалттай байсан; гэрчилгээ гараагүй).
	Failure string `json:"failure,omitempty"`
	// Certificate — ISSUED үед (Certificate()-тэй ижил хэлбэр).
	Certificate *SealCertificate `json:"certificate,omitempty"`
}

// Тамганы гэрчилгээний олголтын CA алдааны кодууд — APIError.Code.
const (
	// CodeSealApproverUnavailable — 409 (RequestCertificate): байгууллагад идэвхтэй eID төхөөрөмжтэй ADMIN төлөөлөгч алга.
	CodeSealApproverUnavailable = "SEAL_APPROVER_UNAVAILABLE"
	// CodeSealRequestNotFound — 404 (CertificateRequest): хүсэлт олдсонгүй (эсвэл өөр байгууллагынх).
	CodeSealRequestNotFound = "SEAL_REQUEST_NOT_FOUND"
	// CodeSealServiceDisabled — 503 (RequestCertificate: Service = SealServiceIssuance; Seal: Service = SealServiceSealing):
	// eID-ийн оператор үйлчилгээг платформ даяар унтраасан. Retry-After-гүй, Retryable() false — давтахгүй; оператор
	// асаасны дараа л ажиллана. Мөн SealCertificateRequest.Failure / SealRequestError.Failure-д (Status FAILED): хүлээгдэж
	// байсан хүсэлтийг ADMIN баталсан ч олголт унтраалттай байсан.
	CodeSealServiceDisabled = "SEAL_SERVICE_DISABLED"
)

// APIError.Service-ийн утгууд (503 CodeSealServiceDisabled).
const (
	// SealServiceIssuance — тамганы гэрчилгээний олголт (POST /seal/certificate/{orgEtsi}).
	SealServiceIssuance = "issuance"
	// SealServiceSealing — тамгалалт (POST /seal/{orgEtsi}; pades.SealPDF).
	SealServiceSealing = "sealing"
)

// errors.Is-ийн sentinel-ууд (*APIError.Is нь Code-оор тулгана).
var (
	ErrSealApproverUnavailable = errors.New("eid: " + CodeSealApproverUnavailable)
	ErrSealRequestNotFound     = errors.New("eid: " + CodeSealRequestNotFound)
	// ErrSealServiceDisabled — 503 *APIError (RequestCertificate, Seal, pades.SealPDF) ба FAILED *SealRequestError
	// (WaitForCertificate; Failure = CodeSealServiceDisabled) хоёуланд нь errors.Is-ээр таарна.
	ErrSealServiceDisabled = errors.New("eid: " + CodeSealServiceDisabled)
)

// SealRequestError — WaitForCertificate: хүсэлт гэрчилгээгүй дууссан. Outcome = REJECTED (ADMIN татгалзсан) / EXPIRED
// (батлах хугацаа дууссан) / FAILED (Failure-д код) → шинэ RequestCertificate; Outcome = "TIMEOUT" — Timeout дууссан ч
// хүсэлт серверт PENDING хэвээр (ижил RequestID-аар дахин хүлээж болно).
type SealRequestError struct {
	Outcome   SealRequestStatus
	RequestID string
	Failure   string
}

// Is — errors.Is(err, ErrSealServiceDisabled): FAILED хүсэлтийн Failure = CodeSealServiceDisabled.
func (e *SealRequestError) Is(target error) bool {
	return target == ErrSealServiceDisabled && e.Failure == CodeSealServiceDisabled
}

// SealRequestTimeout — SealRequestError.Outcome: WaitForCertificate-ийн Timeout дууссан (серверийн төлөв биш).
const SealRequestTimeout SealRequestStatus = "TIMEOUT"

func (e *SealRequestError) Error() string {
	if e.Failure != "" {
		return "eid: тамганы гэрчилгээний хүсэлт " + string(e.Outcome) + " (" + e.Failure + ")"
	}
	return "eid: тамганы гэрчилгээний хүсэлт " + string(e.Outcome)
}

// SealWaitOptions — WaitForCertificate-ийн сонголт (nil = анхдагч).
type SealWaitOptions struct {
	// Timeout — нийт хүлээх дээд хугацаа; ≤ 0 бол DefaultSealWaitTimeout. ctx-ийн deadline ч хүчинтэй.
	Timeout time.Duration
	// Interval — poll хоорондын зай; ≤ 0 бол DefaultSealPollInterval. 429/503-ын Retry-After илүү бол түүнийг дагана.
	Interval time.Duration
}

const (
	// DefaultSealWaitTimeout — CA-ийн батлах цонх (sign session TTL + 2 мин)-оос урт.
	DefaultSealWaitTimeout = 15 * time.Minute
	// DefaultSealPollInterval — CA зөвлөмж 2–5 с.
	DefaultSealPollInterval = 3 * time.Second
)

type sealRequest struct {
	Digest   string `json:"digest"`
	HashType string `json:"hashType"`
}

type sealResponse struct {
	OrgEtsi   string `json:"orgEtsi"`
	Signature *struct {
		Value              string `json:"value"`
		SignatureAlgorithm string `json:"signatureAlgorithm"`
	} `json:"signature"`
	Cert *struct {
		Value            string           `json:"value"`
		CertificateLevel CertificateLevel `json:"certificateLevel"`
	} `json:"cert"`
	SealedAt time.Time `json:"sealedAt"`
}

// Certificate — GET /seal/certificate/{orgEtsi}: байгууллагын одоогийн (хамгийн сүүлд олгогдсон, идэвхтэй) тамганы
// гэрчилгээ (PAdES-ийн SignerCert). Шинээр олгохгүй — олголт RequestCertificate. Идэвхтэй cert алга / цуцлагдсан бол 409.
func (s *SealService) Certificate(ctx context.Context, orgEtsi string) (*SealCertificate, error) {
	var c SealCertificate
	if err := s.h.getJSON(ctx, routeSealCertificate.expand(orgEtsi), 0, &c); err != nil {
		return nil, err
	}
	if len(c.Certificate) == 0 {
		return nil, &ValidationError{Reason: "seal certificate хоосон"}
	}
	return &c, nil
}

// RequestCertificate — POST /seal/certificate/{orgEtsi}: тамганы гэрчилгээний ХҮСЭЛТ (202, Status PENDING). Байгууллагын
// ADMIN төлөөлөгч(ид) eID аппаараа PIN2-оор батална; WaitForCertificate / CertificateRequest-ээр асууна. Байгууллагад
// PENDING хүсэлт байвал CA түүнийг буцаана (шинэ push үгүй). Алдаа: 409 ErrSealApproverUnavailable (идэвхтэй төхөөрөмжтэй
// ADMIN алга), 409 *APIError (байгууллага ACTIVE биш), 403 *ForbiddenError (SEAL:<orgEtsi> эрхгүй), 404 (байгууллага
// олдсонгүй), 429 RATE_LIMITED (байгууллагад цагт 5; RetryAfter), 503 ErrSealServiceDisabled (олголт унтраалттай;
// *APIError.Service = SealServiceIssuance, давтахгүй).
func (s *SealService) RequestCertificate(ctx context.Context, orgEtsi string) (*SealCertificateRequest, error) {
	var r SealCertificateRequest
	if err := s.h.postJSON(ctx, routeSealCertificateRequest.expand(orgEtsi), struct{}{}, &r); err != nil {
		return nil, err
	}
	return checkSealRequest(&r)
}

// CertificateRequest — GET /seal/certificate/{orgEtsi}/requests/{requestId}: хүсэлтийн төлөв; ISSUED үед Certificate
// бөглөгдөнө. Олдоогүй (эсвэл өөр байгууллагынх) → 404 ErrSealRequestNotFound.
func (s *SealService) CertificateRequest(ctx context.Context, orgEtsi, requestID string) (*SealCertificateRequest, error) {
	var r SealCertificateRequest
	if err := s.h.getJSON(ctx, routeSealCertificateRequestStatus.expand(orgEtsi, requestID), 0, &r); err != nil {
		return nil, err
	}
	return checkSealRequest(&r)
}

func checkSealRequest(r *SealCertificateRequest) (*SealCertificateRequest, error) {
	if r.RequestID == "" || r.Status == "" {
		return nil, &ValidationError{Reason: "seal хүсэлтийн хариунд requestId/status алга"}
	}
	if r.Status == SealRequestIssued && (r.Certificate == nil || len(r.Certificate.Certificate) == 0) {
		return nil, &ValidationError{Reason: "ISSUED seal хүсэлтэд certificate алга"}
	}
	return r, nil
}

// WaitForCertificate — хүсэлт ISSUED болтол Interval тутамд асууж олгогдсон гэрчилгээг буцаана. REJECTED / EXPIRED / FAILED
// → *SealRequestError (шинэ хүсэлт хэрэгтэй); Timeout дуусвал Outcome SealRequestTimeout (хүсэлт PENDING хэвээр). Түр алдаа
// (*APIError.Retryable: 429/503 + Retry-After) — RetryAfter-ийг хүлээгээд үргэлжилнэ; бусад алдаа шууд. ctx цуцлагдвал
// ctx.Err().
//
// Олголт унтраалттай үед ADMIN баталсан хүсэлт FAILED (Failure = CodeSealServiceDisabled) болно —
// errors.Is(err, ErrSealServiceDisabled); оператор асаасны дараа шинэ RequestCertificate. 503 CodeSealServiceDisabled
// хариуг (төлөвийн асуулга унтардаггүй ч) давтахгүй, шууд буцаана.
func (s *SealService) WaitForCertificate(ctx context.Context, orgEtsi, requestID string, o *SealWaitOptions) (*SealCertificate, error) {
	interval, timeout := DefaultSealPollInterval, DefaultSealWaitTimeout
	if o != nil && o.Interval > 0 {
		interval = o.Interval
	}
	if o != nil && o.Timeout > 0 {
		timeout = o.Timeout
	}
	deadline := time.Now().Add(timeout)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		wait := interval
		r, err := s.CertificateRequest(ctx, orgEtsi, requestID)
		var apiErr *APIError
		switch {
		case err == nil:
			switch r.Status {
			case SealRequestIssued:
				return r.Certificate, nil
			case SealRequestRejected, SealRequestExpired, SealRequestFailed:
				return nil, &SealRequestError{Outcome: r.Status, RequestID: r.RequestID, Failure: r.Failure}
			}
		case errors.As(err, &apiErr) && apiErr.Retryable():
			wait = max(interval, apiErr.RetryAfter)
		default:
			return nil, err
		}
		left := time.Until(deadline)
		if left <= 0 {
			return nil, &SealRequestError{Outcome: SealRequestTimeout, RequestID: requestID}
		}
		t := time.NewTimer(min(wait, left))
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		case <-t.C:
		}
	}
}

// Seal — POST /seal/{orgEtsi}: digest-ийг байгууллагын тамгаар тамгална. hash: SHA256 | SHA384 | SHA512 ("" = SHA256);
// digest-ийн урт түүнтэй таарна. Хариуны гарын үсгийг хариуны гэрчилгээгээр digest дээр шалгаж, e-Seal гэрчилгээ
// (KeyUsage = зөвхөн nonRepudiation) мөн эсэхийг тулгана — таарахгүй бол *ValidationError. Гинж/цуцлалтыг энэ шалгахгүй
// (pades.SealPDF нь OCSP/CRL + self-validation хийнэ). Алдаа: 403 *ForbiddenError, 429 RATE_LIMITED (Retryable), 503
// ErrSealServiceDisabled (тамгалалт унтраалттай; *APIError.Service = SealServiceSealing, Retry-After-гүй — давтахгүй).
func (s *SealService) Seal(ctx context.Context, orgEtsi string, digest []byte, hash HashAlgorithm) (*SealResult, error) {
	if hash == "" {
		hash = SHA256
	}
	ch, err := cryptoHash(string(hash))
	if err != nil {
		return nil, err
	}
	if len(digest) != ch.Size() {
		return nil, invalid("digest нь %s-ийн урт (%d байт) байх ёстой", hash, ch.Size())
	}
	var raw json.RawMessage
	body := sealRequest{Digest: base64.StdEncoding.EncodeToString(digest), HashType: strings.ReplaceAll(string(hash), "-", "")}
	if err := s.h.postJSON(ctx, routeSeal.expand(orgEtsi), body, &raw); err != nil {
		return nil, err
	}
	var r sealResponse
	if err := decodeJSON(raw, "/seal", &r); err != nil {
		return nil, err
	}
	if r.Signature == nil || r.Signature.Value == "" || r.Cert == nil || r.Cert.Value == "" {
		return nil, &ValidationError{Reason: "seal хариунд signature/cert алга"}
	}
	sig, err := base64.StdEncoding.DecodeString(r.Signature.Value)
	if err != nil {
		return nil, &ValidationError{Reason: "seal signature base64 биш", Cause: err}
	}
	certDER, err := base64.StdEncoding.DecodeString(r.Cert.Value)
	if err != nil {
		return nil, &ValidationError{Reason: "seal cert base64 биш", Cause: err}
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, &ValidationError{Reason: "seal cert задарсангүй", Cause: err}
	}
	if !IsSealCertificate(cert) {
		return nil, &ValidationError{Reason: "хариуны гэрчилгээ e-Seal биш (KeyUsage)"}
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !ecdsa.VerifyASN1(pub, digest, sig) {
		return nil, &ValidationError{Reason: "seal гарын үсэг digest-тэй таарсангүй"}
	}
	return &SealResult{OrgEtsi: r.OrgEtsi, Signature: sig, SignatureAlgorithm: r.Signature.SignatureAlgorithm, Certificate: certDER,
		CertificateLevel: r.Cert.CertificateLevel, SealedAt: r.SealedAt, Raw: raw}, nil
}

// IsSealCertificate — e-Seal профайл: KeyUsage-д nonRepudiation (contentCommitment) байгаа, digitalSignature байхгүй,
// EKU байхгүй (CA/SDK шалгагчийн "seal" ангилалтай ижил дүрэм).
func IsSealCertificate(c *x509.Certificate) bool {
	if c == nil || c.IsCA {
		return false
	}
	return c.KeyUsage&x509.KeyUsageContentCommitment != 0 && c.KeyUsage&x509.KeyUsageDigitalSignature == 0 &&
		len(c.ExtKeyUsage) == 0 && len(c.UnknownExtKeyUsage) == 0
}
