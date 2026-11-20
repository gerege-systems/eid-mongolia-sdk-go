package eid

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// RP-ийн санаачилсан тамганы эрхийн хүсэлт (CA V156, 2026-11-20): RP өөрөө байгууллагын тамга ашиглах эрх (`SEAL:<orgEtsi>`)
// хүснэ. Хүнийг ETSI-ээр биш, ЭНЭ RP-ийн эхлүүлж сүүлийн 5 минутад OK-оор дуусгасан НЭВТРЭЛТИЙН session-оор таньна: тэр
// хүн байгууллагын улсын бүртгэлээр баталгаажсан Гүйцэтгэх захирал (REGISTRY CEO) байх ёстой; push зөвхөн түүнд очиж eID
// аппаараа PIN2-оор зөвшөөрнө. Нэг session → нэг хүсэлт (ижил session-оор дахин дуудвал ижил PENDING). SEAL эрх
// шаардахгүй, billing-д тоологдохгүй.

// SealGrantStatus — тамганы эрхийн хүсэлтийн төлөв (CA dto.RPSealGrantStatus.status).
type SealGrantStatus string

const (
	SealGrantPending  SealGrantStatus = "PENDING"
	SealGrantApproved SealGrantStatus = "APPROVED" // эрх үүссэн — Seal / RequestCertificate ажиллана
	SealGrantRejected SealGrantStatus = "REJECTED"
	SealGrantExpired  SealGrantStatus = "EXPIRED"
	SealGrantFailed   SealGrantStatus = "FAILED"  // Failure-д код (PUSH_FAILED, RP_NOT_ACTIVE, ORG_NOT_ACTIVE, …)
	SealGrantRevoked  SealGrantStatus = "REVOKED" // зөвшөөрсний дараа цуцлагдсан (захирал аппаас, оператор)
	// SealGrantTimeout — SealGrantError.Outcome: WaitForGrant-ийн Timeout дууссан (серверийн төлөв биш; хүсэлт PENDING хэвээр).
	SealGrantTimeout SealGrantStatus = "TIMEOUT"
)

// SealGrant — POST /seal/grants (202) ба GET /seal/grants/{grantId}-ийн хариу (CA dto.RPSealGrantStatus). Батлагчийн
// ETSI / PIN2 session-ийг CA RP-д гаргадаггүй.
type SealGrant struct {
	GrantID string          `json:"grantId"`
	OrgEtsi string          `json:"orgEtsi"`
	Status  SealGrantStatus `json:"status"`
	// ExpiresAt — PENDING хүсэлтийг зөвшөөрөх хугацааны төгсгөл (эрх өөрөө хугацаагүй).
	ExpiresAt time.Time `json:"expiresAt"`
	// ApprovedAt — захирал PIN2-оор зөвшөөрсөн цаг (APPROVED, эсвэл зөвшөөрөгдсөний дараа REVOKED).
	ApprovedAt *time.Time `json:"approvedAt,omitempty"`
	RevokedAt  *time.Time `json:"revokedAt,omitempty"`
	// Failure — FAILED / EXPIRED / REVOKED-ийн машин код: EXPIRED, PUSH_FAILED, RP_NOT_ACTIVE, ORG_NOT_ACTIVE, RP_CHANGED,
	// RP_PERMISSIONS_FULL, CANCELLED, ORG_REVOKED.
	Failure string `json:"failure,omitempty"`
}

// Тамганы эрхийн хүсэлтийн (POST /seal/grants, GET /seal/grants/{grantId}) CA алдааны кодууд. 403-ууд *ForbiddenError.Code,
// бусад нь *APIError.Code. Мөн REQUEST_INVALID (400), ORG_NOT_FOUND (404), ORG_NOT_ACTIVE / SEAL_APPROVER_UNAVAILABLE (409),
// RATE_LIMITED (429 + Retry-After) ирнэ.
const (
	// CodeRPNotRegistered — 403: дуудагч бүртгэлтэй RP биш.
	CodeRPNotRegistered = "RP_NOT_REGISTERED"
	// CodeNotOrgCEO — 403: нэвтэрсэн хүн байгууллагын улсын бүртгэлээр баталгаажсан Гүйцэтгэх захирал биш.
	CodeNotOrgCEO = "NOT_ORG_CEO"
	// CodeAuthSessionNotFound — 404: session байхгүй эсвэл өөр RP-ийнх (CA ялгахгүй).
	CodeAuthSessionNotFound = "AUTH_SESSION_NOT_FOUND"
	// CodeAuthSessionWrongFlow — 409: AUTHENTICATION session биш (гарын үсэг, «Миний QR» г.м.).
	CodeAuthSessionWrongFlow = "AUTH_SESSION_WRONG_FLOW"
	// CodeAuthSessionNotCompleted — 409: нэвтрэлт дуусаагүй эсвэл OK-оос өөр үр дүнтэй.
	CodeAuthSessionNotCompleted = "AUTH_SESSION_NOT_COMPLETED"
	// CodeAuthSessionTooOld — 409: нэвтрэлт дууссанаас хойш 5 минутаас их — захирлыг дахин нэвтрүүлнэ.
	CodeAuthSessionTooOld = "AUTH_SESSION_TOO_OLD"
	// CodeAuthSessionAlreadyUsed — 409: session өөр тамганы эрхийн хүсэлтийн үндэс болсон — дахин нэвтрүүлнэ.
	CodeAuthSessionAlreadyUsed = "AUTH_SESSION_ALREADY_USED"
	// CodeRPNotActive — 409: RP идэвхгүй.
	CodeRPNotActive = "RP_NOT_ACTIVE"
	// CodeSealGrantAlreadyApproved — 409: энэ RP-д байгууллагын тамганы эрх аль хэдийн зөвшөөрөгдсөн.
	CodeSealGrantAlreadyApproved = "SEAL_GRANT_ALREADY_APPROVED"
	// CodeRPPermissionsFull — 409: RP-ийн эрхийн жагсаалт дүүрсэн — eID-ийн операторт хандана.
	CodeRPPermissionsFull = "RP_PERMISSIONS_FULL"
	// CodeSealGrantNotFound — 404 (GrantStatus): хүсэлт олдсонгүй эсвэл өөр RP-ийнх.
	CodeSealGrantNotFound = "SEAL_GRANT_NOT_FOUND"
)

// SealGrantErrorCodes — RequestGrant / GrantStatus-ийн тогтвортой CA кодууд (403, 404, 409; 400 REQUEST_INVALID ба 429
// RATE_LIMITED орохгүй).
var SealGrantErrorCodes = []string{
	CodeRPNotRegistered,
	CodeNotOrgCEO,
	CodeAuthSessionNotFound,
	CodeOrgNotFound,
	CodeAuthSessionWrongFlow,
	CodeAuthSessionNotCompleted,
	CodeAuthSessionTooOld,
	CodeAuthSessionAlreadyUsed,
	CodeOrgNotActive,
	CodeRPNotActive,
	CodeSealGrantAlreadyApproved,
	CodeRPPermissionsFull,
	CodeSealApproverUnavailable,
	CodeSealGrantNotFound,
}

// errors.Is-ийн sentinel-ууд: 403-ынх *ForbiddenError.Is, бусад нь *APIError.Is (Code-оор).
var (
	ErrRPNotRegistered          = errors.New("eid: " + CodeRPNotRegistered)
	ErrNotOrgCEO                = errors.New("eid: " + CodeNotOrgCEO)
	ErrAuthSessionNotFound      = errors.New("eid: " + CodeAuthSessionNotFound)
	ErrAuthSessionWrongFlow     = errors.New("eid: " + CodeAuthSessionWrongFlow)
	ErrAuthSessionNotCompleted  = errors.New("eid: " + CodeAuthSessionNotCompleted)
	ErrAuthSessionTooOld        = errors.New("eid: " + CodeAuthSessionTooOld)
	ErrAuthSessionAlreadyUsed   = errors.New("eid: " + CodeAuthSessionAlreadyUsed)
	ErrRPNotActive              = errors.New("eid: " + CodeRPNotActive)
	ErrSealGrantAlreadyApproved = errors.New("eid: " + CodeSealGrantAlreadyApproved)
	ErrRPPermissionsFull        = errors.New("eid: " + CodeRPPermissionsFull)
	ErrSealGrantNotFound        = errors.New("eid: " + CodeSealGrantNotFound)
	// ErrOrgNotFound — 404 ORG_NOT_FOUND (*APIError).
	ErrOrgNotFound = errors.New("eid: " + CodeOrgNotFound)
)

// sealGrantAPICode — *APIError.Is: тамганы эрхийн хүсэлтийн sentinel-ийн Code ("" = энэ бүлгийнх биш). switch (map биш):
// errors.Is-ийн target харьцуулагдахгүй төрөлтэй байж болно.
func sealGrantAPICode(target error) string {
	switch target {
	case ErrAuthSessionNotFound:
		return CodeAuthSessionNotFound
	case ErrAuthSessionWrongFlow:
		return CodeAuthSessionWrongFlow
	case ErrAuthSessionNotCompleted:
		return CodeAuthSessionNotCompleted
	case ErrAuthSessionTooOld:
		return CodeAuthSessionTooOld
	case ErrAuthSessionAlreadyUsed:
		return CodeAuthSessionAlreadyUsed
	case ErrRPNotActive:
		return CodeRPNotActive
	case ErrSealGrantAlreadyApproved:
		return CodeSealGrantAlreadyApproved
	case ErrRPPermissionsFull:
		return CodeRPPermissionsFull
	case ErrSealGrantNotFound:
		return CodeSealGrantNotFound
	case ErrOrgNotFound:
		return CodeOrgNotFound
	}
	return ""
}

// SealGrantError — WaitForGrant: хүсэлт APPROVED-гүй дууссан. Outcome = REJECTED / EXPIRED / FAILED / REVOKED (Failure-д
// код) → шинэ нэвтрэлт + RequestGrant; Outcome = SealGrantTimeout — Timeout дууссан ч хүсэлт PENDING хэвээр (ижил GrantID-аар
// дахин хүлээж болно).
type SealGrantError struct {
	Outcome SealGrantStatus
	GrantID string
	Failure string
}

func (e *SealGrantError) Error() string {
	if e.Failure != "" {
		return "eid: тамганы эрхийн хүсэлт " + string(e.Outcome) + " (" + e.Failure + ")"
	}
	return "eid: тамганы эрхийн хүсэлт " + string(e.Outcome)
}

type sealGrantRequest struct {
	OrgEtsi   string `json:"orgEtsi"`
	SessionID string `json:"sessionId"`
}

// RequestGrant — POST /seal/grants {orgEtsi, sessionId}: байгууллагын тамга ашиглах эрхийн ХҮСЭЛТ (202, Status PENDING).
// sessionID — энэ RP-ийн эхлүүлж сүүлийн 5 минутад OK-оор дууссан НЭВТРЭЛТИЙН session (Auth.*-ийн SessionID); тэр хүн
// байгууллагын REGISTRY CEO байх ёстой. Push зөвхөн тэр захиралд очно — GrantStatus / WaitForGrant-ээр асууна. Ижил
// session-оор дахин дуудвал ижил PENDING (шинэ push үгүй). Алдаа: 400 ErrRequestInvalid; 403 *ForbiddenError
// (ErrRPNotRegistered, ErrNotOrgCEO); 404 ErrAuthSessionNotFound, ErrOrgNotFound; 409 ErrAuthSessionWrongFlow,
// ErrAuthSessionNotCompleted, ErrAuthSessionTooOld, ErrAuthSessionAlreadyUsed, ErrOrgNotActive, ErrRPNotActive,
// ErrSealGrantAlreadyApproved, ErrRPPermissionsFull, ErrSealApproverUnavailable; 429 RATE_LIMITED (*APIError.Retryable,
// RetryAfter).
func (s *SealService) RequestGrant(ctx context.Context, orgEtsi, sessionID string) (*SealGrant, error) {
	orgEtsi, sessionID = strings.TrimSpace(orgEtsi), strings.TrimSpace(sessionID)
	if orgEtsi == "" || sessionID == "" {
		return nil, invalid("RequestGrant: orgEtsi ба sessionID шаардлагатай")
	}
	var g SealGrant
	if err := s.h.postJSON(ctx, routeSealGrants.expand(), sealGrantRequest{OrgEtsi: orgEtsi, SessionID: sessionID}, &g); err != nil {
		return nil, err
	}
	return checkSealGrant(&g)
}

// GrantStatus — GET /seal/grants/{grantId}: хүсэлтийн төлөв. Олдоогүй эсвэл өөр RP-ийнх → 404 ErrSealGrantNotFound.
func (s *SealService) GrantStatus(ctx context.Context, grantID string) (*SealGrant, error) {
	grantID = strings.TrimSpace(grantID)
	if grantID == "" {
		return nil, invalid("GrantStatus: grantID шаардлагатай")
	}
	var g SealGrant
	if err := s.h.getJSON(ctx, routeSealGrantStatus.expand(grantID), 0, &g); err != nil {
		return nil, err
	}
	return checkSealGrant(&g)
}

func checkSealGrant(g *SealGrant) (*SealGrant, error) {
	if g.GrantID == "" || g.Status == "" {
		return nil, &ValidationError{Reason: "тамганы эрхийн хариунд grantId/status алга"}
	}
	return g, nil
}

// WaitForGrant — хүсэлт APPROVED болтол Interval тутамд GrantStatus асууж түүнийг буцаана. REJECTED / EXPIRED / FAILED /
// REVOKED → *SealGrantError; Timeout дуусвал Outcome SealGrantTimeout (хүсэлт PENDING хэвээр). Түр алдаа
// (*APIError.Retryable: 429/503 + Retry-After) — RetryAfter-ийг хүлээгээд үргэлжилнэ; бусад алдаа шууд. ctx цуцлагдвал
// ctx.Err(). Сонголт WaitForCertificate-тэй ижил (nil = 15 мин / 3 с).
func (s *SealService) WaitForGrant(ctx context.Context, grantID string, o *SealWaitOptions) (*SealGrant, error) {
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
		g, err := s.GrantStatus(ctx, grantID)
		var apiErr *APIError
		switch {
		case err == nil:
			switch g.Status {
			case SealGrantApproved:
				return g, nil
			case SealGrantRejected, SealGrantExpired, SealGrantFailed, SealGrantRevoked:
				return nil, &SealGrantError{Outcome: g.Status, GrantID: g.GrantID, Failure: g.Failure}
			}
		case errors.As(err, &apiErr) && apiErr.Retryable():
			wait = max(interval, apiErr.RetryAfter)
		default:
			return nil, err
		}
		left := time.Until(deadline)
		if left <= 0 {
			return nil, &SealGrantError{Outcome: SealGrantTimeout, GrantID: grantID}
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

// OrgSealGrantsResponse — GET /organization/seal-grants/etsi/{personEtsi} (CA dto.PersonOrgSealGrantsResponse): иргэн
// улсын бүртгэлээр Гүйцэтгэх захирал байгаа байгууллага бүр ба тэдгээрийн амьд (APPROVED / PENDING) RP тамганы эрхүүд.
type OrgSealGrantsResponse struct {
	PersonEtsi    string          `json:"personEtsi"`
	Organizations []OrgSealGrants `json:"organizations"`
	// Raw — серверийн түүхий JSON (SDK задлаагүй шинэ талбарт).
	Raw json.RawMessage `json:"-"`
}

// OrgSealGrants — нэг байгууллага.
type OrgSealGrants struct {
	OrgEtsi string `json:"orgEtsi"`
	OrgName string `json:"orgName"`
	// OrgStatus — ACTIVE | SUSPENDED | REVOKED | …
	OrgStatus string         `json:"orgStatus"`
	Grants    []OrgSealGrant `json:"grants"`
}

// OrgSealGrant — нэг RP-д байгууллагын тамга ашиглах эрх (CA dto.MobileSealGrant).
type OrgSealGrant struct {
	GrantID  string `json:"grantId"`
	RPName   string `json:"rpName"`
	RPDomain string `json:"rpDomain,omitempty"`
	// Status — APPROVED | PENDING.
	Status    SealGrantStatus `json:"status"`
	CreatedAt time.Time       `json:"createdAt"`
	DecidedAt *time.Time      `json:"decidedAt,omitempty"`
	// ExpiresAt — зөвхөн PENDING.
	ExpiresAt    *time.Time `json:"expiresAt,omitempty"`
	ApproverName string     `json:"approverName,omitempty"`
	// SealCount / SealCount30d — энэ RP байгууллагын нэрээр хийсэн амжилттай тамгалалт (нийт / сүүлийн 30 өдөр);
	// LastSealedAt — сүүлд тамгалсан цаг (хэзээ ч үгүй бол nil). CA статистикийг түр уншиж чадаагүй үед гурвуулаа JSON-д
	// гарахгүй → SealCount ба SealCount30d nil («мэдэгдэхгүй», 0 биш).
	SealCount    *int64     `json:"sealCount,omitempty"`
	SealCount30d *int64     `json:"sealCount30d,omitempty"`
	LastSealedAt *time.Time `json:"lastSealedAt,omitempty"`
}

// SealGrants — GET /organization/seal-grants/etsi/{personEtsi} (PKI_READ эрх; иргэн сүүлийн 24 цагт танай RP-ээр нэвтэрсэн
// байх — үгүй бол *ForbiddenError 403): иргэн Гүйцэтгэх захирал байгаа байгууллагууд ба тэдгээрийн RP тамганы эрхүүд (зөвхөн
// унших; цуцлалт eID аппаас). Бусад RP-ийн эрхийг CA зөвхөн өөрийн порталд харуулдаг — бусад RP зөвхөн өөрийнхөө эрхийг
// харна. Иргэн олдохгүй бол *APIError 404.
func (o *OrganizationService) SealGrants(ctx context.Context, personEtsi string) (*OrgSealGrantsResponse, error) {
	var r OrgSealGrantsResponse
	path := routeOrgSealGrants.expand(personEtsi)
	if err := o.h.getJSON(ctx, path, 0, &r.Raw); err != nil {
		return nil, err
	}
	if len(r.Raw) > 0 {
		if err := decodeJSON(r.Raw, path, &r); err != nil {
			return nil, err
		}
	}
	if r.PersonEtsi == "" {
		r.PersonEtsi = personEtsi
	}
	if r.Organizations == nil {
		r.Organizations = []OrgSealGrants{}
	}
	for i := range r.Organizations {
		if r.Organizations[i].Grants == nil {
			r.Organizations[i].Grants = []OrgSealGrant{}
		}
	}
	return &r, nil
}
