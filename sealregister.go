package eid

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"
)

// SealRegistration — POST /seal/{orgEtsi}/registrations-ийн бие (CA V158, docs/PADES_CLIENT_SIDE.md §4.5,
// server/internal/dto SealRegisterRequest-тэй ЯГ ижил; CA DisallowUnknownFields — medium, sessionID, onBehalfOf,
// signerEtsi, pageSha256 илгээвэл 400). Байгууллагын тамгатай PDF-ийн CMS + файлын hash-ууд (мэдүүлэг, иргэний
// PDFSignatureRegistration-тэй ижил тодорхойлолт). pades.SealPDF-ийн Completed.SealRegistration эсвэл
// pades.SealRegistration(completed)-оор бөглөнө.
type SealRegistration struct {
	DocID    string `json:"docID"`    // жижиг үсгийн UUID
	RevIndex int    `json:"revIndex"` // тамганы файл дахь байрлал (1–16)
	CMS      []byte `json:"cms"`      // base64 DER (JSON-д), ≤ 28 672 байт
	// FileName — заавал биш (/verify-д харагдах нэр, ≤ 120 тэмдэгт).
	FileName            string   `json:"fileName,omitempty"`
	InSHA256            string   `json:"inSha256"`
	SigRevSHA256        string   `json:"sigRevSha256"`
	OutSHA256           string   `json:"outSha256"`
	PriorCMSSHA256      []string `json:"priorCmsSha256,omitempty"`
	PriorRevisionSHA256 []string `json:"priorRevisionSha256,omitempty"`
	// PriorSignatures — SDK-д л (CA руу илгээхгүй): PDFSignatureRegistration.PriorSignatures-тэй ижил — 409
	// PRIOR_MISMATCH бол RegisterSealedPDF өмнөх мөрийг revision-оор (горим A) тааруулж дахин оролдоно.
	PriorSignatures []PDFPriorSignature `json:"-"`
}

// SealRegistered — POST /seal/{orgEtsi}/registrations-ийн хариу (CA PDFSignatureRegisterResponse — иргэний бүртгэлтэй
// ижил): 201 шинэ (Created), 200 ижил биеийн давталт (анхны хариу).
type SealRegistered = PDFSignatureRegistered

// POST /seal/{orgEtsi}/registrations (RegisterSealedPDF)-ийн CA алдааны кодууд — APIError.Code (CA
// pades_seal_register.go SealRegisterErrorCodes, handlers_seal_register.go). Бусад нь иргэний бүртгэлийн кодтой
// хуваалцана (CodeRequestTooLarge, CodeCMSInvalid, CodeSignerMismatch, CodeSignerCertInvalid, CodeSignatureInvalid,
// CodeTimestampInvalid, CodeDocIDConflict, CodePriorMismatch, CodeRegistryConflict, CodeRequestInvalid,
// CodeRateLimited, CodeStateUnavailable). SEAL:<orgEtsi> эрхгүй RP → 403 *ForbiddenError (code-гүй).
const (
	// CodeSealNotFound — 409: энэ RP-ийн POST /seal/{orgEtsi}-ээр тамгалсан digest (= SHA-256(signedAttrs)) олдсонгүй,
	// өөр байгууллага/гэрчилгээ, эсвэл тамгалснаас 7 хоног өнгөрсөн (өөр RP-ийн тамга ч ингэж хариулна).
	CodeSealNotFound = "SEAL_NOT_FOUND"
	// CodeSealDocMismatch — 409: тамгалах үед нөөцөлсөн docId/revIndex (SealForDocument) бүртгэлийнхтэй таарахгүй.
	CodeSealDocMismatch = "SEAL_DOC_MISMATCH"
	// CodeDocIDReserved — 409: docID-г өөр, бүртгэгдээгүй QR тамга бага байрлалд нөөцөлсөн (тамга бүртгэгдсэний эсвэл
	// 7 хоногийн дараа дахин).
	CodeDocIDReserved = "DOC_ID_RESERVED"
)

// SealRegisterErrorCodes — POST /seal/{orgEtsi}/registrations-ийн бүх CA код (CA memory.SealRegisterErrorCodes, discovery
// seal.registerErrorCodes; TS SDK SEAL_REGISTER_ERROR_CODES-тэй ижил дараалал).
var SealRegisterErrorCodes = []string{
	CodeRequestTooLarge,
	CodeRequestInvalid,
	CodeRateLimited,
	CodeStateUnavailable,
	CodeCMSInvalid,
	CodeSignerMismatch,
	CodeSignerCertInvalid,
	CodeSignatureInvalid,
	CodeSealNotFound,
	CodeSealDocMismatch,
	CodeTimestampInvalid,
	CodeDocIDReserved,
	CodeDocIDConflict,
	CodePriorMismatch,
	CodeRegistryConflict,
}

// Хэлбэрийн дүрэм — CA normalizeSealRegister (pades_seal_register.go) ба sealReservation (org.go)-тэй ижил.
var (
	sealDocIDRe  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	sealOrgRe    = regexp.MustCompile(`^NTRMN-[0-9A-Z]{1,58}$`)
	sealHex64Re  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	sealRegMaxFN = 120
)

// sealRegisterMaxCMS — CA padesRegisterMaxCMS (= pades.PlaceholderBytes).
const sealRegisterMaxCMS = 28672

// Validate — CA-ийн normalizeSealRegister-ийн хэлбэрийн шалгалт (сүлжээгүй): docID жижиг UUID, revIndex 1–16,
// fileName ≤ 120 тэмдэгт (өгсөн бол), inSha256/sigRevSha256/outSha256 ба prior* нь 64 жижиг hex,
// len(priorCmsSha256)+len(priorRevisionSha256) = revIndex − 1, cms 1…28 672 байт. Алдаа → *ValidationError.
func (r SealRegistration) Validate() error {
	switch {
	case !sealDocIDRe.MatchString(r.DocID):
		return invalid("seal register: docID нь жижиг үсгийн UUID")
	case r.RevIndex < 1 || r.RevIndex > 16:
		return invalid("seal register: revIndex 1–16")
	case strings.TrimSpace(r.FileName) != "" && utf8.RuneCountInString(strings.TrimSpace(r.FileName)) > sealRegMaxFN:
		return invalid("seal register: fileName ≤ 120 тэмдэгт")
	case len(r.CMS) == 0 || len(r.CMS) > sealRegisterMaxCMS:
		return invalid("seal register: cms 1…28 672 байт")
	case len(r.PriorCMSSHA256)+len(r.PriorRevisionSHA256) != r.RevIndex-1:
		return invalid("seal register: priorCmsSha256 + priorRevisionSha256 нийт revIndex − 1")
	}
	for name, h := range map[string]string{"inSha256": r.InSHA256, "sigRevSha256": r.SigRevSHA256, "outSha256": r.OutSHA256} {
		if !sealHex64Re.MatchString(h) {
			return invalid("seal register: %s 64 жижиг hex", name)
		}
	}
	for _, h := range append(append([]string(nil), r.PriorCMSSHA256...), r.PriorRevisionSHA256...) {
		if !sealHex64Re.MatchString(h) {
			return invalid("seal register: prior* 64 жижиг hex")
		}
	}
	return nil
}

// RegisterSealedPDF — POST /seal/{orgEtsi}/registrations (SEAL:<orgEtsi> эрх, CA V158): байгууллагын тамгатай PDF-ийг
// CA-ийн бүртгэлд (/verify/{docID}, байгууллагын мөр) оруулна — иргэний PDF.RegisterSignature-ийн тамганы хувилбар.
// pades.SealPDF-ийн дараа Completed.SealRegistration-оор. Нөхцөл (CA): тамгыг ЭНЭ RP POST /seal/{orgEtsi}-ээр хүссэн
// байх (CMS-ийн SHA-256(signedAttrs) = тамгалсан digest), тамгалснаас 7 хоногийн дотор, нөөцөлсөн docId/revIndex-тэй
// таарах. Давталт идэмпотент (ижил body → 200, Created false; 7 хоног өнгөрсөн ч). 409 PRIOR_MISMATCH бол
// PriorSignatures-ээр (RegisterSignature-тэй ижил дүрэм) дахин оролдоно. Хэлбэрийн алдааг (Validate) сүлжээнд гаргахгүй.
// Алдаа: *APIError Code ∈ SealRegisterErrorCodes (429 RATE_LIMITED — RP-д 10 минутад 600, Retryable), *ForbiddenError
// (403, SEAL:<orgEtsi> эрхгүй), 501 (CA-д PAdES тохируулаагүй). Тамгалалтын унтраалга ба billing хамаарахгүй.
func (s *SealService) RegisterSealedPDF(ctx context.Context, orgEtsi string, r SealRegistration) (*SealRegistered, error) {
	org := strings.TrimSpace(orgEtsi)
	if !sealOrgRe.MatchString(strings.ToUpper(org)) {
		return nil, invalid("seal register: orgEtsi нь NTRMN-…")
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	out, err := s.register(ctx, org, r)
	prior := r.PriorSignatures
	if !isPriorMismatch(err) || len(r.PriorRevisionSHA256) > 0 || len(prior) == 0 || len(prior) != r.RevIndex-1 {
		return out, err
	}
	// Аль өмнөх мөр горим A (revision-оор) болохыг файлаас мэдэх аргагүй — RegisterSignature-тэй ижил хослолууд.
	for _, asRevision := range priorSplits(len(prior)) {
		next := r
		next.PriorCMSSHA256, next.PriorRevisionSHA256 = nil, nil
		for i, ps := range prior {
			if asRevision[i] {
				next.PriorRevisionSHA256 = append(next.PriorRevisionSHA256, ps.RevisionSHA256)
			} else {
				next.PriorCMSSHA256 = append(next.PriorCMSSHA256, ps.CMSSHA256)
			}
		}
		o, e := s.register(ctx, org, next)
		if !isPriorMismatch(e) {
			return o, e
		}
	}
	return nil, err
}

func (s *SealService) register(ctx context.Context, orgEtsi string, r SealRegistration) (*SealRegistered, error) {
	var out SealRegistered
	status, err := s.h.postJSONStatus(ctx, routeSealRegistrations.expand(orgEtsi), r, s.registerTimeout, &out)
	if err != nil {
		return nil, err
	}
	out.Created = status == http.StatusCreated
	return &out, nil
}

// SealForDocument — POST /seal/{orgEtsi} {digest, hashType: SHA256, docId, revIndex} (CA V158): Seal-тэй ижил, нэмээд
// QR-тэй тамганы баримтын нөөц — тамганы дардасны QR (/verify/<docId>/<revIndex>) өөр гарын үсгийн бүртгэлд «хулгайлагдахгүй»
// (CA: бүртгэгдээгүй нөөц 7 хоногийн турш тэр docId-ийн дараагийн байрлалын бүртгэлийг DOC_ID_CONFLICT /
// DOC_ID_RESERVED-ээр хаана). Зөвхөн SHA-256 digest; docID жижиг UUID, revIndex 1–16 (эс бөгөөс *ValidationError, CA
// 400 REQUEST_INVALID). Бүртгэлийн docID/revIndex нөөцтэй таарахгүй бол RegisterSealedPDF 409 SEAL_DOC_MISMATCH.
// pades.SealPDF (SealOptions.QR) үүнийг дуудна.
func (s *SealService) SealForDocument(ctx context.Context, orgEtsi string, digest []byte, docID string, revIndex int) (*SealResult, error) {
	if !sealDocIDRe.MatchString(docID) || revIndex < 1 || revIndex > 16 {
		return nil, invalid("seal: docId жижиг үсгийн UUID, revIndex 1–16")
	}
	return s.seal(ctx, orgEtsi, digest, SHA256, docID, revIndex)
}
