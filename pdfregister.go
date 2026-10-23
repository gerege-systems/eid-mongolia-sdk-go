package eid

import (
	"context"
	"errors"
	"net/http"
)

// Медиум — PDFSignatureRegistration.Medium.
const (
	PDFMediumPhone = "phone"
	PDFMediumToken = "token"
)

// PDFSignatureRegistration — POST /pdf/signatures-ийн бие (CA docs/PADES_CLIENT_SIDE.md §4.3/§4.3.1,
// server/internal/dto PDFSignatureRegisterRequest-тэй ЯГ ижил; CA үл мэдэгдэх талбарыг 400-аар татгалздаг). PDF биш —
// клиент талын PAdES-ийн (pades.Complete) CMS + файлын hash-ууд (мэдүүлэг). Hash бүр 64 жижиг hex.
// pades.Registration(completed, …)-оор бөглөнө.
type PDFSignatureRegistration struct {
	DocID     string `json:"docID"`
	RevIndex  int    `json:"revIndex"`
	Medium    string `json:"medium"`              // PDFMediumPhone | PDFMediumToken
	SessionID string `json:"sessionID,omitempty"` // утсанд заавал (RAW_DIGEST_SIGNATURE session)
	CMS       []byte `json:"cms"`                 // base64 DER (JSON-д), ≤ 28 672 байт
	FileName  string `json:"fileName"`
	InSHA256  string `json:"inSha256"`
	// PageSHA256 — revIndex 1-д заавал (баталгаажуулалтын хуудастай).
	PageSHA256          string   `json:"pageSha256,omitempty"`
	SigRevSHA256        string   `json:"sigRevSha256"`
	OutSHA256           string   `json:"outSha256"`
	PriorCMSSHA256      []string `json:"priorCmsSha256,omitempty"`
	PriorRevisionSHA256 []string `json:"priorRevisionSha256,omitempty"` // горим A-ийн (CA угсарсан) өмнөх гарын үсэг
	// OnBehalfOf — NTRMN-…: байгууллагын нэрийн өмнөөс (CMS-ийн claimedRole-ийг CA тухайн мөчийн төлөөллөөр тулгана).
	OnBehalfOf string `json:"onBehalfOf,omitempty"`
	// SignerEtsi — заавал биш (PNOMN-…): ирсэн бол CMS-ийн зурагчийн SERIALNUMBER-тэй тэнцүү (эс бөгөөс 409 SIGNER_MISMATCH).
	SignerEtsi string `json:"signerEtsi,omitempty"`
	// Images — харагдах дүрслэлд шигтгэсэн зураг бүрийн {kind, sha256} (pades APPEARANCE_SPEC.md §6.6): CA зурагчийн/
	// байгууллагын хадгалсан PNG-тэй тулгана. Зураггүй бол илгээхгүй.
	Images []PDFSignatureImage `json:"images,omitempty"`
	// PriorSignatures — SDK-д л (CA руу илгээхгүй): өмнөх гарын үсэг бүрийн хоёр түлхүүр, баримтын дарааллаар;
	// pades.Registration бөглөнө. CA өмнөх мөр бүрийг өөрийнх нь түлхүүрээр таньдаг (клиент талын мөр — CMS, горим A —
	// revision), файлаас аль нь болохыг ялгах боломжгүй. Тиймээс RegisterSignature эхлээд PriorCMSSHA256-аар илгээж,
	// 409 PRIOR_MISMATCH бол эхний k-г revision-оор (горим A нь клиент талынхаас өмнө), өмнөх нь ≤ 4 бол бүх хослолыг
	// оролдоно. PriorRevisionSHA256-г гараар өгсөн бол оролдохгүй.
	PriorSignatures []PDFPriorSignature `json:"-"`
}

// PDFSignatureImage — PDFSignatureRegistration.Images-ийн нэг мөр.
type PDFSignatureImage struct {
	Kind   string `json:"kind"`   // PDFImageSignature | PDFImageStamp
	SHA256 string `json:"sha256"` // CA-ийн хадгалсан PNG-ийн sha256 (64 жижиг hex)
}

// PDFSignatureImage.Kind утгууд.
const (
	PDFImageSignature = "signature" // иргэний гарын үсгийн зураг
	PDFImageStamp     = "stamp"     // байгууллагын тамганы зураг
)

// PDFPriorSignature — өмнөх нэг гарын үсгийн хоёр түлхүүр (PDFSignatureRegistration.PriorSignatures).
type PDFPriorSignature struct {
	CMSSHA256      string // CMS DER-ийн sha256 — клиент талын мөр
	RevisionSHA256 string // sha256(doc[0 : ByteRange[2]+ByteRange[3]]) — горим A-ийн мөр (CA sig_rev_sha256)
}

// PDFSignatureRegistered — 201 (шинэ) эсвэл 200 (ижил body-ийн давталт — анхны хариу).
type PDFSignatureRegistered struct {
	DocID        string `json:"docID"`
	RevIndex     int    `json:"revIndex"`
	RegisteredAt string `json:"registeredAt"` // RFC 3339, +08
	VerifyURL    string `json:"verifyUrl"`
	// Created — true: 201 (шинээр бүртгэв); false: 200 (ижил биеийн идэмпотент давталт, анхны хариу).
	Created bool `json:"-"`
}

// POST /pdf/signatures (RegisterSignature)-ийн CA алдааны кодууд — APIError.Code / ForbiddenError.Code (CA
// pades_register.go, handlers_pdf.go). CodeRequestInvalid, CodeRepresentationRevoked, CodeRateLimited,
// CodeStateUnavailable нь бусад урсгалтай хуваалцна. Session олдоогүй бол 404 code-гүй.
const (
	// CodeRequestTooLarge — 413: body 64 KiB-аас их.
	CodeRequestTooLarge = "REQUEST_TOO_LARGE"
	// CodeCMSInvalid — 400: cms задарсангүй эсвэл профайлд (pades-client/1) нийцэхгүй.
	CodeCMSInvalid = "CMS_INVALID"
	// CodeSignatureInvalid — 400: CMS-ийн гарын үсэг signedAttrs-тэй таарахгүй.
	CodeSignatureInvalid = "SIGNATURE_INVALID"
	// CodeTimestampInvalid — 400: signatureTimeStampToken хүчингүй (imprint, TSA гинж эсвэл цаг).
	CodeTimestampInvalid = "TIMESTAMP_INVALID"
	// CodeSignerMismatch — 409: SignerEtsi нь CMS-ийн зурагчийн гэрчилгээтэй таарахгүй.
	CodeSignerMismatch = "SIGNER_MISMATCH"
	// CodeSignerCertInvalid — 409: утасны SIGN гэрчилгээ хүчингүй (CA-аас биш, хугацаа, цуцлагдсан, бүртгэлгүй).
	CodeSignerCertInvalid = "SIGNER_CERT_INVALID"
	// CodeTokenCertInvalid — 409: токены гэрчилгээ хүчингүй (medium token).
	CodeTokenCertInvalid = "TOKEN_CERT_INVALID"
	// CodeTokenOrgMismatch — 403: OnBehalfOf нь токены байгууллагын холбоостой таарахгүй.
	CodeTokenOrgMismatch = "TOKEN_ORG_MISMATCH"
	// CodeSessionMismatch — 409: session-ий digest / гарын үсэг / гэрчилгээ CMS-тэй таарахгүй эсвэл гарын үсгийнх биш.
	CodeSessionMismatch = "SESSION_MISMATCH"
	// CodeSessionNotComplete — 409: session дуусаагүй.
	CodeSessionNotComplete = "SESSION_NOT_COMPLETE"
	// CodeSessionFailed — 409: session амжилттай дуусаагүй.
	CodeSessionFailed = "SESSION_FAILED"
	// CodeClaimedRoleMismatch — 409: claimedRole / onBehalfOf тухайн мөчийн төлөөлөл эсвэл session-ийнхтэй таарахгүй.
	CodeClaimedRoleMismatch = "CLAIMED_ROLE_MISMATCH"
	// CodeDocIDConflict — 409: docID аль хэдийн бүртгэлтэй (revIndex > 1 ба prior* илгээнэ).
	CodeDocIDConflict = "DOC_ID_CONFLICT"
	// CodeRegistryConflict — 409: messageDigest, CMS эсвэл файлын hash өөр бүртгэлд бий.
	CodeRegistryConflict = "REGISTRY_CONFLICT"
	// CodeDocNotFound — 404: docID бүртгэлгүй (эхний гарын үсэгт revIndex 1).
	CodeDocNotFound = "DOC_NOT_FOUND"
	// CodePriorMismatch — 409: revIndex эсвэл priorCmsSha256/priorRevisionSha256 бүртгэлтэй таарахгүй.
	CodePriorMismatch = "PRIOR_MISMATCH"
	// CodeImageMismatch — 409: images[] (kind, sha256) нь зурагчийн / onBehalfOf байгууллагын CA дээрх ОДООГИЙН
	// хадгалсан зурагтай таарахгүй (алга, солигдсон эсвэл устгасан; pades APPEARANCE_SPEC.md §6.6).
	CodeImageMismatch = "IMAGE_MISMATCH"
)

// PDFRegisterErrorCodes — POST /pdf/signatures-ийн бүх CA код (TS SDK PDF_REGISTER_ERROR_CODES-тэй ижил дараалал).
var PDFRegisterErrorCodes = []string{
	CodeRequestInvalid,
	CodeRequestTooLarge,
	CodeCMSInvalid,
	CodeSignatureInvalid,
	CodeTimestampInvalid,
	CodeSignerMismatch,
	CodeSignerCertInvalid,
	CodeTokenCertInvalid,
	CodeTokenOrgMismatch,
	CodeSessionMismatch,
	CodeSessionNotComplete,
	CodeSessionFailed,
	CodeClaimedRoleMismatch,
	CodeRepresentationRevoked,
	CodeDocIDConflict,
	CodeRegistryConflict,
	CodeDocNotFound,
	CodePriorMismatch,
	CodeImageMismatch,
	CodeRateLimited,
	CodeStateUnavailable,
}

// RegisterSignature — POST /pdf/signatures (SIGN эрх): клиент талын PAdES гарын үсгийг CA-ийн бүртгэлд (docID,
// /verify) оруулна. pades.Complete-ийн дараа заавал. Давталт идэмпотент (ижил body → 200). Алдаа: *APIError /
// *ForbiddenError Code ∈ PDFRegisterErrorCodes (CodePriorMismatch, CodeDocNotFound г.м.).
func (p *PDFService) RegisterSignature(ctx context.Context, r PDFSignatureRegistration) (*PDFSignatureRegistered, error) {
	switch {
	case r.DocID == "" || r.RevIndex < 1 || len(r.CMS) == 0:
		return nil, errors.New("eid: pdf register: docID, revIndex, cms заавал")
	case r.Medium != PDFMediumPhone && r.Medium != PDFMediumToken:
		return nil, errors.New("eid: pdf register: medium нь phone | token")
	case r.Medium == PDFMediumPhone && r.SessionID == "":
		return nil, errors.New("eid: pdf register: утсанд sessionID заавал")
	case r.RevIndex == 1 && r.PageSHA256 == "":
		return nil, errors.New("eid: pdf register: revIndex 1-д pageSha256 заавал (баталгаажуулалтын хуудастай)")
	}
	out, err := p.register(ctx, r)
	prior := r.PriorSignatures
	if !isPriorMismatch(err) || len(r.PriorRevisionSHA256) > 0 || len(prior) == 0 || len(prior) != r.RevIndex-1 {
		return out, err
	}
	// Аль өмнөх мөр горим A (revision-оор) болохыг файлаас мэдэх аргагүй — хослолыг оролдоно (priorSplits).
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
		o, e := p.register(ctx, next)
		if !isPriorMismatch(e) {
			return o, e
		}
	}
	return nil, err
}

func (p *PDFService) register(ctx context.Context, r PDFSignatureRegistration) (*PDFSignatureRegistered, error) {
	var out PDFSignatureRegistered
	status, err := p.h.postJSONStatus(ctx, routePDFSignatures.expand(), r, p.timeout, &out)
	if err != nil {
		return nil, err
	}
	out.Created = status == http.StatusCreated
	return &out, nil
}

func isPriorMismatch(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Code == CodePriorMismatch
}

// priorSplits — PRIOR_MISMATCH-ийн дараах оролдлогууд (true = тухайн өмнөх гарын үсгийг revision-оор): эхлээд эхний k
// (k = 1…n; горим A нь клиент талынхаас өмнө — CA §15 устгагдаж буй), дараа нь n ≤ 4 бол үлдсэн бүх хослол. Бүгдийг
// CMS-ээр (k = 0) аль хэдийн оролдсон. TS priorSplits-тэй ижил дараалал.
func priorSplits(n int) [][]bool {
	var out [][]bool
	seen := map[int]bool{}
	mask := func(m int) []bool {
		b := make([]bool, n)
		for i := range b {
			b[i] = m&(1<<i) != 0
		}
		return b
	}
	for k := 1; k <= n; k++ {
		seen[1<<k-1] = true
		out = append(out, mask(1<<k-1))
	}
	if n <= 4 {
		for m := 1; m < 1<<n; m++ {
			if !seen[m] {
				out = append(out, mask(m))
			}
		}
	}
	return out
}
