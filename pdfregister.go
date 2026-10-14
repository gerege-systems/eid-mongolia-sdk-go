package eid

import (
	"context"
	"errors"
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
}

// PDFSignatureRegistered — 201 (шинэ) эсвэл 200 (ижил body-ийн давталт — анхны хариу).
type PDFSignatureRegistered struct {
	DocID        string `json:"docID"`
	RevIndex     int    `json:"revIndex"`
	RegisteredAt string `json:"registeredAt"` // RFC 3339, +08
	VerifyURL    string `json:"verifyUrl"`
}

// RegisterSignature — POST /pdf/signatures (SIGN эрх): клиент талын PAdES гарын үсгийг CA-ийн бүртгэлд (docID,
// /verify) оруулна. pades.Complete-ийн дараа заавал. Давталт идэмпотент (ижил body → 200). Алдаа (*APIError Code):
// 400 REQUEST_INVALID / CMS_INVALID / SIGNATURE_INVALID / TIMESTAMP_INVALID, 403 REPRESENTATION_REVOKED /
// TOKEN_ORG_MISMATCH, 404 DOC_NOT_FOUND, 409 DOC_ID_CONFLICT / PRIOR_MISMATCH / REGISTRY_CONFLICT / SESSION_MISMATCH /
// SIGNER_MISMATCH / CLAIMED_ROLE_MISMATCH …, 413 REQUEST_TOO_LARGE, 429 RATE_LIMITED.
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
	var out PDFSignatureRegistered
	if err := p.h.postJSONTimeout(ctx, routePDFSignatures.expand(), r, p.timeout, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
