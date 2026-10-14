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
	// PriorSignatures — SDK-д л (CA руу илгээхгүй): өмнөх гарын үсэг бүрийн хоёр түлхүүр, баримтын дарааллаар;
	// pades.Registration бөглөнө. CA өмнөх мөр бүрийг өөрийнх нь түлхүүрээр таньдаг (клиент талын мөр — CMS, горим A —
	// revision), файлаас аль нь болохыг ялгах боломжгүй. Тиймээс RegisterSignature эхлээд PriorCMSSHA256-аар илгээж,
	// 409 PRIOR_MISMATCH бол эхний k-г revision-оор (горим A нь клиент талынхаас өмнө), өмнөх нь ≤ 4 бол бүх хослолыг
	// оролдоно. PriorRevisionSHA256-г гараар өгсөн бол оролдохгүй.
	PriorSignatures []PDFPriorSignature `json:"-"`
}

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
	return errors.As(err, &ae) && ae.Code == "PRIOR_MISMATCH"
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
