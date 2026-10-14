package eid

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// USB токены PAdES (CA docs/PADES_SIGNING.md §16.5, TOKEN_CERT.md): session / утас оролцохгүй — RP эх PDF ба токены
// SIGN гэрчилгээг илгээж (TokenPrepare), токеноор HashToSign-ийг CKM_ECDSA (урьдчилан hash-лагдсан, P-256)-аар
// зурж түүхий r||s-ийг илгээнэ (TokenFinalize), CA PAdES-BASELINE-LT баримтыг угсарна (TokenDocument). SIGN эрх.
// Эдгээр зам CA-д байгаа ч /.well-known/eid-д хараахан жагсаагдаагүй (routes.go rpRoutesUndiscovered).

// PDFTokenPrepareInput — POST /pdf/token/prepare-ийн оролт.
type PDFTokenPrepareInput struct {
	// PDF — эх PDF (≤ 10 223 616 байт).
	PDF []byte
	// FileName — баримтын нэр (≤ 120 тэмдэгт, заавал).
	FileName string
	// SignerEtsi — иргэний ETSI (PNOMN-…), токены гэрчилгээний SERIALNUMBER-тэй таарна.
	SignerEtsi string
	// Certificate — токены SIGN гэрчилгээ (DER): eID Mongolia Issuing CA-аас, ACTIVE токенд холбогдсон.
	Certificate []byte
	// DocID — олон гарын үсэгтэй баримтын docID (заавал биш, UUID).
	DocID string
	// OnBehalfOf — байгууллагын токенд ЗААВАЛ тухайн байгууллага (NTRMN-…); хувийн токенд хоосон. Зөрвөл 403
	// TOKEN_ORG_MISMATCH.
	OnBehalfOf string
}

// PDFTokenPrepareSession — prepare-ийн хариу.
type PDFTokenPrepareSession struct {
	SigningID string
	DocID     string
	// HashToSign — токеноор зурах 32 байт (SHA-256 DTBS). CKM_ECDSA (prehashed) → түүхий r||s (64 байт).
	HashToSign         []byte
	HashAlgorithm      string
	SignatureAlgorithm string
	// SignatureFormat — "RAW_RS".
	SignatureFormat string
	// ExpiresAt — TokenFinalize-ийн эцсийн хугацаа (prepare-ээс 10 мин).
	ExpiresAt time.Time
	Raw       json.RawMessage
}

type pdfTokenPrepareRequest struct {
	RelyingPartyUUID string            `json:"relyingPartyUUID"`
	RelyingPartyName string            `json:"relyingPartyName"`
	Signer           map[string]string `json:"signer"`
	Certificate      string            `json:"certificate"`
	FileName         string            `json:"fileName"`
	DocID            string            `json:"docID,omitempty"`
	OnBehalfOf       string            `json:"onBehalfOf,omitempty"`
}

// TokenPrepare — POST /pdf/token/prepare (multipart: request JSON + pdf). Түр алдаа: *APIError 429
// CodePDFPrepareBusy / CodeRateLimited, 503 CodeTSAUnavailable / CodeLTVUnavailable / CodeStateUnavailable —
// RetryAfter-ийн дараа дахин (Retryable). Гэрчилгээ токенд холбогдоогүй / цуцлагдсан → 409 TOKEN_CERT_INVALID.
func (p *PDFService) TokenPrepare(ctx context.Context, in PDFTokenPrepareInput) (*PDFTokenPrepareSession, error) {
	if len(in.PDF) == 0 || len(in.Certificate) == 0 || strings.TrimSpace(in.SignerEtsi) == "" || strings.TrimSpace(in.FileName) == "" {
		return nil, errors.New("eid: pdf token: PDF, Certificate, SignerEtsi, FileName шаардлагатай")
	}
	reqJSON, err := json.Marshal(pdfTokenPrepareRequest{
		RelyingPartyUUID: p.creds.RPUUID,
		RelyingPartyName: p.creds.RPName,
		Signer:           map[string]string{"etsi": strings.TrimSpace(in.SignerEtsi)},
		Certificate:      base64.StdEncoding.EncodeToString(in.Certificate),
		FileName:         in.FileName,
		DocID:            strings.TrimSpace(in.DocID),
		OnBehalfOf:       strings.TrimSpace(in.OnBehalfOf),
	})
	if err != nil {
		return nil, fmt.Errorf("eid: pdf token request encode: %w", err)
	}
	body, ctype, err := pdfMultipart(reqJSON, in.FileName, in.PDF)
	if err != nil {
		return nil, err
	}
	var raw json.RawMessage
	if err := p.h.doJSON(ctx, routePDFTokenPrepare.method, routePDFTokenPrepare.expand(), body, ctype, p.timeout, &raw); err != nil {
		return nil, err
	}
	var r struct {
		SigningID          string `json:"signingID"`
		DocID              string `json:"docID"`
		HashToSign         string `json:"hashToSign"`
		HashAlgorithm      string `json:"hashAlgorithm"`
		SignatureAlgorithm string `json:"signatureAlgorithm"`
		SignatureFormat    string `json:"signatureFormat"`
		ExpiresAt          string `json:"expiresAt"`
	}
	if err := decodeJSON(raw, routePDFTokenPrepare.path, &r); err != nil {
		return nil, err
	}
	h, err := base64.StdEncoding.DecodeString(r.HashToSign)
	if err != nil || len(h) != 32 || r.SigningID == "" {
		return nil, invalid("pdf token prepare: signingID / hashToSign (32 байт) буруу")
	}
	exp, _ := time.Parse(time.RFC3339, r.ExpiresAt)
	return &PDFTokenPrepareSession{
		SigningID: r.SigningID, DocID: r.DocID, HashToSign: h, HashAlgorithm: r.HashAlgorithm,
		SignatureAlgorithm: r.SignatureAlgorithm, SignatureFormat: r.SignatureFormat, ExpiresAt: exp, Raw: raw,
	}, nil
}

// TokenFinalize — POST /pdf/token/{signingID}/finalize {signature: base64 түүхий r||s}. signature = 64 байт (P-256
// r||s, DER БИШ). Амжвал READY баримтын блок (OutSHA256 — TokenDocument-оор татсан файлтай DocumentVerified-аар
// тулга). READY-ээс хойш идэмпотент. Алдаа: 400 SIGNATURE_INVALID (3 удаа → баримт FAILED), 409 DOCUMENT_FAILED,
// 410 DOCUMENT_EXPIRED, 503 CodeDocumentPending / CodeTSAUnavailable / CodeLTVUnavailable — ижил гарын үсгийг
// RetryAfter-ийн дараа дахин илгээнэ.
func (p *PDFService) TokenFinalize(ctx context.Context, signingID string, signature []byte) (*PDFSessionBlock, error) {
	if len(signature) != 64 {
		return nil, errors.New("eid: pdf token: signature нь түүхий r||s 64 байт байх ёстой (P-256, DER биш)")
	}
	var out PDFSessionBlock
	err := p.h.postJSONTimeout(ctx, routePDFTokenFinalize.expand(signingID),
		map[string]string{"signature": base64.StdEncoding.EncodeToString(signature)}, p.timeout, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// TokenDocument — GET /pdf/token/{signingID}/document: гарын үсэгтэй PDF (зөвхөн үүсгэсэн RP, expiresAt хүртэл).
// Config.PDFMaxBytes хүртэл санах ойд уншина. DocumentVerified(bytes, finalizeBlock)-оор заавал тулга.
func (p *PDFService) TokenDocument(ctx context.Context, signingID string) ([]byte, error) {
	return p.h.getBytes(ctx, routePDFTokenDocument.expand(signingID), p.timeout, p.maxBytes)
}
