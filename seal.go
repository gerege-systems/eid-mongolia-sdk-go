package eid

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// SealService — байгууллагын цахим тамга (e-Seal): байгууллагын HSM дэх түлхүүрээр digest тамгална. Интерактив биш
// (иргэн, PIN, апп оролцохгүй) — хариу шууд (session-гүй). RP-д тухайн байгууллагын `SEAL:<orgEtsi>` эрх хэрэгтэй (үгүй бол
// *ForbiddenError, 403). Хэт олон хүсэлтэд CA 429 буцаана — *APIError.Retryable() / RetryAfter-ийн дараа дахин.
//
// PDF-ийг тамгалах бол pades.SealPDF (PAdES-BASELINE-LT, RFC 3161 timestamp заавал).
// Тамганы гэрчилгээ олгох (POST /seal/certificate/{orgEtsi}) энэ хувилбарт алга — байгууллагын баталгаажуулалттай олголтын
// урсгал CA-д нэвтэрмэгц нэмэгдэнэ.
type SealService struct {
	h *httpDoer
}

// SealCertificate — GET /seal/certificate/{orgEtsi}-ийн хариу (CA dto.SealCertificateResponse).
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
	Certificate      []byte
	CertificateLevel CertificateLevel
	SealedAt         time.Time
	// Raw — серверийн түүхий JSON.
	Raw json.RawMessage
}

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

// Certificate — GET /seal/certificate/{orgEtsi}: байгууллагын идэвхтэй тамганы гэрчилгээ (PAdES-ийн SignerCert).
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

// Seal — POST /seal/{orgEtsi}: digest-ийг байгууллагын тамгаар тамгална. hash: SHA256 | SHA384 | SHA512 ("" = SHA256);
// digest-ийн урт түүнтэй таарна. Хариуны гарын үсгийг хариуны гэрчилгээгээр digest дээр шалгаж, e-Seal гэрчилгээ
// (KeyUsage = зөвхөн nonRepudiation) мөн эсэхийг тулгана — таарахгүй бол *ValidationError. Гинж/цуцлалтыг энэ шалгахгүй
// (pades.SealPDF нь OCSP/CRL + self-validation хийнэ).
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
