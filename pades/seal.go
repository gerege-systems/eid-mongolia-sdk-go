package pades

import (
	"bytes"
	"context"
	"crypto/x509"
	"time"

	eid "github.com/gerege-systems/eid-mongolia-sdk-go"
)

// Sealer — байгууллагын тамганы RP-API (*eid.SealService хангана; тестэд орлуулж болно).
type Sealer interface {
	Certificate(ctx context.Context, orgEtsi string) (*eid.SealCertificate, error)
	Seal(ctx context.Context, orgEtsi string, digest []byte, hash eid.HashAlgorithm) (*eid.SealResult, error)
}

// SealOptions — SealPDF-ийн тохиргоо. Байгууллагын тамга үл харагдах, баталгаажуулалтын (QR) хуудасгүй: verify хуудас нь
// CA-ийн бүртгэл (/verify/{docId}) рүү заадаг ч тамга иргэний гарын үсгийн бүртгэлд (POST /pdf/signatures) ордоггүй.
type SealOptions struct {
	// Reason — /Reason (≤ 127 UTF-16 нэгж).
	Reason string
	// SignerName — /Name; хоосон бол гэрчилгээний CN (байгууллагын нэр).
	SignerName string
	// SigningTime — /M; тэг бол одоо.
	SigningTime time.Time
	// Chain — олгогч гинж DER (05, 03, 02); хоосон бол шигтгэсэн eID гинжээс.
	Chain [][]byte
	// Complete — TSA/OCSP/CRL тохиргоо (Complete-тэй ижил). RFC 3161 timestamp ЗААВАЛ: TSA унавал CodeTSAUnavailable,
	// тамгагүй файл буцаахгүй.
	Complete CompleteOptions
}

// SealPDF — PDF-ийг байгууллагын цахим тамгаар (e-Seal) тамгална: тамганы гэрчилгээ (GET /seal/certificate/{orgEtsi}) →
// Prepare → DTBS-ийг POST /seal/{orgEtsi}-ээр (SHA-256) тамгалуулна → Complete (TSA + OCSP/CRL + DSS + self-validation)
// → PAdES-BASELINE-LT. PDF CA руу очихгүй — зөвхөн 32 байт DTBS. Шалгагчид (CA, SDK) энэ гарын үсгийг usage "seal"
// (байгууллагын тамга) гэж ангилна.
//
// Алдаа: *Error (CodeSignerInvalid — гэрчилгээ e-Seal биш эсвэл тамгалах хооронд гэрчилгээ солигдсон; Prepare/Complete-ийн
// бусад код) эсвэл Sealer-ийн алдаа хэвээр (*eid.ForbiddenError — SEAL эрхгүй; *eid.APIError 429 — Retryable()).
func SealPDF(ctx context.Context, s Sealer, orgEtsi string, pdf []byte, o SealOptions) (*Completed, error) {
	if s == nil {
		return nil, newErr(CodeRequestInvalid, "Sealer nil", nil)
	}
	sc, err := s.Certificate(ctx, orgEtsi)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(sc.Certificate)
	if err != nil {
		return nil, newErr(CodeSignerInvalid, "тамганы гэрчилгээ задарсангүй", err)
	}
	if !eid.IsSealCertificate(cert) {
		return nil, newErr(CodeSignerInvalid, "гэрчилгээ e-Seal биш (KeyUsage = зөвхөн nonRepudiation байх ёстой)", nil)
	}
	p, err := Prepare(pdf, PrepareOptions{SignerCert: cert.Raw, Chain: o.Chain, SignerName: o.SignerName, Reason: o.Reason,
		SigningTime: o.SigningTime})
	if err != nil {
		return nil, err
	}
	r, err := s.Seal(ctx, orgEtsi, p.DTBS, eid.SHA256)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(r.Certificate, cert.Raw) {
		return nil, newErr(CodeSignerInvalid, "тамгалах хооронд байгууллагын тамганы гэрчилгээ солигдсон — дахин оролдоно уу", nil)
	}
	return Complete(ctx, p.State, r.Signature, o.Complete)
}
