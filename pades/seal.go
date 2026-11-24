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

// SealOptions — SealPDF-ийн тохиргоо. Баталгаажуулалтын (QR) хуудас нэмэхгүй: verify хуудас нь CA-ийн бүртгэл
// (/verify/{docId}) рүү заадаг ч тамга иргэний гарын үсгийн бүртгэлд (POST /pdf/signatures) ордоггүй. Анхдагчаар тамга
// ХАРАГДАНА: баримтын сүүлийн (eID verify биш) хуудсанд байгууллагын тамганы дардас (APPEARANCE_SPEC.md §6 — QR/холбоосгүй),
// баруун доод буланд, агуулгатай давхцвал чөлөөт байрлал руу (PLACEMENT_SPEC.md).
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
	// Appearance — дардасны байршил (иргэний харагдах гарын үсэгтэй ижил утга: Page, X, Y, Width, Height, Lang, Exact);
	// буруу бол REQUEST_INVALID. nil бол автомат (APPEARANCE_SPEC.md §6.4): сүүлийн (eID verify биш) хуудасны баруун доод
	// буланд ≤ SealStampWidth × SealStampHeight (жижиг хуудсанд багтаана), Exact биш; хуудсанд дардас багтахгүй бол
	// үл харагдах тамга (Completed.Placement nil). Invisible үед үл тооно.
	Appearance *Appearance
	// Invisible — дардасгүй (v0.29-ийн SealPDF-тэй байт-ижил гаралт).
	Invisible bool
}

// Автомат дардасны дээд хэмжээ ба захын зай (pt) — APPEARANCE_SPEC.md §6.4: w = min(SealStampWidth, pw − 8),
// h = min(SealStampHeight, ph − 8), x = pw − w − min(SealStampMargin, (pw − w)/2), y = min(SealStampMargin, (ph − h)/2).
const (
	SealStampWidth  = 220
	SealStampHeight = 64
	SealStampMargin = 36
)

// SealPDF — PDF-ийг байгууллагын цахим тамгаар (e-Seal) тамгална: тамганы гэрчилгээ (GET /seal/certificate/{orgEtsi}) →
// Prepare → DTBS-ийг POST /seal/{orgEtsi}-ээр (SHA-256) тамгалуулна → Complete (TSA + OCSP/CRL + DSS + self-validation)
// → PAdES-BASELINE-LT. PDF CA руу очихгүй — зөвхөн 32 байт DTBS. Шалгагчид (CA, SDK) энэ гарын үсгийг usage "seal"
// (байгууллагын тамга) гэж ангилна. Анхдагчаар дардас харагдана (SealOptions); байршил Completed.Placement-д.
// Энэ хувилбараас ӨМНӨХ шалгагчид (CA, TS SDK) тамганы дардсыг таньдаггүй тул өмнөх гарын үсгийг modified гэж мэдээлнэ —
// тэдгээр шинэчлэгдэх хүртэл Invisible: true ашиглана уу.
//
// Алдаа: *Error (CodeSignerInvalid — гэрчилгээ e-Seal биш эсвэл тамгалах хооронд гэрчилгээ солигдсон; Prepare/Complete-ийн
// бусад код) эсвэл Sealer-ийн алдаа хэвээр (*eid.ForbiddenError — SEAL эрхгүй; *eid.APIError 429 — Retryable(); 409
// eid.ErrSealNotIssued / ErrSealCertRevoked / ErrSealCertExpired / ErrSealCertNotYetValid / ErrSealKeyUnavailable /
// ErrOrgNotActive — идэвхтэй тамга алга; 503
// eid.ErrSealServiceDisabled — тамгалалтыг оператор унтраасан: SealPDF давтахгүй, тамгагүй файл буцаахгүй, RP ч автоматаар
// давтахгүй).
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
	po := PrepareOptions{SignerCert: cert.Raw, Chain: o.Chain, SignerName: o.SignerName, Reason: o.Reason, SigningTime: o.SigningTime}
	auto := false
	if !o.Invisible {
		if po.Appearance = o.Appearance; po.Appearance == nil {
			po.Appearance = defaultSealAppearance(pdf)
			auto = po.Appearance != nil
		}
	}
	p, err := Prepare(pdf, po)
	if code := ErrorCode(err); auto && (code == CodeRequestInvalid || code == CodePDFTooLarge) {
		// Автомат дардас хуудсанд багтсангүй (бичвэр, хайрцаг), эсвэл дардасны ~82 KB фонтоор гаралт хэмжээнээс хэтэрсэн —
		// дуудагч юу ч хүсээгүй тул үл харагдах тамга (§6.4).
		po.Appearance = nil
		p, err = Prepare(pdf, po)
	}
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
	res, err := Complete(ctx, p.State, r.Signature, o.Complete)
	if err != nil {
		return nil, err
	}
	res.Placement = p.Placement
	return res, nil
}

// defaultSealAppearance — автомат дардас (APPEARANCE_SPEC.md §6.4): хуудсыг НЭГ удаа шийднэ — SuggestPlacement-ийн page 0
// (сүүлийн eID verify биш хуудас, PLACEMENT_SPEC §1a, §6b) — ба түүнийг Page-ээр тодорхой дамжуулна; тэр хуудасны харагдах
// хэмжээнд багтаасан баруун доод булан. Хуудсыг уншиж чадахгүй эсвэл 8 pt-оос нарийн/намхан бол nil (үл харагдах тамга;
// жинхэнэ алдааг Prepare өөрөө буцаана).
func defaultSealAppearance(pdf []byte) *Appearance {
	s, err := SuggestPlacement(pdf, Appearance{Width: 1, Height: 1})
	if err != nil {
		return nil
	}
	const gap = 4 // хуудасны ирмэгээс дардас хүртэл хамгийн бага зай (pt)
	w, h := min(SealStampWidth, s.PageWidth-2*gap), min(SealStampHeight, s.PageHeight-2*gap)
	if w <= 0 || h <= 0 {
		return nil
	}
	return &Appearance{Page: s.Page, X: s.PageWidth - w - min(SealStampMargin, (s.PageWidth-w)/2), Y: min(SealStampMargin, (s.PageHeight-h)/2),
		Width: w, Height: h}
}
