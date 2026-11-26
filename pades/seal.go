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

// DocumentSealer — тамгалахдаа docId/revIndex-ийг нөөцөлдөг Sealer (*eid.SealService хангана; CA V158). SealOptions.QR-д
// заавал: QR-тэй дардас /verify/<docId>/<revIndex>-ийг амладаг тул тэр байрлалыг тамгалах үед нөөцөлнө.
type DocumentSealer interface {
	Sealer
	SealForDocument(ctx context.Context, orgEtsi string, digest []byte, docID string, revIndex int) (*eid.SealResult, error)
}

// SealOptions — SealPDF-ийн тохиргоо. Баталгаажуулалтын хуудас нэмэхгүй (тамганы бүртгэл хуудасгүй баримт үүсгэнэ — CA
// V158). Анхдагчаар тамга ХАРАГДАНА: баримтын сүүлийн (eID verify биш) хуудсанд байгууллагын тамганы дардас
// (APPEARANCE_SPEC.md §6 — QR/холбоосгүй; QR-тэй бол SealOptions.QR),
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
	// QR — тамганы дардсыг QR-тэй зурна (APPEARANCE_SPEC.md §6.5, golden v13): QR = /verify/<docId>/<revIndex>. Sealer нь
	// DocumentSealer байх ёстой (docId/revIndex-ийг тамгалах үед нөөцөлнө — CA V158), эс бөгөөс REQUEST_INVALID. QR нь
	// бүртгэлийг амладаг: Completed.SealRegistration-ийг 7 хоногийн дотор eid.Client.Seal.RegisterSealedPDF-ээр бүртгэнэ.
	// Invisible-тэй хамт → REQUEST_INVALID. Автомат дардас хуудсанд багтахгүй бол (QR-тэй дардас ≥ 45 pt өндөр) үл харагдах
	// тамга, нөөцгүй (Completed.Placement nil). false (анхдагч) — QR-гүй дардас (§6.2), golden v12-тэй байт-ижил.
	QR bool
	// DocID — баримтын UUID (жижиг үсэг; PrepareOptions.DocID, APPEARANCE_SPEC.md §6.6): гарын үсэггүй баримтад хоосон бол
	// санамсаргүй; гарын үсэгтэй баримтад verify хуудас / QR-тэй тамганы docId олдвол түүнийг (зөрвөл REQUEST_INVALID),
	// олдохгүй бол энэ утга — хоосон бол Completed.DocID "" ба Completed.SealRegistration nil (бүртгэх боломжгүй; QR бол
	// REQUEST_INVALID). Дардасны байтад зөвхөн QR үед орно.
	DocID string
	// FileName — CA-ийн бүртгэл дэх нэр (/verify; заавал биш, NFC, ≤ 120 тэмдэгт — эс бөгөөс REQUEST_INVALID). PDF-д
	// бичигдэхгүй.
	FileName string
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
// CA-ийн /verify/{docId}-д бүртгэх бол Completed.SealRegistration-ийг eid.Client.Seal.RegisterSealedPDF-ээр (7 хоногийн
// дотор, тамгалсан RP өөрөө) — SealOptions.QR үед заавал (QR нь бүртгэлийг амладаг).
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
	ds, reserves := s.(DocumentSealer)
	switch {
	case o.QR && o.Invisible:
		return nil, newErr(CodeRequestInvalid, "QR ба Invisible хамт боломжгүй", nil)
	case o.QR && !reserves:
		return nil, newErr(CodeRequestInvalid, "QR-тэй тамганд DocumentSealer (eid.Client.Seal) заавал — docId/revIndex нөөц", nil)
	}
	fileName := ""
	if o.FileName != "" {
		name, ok := cleanFileName(o.FileName)
		if !ok {
			return nil, newErr(CodeRequestInvalid, "fileName ≤ 120 тэмдэгт", nil)
		}
		fileName = name
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
	po := PrepareOptions{SignerCert: cert.Raw, Chain: o.Chain, SignerName: o.SignerName, Reason: o.Reason, SigningTime: o.SigningTime,
		DocID: o.DocID, FileName: fileName, sealQR: o.QR}
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
	if o.QR && p.DocID == "" {
		// Гарын үсэгтэй баримтад verify хуудас / QR-тэй тамга алга, DocID өгөөгүй — QR-ийг тавих (ба бүртгэх) docId алга.
		return nil, newErr(CodeRequestInvalid, "QR-тэй тамганд docId заавал (SealOptions.DocID)", nil)
	}
	var r *eid.SealResult
	if o.QR && po.Appearance != nil {
		// QR-тэй дардас зурагдсан: /verify/<docId>/<revIndex>-ийг тамгалах үед нөөцөлнө (CA V158; бүртгэл тулгана —
		// SEAL_DOC_MISMATCH).
		st, err := decodeState(p.State)
		if err != nil {
			return nil, newErr(CodeStateInvalid, "state задарсангүй", err)
		}
		r, err = ds.SealForDocument(ctx, orgEtsi, p.DTBS, p.DocID, st.RevIndex)
		if err != nil {
			return nil, err
		}
	} else if r, err = s.Seal(ctx, orgEtsi, p.DTBS, eid.SHA256); err != nil {
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
	if res.DocID != "" {
		reg, err := SealRegistration(res)
		if err != nil {
			return nil, err
		}
		res.SealRegistration = &reg
	}
	return res, nil
}

// SealRegistration — e-Seal-ийн Completed-ээс CA-ийн тамганы бүртгэлийн бие (eid.SealRegistration, CA
// dto.SealRegisterRequest-тэй ижил) бөглөнө; SealPDF үүнийг Completed.SealRegistration-д аль хэдийн тавьдаг. Hash-ууд нь
// иргэний Registration-тэй ЯГ ижил тодорхойлолт (Complete тооцсон): inSha256 = sha256(оролт), sigRevSha256 =
// sha256(гаралт[:ByteRange[2]+ByteRange[3]]), outSha256 = sha256(гаралт), priorCmsSha256 = өмнөх гарын үсэг бүрийн
// /Contents CMS DER-ийн sha256 (CA validate.SignatureProof-ийн cms_sha256), PriorSignatures нь PRIOR_MISMATCH-ийн
// revision хослол. CA CMS-ийн SHA-256(signedAttrs)-ийг тамгалсан digest-тэй тулгадаг — энэ нь Prepared.DTBS (SealPDF
// тамгалуулсан утга). Алдаа: REQUEST_INVALID — nil, DocID хоосон, эсвэл зурагч e-Seal биш (иргэнд Registration).
func SealRegistration(c *Completed) (eid.SealRegistration, error) {
	if c == nil {
		return eid.SealRegistration{}, newErr(CodeRequestInvalid, "Completed nil", nil)
	}
	if c.DocID == "" {
		return eid.SealRegistration{}, newErr(CodeRequestInvalid, "docId хоосон — гарын үсэгтэй баримтад SealOptions.DocID", nil)
	}
	if cert, err := x509.ParseCertificate(c.SignerCert); err != nil || !eid.IsSealCertificate(cert) {
		return eid.SealRegistration{}, newErr(CodeRequestInvalid, "зурагч e-Seal биш — иргэний гарын үсэгт Registration", nil)
	}
	r := eid.SealRegistration{DocID: c.DocID, RevIndex: c.RevIndex, CMS: c.CMS, FileName: c.FileName, InSHA256: c.InSHA256,
		SigRevSHA256: c.SigRevSHA256, OutSHA256: c.OutSHA256}
	if len(c.PriorCMSSHA256) > 0 {
		r.PriorCMSSHA256 = append([]string(nil), c.PriorCMSSHA256...)
		if len(c.PriorRevisionSHA256) == len(c.PriorCMSSHA256) {
			for i, h := range c.PriorCMSSHA256 {
				r.PriorSignatures = append(r.PriorSignatures, eid.PDFPriorSignature{CMSSHA256: h, RevisionSHA256: c.PriorRevisionSHA256[i]})
			}
		}
	}
	return r, nil
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
