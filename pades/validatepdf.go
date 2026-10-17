package pades

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"math/big"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"

	eid "github.com/gerege-systems/eid-mongolia-sdk-go"
	"github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/validate"
)

// ValidateOptions — ValidatePDF-ийн тохиргоо (бүгд заавал биш).
type ValidateOptions struct {
	// Roots — итгэлийн тулгуур DER; хоосон бол Mongolian National Root CA.
	Roots [][]byte
	// Intermediates — нэмэлт завсрын CA DER (шигтгэсэн 02–05-аас гадна).
	Intermediates [][]byte
	// Issuers — eID-ийн олгогч гэж үзэх нэмэлт CA DER (шигтгэсэн 04/05-аас гадна; тест).
	Issuers [][]byte
	// Time — шалгах цаг (цагийн тэмдэггүй гарын үсэгт); тэг бол одоо.
	Time time.Time
	// Offline — сүлжээ рүү гарахгүй: цуцлалтыг зөвхөн баримтын DSS-ийн OCSP/CRL-ээс.
	Offline bool
	// HTTPClient — OCSP/CRL татах (анхдагч: 10 с timeout, redirect дагахгүй).
	HTTPClient *http.Client
}

// ValidatePDF — PDF доторх бүх PAdES/CMS гарын үсгийг CA-ийн нийтийн шалгагчийн (/v3/validate/pdf) кодоор шалгана:
// ByteRange/messageDigest-ийн бүрэн бүтэн байдал, CMS гарын үсэг, гинж (үндэсний Root CA 01 хүртэл), KU/EKU, хугацаа,
// RFC 3161 цагийн тэмдэг, гарын үсгийн дараах revision (modified_after_signing, харагдах гарын үсэг — APPEARANCE_SPEC
// §5), LTV ба гэрчилгээний түвшин (certificate_level). Тайлан CA-ийн /v3/validate/pdf-тэй ижил JSON хэлбэртэй.
//
// Цуцлалт (eID-ийн 04/05-аас гарсан гэрчилгээнд): онлайн — гэрчилгээний AIA OCSP, эс бөгөөс CDP CRL (олгогчийн
// гарын үсгээр шалгана); хариу авч чадаагүй эсвэл Offline бол баримтын DSS-ийн OCSP/CRL. Аль нь ч үгүй бол
// revocation_unavailable (indeterminate). Баримт сүлжээгээр хаашаа ч илгээгдэхгүй — зөвхөн гэрчилгээний serial (OCSP).
//
// Алдаа (*Error): PDF_TOO_LARGE (> 10 MiB), PDF_INVALID (задрахгүй), PDF_ENCRYPTED (/Encrypt — ямар ч шифрлэлт, хоосон
// нууц үгтэй ч), PDF_NO_SIGNATURE, PDF_TOO_MANY_SIGNATURES (> 16), REQUEST_INVALID (Roots/Intermediates/Issuers
// задрахгүй) — CA-ийн too_large / not_pdf / encrypted / no_signature / too_many_signatures-тэй харгалзана.
func ValidatePDF(ctx context.Context, doc []byte, o ValidateOptions) (*Report, error) {
	if len(doc) > MaxOutputBytes {
		return nil, newErr(CodePDFTooLarge, "PDF 10 MiB-аас их", nil)
	}
	roots, err := parseRoots(o.Roots)
	if err != nil {
		return nil, newErr(CodeRequestInvalid, "roots", err)
	}
	inter, err := parseDERs(o.Intermediates)
	if err != nil {
		return nil, newErr(CodeRequestInvalid, "intermediates", err)
	}
	extraIssuers, err := parseDERs(o.Issuers)
	if err != nil {
		return nil, newErr(CodeRequestInvalid, "issuers", err)
	}
	raws, err := validate.Extract(doc)
	switch {
	case errors.Is(err, validate.ErrNoSignature):
		return nil, newErr(CodePDFNoSignature, "баримтад цахим гарын үсэг алга", err)
	case errors.Is(err, validate.ErrTooMany):
		return nil, newErr(CodePDFTooManySignatures, "баримтад хэт олон гарын үсэг байна", err)
	case errors.Is(err, validate.ErrEncrypted):
		return nil, newErr(CodePDFEncrypted, "шифрлэгдсэн PDF-ийг шалгах боломжгүй — нууцлалыг арилгаад дахин оролдоно уу", err)
	case err != nil:
		return nil, newErr(CodePDFInvalid, "PDF задарсангүй", err)
	}
	var now func() time.Time
	if !o.Time.IsZero() {
		t := o.Time
		now = func() time.Time { return t }
	}
	v := newValidator(roots, inter, extraIssuers, now, raws)
	if !o.Offline {
		v.Status = newOnlineStatus(ctx, newFetcher(o.HTTPClient), raws, v.Issuers, v.Status, o.Time)
	}
	rep, err := v.ValidatePDF(ctx, doc)
	if err != nil {
		return nil, newErr(CodePDFInvalid, "шалгаж чадсангүй", err)
	}
	for i := range rep.Signatures {
		s := &rep.Signatures[i]
		if s.ChainTrusted && i < len(raws) {
			if leaf, err := x509.ParseCertificate(raws[i].Leaf); err == nil {
				if lvl, err := eid.CertificateLevelOf(leaf, "RAW_DIGEST_SIGNATURE"); err == nil {
					s.CertificateLevel = string(lvl)
				}
			}
		}
		s.KeyMedium = keyMedium(s)
	}
	return rep, nil
}

// keyMedium — CA !377 key_medium-ийн локал хувилбар: CA нь бүртгэлээс (pdf_signatures.medium / certificates.key_medium)
// тогтооно; энд зөвхөн гэрчилгээнээс — eID-ийн олгосон SIGN гэрчилгээ qcStatements QcCompliance-тэй (QUALIFIED/QSCD) бол
// "phone" (USB токены P-CITIZEN-SIGN-TOKEN нь qcStatements-гүй); бусад (токен ба хуучин утасны гэрчилгээг гэрчилгээнээс
// ялгах боломжгүй) "unknown".
func keyMedium(s *SignatureReport) string {
	if c := s.Certificate; c != nil && c.IssuedByEID && c.Usage == "sign" &&
		(s.CertificateLevel == string(eid.LevelQualified) || s.CertificateLevel == string(eid.LevelQSCD)) {
		return "phone"
	}
	return "unknown"
}

// onlineStatus — validate.StatusSource: eID олгогчийн гаргасан гэрчилгээний ОДООГИЙН төлвийг (CA өөрийн бүртгэлээс
// уншдагтай ижил утга) AIA OCSP, эс бөгөөс CDP CRL-ээс; хариугүй бол fallback (баримтын DSS).
type onlineStatus struct {
	ctx      context.Context
	f        *fetcher
	leaves   map[string]leafIssuer // serial (hex) → гэрчилгээ + олгогч
	fallback validate.StatusSource
	cache    map[string]validate.CertStatus
	at       time.Time // шалгах цаг (тэг бол одоо): хариуны хүчинтэй хугацааг үүгээр
}

type leafIssuer struct {
	leaf, issuer *x509.Certificate
	ambiguous    bool // ижил serial-тэй өөр гэрчилгээ — төлөв тогтоохгүй (fail-closed)
}

func newOnlineStatus(ctx context.Context, f *fetcher, raws []validate.RawSignature, issuers []*x509.Certificate, fallback validate.StatusSource, at time.Time) *onlineStatus {
	s := &onlineStatus{ctx: ctx, f: f, leaves: map[string]leafIssuer{}, fallback: fallback, cache: map[string]validate.CertStatus{}, at: at}
	for _, r := range raws {
		leaf, err := x509.ParseCertificate(r.Leaf)
		if err != nil {
			continue
		}
		key := leaf.SerialNumber.Text(16)
		if prev, ok := s.leaves[key]; ok {
			if !bytes.Equal(prev.leaf.Raw, leaf.Raw) {
				prev.ambiguous = true
				s.leaves[key] = prev
			}
			continue
		}
		for _, is := range issuers {
			if bytes.Equal(leaf.RawIssuer, is.RawSubject) && leaf.CheckSignatureFrom(is) == nil {
				s.leaves[key] = leafIssuer{leaf: leaf, issuer: is}
				break
			}
		}
	}
	return s
}

func (s *onlineStatus) CertStatus(serial *big.Int) (validate.CertStatus, error) {
	key := serial.Text(16)
	if st, ok := s.cache[key]; ok {
		return st, nil
	}
	li, ok := s.leaves[key]
	if !ok || li.ambiguous {
		return validate.CertStatus{}, nil
	}
	st, ok := s.ocsp(li)
	if !ok {
		st, ok = s.crl(li)
	}
	if !ok {
		if s.fallback == nil {
			return validate.CertStatus{}, nil
		}
		var err error
		if st, err = s.fallback.CertStatus(serial); err != nil {
			return validate.CertStatus{}, err
		}
	}
	s.cache[key] = st
	return st, nil
}

func (s *onlineStatus) now() time.Time {
	if !s.at.IsZero() {
		return s.at
	}
	return time.Now()
}

const (
	onlineOCSPMaxBytes = 16 << 10
	onlineClockSkew    = 5 * time.Minute
)

// ocsp — AIA responder бүрээс; олгогч эсвэл олгогчийн id-kp-OCSPSigning responder зурсан, энэ serial, thisUpdate
// ирээдүйд биш, nextUpdate өнгөрөөгүй. unknown → Issued=false (олгогч энэ serial-ийг мэдэхгүй).
func (s *onlineStatus) ocsp(li leafIssuer) (validate.CertStatus, bool) {
	req, err := ocsp.CreateRequest(li.leaf, li.issuer, nil)
	if err != nil {
		return validate.CertStatus{}, false
	}
	now := s.now()
	for _, u := range li.leaf.OCSPServer {
		der, err := s.f.do(s.ctx, http.MethodPost, u, "application/ocsp-request", req)
		if err != nil || len(der) > onlineOCSPMaxBytes {
			continue
		}
		resp, err := parseOCSPFrom(der, li.leaf, li.issuer)
		if err != nil || resp.SerialNumber == nil || resp.SerialNumber.Cmp(li.leaf.SerialNumber) != 0 {
			continue
		}
		if rc := resp.Certificate; rc != nil && !sameCertKey(rc, li.issuer) &&
			(!responderOK(resp, li.issuer) || now.Before(rc.NotBefore) || now.After(rc.NotAfter)) {
			continue
		}
		if resp.ThisUpdate.After(now.Add(onlineClockSkew)) || !resp.NextUpdate.IsZero() && resp.NextUpdate.Before(now) {
			continue
		}
		switch resp.Status {
		case ocsp.Good:
			return validate.CertStatus{Issued: true}, true
		case ocsp.Revoked:
			return validate.CertStatus{Issued: true, Revoked: true, RevokedAt: resp.RevokedAt}, true
		default:
			return validate.CertStatus{}, true
		}
	}
	return validate.CertStatus{}, false
}

// crl — CDP-ийн CRL: олгогчийн гарын үсэгтэй, nextUpdate өнгөрөөгүй.
func (s *onlineStatus) crl(li leafIssuer) (validate.CertStatus, bool) {
	now := s.now()
	for _, u := range li.leaf.CRLDistributionPoints {
		der, err := s.f.do(s.ctx, http.MethodGet, u, "", nil)
		if err != nil {
			continue
		}
		crl, err := x509.ParseRevocationList(der)
		if err != nil || !bytes.Equal(crl.RawIssuer, li.issuer.RawSubject) || crl.CheckSignatureFrom(li.issuer) != nil ||
			!crl.NextUpdate.IsZero() && crl.NextUpdate.Before(now) {
			continue
		}
		for _, e := range crl.RevokedCertificateEntries {
			if e.SerialNumber.Cmp(li.leaf.SerialNumber) == 0 {
				return validate.CertStatus{Issued: true, Revoked: true, RevokedAt: e.RevocationTime}, true
			}
		}
		return validate.CertStatus{Issued: true}, true
	}
	return validate.CertStatus{}, false
}

// parseOCSPFrom — ocsp.ParseResponseForCert (leaf nil бол ParseResponse) + RFC 6960 §4.2.2.2: олгогч өөрөө зурж
// хариундаа ӨӨРИЙН гэрчилгээг шигтгэсэн хариуг x/crypto/ocsp «bad signature» гэж татгалздаг — шигтгэсэн cert нь
// олгогч мөн (raw эсвэл subject+SPKI) бол хариуг олгогчийн түлхүүрээр шалгана (eid.NewOCSPChecker-тэй ижил).
func parseOCSPFrom(der []byte, leaf, issuer *x509.Certificate) (*ocsp.Response, error) {
	resp, err := ocsp.ParseResponseForCert(der, leaf, issuer)
	if err == nil {
		return resp, nil
	}
	if alt, aerr := ocsp.ParseResponseForCert(der, leaf, nil); aerr == nil && alt.Certificate != nil &&
		sameCertKey(alt.Certificate, issuer) && alt.CheckSignatureFrom(issuer) == nil {
		return alt, nil
	}
	return nil, err
}

// sameCertKey — a, b нь ижил гэрчилгээ (байт-ижил) эсвэл ижил subject + түлхүүр (дахин олгосон ижил CA).
func sameCertKey(a, b *x509.Certificate) bool {
	return bytes.Equal(a.Raw, b.Raw) ||
		(bytes.Equal(a.RawSubject, b.RawSubject) && bytes.Equal(a.RawSubjectPublicKeyInfo, b.RawSubjectPublicKeyInfo))
}
