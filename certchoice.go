package eid

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"time"
)

// Certificate-choice (Smart-ID v3) — иргэн утсан дээрээ гарын үсгийн гэрчилгээгээ сонгож (PIN-гүй) RP-д өгнө. RP
// SIGN гэрчилгээ + documentNumber-ийг гарын үсэг зурахаас ӨМНӨ мэдэх шаардлагатай урсгалд (client-side PAdES: CMS
// signedAttrs-ийн signingCertificateV2) заавал:
//
//	s  := c.Sign.CertificateChoiceByEtsi(…)          // эсвэл CertificateChoiceDeviceLink (QR)
//	r  := c.Session.WaitForResult(…, s.SessionID, …)
//	sg := c.Validator.ValidateCertificateChoice(r, s.SessionID)   // → Signer{Certificate, DocumentNumber}
//	… DTBS-ийг sg.Certificate-аар угсарна …
//	ss := c.Sign.DigestForSigner(…, sg, dtbsB64, …)  // ЯГ тэр төхөөрөмж рүү (documentNumber)
//	sig := c.Validator.ValidateSign(r2, …, ValidateSignOptions{ExpectedCertificate: sg.Certificate, ExpectedAlgorithm: …})

// CertChoiceOptions — certificate-choice session-ий тохиргоо. nil = анхдагч.
type CertChoiceOptions struct {
	// CertificateLevel — "" = Client-ийн анхдагч.
	CertificateLevel CertificateLevel
}

// certChoiceRequest — CA dto.CertificateChoiceRequest (үл мэдэгдэх талбарыг CA 400-аар татгалздаг — interactions,
// initialCallbackUrl БАЙХГҮЙ).
type certChoiceRequest struct {
	RelyingPartyUUID string           `json:"relyingPartyUUID"`
	RelyingPartyName string           `json:"relyingPartyName"`
	CertificateLevel CertificateLevel `json:"certificateLevel,omitempty"`
}

func (s *SignService) certChoiceBody(o *CertChoiceOptions) certChoiceRequest {
	if o == nil {
		o = &CertChoiceOptions{}
	}
	return certChoiceRequest{
		RelyingPartyUUID: s.creds.RPUUID,
		RelyingPartyName: s.creds.RPName,
		CertificateLevel: orDefault(o.CertificateLevel, s.level),
	}
}

// CertificateChoiceByEtsi — push: иргэний (РД / civil_id / ETSI) утас руу гэрчилгээ сонгуулах хүсэлт. Үр дүнг
// Session.WaitForResult → Validator.ValidateCertificateChoice. CERT эрх шаардана.
func (s *SignService) CertificateChoiceByEtsi(ctx context.Context, id string, o *CertChoiceOptions) (*NotificationSession, error) {
	sent := time.Now()
	var r sessionStartResponse
	if err := s.h.postJSON(ctx, routeCertChoiceEtsi.expand(id), s.certChoiceBody(o), &r); err != nil {
		return nil, err
	}
	return &NotificationSession{SessionID: r.SessionID, VC: string(r.VC), ExpiresAt: r.expiresAt(sent, s.ttl)}, nil
}

// CertificateChoiceDeviceLink — QR: иргэн хэн болохыг урьдчилж мэдэхгүй үед гэрчилгээ сонгуулах. CA-ийн
// certificate-choice хүсэлт initialCallbackUrl авдаггүй тул ЗӨВХӨН QR холбоос (s.LinkInput(LinkQR, …)). CERT эрх.
func (s *SignService) CertificateChoiceDeviceLink(ctx context.Context, o *CertChoiceOptions) (*DeviceLinkSession, error) {
	sent := time.Now()
	body := s.certChoiceBody(o)
	var r sessionStartResponse
	if err := s.h.postJSON(ctx, routeCertChoiceDeviceLink.expand(), body, &r); err != nil {
		return nil, err
	}
	return &DeviceLinkSession{
		SessionID:        r.SessionID,
		SessionToken:     r.SessionToken,
		SessionSecret:    r.SessionSecret,
		DeviceLinkBase:   r.DeviceLinkBase,
		VC:               string(r.VC),
		ReceivedAt:       time.Now(),
		SessionType:      SessionCert,
		RelyingPartyName: body.RelyingPartyName,
		ExpiresAt:        r.expiresAt(sent, s.ttl),
	}, nil
}

// Signer — certificate-choice-оор баталгаажсан гарын үсэг зурагч: гарын үсгийн гэрчилгээ + түүнийг эзэмшдэг ЯГ ТЭР
// төхөөрөмжийн DocumentNumber. Sign.DigestForSigner / DeviceLinkForSigner-д өгнө.
type Signer struct {
	// DocumentNumber — гэрчилгээг сонгосон төхөөрөмж (sign session-ийг ҮҮГЭЭР эхлүүлнэ).
	DocumentNumber string
	// Certificate — иргэний SIGN гэрчилгээ (KeyUsage contentCommitment); CertificateDERB64 — DER, стандарт base64.
	Certificate       *x509.Certificate
	CertificateDERB64 string
	CertificateLevel  string
	Subject           Subject
	// CertChoiceSessionID — certificate-choice session (linked sign-ийн linkedSessionID). "" бол DigestForSigner
	// /notification/document замаар явна.
	CertChoiceSessionID string
}

// ValidateCertificateChoice — certificate-choice session-ий хариуг шалгана: COMPLETE/OK (эс бөгөөс
// *SessionFailedError), гэрчилгээ ба documentNumber байгаа, хугацаа, certLevel, зориулалт (гарын үсгийн —
// contentCommitment, CheckKeyUsage үед), гинж, issuer. Энэ хариунд гарын үсэг БАЙХГҮЙ — иргэнийг таниагүй (нэвтрэлт
// биш); зөвхөн дараагийн sign session-ий гэрчилгээг урьдчилж мэдэхэд. sessionID — certificate-choice session.
func (v *Validator) ValidateCertificateChoice(r *SessionResult, sessionID string) (*Signer, error) {
	if err := sessionDone(r); err != nil {
		return nil, err
	}
	leaf, err := v.leafOf(r, "RAW_DIGEST_SIGNATURE")
	if err != nil {
		return nil, err
	}
	return &Signer{
		DocumentNumber:      r.DocumentNumber,
		Certificate:         leaf,
		CertificateDERB64:   base64.StdEncoding.EncodeToString(leaf.Raw),
		CertificateLevel:    r.CertificateLevel,
		Subject:             ParseSubject(leaf),
		CertChoiceSessionID: sessionID,
	}, nil
}
