package eid

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"strings"
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
	// CallbackURL — ЗӨВХӨН CertificateChoiceDeviceLink: ижил төхөөрөмжийн буцах https URL (initialCallbackUrl). Өгвөл
	// Web2App/App2App холбоос боломжтой болж, утас linked SIGN дууссаны дараа л энэ URL-ийг нээнэ (query: RP-ийн өөрийн
	// параметр + sessionSecretDigest + sessionId — SessionSecretDigest, VerifySessionSecretDigest). Host нь RP-ийн
	// callbackHosts-д байх ёстой (эс бөгөөс CA талбарыг хаяж session QR-only болно). CertificateChoiceByEtsi үүнийг илгээхгүй.
	CallbackURL string
}

// certChoiceRequest — CA dto.CertificateChoiceRequest (үл мэдэгдэх талбарыг CA 400-аар татгалздаг — interactions
// БАЙХГҮЙ; initialCallbackUrl зөвхөн device-link).
type certChoiceRequest struct {
	RelyingPartyUUID   string           `json:"relyingPartyUUID"`
	RelyingPartyName   string           `json:"relyingPartyName"`
	CertificateLevel   CertificateLevel `json:"certificateLevel,omitempty"`
	InitialCallbackURL string           `json:"initialCallbackUrl,omitempty"`
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

// CertificateChoiceDeviceLink — device link: иргэн хэн болохыг урьдчилж мэдэхгүй үед гэрчилгээ сонгуулах. QR
// (s.LinkInput(LinkQR, …)); CertChoiceOptions.CallbackURL-тай бол Web2App/App2App-ийг ч (ижил төхөөрөмж дээрх linked
// гарын үсгийн буцах зам — README «Утсан дээр linked гарын үсэг»). CERT эрх.
func (s *SignService) CertificateChoiceDeviceLink(ctx context.Context, o *CertChoiceOptions) (*DeviceLinkSession, error) {
	sent := time.Now()
	body := s.certChoiceBody(o)
	if o != nil {
		body.InitialCallbackURL = strings.TrimSpace(o.CallbackURL)
	}
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
		CallbackURL:      body.InitialCallbackURL,
		ExpiresAt:        r.expiresAt(sent, s.ttl),
	}, nil
}

// decodeSessionSecret — sessionSecret: стандарт base64 (CA-ийн хэлбэр), үгүй бол base64url (padding-тэй/гүй).
func decodeSessionSecret(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, dlErr("sessionSecret хоосон")
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) > 0 {
			return b, nil
		}
	}
	return nil, dlErr("sessionSecret base64 биш")
}

// SessionSecretDigest — linked signing-ийн callback-ийн `sessionSecretDigest` параметр:
// BASE64URL-NOPAD(SHA-256(base64-decode(sessionSecret))). sessionSecret — certificate-choice device-link session-ий
// (DeviceLinkSession.SessionSecret). Оролт base64 биш бол *DeviceLinkError.
func SessionSecretDigest(sessionSecret string) (string, error) {
	b, err := decodeSessionSecret(sessionSecret)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(h[:]), nil
}

// VerifySessionSecretDigest — callback-ээр ирсэн sessionSecretDigest нь sessionSecret-ийнхтэй таарч байгааг тогтмол
// хугацаанд шалгана. Буруу хэлбэртэй оролт бол false.
func VerifySessionSecretDigest(digest, sessionSecret string) bool {
	want, err := SessionSecretDigest(sessionSecret)
	if err != nil || digest == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(digest), []byte(want)) == 1
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
// contentCommitment; SkipKeyUsageCheck үед алгасна), гинж, issuer. Энэ хариунд гарын үсэг БАЙХГҮЙ — иргэнийг таниагүй (нэвтрэлт
// биш); зөвхөн дараагийн sign session-ий гэрчилгээг урьдчилж мэдэхэд. sessionID — certificate-choice session.
func (v *Validator) ValidateCertificateChoice(r *SessionResult, sessionID string) (*Signer, error) {
	if err := sessionDone(r); err != nil {
		return nil, err
	}
	leaf, level, err := v.leafOf(r, "RAW_DIGEST_SIGNATURE")
	if err != nil {
		return nil, err
	}
	return &Signer{
		DocumentNumber:      r.DocumentNumber,
		Certificate:         leaf,
		CertificateDERB64:   base64.StdEncoding.EncodeToString(leaf.Raw),
		CertificateLevel:    string(level),
		Subject:             ParseSubject(leaf),
		CertChoiceSessionID: sessionID,
	}, nil
}
