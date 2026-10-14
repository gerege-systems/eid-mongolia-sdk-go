package eid

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

// SignOptions — гарын үсгийн session-ий нэмэлт тохиргоо. nil = анхдагч.
type SignOptions struct {
	CertificateLevel CertificateLevel
	// CallbackURL — ижил төхөөрөмжийн буцах https URL (initialCallbackUrl). Device link-д Web2App/App2App холбоос
	// зөвхөн үүнтэй session-д хүчинтэй; host нь RP-ийн callbackHosts-д байх ёстой.
	CallbackURL string
	// HashAlgorithm — digest-ийн hash ("" = SHA-256). Digest-ийн урт = hLen.
	HashAlgorithm HashAlgorithm
	// SignatureAlgorithm — "" = rsassa-pss (PKCS#1 v1.5 нь deprecated). DigestForSigner / DeviceLinkForSigner-д
	// "" = sha256WithRSAEncryption (PAdES/CMS).
	SignatureAlgorithm SignatureAlgorithm
	// OnBehalfOf — байгууллагын нэрийн өмнөөс (NTRMN-<бүртгэл>). Гарын үсэг иргэний PIN2 гэрчилгээгээр;
	// байгууллага digest-д ОРОХГҮЙ. Татгалзвал ForbiddenError/APIError.Code (OnBehalfErrorCodes).
	OnBehalfOf string
	// FileName — гарын үсэг зурагдах баримтын нэр: CA-ийн /verify хуудас ба иргэний түүхэнд харагдана. Заавал биш —
	// өгөөгүй бол CA interaction текстээс таамаглана.
	FileName string
}

// SignService — иргэн PIN2 (non-repudiation)-оор баримтын digest-д хууль ёсны гарын үсэг зурна. Хариуг
// Validator.ValidateSign-аар тэр digest-ийн эсрэг шалгана.
type SignService struct {
	h     *httpDoer
	creds Credentials
	level CertificateLevel
	ttl   time.Duration
}

type signProtocolParams struct {
	Digest                       string             `json:"digest"`
	SignatureAlgorithm           SignatureAlgorithm `json:"signatureAlgorithm"`
	SignatureAlgorithmParameters hashParam          `json:"signatureAlgorithmParameters"`
}

type signRequest struct {
	RelyingPartyUUID            string             `json:"relyingPartyUUID"`
	RelyingPartyName            string             `json:"relyingPartyName"`
	CertificateLevel            CertificateLevel   `json:"certificateLevel"`
	SignatureProtocol           string             `json:"signatureProtocol"`
	SignatureProtocolParameters signProtocolParams `json:"signatureProtocolParameters"`
	Interactions                string             `json:"interactions"`
	InitialCallbackURL          string             `json:"initialCallbackUrl,omitempty"`
	OnBehalfOf                  string             `json:"onBehalfOf,omitempty"`
	FileName                    string             `json:"fileName,omitempty"`
	// LinkedSessionID — зөвхөн /signature/notification/linked: өмнөх certificate-choice session.
	LinkedSessionID string `json:"linkedSessionID,omitempty"`
}

// body — v3 nested body + RP-д хадгалах SignContext (ижил утгуудаас — байт зөрөхгүй).
func (s *SignService) body(digestB64 string, interactions []Interaction, o *SignOptions, defAlg SignatureAlgorithm) (*signRequest, *SignContext, error) {
	if o == nil {
		o = &SignOptions{}
	}
	ib64, err := InteractionsToBase64(interactions)
	if err != nil {
		return nil, nil, err
	}
	sc := &SignContext{
		Digest:             digestB64,
		HashAlgorithm:      orDefault(o.HashAlgorithm, SHA256),
		SignatureAlgorithm: orDefault(o.SignatureAlgorithm, defAlg),
		RelyingPartyName:   s.creds.RPName,
		Interactions:       ib64,
		InitialCallbackURL: strings.TrimSpace(o.CallbackURL),
	}
	return &signRequest{
		RelyingPartyUUID:  s.creds.RPUUID,
		RelyingPartyName:  sc.RelyingPartyName,
		CertificateLevel:  orDefault(o.CertificateLevel, s.level),
		SignatureProtocol: "RAW_DIGEST_SIGNATURE",
		SignatureProtocolParameters: signProtocolParams{
			Digest:                       digestB64,
			SignatureAlgorithm:           sc.SignatureAlgorithm,
			SignatureAlgorithmParameters: hashParam{HashAlgorithm: sc.HashAlgorithm},
		},
		Interactions:       ib64,
		InitialCallbackURL: sc.InitialCallbackURL,
		OnBehalfOf:         strings.TrimSpace(o.OnBehalfOf),
		FileName:           strings.TrimSpace(o.FileName),
	}, sc, nil
}

func (s *SignService) notification(ctx context.Context, path string, req *signRequest, sc *SignContext) (*NotificationSession, error) {
	sent := time.Now()
	var r sessionStartResponse
	if err := s.h.postJSON(ctx, path, req, &r); err != nil {
		return nil, err
	}
	// Sign урсгалд rpChallenge байхгүй — гарын үсэг digest-ийн эсрэг баталгаажна.
	return &NotificationSession{SessionID: r.SessionID, VC: string(r.VC), Sign: sc, ExpiresAt: SessionExpiry(sent, s.ttl)}, nil
}

func (s *SignService) deviceLink(ctx context.Context, path string, req *signRequest, sc *SignContext) (*DeviceLinkSession, error) {
	sent := time.Now()
	var r sessionStartResponse
	if err := s.h.postJSON(ctx, path, req, &r); err != nil {
		return nil, err
	}
	return &DeviceLinkSession{
		SessionID:      r.SessionID,
		SessionToken:   r.SessionToken,
		SessionSecret:  r.SessionSecret,
		DeviceLinkBase: r.DeviceLinkBase,
		VC:             string(r.VC),
		ReceivedAt:     time.Now(),
		SessionType:    SessionSign,
		Sign:           sc,
		ExpiresAt:      SessionExpiry(sent, s.ttl),
	}, nil
}

func (s *SignService) startNotification(ctx context.Context, path, digestB64 string, interactions []Interaction, o *SignOptions) (*NotificationSession, error) {
	req, sc, err := s.body(digestB64, interactions, o, AlgRSASSAPSS)
	if err != nil {
		return nil, err
	}
	return s.notification(ctx, path, req, sc)
}

func (s *SignService) startDeviceLink(ctx context.Context, path, digestB64 string, interactions []Interaction, o *SignOptions) (*DeviceLinkSession, error) {
	req, sc, err := s.body(digestB64, interactions, o, AlgRSASSAPSS)
	if err != nil {
		return nil, err
	}
	return s.deviceLink(ctx, path, req, sc)
}

// DigestByEtsi — бэлэн digest (стандарт base64)-ээр push sign: РД / civil_id / ETSI. Баримт (PDF/файл)-ын
// байтын SHA-256-ийг гаднаас бэлдэж өгнө (SHA256Base64).
//
// (!) Олон утастай иргэнд CA etsi-г ЭХНИЙ идэвхтэй төхөөрөмж рүү шийднэ — гарын үсэг тухайн утасны гэрчилгээгээр.
// Гэрчилгээг урьдчилж мэдэх шаардлагатай (PAdES/CMS) бол CertificateChoiceByEtsi → DigestForSigner.
func (s *SignService) DigestByEtsi(ctx context.Context, id, digestB64 string, interactions []Interaction, o *SignOptions) (*NotificationSession, error) {
	return s.startNotification(ctx, routeSignNotificationEtsi.expand(id), digestB64, interactions, o)
}

// DigestByDocument — бэлэн digest-ээр push sign, баримтын дугаараар (auth / certificate-choice-оос гарсан
// DocumentNumber — тодорхой төхөөрөмж).
func (s *SignService) DigestByDocument(ctx context.Context, documentNumber, digestB64 string, interactions []Interaction, o *SignOptions) (*NotificationSession, error) {
	return s.startNotification(ctx, routeSignNotificationDocument.expand(documentNumber), digestB64, interactions, o)
}

// TextByEtsi — текстийн SHA-256 digest-ийг дотроо тооцоод push sign (богино текст баримтад).
func (s *SignService) TextByEtsi(ctx context.Context, id, text string, interactions []Interaction, o *SignOptions) (*NotificationSession, error) {
	return s.DigestByEtsi(ctx, id, SHA256Base64([]byte(text)), interactions, o)
}

// DeviceLinkByEtsi — QR / Web2App / App2App sign: тодорхой иргэн (РД / civil_id / ETSI). Холбоосыг
// s.LinkInput(...) → BuildDeviceLink-ээр угсарна; Web2App/App2App-д SignOptions.CallbackURL заавал.
// ValidateSign-д ExpectedFlowType = харуулсан холбоосын төрөл.
func (s *SignService) DeviceLinkByEtsi(ctx context.Context, id, digestB64 string, interactions []Interaction, o *SignOptions) (*DeviceLinkSession, error) {
	return s.startDeviceLink(ctx, routeSignDeviceLinkEtsi.expand(id), digestB64, interactions, o)
}

// DeviceLinkByDocument — QR / Web2App / App2App sign, баримтын дугаараар (тодорхой төхөөрөмж).
func (s *SignService) DeviceLinkByDocument(ctx context.Context, documentNumber, digestB64 string, interactions []Interaction, o *SignOptions) (*DeviceLinkSession, error) {
	return s.startDeviceLink(ctx, routeSignDeviceLinkDocument.expand(documentNumber), digestB64, interactions, o)
}

// ── Гэрчилгээ урьдчилж мэдэгдэх гарын үсэг (client-side PAdES / CMS) ──

// signerBody — Signer-ийн гэрчилгээнд зориулсан body: PAdES-ийн анхдагч (sha256WithRSAEncryption, SHA-256), digest-ийн
// урт hash-тай таарахыг session эхлүүлэхээс ӨМНӨ шалгана.
func (s *SignService) signerBody(signer *Signer, digestB64 string, interactions []Interaction, o *SignOptions) (*signRequest, *SignContext, error) {
	if signer == nil || strings.TrimSpace(signer.DocumentNumber) == "" {
		return nil, nil, errors.New("eid: Signer.DocumentNumber хоосон — ValidateCertificateChoice-ийн үр дүнг өг")
	}
	req, sc, err := s.body(digestB64, interactions, o, AlgSHA256WithRSA)
	if err != nil {
		return nil, nil, err
	}
	ch, err := cryptoHash(string(sc.HashAlgorithm))
	if err != nil {
		return nil, nil, err
	}
	if d, err := base64.StdEncoding.DecodeString(digestB64); err != nil || len(d) != ch.Size() {
		return nil, nil, fmt.Errorf("eid: digest нь стандарт base64, %s-ийн урт (%d байт) байх ёстой", sc.HashAlgorithm, ch.Size())
	}
	return req, sc, nil
}

// DigestForSigner — certificate-choice-оор сонгосон ЯГ ТЭР төхөөрөмж (Signer.DocumentNumber) рүү push sign. Олон
// утастай иргэнд etsi-ээр эхлүүлбэл өөр утас (өөр гэрчилгээ) зурж, гэрчилгээг урьдчилж оруулсан CMS (PAdES
// signingCertificateV2) хүчингүй болдог — тиймээс digest-ийг ҮРГЭЛЖ documentNumber-аар зуруулна.
//
// Signer.CertChoiceSessionID байвал /signature/notification/linked/{documentNumber} (linkedSessionID = cert choice),
// эс бөгөөс /signature/notification/document/{documentNumber}. Анхдагч SignatureAlgorithm = sha256WithRSAEncryption,
// HashAlgorithm = SHA-256 (digest = 32 байт DTBS). Хариуг шалгахдаа:
//
//	c.Validator.ValidateSign(r, s.Sign.Digest, s.Sign.HashAlgorithm, eid.ValidateSignOptions{
//		ExpectedAlgorithm: s.Sign.SignatureAlgorithm, ExpectedCertificate: signer.Certificate,
//		ExpectedFlowType: eid.FlowNotification})
func (s *SignService) DigestForSigner(ctx context.Context, signer *Signer, digestB64 string, interactions []Interaction, o *SignOptions) (*NotificationSession, error) {
	req, sc, err := s.signerBody(signer, digestB64, interactions, o)
	if err != nil {
		return nil, err
	}
	path := routeSignNotificationDocument.expand(signer.DocumentNumber)
	if id := strings.TrimSpace(signer.CertChoiceSessionID); id != "" {
		path = routeSignNotificationLinked.expand(signer.DocumentNumber)
		req.LinkedSessionID = id
	}
	return s.notification(ctx, path, req, sc)
}

// DeviceLinkForSigner — DigestForSigner-ийн QR / Web2App / App2App хувилбар: /signature/device-link/document/{documentNumber}.
func (s *SignService) DeviceLinkForSigner(ctx context.Context, signer *Signer, digestB64 string, interactions []Interaction, o *SignOptions) (*DeviceLinkSession, error) {
	req, sc, err := s.signerBody(signer, digestB64, interactions, o)
	if err != nil {
		return nil, err
	}
	return s.deviceLink(ctx, routeSignDeviceLinkDocument.expand(signer.DocumentNumber), req, sc)
}
