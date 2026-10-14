package eid

import (
	"context"
	"strings"
	"time"
)

// AuthOptions — нэвтрэлтийн session-ий нэмэлт тохиргоо. nil = анхдагч.
type AuthOptions struct {
	// CertificateLevel — энэ session-д certLevel ("" = Client-ийн анхдагч).
	CertificateLevel CertificateLevel
	// CallbackURL — ижил төхөөрөмжийн (Web2App/App2App) буцах https URL. Өгвөл initialCallbackUrl-аар илгээж,
	// санал болгох урсгалд App2App, Web2App нэмэгдэнэ. Host нь RP-ийн callbackHosts-д байх ёстой.
	CallbackURL string
	// OnBehalfOf — байгууллагаар нэвтрэх: байгууллагын ETSI (NTRMN-<бүртгэл>). Сервер төлөөллийн эрхийг шалгаж
	// (эрхгүй бол 403 ForbiddenError.Code), дууссан session-д SessionResult.OnBehalfOf буцаана. Байгууллага нь
	// ACSP_V2 гарын үсэгт ОРОХГҮЙ — RP үүнийг SessionResult-аас л уншина.
	OnBehalfOf string
	// SignatureAlgorithm — "" = rsassa-pss.
	SignatureAlgorithm SignatureAlgorithm
	// HashAlgorithm — ACSP_V2 payload-ийн hash, "" = SHA-512 (Smart-ID v3 жишээтэй ижил).
	HashAlgorithm HashAlgorithm
}

// AuthService — иргэнийг нэвтрүүлэх (PIN1). Бүгд rpChallenge үүсгэж, хариуны ACSP_V2 гарын үсгийг
// Validator.ValidateAuth-аар шалгана.
type AuthService struct {
	h     *httpDoer
	creds Credentials
	level CertificateLevel
}

type authProtocolParams struct {
	RPChallenge                  string             `json:"rpChallenge"`
	SignatureAlgorithm           SignatureAlgorithm `json:"signatureAlgorithm"`
	SignatureAlgorithmParameters hashParam          `json:"signatureAlgorithmParameters"`
}

type hashParam struct {
	HashAlgorithm HashAlgorithm `json:"hashAlgorithm"`
}

type authRequest struct {
	RelyingPartyUUID            string             `json:"relyingPartyUUID"`
	RelyingPartyName            string             `json:"relyingPartyName"`
	CertificateLevel            CertificateLevel   `json:"certificateLevel"`
	SignatureProtocol           string             `json:"signatureProtocol"`
	SignatureProtocolParameters authProtocolParams `json:"signatureProtocolParameters"`
	Interactions                string             `json:"interactions"`
	InitialCallbackURL          string             `json:"initialCallbackUrl,omitempty"`
	OnBehalfOf                  string             `json:"onBehalfOf,omitempty"`
}

type sessionStartResponse struct {
	SessionID      string  `json:"sessionID"`
	SessionToken   string  `json:"sessionToken"`
	SessionSecret  string  `json:"sessionSecret"`
	DeviceLinkBase string  `json:"deviceLinkBase"`
	VC             vcValue `json:"vc"`
}

// body — v3 nested body + validator-т хэрэгтэй контекст (ижил утгуудаас — байт зөрөхгүй).
func (a *AuthService) body(interactions []Interaction, flows []FlowType, o *AuthOptions) (*authRequest, *ACSPContext, error) {
	if o == nil {
		o = &AuthOptions{}
	}
	challenge, err := RandomChallenge(64)
	if err != nil {
		return nil, nil, err
	}
	ib64, err := InteractionsToBase64(interactions)
	if err != nil {
		return nil, nil, err
	}
	callback := strings.TrimSpace(o.CallbackURL)
	if callback != "" {
		flows = append(flows, FlowApp2App, FlowWeb2App)
	}
	acsp := &ACSPContext{
		RPChallenge:        challenge,
		RelyingPartyName:   a.creds.RPName,
		BrokeredRpName:     "",
		Interactions:       ib64,
		InitialCallbackURL: callback,
		FlowTypes:          flows,
		SignatureAlgorithm: orDefault(o.SignatureAlgorithm, AlgRSASSAPSS),
		HashAlgorithm:      orDefault(o.HashAlgorithm, SHA512),
	}
	return &authRequest{
		RelyingPartyUUID:  a.creds.RPUUID,
		RelyingPartyName:  acsp.RelyingPartyName,
		CertificateLevel:  orDefault(o.CertificateLevel, a.level),
		SignatureProtocol: "ACSP_V2",
		SignatureProtocolParameters: authProtocolParams{
			RPChallenge:                  challenge,
			SignatureAlgorithm:           acsp.SignatureAlgorithm,
			SignatureAlgorithmParameters: hashParam{HashAlgorithm: acsp.HashAlgorithm},
		},
		Interactions:       ib64,
		InitialCallbackURL: callback,
		OnBehalfOf:         strings.TrimSpace(o.OnBehalfOf),
	}, acsp, nil
}

func (a *AuthService) notification(ctx context.Context, path string, interactions []Interaction, o *AuthOptions) (*NotificationSession, error) {
	req, acsp, err := a.body(interactions, []FlowType{FlowNotification}, o)
	if err != nil {
		return nil, err
	}
	var r sessionStartResponse
	if err := a.h.postJSON(ctx, path, req, &r); err != nil {
		return nil, err
	}
	return &NotificationSession{SessionID: r.SessionID, VC: string(r.VC), RPChallenge: acsp.RPChallenge, ACSP: acsp}, nil
}

func (a *AuthService) deviceLink(ctx context.Context, path string, interactions []Interaction, o *AuthOptions) (*DeviceLinkSession, error) {
	req, acsp, err := a.body(interactions, []FlowType{FlowQR}, o)
	if err != nil {
		return nil, err
	}
	var r sessionStartResponse
	if err := a.h.postJSON(ctx, path, req, &r); err != nil {
		return nil, err
	}
	return &DeviceLinkSession{
		SessionID:      r.SessionID,
		SessionToken:   r.SessionToken,
		SessionSecret:  r.SessionSecret,
		DeviceLinkBase: r.DeviceLinkBase,
		VC:             string(r.VC),
		RPChallenge:    acsp.RPChallenge,
		ACSP:           acsp,
		ReceivedAt:     time.Now(),
		SessionType:    SessionAuth,
	}, nil
}

// NotificationByEtsi — push: РД / иргэний дугаар / ETSI (PNOMN-…)-ээр (сервер төрлийг танина). Иргэний утас руу
// мэдэгдэл очно. Validator.ValidateAuth-д ExpectedFlowType = FlowNotification.
func (a *AuthService) NotificationByEtsi(ctx context.Context, id string, interactions []Interaction, o *AuthOptions) (*NotificationSession, error) {
	return a.notification(ctx, routeAuthNotificationEtsi.expand(id), interactions, o)
}

// NotificationByDocument — push: баримтын дугаараар (тодорхой төхөөрөмж рүү).
func (a *AuthService) NotificationByDocument(ctx context.Context, documentNumber string, interactions []Interaction, o *AuthOptions) (*NotificationSession, error) {
	return a.notification(ctx, routeAuthNotificationDocument.expand(documentNumber), interactions, o)
}

// DeviceLinkAnonymous — QR / Web2App / App2App: иргэн хэн болохыг урьдчилж мэдэхгүй. Холбоосыг BuildDeviceLink-ээр.
func (a *AuthService) DeviceLinkAnonymous(ctx context.Context, interactions []Interaction, o *AuthOptions) (*DeviceLinkSession, error) {
	return a.deviceLink(ctx, routeAuthDeviceLinkAnonymous.expand(), interactions, o)
}

// DeviceLinkByEtsi — QR / Web2App / App2App: тодорхой иргэн (РД / civil_id / ETSI).
func (a *AuthService) DeviceLinkByEtsi(ctx context.Context, id string, interactions []Interaction, o *AuthOptions) (*DeviceLinkSession, error) {
	return a.deviceLink(ctx, routeAuthDeviceLinkEtsi.expand(id), interactions, o)
}

func orDefault[T ~string](v, def T) T {
	if v == "" {
		return def
	}
	return v
}
