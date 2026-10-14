package eid

import (
	"context"
	"strings"
)

// SignOptions — гарын үсгийн session-ий нэмэлт тохиргоо. nil = анхдагч.
type SignOptions struct {
	CertificateLevel CertificateLevel
	// CallbackURL — ижил төхөөрөмжийн буцах https URL (initialCallbackUrl).
	CallbackURL string
	// HashAlgorithm — digest-ийн hash ("" = SHA-256). Digest-ийн урт = hLen.
	HashAlgorithm HashAlgorithm
	// SignatureAlgorithm — "" = rsassa-pss (PKCS#1 v1.5 нь deprecated).
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
}

func (s *SignService) start(ctx context.Context, path, digestB64 string, interactions []Interaction, o *SignOptions) (*NotificationSession, error) {
	if o == nil {
		o = &SignOptions{}
	}
	ib64, err := InteractionsToBase64(interactions)
	if err != nil {
		return nil, err
	}
	req := signRequest{
		RelyingPartyUUID:  s.creds.RPUUID,
		RelyingPartyName:  s.creds.RPName,
		CertificateLevel:  orDefault(o.CertificateLevel, s.level),
		SignatureProtocol: "RAW_DIGEST_SIGNATURE",
		SignatureProtocolParameters: signProtocolParams{
			Digest:                       digestB64,
			SignatureAlgorithm:           orDefault(o.SignatureAlgorithm, AlgRSASSAPSS),
			SignatureAlgorithmParameters: hashParam{HashAlgorithm: orDefault(o.HashAlgorithm, SHA256)},
		},
		Interactions:       ib64,
		InitialCallbackURL: strings.TrimSpace(o.CallbackURL),
		OnBehalfOf:         strings.TrimSpace(o.OnBehalfOf),
		FileName:           strings.TrimSpace(o.FileName),
	}
	var r sessionStartResponse
	if err := s.h.postJSON(ctx, path, req, &r); err != nil {
		return nil, err
	}
	// Sign урсгалд rpChallenge байхгүй — гарын үсэг digest-ийн эсрэг баталгаажна.
	return &NotificationSession{SessionID: r.SessionID, VC: string(r.VC)}, nil
}

// DigestByEtsi — бэлэн digest (стандарт base64)-ээр push sign: РД / civil_id / ETSI. Баримт (PDF/файл)-ын
// байтын SHA-256-ийг гаднаас бэлдэж өгнө (SHA256Base64).
func (s *SignService) DigestByEtsi(ctx context.Context, id, digestB64 string, interactions []Interaction, o *SignOptions) (*NotificationSession, error) {
	return s.start(ctx, routeSignNotificationEtsi.expand(id), digestB64, interactions, o)
}

// DigestByDocument — бэлэн digest-ээр push sign, баримтын дугаараар (auth-аас гарсан DocumentNumber).
func (s *SignService) DigestByDocument(ctx context.Context, documentNumber, digestB64 string, interactions []Interaction, o *SignOptions) (*NotificationSession, error) {
	return s.start(ctx, routeSignNotificationDocument.expand(documentNumber), digestB64, interactions, o)
}

// TextByEtsi — текстийн SHA-256 digest-ийг дотроо тооцоод push sign (богино текст баримтад).
func (s *SignService) TextByEtsi(ctx context.Context, id, text string, interactions []Interaction, o *SignOptions) (*NotificationSession, error) {
	return s.DigestByEtsi(ctx, id, SHA256Base64([]byte(text)), interactions, o)
}
