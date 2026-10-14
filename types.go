package eid

import "time"

// RP-API-ийн wire-contract төрлүүд. JSON талбарын нэр серверийн RP-API v3-тай ЯГ ИЖИЛ (camelCase).

// CertificateLevel — гэрчилгээний баталгаажуулалтын түвшин (eIDAS LoA). ADVANCED < QUALIFIED < QSCD.
type CertificateLevel string

const (
	LevelAdvanced  CertificateLevel = "ADVANCED"
	LevelQualified CertificateLevel = "QUALIFIED"
	LevelQSCD      CertificateLevel = "QSCD"
)

// SignatureAlgorithm — гарын үсгийн алгоритм. rsassa-pss анхдагч; ecdsa-with-SHA256 — хуучин threshold-ECDSA cert.
type SignatureAlgorithm string

const (
	AlgRSASSAPSS       SignatureAlgorithm = "rsassa-pss"
	AlgSHA256WithRSA   SignatureAlgorithm = "sha256WithRSAEncryption"
	AlgSHA384WithRSA   SignatureAlgorithm = "sha384WithRSAEncryption"
	AlgSHA512WithRSA   SignatureAlgorithm = "sha512WithRSAEncryption"
	AlgECDSAWithSHA256 SignatureAlgorithm = "ecdsa-with-SHA256"
)

// HashAlgorithm — hash алгоритм (Smart-ID v3 нэршил).
type HashAlgorithm string

const (
	SHA256 HashAlgorithm = "SHA-256"
	SHA384 HashAlgorithm = "SHA-384"
	SHA512 HashAlgorithm = "SHA-512"
)

// FlowType — урсгалын төрөл (хариуны signature.flowType); RP өөрийн санал болгосонтой тулгана.
type FlowType string

const (
	FlowQR           FlowType = "QR"
	FlowApp2App      FlowType = "App2App"
	FlowWeb2App      FlowType = "Web2App"
	FlowNotification FlowType = "Notification"
)

// Session-ийн төлөв ба эцсийн үр дүнгийн түгээмэл утгууд (SessionResult.State / EndResult).
const (
	StateRunning  = "RUNNING"
	StateComplete = "COMPLETE"

	EndResultOK                             = "OK"
	EndResultUserRefused                    = "USER_REFUSED"
	EndResultUserRefusedDisplayTextAndPIN   = "USER_REFUSED_DISPLAYTEXTANDPIN"
	EndResultUserRefusedVCChoice            = "USER_REFUSED_VC_CHOICE"
	EndResultUserRefusedConfirmationMessage = "USER_REFUSED_CONFIRMATIONMESSAGE"
	EndResultUserRefusedCertChoice          = "USER_REFUSED_CERT_CHOICE"
	EndResultTimeout                        = "TIMEOUT"
	EndResultDocumentUnusable               = "DOCUMENT_UNUSABLE"
	EndResultWrongVC                        = "WRONG_VC"
	EndResultProtocolFailure                = "PROTOCOL_FAILURE"
)

// Interaction — иргэний утсан дээр харагдах харилцан үйлдэл. displayTextAndPIN нь PIN асууж текст харуулна
// (хамгийн түгээмэл). DisplayText60 — 60 тэмдэгт хүртэл; DisplayText200 — 200 хүртэл.
type Interaction struct {
	// Type — "displayTextAndPIN" | "confirmationMessage" | "confirmationMessageAndVerificationCodeChoice".
	Type           string `json:"type"`
	DisplayText60  string `json:"displayText60,omitempty"`
	DisplayText200 string `json:"displayText200,omitempty"`
}

// ACSPContext — auth session-ийн ACSP_V2 контекст: RP хүсэлтэд илгээсэн утгууд. Validator үүн + хариугаар
// payload-ийг дахин угсарна. Session эхлүүлэхэд SDK бөглөнө; RP үүнийг session-тэй хамт серверт хадгална
// (JSON-оор хадгалж болно).
type ACSPContext struct {
	RPChallenge      string `json:"rpChallenge"`
	RelyingPartyName string `json:"relyingPartyName"`
	BrokeredRpName   string `json:"brokeredRpName"`
	// Interactions — илгээсэн base64 МӨР (дахин serialize хийхгүй).
	Interactions       string `json:"interactions"`
	InitialCallbackURL string `json:"initialCallbackUrl"`
	// FlowTypes — RP-ийн санал болгосон урсгалууд; хариуны flowType эдгээрийн нэг байх ёстой.
	FlowTypes          []FlowType         `json:"flowTypes"`
	SignatureAlgorithm SignatureAlgorithm `json:"signatureAlgorithm"`
	HashAlgorithm      HashAlgorithm      `json:"hashAlgorithm"`
}

// NotificationSession — push (notification) session эхлүүлсний хариу.
//
// VC — иргэний дэлгэцэд ХАРУУЛАХ 5 оронтой баталгаажуулах код: утсан дээрх кодтой ижил эсэхийг НҮДЭЭР тулгах
// зориулалттай. VC нь ПИН БИШ — хэрэглэгчээр оруулуулахгүй, зөвхөн харуулна.
type NotificationSession struct {
	SessionID string `json:"sessionId"`
	VC        string `json:"vc"`
	// RPChallenge — RP-ийн илгээсэн санамсаргүй challenge (base64). Sign session-д "".
	RPChallenge string `json:"rpChallenge"`
	// ACSP — auth session-д validator-т өгөх контекст; sign session-д nil.
	ACSP *ACSPContext `json:"acsp,omitempty"`
}

// DeviceLinkSession — device-link (QR/Web2App/App2App) session. SessionToken, SessionSecret-ийг ЗӨВХӨН
// backend-д хадгална — браузер/апп руу бүү гарга.
type DeviceLinkSession struct {
	SessionID     string `json:"sessionId"`
	SessionToken  string `json:"sessionToken"`
	SessionSecret string `json:"sessionSecret"`
	// DeviceLinkBase — холбоосын суурь URL (ж: https://ca.eidmongolia.mn/dl). Холбоосыг BuildDeviceLink-ээр угсарна.
	DeviceLinkBase string `json:"deviceLinkBase"`
	// VC — 5 оронтой баталгаажуулах код (ПИН БИШ), RP UI-д харуулна.
	VC          string       `json:"vc"`
	RPChallenge string       `json:"rpChallenge"`
	ACSP        *ACSPContext `json:"acsp,omitempty"`
	// ReceivedAt — RP backend хариуг хүлээн авсан мөч (QR-ийн elapsedSeconds-ийн эх).
	ReceivedAt time.Time `json:"receivedAt"`
}

// SignatureAlgorithmParameters — rsassa-pss хариуны параметр (signature.signatureAlgorithmParameters).
type SignatureAlgorithmParameters struct {
	HashAlgorithm    string            `json:"hashAlgorithm"`
	MaskGenAlgorithm *MaskGenAlgorithm `json:"maskGenAlgorithm,omitempty"`
	// SaltLength — nil = хариунд алга.
	SaltLength   *int   `json:"saltLength,omitempty"`
	TrailerField string `json:"trailerField,omitempty"`
}

// MaskGenAlgorithm — PSS MGF1 параметр.
type MaskGenAlgorithm struct {
	Algorithm  string `json:"algorithm"`
	Parameters *struct {
		HashAlgorithm string `json:"hashAlgorithm"`
	} `json:"parameters,omitempty"`
}

// SessionResult — session poll-ийн нэгтгэсэн үр дүн (validator-т орох түүхий материал). Хариунд байхгүй мөр
// талбар "" байна.
type SessionResult struct {
	State          string
	EndResult      string
	DocumentNumber string
	// CertificateDERB64 — иргэний X.509 гэрчилгээ (DER, base64).
	CertificateDERB64 string
	CertificateLevel  string
	// SignatureValueB64 — гарын үсэг (base64).
	SignatureValueB64  string
	SignatureAlgorithm string
	SignatureProtocol  string
	// ACSP_V2 (auth): серверийн санамсаргүй утга (base64), утасны challenge (base64url), урсгал.
	ServerRandom  string
	UserChallenge string
	FlowType      string
	// InitialCallbackURL — ACSP_V2 payload-д зурагдсан initialCallbackUrl (signature.initialCallbackUrl).
	// QR/Notification → "", Web2App/App2App → RP-ийн callback. nil = хариунд талбар алга (хуучин CA).
	InitialCallbackURL           *string
	SignatureAlgorithmParameters *SignatureAlgorithmParameters
	InteractionTypeUsed          string
	// OnBehalfOf — байгууллагын нэрийн өмнөөс байсан бол СЕРВЕР төлөөллийг шалгасны баталгаа; nil = хувь хүн.
	// RP энэ талбарт л итгэнэ (клиентийн сонголтод биш).
	OnBehalfOf *OrgResult
	// PDF — PAdES (/pdf/sign/prepare) session-ий pdf блок; PDF урсгал биш бол nil.
	PDF *PDFSessionBlock
}

// OrgResult — session-ий байгууллагын блок (бүртгэлээс real-time). Эрх хураагдсан бол Role/RightType "".
type OrgResult struct {
	OrgEtsi   string `json:"orgEtsi"`
	OrgName   string `json:"orgName"`
	Role      string `json:"role"`
	RightType string `json:"rightType"`
}

// PDF баримтын төлөв.
const (
	PDFPending = "PENDING"
	PDFReady   = "READY"
	PDFFailed  = "FAILED"
	PDFExpired = "EXPIRED"
)

// PDFSessionBlock — GET /session/{id}-ийн pdf объект (PAdES, CA угсарна).
type PDFSessionBlock struct {
	DocID          string `json:"docID"`
	DocumentStatus string `json:"documentStatus"`
	// ErrorCode — FAILED үед (ж: REPRESENTATION_REVOKED).
	ErrorCode string `json:"errorCode,omitempty"`
	// OutSHA256 — гарын үсэгтэй PDF-ийн SHA-256 (hex) — татсан файлтай тулгана.
	OutSHA256      string         `json:"outSha256,omitempty"`
	Size           int64          `json:"size,omitempty"`
	ExpiresAt      string         `json:"expiresAt,omitempty"`
	SignatureLevel string         `json:"signatureLevel,omitempty"`
	Signer         *PDFSigner     `json:"signer,omitempty"`
	Validation     *PDFValidation `json:"validation,omitempty"`
}

// PDFSigner — PAdES гаралтын гарын үсэг зурагч.
type PDFSigner struct {
	Etsi       string `json:"etsi"`
	CertSerial string `json:"certSerial"`
	// OnBehalfOf — байгууллагын ETSI (NTRMN-…), баримтад бичигдсэн утга.
	OnBehalfOf string `json:"onBehalfOf,omitempty"`
	// ClaimedRole — CMS signer-attributes-v2: «<албан тушаал>, <нэр> (NTRMN-…)».
	ClaimedRole string `json:"claimedRole,omitempty"`
}

// PDFValidation — CA-ийн гаралтын шалгалтын дүн.
type PDFValidation struct {
	Indication string `json:"indication"`
	LTV        bool   `json:"ltv"`
	Signatures int    `json:"signatures"`
}

// Representation — иргэний төлөөлж чадах нэг байгууллага.
type Representation struct {
	// OrgEtsi — NTRMN-<бүртгэл>, OnBehalfOf-д өгөх утга.
	OrgEtsi     string `json:"orgEtsi"`
	OrgRegister string `json:"orgRegister"`
	OrgName     string `json:"orgName"`
	OrgNameEn   string `json:"orgNameEn,omitempty"`
	Role        string `json:"role,omitempty"`
	// RightType — ADMIN | MANAGER.
	RightType string `json:"rightType"`
	// Source — REGISTRY | MANUAL.
	Source string `json:"source"`
	// ValidFrom, ValidTo — ISO 8601; ValidTo "" = хугацаагүй.
	ValidFrom string `json:"validFrom"`
	ValidTo   string `json:"validTo,omitempty"`
}

// RepresentationsResponse — GET /organization/representations/etsi/{personEtsi} хариу.
type RepresentationsResponse struct {
	PersonEtsi      string           `json:"personEtsi"`
	Representations []Representation `json:"representations"`
}

// Credentials — RP-ийн таних тэмдэг + API secret.
type Credentials struct {
	// RPUUID — бүртгэлтэй RP UUID (relyingPartyUUID).
	RPUUID string
	// RPName — дэд системийн нэр (ж: «Интернэт банк»), ≤ 120 тэмдэгт (сервер илүүг таслана).
	RPName string
	// APISecret — rp_sk_…; зөвхөн backend-д.
	APISecret string
}
