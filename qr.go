package eid

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// «Миний QR» (биечлэн шалгах): иргэн апп дээрээ нэг удаагийн QR (120 с) харуулна → RP скан хийж QR.Start-аар
// хүссэн аттрибутаа CA-аас асууна → иргэн утсан дээрээ PIN1-ээр зөвшөөрнө → QR.Result нь CA-ийн ES256 гарын үсэгтэй
// presentation (JWS)-ийг JWKS-ээр шалгаж, ЗӨВХӨН хүссэн аттрибутуудыг буцаана. Гэрчилгээ, person блок ирэхгүй.
// RP-д AUTH + QR_PRESENT + аттрибут бүрд QR_ATTR:<нэр> эрх хэрэгтэй.

// QR аттрибутын каталог (CA гэрээ v1, 2026-10-23).
const (
	QRAttrAgeOver18 = "age_over_18" // bool — 18 нас хүрсэн эсэх (төрсөн огноог задлахгүй)
	QRAttrAgeOver21 = "age_over_21" // bool — 21 нас хүрсэн эсэх
	QRAttrFullName  = "full_name"   // {surname, givenName} — кирилл
	QRAttrPhone     = "phone"       // E.164 мөр
	QRAttrBirthDate = "birth_date"  // YYYY-MM-DD (мэдрэмтгий)
	QRAttrCivilID   = "civil_id"    // иргэний дугаар (мэдрэмтгий)
)

// QRAttributes — каталогийн бүх аттрибут (дараалал = баримтын дараалал).
var QRAttributes = []string{QRAttrAgeOver18, QRAttrAgeOver21, QRAttrFullName, QRAttrPhone, QRAttrBirthDate, QRAttrCivilID}

const (
	// QRPrefix — иргэний аппын QR-ийн агуулгын угтвар: "EIDMN-QR1:<token>".
	QRPrefix = "EIDMN-QR1:"
	// DefaultQRIssuer — presentation JWS-ийн iss.
	DefaultQRIssuer = "https://ca.eidmongolia.mn"
	// DefaultQRJWKSURL — CA-ийн presentation гарын үсгийн нийтийн түлхүүрүүд (JWKS).
	DefaultQRJWKSURL = "https://ca.eidmongolia.mn/.well-known/eid-jwks.json"
	// DefaultQRJWKSCacheTTL — JWKS-ийг кэшлэх хугацаа; танихгүй kid ирвэл (≥ 30 с-ийн зайтай) шууд дахин татна.
	DefaultQRJWKSCacheTTL = time.Hour
	// DefaultQRMaxAge — presentation-ийн iat-аас хойш хүлээн авах дээд хугацаа.
	DefaultQRMaxAge = 10 * time.Minute
	// QRClockSkew — iat ирээдүйд байж болох зөрүү.
	QRClockSkew = 60 * time.Second

	qrJWKSMinRefresh = 30 * time.Second
	qrMaxJWS         = 16 << 10
	qrMaxJWKS        = 64 << 10
)

// QR алдааны кодууд — *QRError.Code (APIError.Code-д QR_TOKEN_INVALID ирнэ). TS / .NET SDK-д ижил.
const (
	// CodeQRFormatInvalid — сканнердсан мөр "EIDMN-QR1:<43 тэмдэгт base64url>" (эсвэл зөвхөн токен) биш. Клиент талын.
	CodeQRFormatInvalid = "QR_FORMAT_INVALID"
	// CodeQRTokenInvalid — 404: токен танигдахгүй / хугацаа дууссан (120 с) / ашиглагдсан → иргэнээс шинэ QR гаргуул.
	CodeQRTokenInvalid = "QR_TOKEN_INVALID"
	// CodeQRAttributesInvalid — аттрибутын жагсаалт хоосон, каталогид алга, эсвэл давхардсан. Клиент талын.
	CodeQRAttributesInvalid = "QR_ATTRIBUTES_INVALID"
	// CodeQRPresentationInvalid — presentation (JWS) шалгалтад унасан: гарын үсэг, iss/aud/sid/nonce, хугацаа, аттрибут.
	// Хариунд ИТГЭХГҮЙ.
	CodeQRPresentationInvalid = "QR_PRESENTATION_INVALID"
	// CodeQRJWKSUnavailable — CA-ийн JWKS татагдсангүй / буруу. Түр алдаа — дахин оролдож болно (session-ий үр дүн
	// CA дээр хугацаа дуустал хадгалагдана).
	CodeQRJWKSUnavailable = "QR_JWKS_UNAVAILABLE"
)

// errors.Is-ийн sentinel-ууд: *QRError (ба QR_TOKEN_INVALID-д *APIError) Code-оор тулгана.
var (
	ErrQRFormatInvalid       = errors.New("eid: " + CodeQRFormatInvalid)
	ErrQRTokenInvalid        = errors.New("eid: " + CodeQRTokenInvalid)
	ErrQRAttributesInvalid   = errors.New("eid: " + CodeQRAttributesInvalid)
	ErrQRPresentationInvalid = errors.New("eid: " + CodeQRPresentationInvalid)
	ErrQRJWKSUnavailable     = errors.New("eid: " + CodeQRJWKSUnavailable)
)

var qrSentinels = map[string]error{
	CodeQRFormatInvalid:       ErrQRFormatInvalid,
	CodeQRTokenInvalid:        ErrQRTokenInvalid,
	CodeQRAttributesInvalid:   ErrQRAttributesInvalid,
	CodeQRPresentationInvalid: ErrQRPresentationInvalid,
	CodeQRJWKSUnavailable:     ErrQRJWKSUnavailable,
}

// QRError — «Миний QR»-ийн клиент талын алдаа (Code — дээрх CodeQR*). CA-ийн 404 QR_TOKEN_INVALID нь *APIError
// хэвээр ирнэ — хоёуланг нь errors.Is(err, ErrQRTokenInvalid)-ээр барина.
type QRError struct {
	Code   string
	Reason string
	Cause  error
}

func (e *QRError) Error() string { return "eid: " + e.Code + ": " + e.Reason }

func (e *QRError) Unwrap() error { return e.Cause }

func (e *QRError) Is(target error) bool { return qrSentinels[e.Code] == target }

func qrErr(code, format string, a ...any) *QRError {
	return &QRError{Code: code, Reason: fmt.Sprintf(format, a...)}
}

var qrTokenRe = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// ParseQR — сканнердсан QR-ийн агуулгаас токеныг гаргана: "EIDMN-QR1:<token>" эсвэл зөвхөн токен (43 тэмдэгт
// base64url). Хоосон зай хасагдана. Буруу бол *QRError{CodeQRFormatInvalid}.
func ParseQR(scanned string) (string, error) {
	s := strings.TrimPrefix(strings.TrimSpace(scanned), QRPrefix)
	if !qrTokenRe.MatchString(s) {
		return "", qrErr(CodeQRFormatInvalid, "eID «Миний QR» биш")
	}
	return s, nil
}

func checkQRAttributes(attrs []string) error {
	if len(attrs) == 0 {
		return qrErr(CodeQRAttributesInvalid, "аттрибут сонгоогүй")
	}
	seen := make(map[string]bool, len(attrs))
	for _, a := range attrs {
		if !isQRAttribute(a) {
			return qrErr(CodeQRAttributesInvalid, "каталогид алга: %q", a)
		}
		if seen[a] {
			return qrErr(CodeQRAttributesInvalid, "давхардсан: %s", a)
		}
		seen[a] = true
	}
	return nil
}

func isQRAttribute(a string) bool {
	for _, c := range QRAttributes {
		if a == c {
			return true
		}
	}
	return false
}

// QRConfig — Config.QR: presentation шалгалтын тохиргоо. Тэг утга = анхдагч (prod CA).
type QRConfig struct {
	// JWKSURL — "" = DefaultQRJWKSURL. https (http зөвхөн loopback).
	JWKSURL string
	// Issuer — хүлээгдэх iss; "" = DefaultQRIssuer.
	Issuer string
	// JWKSCacheTTL — 0 = DefaultQRJWKSCacheTTL.
	JWKSCacheTTL time.Duration
	// MaxAge — iat-аас хойшхи дээд хугацаа; 0 = DefaultQRMaxAge.
	MaxAge time.Duration
}

// QRStartRequest — QR.Start-ийн оролт.
type QRStartRequest struct {
	// QR — сканнердсан агуулга ("EIDMN-QR1:<token>") эсвэл ParseQR-ийн токен.
	QR string
	// Attributes — хүсэх аттрибутууд (QRAttributes-ийн дэд олонлог, давхардалгүй, ≥ 1). RP-д QR_ATTR:<нэр> эрх бүгдэд нь.
	Attributes []string
	// Nonce — RP-ийн өөрийн nonce (сонголттой); JWS-ийн nonce-д буцаж ирнэ. "" бол rpChallenge.
	Nonce string
}

// QRSession — QR.Start-ийн хариу. VC-г кассын дэлгэцэнд харуулна (иргэний утсанд ижил код). Энэ бүтцийг (JSON-оор
// сериалчилж болно) QR.Result-д дамжуулна — nonce ба хүссэн аттрибутыг шалгалтад хэрэглэнэ.
type QRSession struct {
	SessionID  string    `json:"sessionID"`
	VC         string    `json:"vc"`
	Nonce      string    `json:"nonce"`
	Attributes []string  `json:"attributes"`
	ExpiresAt  time.Time `json:"expiresAt,omitzero"`
}

// QRFullName — full_name аттрибут (кирилл).
type QRFullName struct {
	Surname   string `json:"surname"`
	GivenName string `json:"givenName"`
}

// QRAttrs — баталгаажсан аттрибутууд; хүсээгүй эсвэл байхгүй (unavailable) нь nil.
type QRAttrs struct {
	AgeOver18 *bool       `json:"age_over_18,omitempty"`
	AgeOver21 *bool       `json:"age_over_21,omitempty"`
	FullName  *QRFullName `json:"full_name,omitempty"`
	Phone     *string     `json:"phone,omitempty"`
	BirthDate *string     `json:"birth_date,omitempty"`
	CivilID   *string     `json:"civil_id,omitempty"`
}

// QRPresentation — шалгагдсан presentation.
type QRPresentation struct {
	// Subject — sub: энэ RP-д зориулсан тогтмол pairwise id (иргэний дугаар биш); ижил иргэн → ижил утга.
	Subject string
	// Attrs — хүссэн, байгаа аттрибутууд.
	Attrs QRAttrs
	// Unavailable — хүссэн боловч иргэний бүртгэлд байхгүй аттрибутууд (алдаа биш).
	Unavailable []string
	SessionID   string
	IssuedAt    time.Time
	// JWS — түүхий compact JWS (аудит / дахин шалгахад хадгалж болно).
	JWS string
}

// QRExpect — VerifyQRPresentation-ийн хүлээлт.
type QRExpect struct {
	Issuer     string   // "" = DefaultQRIssuer
	Audience   string   // RP UUID
	SessionID  string   // QRSession.SessionID
	Nonce      string   // QRSession.Nonce
	Attributes []string // QRSession.Attributes
	Now        time.Time
	MaxAge     time.Duration // 0 = DefaultQRMaxAge
}

// JWK — EC (P-256) нийтийн түлхүүр.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
}

// JWKS — {"keys":[…]}.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// ParseJWKS — JWKS JSON-ийг задална (түлхүүрүүдийг kid-ээр хайхад VerifyQRPresentation шалгана).
func ParseJWKS(raw []byte) (*JWKS, error) {
	var k JWKS
	if err := json.Unmarshal(raw, &k); err != nil {
		return nil, &QRError{Code: CodeQRJWKSUnavailable, Reason: "JWKS JSON биш", Cause: err}
	}
	return &k, nil
}

// key — kid-тэй ES256 түлхүүр; олдохгүй / тохирохгүй бол nil.
func (k *JWKS) key(kid string) (*ecdsa.PublicKey, error) {
	if k == nil {
		return nil, nil
	}
	for _, j := range k.Keys {
		if j.Kid != kid {
			continue
		}
		if j.Kty != "EC" || j.Crv != "P-256" || (j.Alg != "" && j.Alg != "ES256") || (j.Use != "" && j.Use != "sig") {
			return nil, qrErr(CodeQRPresentationInvalid, "kid %q нь ES256 P-256 түлхүүр биш", kid)
		}
		x, errX := base64.RawURLEncoding.DecodeString(j.X)
		y, errY := base64.RawURLEncoding.DecodeString(j.Y)
		if errX != nil || errY != nil || len(x) != 32 || len(y) != 32 {
			return nil, qrErr(CodeQRPresentationInvalid, "kid %q: x/y буруу", kid)
		}
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
		if err != nil {
			return nil, qrErr(CodeQRPresentationInvalid, "kid %q: цэг муруй дээр алга", kid)
		}
		return pub, nil
	}
	return nil, nil
}

// errQRUnknownKid — JWKS-д kid алга (QRService дахин татна).
var errQRUnknownKid = errors.New("unknown kid")

// VerifyQRPresentation — compact JWS-ийг jwks-ээр шалгаж (ES256, kid), claim-уудыг exp-тэй тулгана: iss, aud (RP UUID),
// sid, nonce, iat (≤ now+QRClockSkew, ≥ now−MaxAge), exp (байвал), attrs ∪ unavailable = хүссэн аттрибутууд яг,
// аттрибут бүрийн төрөл. Алдаа бол *QRError{CodeQRPresentationInvalid} — хариунд ИТГЭХГҮЙ. Сүлжээгүй, цэвэр функц
// (хадгалсан presentation-ийг дахин шалгах, тестэд).
func VerifyQRPresentation(jws string, jwks *JWKS, exp QRExpect) (*QRPresentation, error) {
	p, err := verifyQR(jws, jwks, exp)
	if errors.Is(err, errQRUnknownKid) {
		return nil, qrErr(CodeQRPresentationInvalid, "JWKS-д kid алга")
	}
	return p, err
}

func verifyQR(jws string, jwks *JWKS, exp QRExpect) (*QRPresentation, error) {
	bad := func(format string, a ...any) error { return qrErr(CodeQRPresentationInvalid, format, a...) }
	if len(jws) == 0 || len(jws) > qrMaxJWS {
		return nil, bad("JWS хоосон эсвэл хэт урт")
	}
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return nil, bad("compact JWS биш")
	}
	hb, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	pb, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	sig, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, bad("base64url буруу")
	}
	var hdr map[string]any
	if json.Unmarshal(hb, &hdr) != nil {
		return nil, bad("header JSON биш")
	}
	if hdr["alg"] != "ES256" {
		return nil, bad("alg ES256 биш")
	}
	if _, ok := hdr["crit"]; ok {
		return nil, bad("crit дэмжихгүй")
	}
	kid, _ := hdr["kid"].(string)
	if kid == "" {
		return nil, bad("kid алга")
	}
	pub, err := jwks.key(kid)
	if err != nil {
		return nil, err
	}
	if pub == nil {
		return nil, errQRUnknownKid
	}
	if len(sig) != 64 {
		return nil, bad("ES256 гарын үсэг 64 байт биш")
	}
	h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(pub, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return nil, bad("гарын үсэг таарсангүй")
	}
	return checkQRClaims(pb, jws, exp)
}

func checkQRClaims(payload []byte, jws string, exp QRExpect) (*QRPresentation, error) {
	bad := func(format string, a ...any) error { return qrErr(CodeQRPresentationInvalid, format, a...) }
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var c map[string]any
	if dec.Decode(&c) != nil || c == nil {
		return nil, bad("payload JSON объект биш")
	}
	iss := orDefault(exp.Issuer, DefaultQRIssuer)
	if c["iss"] != iss {
		return nil, bad("iss таарсангүй")
	}
	if exp.Audience == "" || c["aud"] != exp.Audience {
		return nil, bad("aud (RP UUID) таарсангүй")
	}
	if exp.SessionID == "" || c["sid"] != exp.SessionID {
		return nil, bad("sid таарсангүй")
	}
	if exp.Nonce == "" || c["nonce"] != exp.Nonce {
		return nil, bad("nonce таарсангүй")
	}
	sub, _ := c["sub"].(string)
	if sub == "" {
		return nil, bad("sub алга")
	}
	now := exp.Now
	if now.IsZero() {
		now = time.Now()
	}
	maxAge := exp.MaxAge
	if maxAge <= 0 {
		maxAge = DefaultQRMaxAge
	}
	iat, ok := numericDate(c["iat"])
	if !ok {
		return nil, bad("iat алга")
	}
	if iat.After(now.Add(QRClockSkew)) {
		return nil, bad("iat ирээдүйд")
	}
	if now.Sub(iat) > maxAge {
		return nil, bad("presentation хуучирсан")
	}
	if v, present := c["exp"]; present {
		e, ok := numericDate(v)
		if !ok || !now.Before(e.Add(QRClockSkew)) {
			return nil, bad("exp дууссан")
		}
	}

	want := make(map[string]bool, len(exp.Attributes))
	for _, a := range exp.Attributes {
		want[a] = true
	}
	got := make(map[string]bool, len(want))
	attrs, ok := c["attrs"].(map[string]any)
	if !ok {
		if _, present := c["attrs"]; present {
			return nil, bad("attrs объект биш")
		}
		attrs = map[string]any{}
	}
	out := &QRPresentation{Subject: sub, SessionID: exp.SessionID, IssuedAt: iat, JWS: jws, Unavailable: []string{}}
	for name, v := range attrs {
		if !want[name] {
			return nil, bad("хүсээгүй аттрибут: %s", name)
		}
		if err := setQRAttr(&out.Attrs, name, v); err != nil {
			return nil, err
		}
		got[name] = true
	}
	if raw, present := c["unavailable"]; present {
		list, ok := raw.([]any)
		if !ok {
			return nil, bad("unavailable массив биш")
		}
		for _, x := range list {
			name, _ := x.(string)
			if !want[name] || got[name] {
				return nil, bad("unavailable буруу: %v", x)
			}
			got[name] = true
			out.Unavailable = append(out.Unavailable, name)
		}
	}
	if len(got) != len(want) {
		return nil, bad("хүссэн аттрибутын хариу дутуу")
	}
	return out, nil
}

var (
	qrPhoneRe = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)
	qrDateRe  = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
)

func setQRAttr(a *QRAttrs, name string, v any) error {
	bad := func() error { return qrErr(CodeQRPresentationInvalid, "%s-ийн төрөл буруу", name) }
	str := func() (*string, error) {
		s, ok := v.(string)
		if !ok || s == "" {
			return nil, bad()
		}
		return &s, nil
	}
	var err error
	switch name {
	case QRAttrAgeOver18, QRAttrAgeOver21:
		b, ok := v.(bool)
		if !ok {
			return bad()
		}
		if name == QRAttrAgeOver18 {
			a.AgeOver18 = &b
		} else {
			a.AgeOver21 = &b
		}
	case QRAttrFullName:
		o, ok := v.(map[string]any)
		if !ok {
			return bad()
		}
		sn, ok1 := o["surname"].(string)
		gn, ok2 := o["givenName"].(string)
		if !ok1 || !ok2 || gn == "" {
			return bad()
		}
		a.FullName = &QRFullName{Surname: sn, GivenName: gn}
	case QRAttrPhone:
		if a.Phone, err = str(); err == nil && !qrPhoneRe.MatchString(*a.Phone) {
			return bad()
		}
	case QRAttrBirthDate:
		if a.BirthDate, err = str(); err == nil {
			if _, perr := time.Parse("2006-01-02", *a.BirthDate); perr != nil || !qrDateRe.MatchString(*a.BirthDate) {
				return bad()
			}
		}
	case QRAttrCivilID:
		a.CivilID, err = str()
	default:
		return bad()
	}
	return err
}

// numericDate — JSON NumericDate (секунд, бутархай байж болно).
func numericDate(v any) (time.Time, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return time.Time{}, false
	}
	f, err := n.Float64()
	if err != nil || f <= 0 || f > 1e11 {
		return time.Time{}, false
	}
	return time.Unix(0, int64(f*1e9)), true
}

// QRService — «Миний QR»: Parse → Start → Result. Goroutine-safe (JWKS кэш дотроо).
type QRService struct {
	h     *httpDoer
	creds Credentials
	cfg   QRConfig

	mu          sync.Mutex
	jwks        *JWKS
	fetchedAt   time.Time
	lastAttempt time.Time
}

// Parse — ParseQR.
func (s *QRService) Parse(scanned string) (string, error) { return ParseQR(scanned) }

type qrStartBody struct {
	QR                          string         `json:"qr"`
	Attributes                  []string       `json:"attributes"`
	RelyingPartyUUID            string         `json:"relyingPartyUUID"`
	RelyingPartyName            string         `json:"relyingPartyName"`
	SignatureProtocol           string         `json:"signatureProtocol"`
	SignatureProtocolParameters qrStartProtoPP `json:"signatureProtocolParameters"`
	Nonce                       string         `json:"nonce,omitempty"`
}

type qrStartProtoPP struct {
	RPChallenge string `json:"rpChallenge"`
}

// Start — POST /authentication/qr: QR-ийн токеныг (нэг удаа хэрэглэгдэнэ) CA-д өгч, иргэний утас руу хүсэлт илгээнэ.
// Хариуны VC-г кассын дэлгэцэнд харуул. Алдаа: *QRError (FORMAT / ATTRIBUTES — CA руу илгээхгүй), 404 *APIError
// QR_TOKEN_INVALID (errors.Is(err, ErrQRTokenInvalid) — шинэ QR гаргуул), 403 *ForbiddenError (QR_PRESENT /
// QR_ATTR:* эрх алга).
func (s *QRService) Start(ctx context.Context, req QRStartRequest) (*QRSession, error) {
	token, err := ParseQR(req.QR)
	if err != nil {
		return nil, err
	}
	if err := checkQRAttributes(req.Attributes); err != nil {
		return nil, err
	}
	challenge, err := RandomChallenge(32)
	if err != nil {
		return nil, err
	}
	nonce := strings.TrimSpace(req.Nonce)
	body := qrStartBody{
		QR:                          QRPrefix + token,
		Attributes:                  append([]string(nil), req.Attributes...),
		RelyingPartyUUID:            s.creds.RPUUID,
		RelyingPartyName:            s.creds.RPName,
		SignatureProtocol:           "ACSP_V2",
		SignatureProtocolParameters: qrStartProtoPP{RPChallenge: challenge},
		Nonce:                       nonce,
	}
	var r sessionStartResponse
	if err := s.h.postJSON(ctx, routeAuthQR.expand(), body, &r); err != nil {
		return nil, err
	}
	if r.SessionID == "" {
		return nil, fmt.Errorf("eid: POST %s: sessionID алга", routeAuthQR.path)
	}
	if nonce == "" {
		nonce = challenge
	}
	return &QRSession{SessionID: r.SessionID, VC: string(r.VC), Nonce: nonce, Attributes: body.Attributes, ExpiresAt: r.caExpiresAt()}, nil
}

// Result — session дуустал long-poll хийж (WaitOptions nil бол sess.ExpiresAt-аар), presentation-ийг CA-ийн JWKS-ээр
// шалгана. Иргэн татгалзсан / хугацаа дууссан бол *SessionFailedError (USER_REFUSED, TIMEOUT г.м.). Шалгалт унавал
// *QRError{CodeQRPresentationInvalid} — ИТГЭХГҮЙ; JWKS татагдахгүй бол *QRError{CodeQRJWKSUnavailable} (дахин
// оролдож болно).
func (s *QRService) Result(ctx context.Context, sess *QRSession, o *WaitOptions) (*QRPresentation, error) {
	if sess == nil || sess.SessionID == "" {
		return nil, errors.New("eid: QR.Result: QRSession шаардлагатай")
	}
	if o == nil {
		o = &WaitOptions{ExpiresAt: sess.ExpiresAt}
	}
	r, err := (&SessionService{h: s.h}).WaitForResult(ctx, sess.SessionID, o)
	if err != nil {
		return nil, err
	}
	if r.State != StateComplete {
		return nil, &SessionFailedError{EndResult: "TIMEOUT"}
	}
	if r.EndResult != "OK" {
		return nil, &SessionFailedError{EndResult: r.EndResult}
	}
	if r.Presentation == nil || r.Presentation.JWS == "" {
		return nil, qrErr(CodeQRPresentationInvalid, "хариунд presentation алга")
	}
	return s.Verify(ctx, r.Presentation.JWS, sess)
}

// Verify — хадгалсан presentation JWS-ийг QRSession-тэй тулгаж шалгана (JWKS кэшээр; танихгүй kid → дахин татна).
func (s *QRService) Verify(ctx context.Context, jws string, sess *QRSession) (*QRPresentation, error) {
	exp := QRExpect{
		Issuer: s.cfg.Issuer, Audience: s.creds.RPUUID, SessionID: sess.SessionID, Nonce: sess.Nonce,
		Attributes: sess.Attributes, MaxAge: s.cfg.MaxAge,
	}
	keys, err := s.keys(ctx, false)
	if err != nil {
		return nil, err
	}
	p, err := verifyQR(jws, keys, exp)
	if !errors.Is(err, errQRUnknownKid) {
		return p, err
	}
	// Түлхүүр солигдсон байж болно — нэг удаа шинээр татна.
	if keys, err = s.keys(ctx, true); err != nil {
		return nil, err
	}
	return VerifyQRPresentation(jws, keys, exp)
}

// keys — кэштэй JWKS; force бол (сүүлийн оролдлогоос ≥ qrJWKSMinRefresh өнгөрсөн бол) дахин татна.
func (s *QRService) keys(ctx context.Context, force bool) (*JWKS, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ttl := s.cfg.JWKSCacheTTL
	if ttl <= 0 {
		ttl = DefaultQRJWKSCacheTTL
	}
	now := time.Now()
	fresh := s.jwks != nil && now.Sub(s.fetchedAt) < ttl
	if fresh && (!force || now.Sub(s.lastAttempt) < qrJWKSMinRefresh) {
		return s.jwks, nil
	}
	s.lastAttempt = now
	k, err := s.fetchJWKS(ctx)
	if err != nil {
		return nil, err
	}
	s.jwks, s.fetchedAt = k, now
	return k, nil
}

func (s *QRService) fetchJWKS(ctx context.Context) (*JWKS, error) {
	u := orDefault(s.cfg.JWKSURL, DefaultQRJWKSURL)
	fail := func(cause error, format string, a ...any) error {
		return &QRError{Code: CodeQRJWKSUnavailable, Reason: fmt.Sprintf(format, a...), Cause: cause}
	}
	pu, err := url.Parse(u)
	if err != nil || (pu.Scheme != "https" && !(pu.Scheme == "http" && isLoopback(pu.Hostname()))) {
		return nil, fail(err, "JWKSURL https байх ёстой")
	}
	ctx, cancel := s.h.withTimeout(ctx, 0)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fail(err, "хүсэлт")
	}
	req.Header.Set("Accept", "application/json") // RP secret ЭНД ИЛГЭЭХГҮЙ — нийтийн түлхүүр
	res, err := s.h.hc.Do(req)
	if err != nil {
		return nil, fail(unwrapURL(err), "татагдсангүй")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fail(nil, "HTTP %d", res.StatusCode)
	}
	raw, err := readLimited(res, qrMaxJWKS, http.MethodGet, pu.Path)
	if err != nil {
		return nil, fail(err, "уншигдсангүй")
	}
	k, err := ParseJWKS(raw)
	if err != nil {
		return nil, err
	}
	if len(k.Keys) == 0 {
		return nil, fail(nil, "JWKS хоосон")
	}
	return k, nil
}
