package eid

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Device link v3 (Smart-ID RP-API v3 «dynamic link») — QR / Web2App / App2App холбоосыг RP BACKEND угсарна:
// authCode = HMAC-SHA256(sessionSecret)-ээр хамгаалагдсан, QR-д elapsedSeconds секунд тутам шинэчлэгдэнэ.
// SessionSecret-ийг браузер/апп руу ХЭЗЭЭ Ч бүү гарга; QR-ийг секунд тутам backend endpoint-оос өг.
// Legacy /dl?sessionId&vc холбоос 2026-10-07-нд серверээс хасагдсан — SDK-д байхгүй.

// DeviceLinkType — холбоосын төрөл; апп гарын үсгийн flowType-д яг энэ утгыг зурна (authCode-оор хамгаалагдсан).
type DeviceLinkType string

const (
	LinkQR      DeviceLinkType = "QR"
	LinkWeb2App DeviceLinkType = "Web2App"
	LinkApp2App DeviceLinkType = "App2App"
)

// DeviceLinkSessionType — session-ий урсгал.
type DeviceLinkSessionType string

const (
	SessionAuth DeviceLinkSessionType = "auth"
	SessionSign DeviceLinkSessionType = "sign"
	SessionCert DeviceLinkSessionType = "cert"
)

// DeviceLinkInput — BuildDeviceLink-ийн оролт.
type DeviceLinkInput struct {
	// DeviceLinkBase — session start хариуны deviceLinkBase (ж: https://ca.eidmongolia.mn/dl).
	DeviceLinkBase string
	DeviceLinkType DeviceLinkType
	// SessionToken — хариуны sessionToken, ЯГ ХЭВЭЭР.
	SessionToken string
	// SessionSecret — хариуны sessionSecret (стандарт Base64, padding-тэй). ЗӨВХӨН backend-д.
	SessionSecret string
	SessionType   DeviceLinkSessionType
	// Lang — ISO 639-2 гурван жижиг үсэг (mon, eng) — /dl fallback хуудасны хэл.
	Lang string
	// ReceivedAt — RP backend session start хариуг хүлээн авсан мөч. QR-д заавал.
	ReceivedAt time.Time
	// Now — одоогийн цаг (тест). Тэг = time.Now().
	Now time.Time
	// RPChallenge — auth: илгээсэн rpChallenge (base64 текстээрээ).
	RPChallenge string
	// Digest — sign: илгээсэн digest (base64 текст).
	Digest string
	// RelyingPartyName — session start хүсэлтэд илгээсэн ЯГ тэр нэр.
	RelyingPartyName string
	// Interactions — auth/sign: илгээсэн interactions-ийн base64 МӨР; cert: "".
	Interactions string
	// InitialCallbackURL — хүсэлтэд илгээсэн түүхий URL. Web2App/App2App-д заавал; QR-д authCode-д ОРОХГҮЙ.
	InitialCallbackURL string
	// SchemeName — "" = "smart-id".
	SchemeName string
	// BrokeredRpName — eID broker дэмждэггүй, "".
	BrokeredRpName string
}

var (
	tokenRE  = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	langRE   = regexp.MustCompile(`^[a-z]{3}$`)
	stdB64RE = regexp.MustCompile(`^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$`)
)

var protocolOf = map[DeviceLinkSessionType]string{SessionAuth: "ACSP_V2", SessionSign: "RAW_DIGEST_SIGNATURE", SessionCert: ""}

func dlErr(msg string) error { return &DeviceLinkError{Reason: msg} }

// BuildDeviceLink — device link v3-ийг бүтнээр нь угсарна (…&authCode=…). Цэвэр функц.
//
//	QR:      {base}?deviceLinkType=QR&elapsedSeconds={E}&sessionToken={T}&sessionType={S}&version=1.0&lang={L}&authCode={A}
//	Web2App: {base}?deviceLinkType=Web2App&sessionToken={T}&sessionType={S}&version=1.0&lang={L}&authCode={A}
//
// QR холбоос ~20 секундэд хүчингүй болдог тул секунд тутам дахин дуудаж харуул (TickQRDeviceLink). Web2App/App2App
// холбоосыг нэг удаа угсарна. Оролт буруу бол *DeviceLinkError.
func BuildDeviceLink(p DeviceLinkInput) (string, error) {
	base := strings.TrimSpace(p.DeviceLinkBase)
	if base == "" {
		return "", dlErr("deviceLinkBase хоосон — device-link session-ий хариуг шалга")
	}
	u, err := url.Parse(base)
	if err != nil {
		return "", dlErr("deviceLinkBase буруу URL: " + base)
	}
	if u.Scheme != "https" || u.Host == "" || strings.ContainsAny(base, "?#") {
		return "", dlErr("deviceLinkBase нь query/fragment-гүй https URL байх ёстой")
	}
	switch p.DeviceLinkType {
	case LinkQR, LinkWeb2App, LinkApp2App:
	default:
		return "", dlErr("deviceLinkType " + string(p.DeviceLinkType) + " (QR | Web2App | App2App)")
	}
	protocol, ok := protocolOf[p.SessionType]
	if !ok {
		return "", dlErr("sessionType " + string(p.SessionType) + " (auth | sign | cert)")
	}
	if !tokenRE.MatchString(p.SessionToken) {
		return "", dlErr("sessionToken хэлбэр буруу")
	}
	if !langRE.MatchString(p.Lang) {
		return "", dlErr("lang нь ISO 639-2 гурван жижиг үсэг (mon, eng)")
	}
	if p.SessionSecret == "" || !stdB64RE.MatchString(p.SessionSecret) {
		return "", dlErr("sessionSecret стандарт Base64 (padding-тэй) биш")
	}
	key, err := base64.StdEncoding.DecodeString(p.SessionSecret)
	if err != nil {
		return "", dlErr("sessionSecret стандарт Base64 (padding-тэй) биш")
	}

	var challenge string
	switch p.SessionType {
	case SessionAuth:
		if p.RPChallenge == "" {
			return "", dlErr("auth session-д rpChallenge заавал")
		}
		challenge = p.RPChallenge
	case SessionSign:
		if p.Digest == "" {
			return "", dlErr("sign session-д digest заавал")
		}
		challenge = p.Digest
	default:
		if p.RPChallenge != "" || p.Digest != "" {
			return "", dlErr("cert session-д rpChallenge/digest байхгүй")
		}
	}

	qr := p.DeviceLinkType == LinkQR
	callback := ""
	if !qr {
		callback = p.InitialCallbackURL
		if callback == "" {
			return "", dlErr(string(p.DeviceLinkType) + " холбоос initialCallbackUrl-тай session-д л хүчинтэй")
		}
	}

	elapsed := ""
	if qr {
		if p.ReceivedAt.IsZero() {
			return "", dlErr("QR холбоосонд ReceivedAt заавал")
		}
		now := p.Now
		if now.IsZero() {
			now = time.Now()
		}
		// Цаг ухарсан ч (NTP) сөрөг утга гаргахгүй — сервер ирээдүйн elapsed-ийг татгалздаг.
		e := int64(max(0, now.Sub(p.ReceivedAt)) / time.Second)
		elapsed = "&elapsedSeconds=" + strconv.FormatInt(e, 10)
	}

	unprotected := base + "?deviceLinkType=" + string(p.DeviceLinkType) + elapsed +
		"&sessionToken=" + p.SessionToken + "&sessionType=" + string(p.SessionType) +
		"&version=1.0&lang=" + p.Lang
	scheme := p.SchemeName
	if scheme == "" {
		scheme = "smart-id"
	}
	payload := strings.Join([]string{
		scheme, protocol, challenge, b64(p.RelyingPartyName), b64(p.BrokeredRpName),
		p.Interactions, callback, unprotected,
	}, "|")
	m := hmac.New(sha256.New, key)
	m.Write([]byte(payload))
	return unprotected + "&authCode=" + base64.RawURLEncoding.EncodeToString(m.Sum(nil)), nil
}

// TickQRDeviceLink — SSE/WebSocket-д: QR холбоосыг шууд нэг удаа, дараа нь interval (≤ 0 бол 1s) тутам onLink-ээр
// гаргана; ctx цуцлагдах хүртэл блоклоно (session дуусах / клиент салахад ctx-ийг цуцал). Оролт буруу бол эхний
// tick-д шууд *DeviceLinkError буцаана. HTTP poll ашиглавал хэрэггүй — хүсэлт бүрд BuildDeviceLink дууд.
func TickQRDeviceLink(ctx context.Context, in DeviceLinkInput, interval time.Duration, onLink func(link string)) error {
	if interval <= 0 {
		interval = time.Second
	}
	in.DeviceLinkType = LinkQR
	tick := func(now time.Time) error {
		in.Now = now
		link, err := BuildDeviceLink(in)
		if err != nil {
			return err
		}
		onLink(link)
		return nil
	}
	if err := tick(time.Now()); err != nil {
		return err
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case now := <-t.C:
			if err := tick(now); err != nil {
				return err
			}
		}
	}
}
