package eid

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	_ "crypto/sha512" // SHA-384/512 бүртгэл
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// Крипто туслахууд — digest, санамсаргүй challenge, ACSP_V2 payload.
//
// ACSP_V2 payload нь Smart-ID RP-API v3 (signature_protocols.html)-тэй БАЙТ-ИЖИЛ: сервер, утас, RP SDK
// '|'-ээр холбосон нэг мөрийг угсарна — нэг байт зөрвөл гарын үсэг таарахгүй.

// SHA256Base64 — SHA-256 digest, стандарт base64. Sign урсгалын баримтын digest үүсгэхэд.
func SHA256Base64(data []byte) string {
	h := sha256.Sum256(data)
	return base64.StdEncoding.EncodeToString(h[:])
}

// RandomChallenge — санамсаргүй RP challenge (n байт, n ≤ 0 бол 64), стандарт base64. Auth урсгалд replay-ээс хамгаална.
func RandomChallenge(n int) (string, error) {
	if n <= 0 {
		n = 64
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("eid: random challenge: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// InteractionsToBase64 — interactions массивыг RP-API v3-ийн base64 мөр болгоно. RP энэ МӨРИЙГ хадгалж validator-т
// өгнө (дахин serialize хийхгүй — JSON байт зөрж болно).
func InteractionsToBase64(interactions []Interaction) (string, error) {
	if interactions == nil {
		interactions = []Interaction{}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // JS JSON.stringify-тай ижил: < > & хэвээр
	if err := enc.Encode(interactions); err != nil {
		return "", fmt.Errorf("eid: interactions encode: %w", err)
	}
	return base64.StdEncoding.EncodeToString(unescapeLineSeparators(bytes.TrimSuffix(buf.Bytes(), []byte("\n")))), nil
}

// unescapeLineSeparators — encoding/json нь U+2028/U+2029-ийг үргэлж  /  болгодог; JS JSON.stringify
// түүхийгээр нь үлдээдэг. TS SDK-тэй байт-ижил байхын тулд буцааж түүхий UTF-8 болгоно (\\ хос escape-ийг алгасна).
func unescapeLineSeparators(b []byte) []byte {
	if !bytes.Contains(b, []byte(`\u202`)) {
		return b
	}
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] != '\\' || i+1 >= len(b) {
			out = append(out, b[i])
			continue
		}
		if b[i+1] == 'u' && i+5 < len(b) && string(b[i+2:i+5]) == "202" && (b[i+5] == '8' || b[i+5] == '9') {
			out = append(out, " "[:2]...)
			out = append(out, 0xa8+(b[i+5]-'8'))
			i += 5
			continue
		}
		out = append(out, b[i], b[i+1]) // бусад escape (\\ ч мөн) хэвээр
		i++
	}
	return out
}

// ACSPV2Params — ACSP_V2 payload-ийн бүх орц (Smart-ID v3 §ACSP_V2 digest calculation).
type ACSPV2Params struct {
	// SchemeName — "" = "smart-id".
	SchemeName string
	// ServerRandom — base64, хариунаас ЯГ ТЭР ХЭВЭЭР.
	ServerRandom string
	// RPChallenge — base64, RP-ийн илгээсэн.
	RPChallenge string
	// UserChallenge — base64url 43 тэмдэгт, хариунаас.
	UserChallenge string
	// RelyingPartyName — хүсэлтэд илгээсэн түүхий мөр.
	RelyingPartyName string
	// BrokeredRpName — одоогоор "".
	BrokeredRpName string
	// Interactions — хүсэлтэд илгээсэн base64 МӨР.
	Interactions        string
	InteractionTypeUsed string
	// InitialCallbackURL — payload-д зурагдсан түүхий мөр, байхгүй бол "".
	InitialCallbackURL string
	FlowType           string
}

// BuildACSPV2Payload — гарын үсэг зурагдах UTF-8 байтууд:
//
//	schemeName|ACSP_V2|serverRandom|rpChallenge|userChallenge|B64(rpName)|B64(brokeredRpName)|
//	B64(SHA-256(interactions))|interactionTypeUsed|initialCallbackUrl|flowType
func BuildACSPV2Payload(p ACSPV2Params) []byte {
	scheme := p.SchemeName
	if scheme == "" {
		scheme = "smart-id"
	}
	ih := sha256.Sum256([]byte(p.Interactions))
	return []byte(strings.Join([]string{
		scheme,
		"ACSP_V2",
		p.ServerRandom,
		p.RPChallenge,
		p.UserChallenge,
		b64(p.RelyingPartyName),
		b64(p.BrokeredRpName),
		base64.StdEncoding.EncodeToString(ih[:]),
		p.InteractionTypeUsed,
		p.InitialCallbackURL,
		p.FlowType,
	}, "|"))
}

// ACSPV2Digest — HASH_{hashAlgorithm}(payload).
func ACSPV2Digest(p ACSPV2Params, h HashAlgorithm) ([]byte, error) {
	ch, err := cryptoHash(string(h))
	if err != nil {
		return nil, err
	}
	d := ch.New()
	d.Write(BuildACSPV2Payload(p))
	return d.Sum(nil), nil
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// cryptoHash — "SHA-256" | "SHA-384" | "SHA-512" → crypto.Hash.
func cryptoHash(name string) (crypto.Hash, error) {
	switch name {
	case "SHA-256":
		return crypto.SHA256, nil
	case "SHA-384":
		return crypto.SHA384, nil
	case "SHA-512":
		return crypto.SHA512, nil
	}
	return 0, &ValidationError{Reason: "дэмжигдээгүй hashAlgorithm: " + name}
}
