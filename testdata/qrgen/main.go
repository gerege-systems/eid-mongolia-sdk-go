// Cross-SDK «Миний QR» test vector generator. Run once: `cd testdata/qrgen && go run main.go > ../qr_vectors.json`, then copy the file to the TS (test/fixtures) and .NET (testdata) SDKs — new keys each run.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
)

var b64 = base64.RawURLEncoding

const (
	iss   = "https://ca.eidmongolia.mn"
	aud   = "6f1c2b9e-3a4d-4e5f-8a7b-9c0d1e2f3a4b"
	sid   = "0b8f3f0e-1111-4222-8333-444455556666"
	nonce = "cashier-7f3a9c"
	sub   = "Zk3vQh2m9cTqL8rW1xYb5nPdA0sE6uJgHtKoVfRiMlC"
	iat   = int64(1792800000)
	kid   = "eid-qr-2026-10"
)

var key *ecdsa.PrivateKey

func jwk(k *ecdsa.PublicKey, kid, crv string) map[string]any {
	raw, _ := k.Bytes() // 04||X||Y
	n := (len(raw) - 1) / 2
	return map[string]any{"kty": "EC", "crv": crv, "kid": kid, "alg": "ES256", "use": "sig",
		"x": b64.EncodeToString(raw[1 : 1+n]), "y": b64.EncodeToString(raw[1+n:])}
}

func sign(hdr, payload any, der bool) string {
	hb, _ := json.Marshal(hdr)
	pb, _ := json.Marshal(payload)
	in := b64.EncodeToString(hb) + "." + b64.EncodeToString(pb)
	h := sha256.Sum256([]byte(in))
	if der {
		sig, _ := ecdsa.SignASN1(rand.Reader, key, h[:])
		return in + "." + b64.EncodeToString(sig)
	}
	r, s, _ := ecdsa.Sign(rand.Reader, key, h[:])
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return in + "." + b64.EncodeToString(sig)
}

func hdr() map[string]any { return map[string]any{"alg": "ES256", "kid": kid, "typ": "JWT"} }

func payload(attrs map[string]any, unavailable []string) map[string]any {
	p := map[string]any{"iss": iss, "aud": aud, "sid": sid, "sub": sub, "iat": iat, "nonce": nonce, "attrs": attrs}
	if unavailable != nil {
		p["unavailable"] = unavailable
	}
	return p
}

func expect(attrs ...string) map[string]any {
	return map[string]any{"issuer": iss, "audience": aud, "sessionID": sid, "nonce": nonce, "attributes": attrs, "now": iat + 5}
}

func with(m map[string]any, k string, v any) map[string]any {
	o := map[string]any{}
	for a, b := range m {
		o[a] = b
	}
	if v == nil {
		delete(o, k)
	} else {
		o[k] = v
	}
	return o
}

func main() {
	key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	jwks := map[string]any{"keys": []any{jwk(&key.PublicKey, kid, "P-256"), jwk(&other.PublicKey, "eid-qr-p384", "P-384")}}

	tok := "q9Xk3vQh2m9cTqL8rW1xYb5nPdA0sE6uJgHtKoVfRiM"
	parse := []map[string]any{
		{"in": "EIDMN-QR1:" + tok, "token": tok},
		{"in": "  EIDMN-QR1:" + tok + "\n", "token": tok},
		{"in": tok, "token": tok},
		{"in": "EIDMN-QR2:" + tok, "error": "QR_FORMAT_INVALID"},
		{"in": "eidmn-qr1:" + tok, "error": "QR_FORMAT_INVALID"},
		{"in": "EIDMN-QR1:" + tok[:42], "error": "QR_FORMAT_INVALID"},
		{"in": "EIDMN-QR1:" + tok + "A", "error": "QR_FORMAT_INVALID"},
		{"in": "EIDMN-QR1:" + tok[:42] + "+", "error": "QR_FORMAT_INVALID"},
		{"in": "EIDMN-QR1:" + tok[:42] + "=", "error": "QR_FORMAT_INVALID"},
		{"in": "https://eidmongolia.mn/?qr=" + tok, "error": "QR_FORMAT_INVALID"},
		{"in": "", "error": "QR_FORMAT_INVALID"},
	}

	t, f := true, false
	_ = f
	fullName := map[string]any{"surname": "Батболд", "givenName": "Өнөрмаа"}
	all := map[string]any{"age_over_18": true, "age_over_21": false, "full_name": fullName, "phone": "+97699112233",
		"birth_date": "2004-05-17", "civil_id": "123456789012"}
	age := payload(map[string]any{"age_over_18": t}, nil)
	loyalty := payload(map[string]any{"full_name": fullName}, []string{"phone"})
	type V = map[string]any
	ok := func(name, jws string, exp map[string]any, attrs map[string]any, unavail []string) V {
		return V{"name": name, "jws": jws, "expect": exp, "result": V{"sub": sub, "attrs": attrs, "unavailable": unavail}}
	}
	bad := func(name, jws string, exp map[string]any) V {
		return V{"name": name, "jws": jws, "expect": exp, "error": "QR_PRESENTATION_INVALID"}
	}
	ageJWS := sign(hdr(), age, false)
	parts := splitJWS(ageJWS)
	tampered := parts[0] + "." + b64.EncodeToString(mustJSON(payload(map[string]any{"age_over_18": true, "x": 1}, nil))) + "." + parts[2]
	tampered2 := parts[0] + "." + b64.EncodeToString(mustJSON(with(age, "aud", "other-rp"))) + "." + parts[2]
	verify := []V{
		ok("age_over_18", ageJWS, expect("age_over_18"), V{"age_over_18": true}, []string{}),
		ok("loyalty_phone_unavailable", sign(hdr(), loyalty, false), expect("full_name", "phone"), V{"full_name": fullName}, []string{"phone"}),
		ok("all_attributes", sign(hdr(), payload(all, []string{}), false), expect("age_over_18", "age_over_21", "full_name", "phone", "birth_date", "civil_id"), all, []string{}),
		ok("all_unavailable_no_attrs_key", sign(hdr(), with(payload(nil, []string{"birth_date"}), "attrs", nil), false), expect("birth_date"), V{}, []string{"birth_date"}),
		bad("tampered_payload", tampered, expect("age_over_18")),
		bad("tampered_aud", tampered2, expect("age_over_18")),
		bad("wrong_audience", ageJWS, with(expect("age_over_18"), "audience", "another-rp-uuid")),
		bad("wrong_session", ageJWS, with(expect("age_over_18"), "sessionID", "another-session")),
		bad("wrong_nonce", ageJWS, with(expect("age_over_18"), "nonce", "other-nonce")),
		bad("wrong_issuer", ageJWS, with(expect("age_over_18"), "issuer", "https://evil.example")),
		bad("alg_hs256", sign(with(hdr(), "alg", "HS256"), age, false), expect("age_over_18")),
		bad("alg_none", splitJWS(sign(with(hdr(), "alg", "none"), age, false))[0]+"."+parts[1]+".", expect("age_over_18")),
		bad("no_kid", sign(with(hdr(), "kid", nil), age, false), expect("age_over_18")),
		bad("unknown_kid", sign(with(hdr(), "kid", "eid-qr-1999"), age, false), expect("age_over_18")),
		bad("kid_wrong_curve", sign(with(hdr(), "kid", "eid-qr-p384"), age, false), expect("age_over_18")),
		bad("crit_header", sign(with(hdr(), "crit", []string{"exp"}), age, false), expect("age_over_18")),
		bad("signature_der", sign(hdr(), age, true), expect("age_over_18")),
		bad("signature_padded", ageJWS+"=", expect("age_over_18")),
		bad("extra_attribute", sign(hdr(), payload(V{"age_over_18": true, "civil_id": "123456789012"}, nil), false), expect("age_over_18")),
		bad("missing_attribute", ageJWS, expect("age_over_18", "phone")),
		bad("attr_and_unavailable", sign(hdr(), payload(V{"age_over_18": true}, []string{"age_over_18"}), false), expect("age_over_18")),
		bad("bool_as_string", sign(hdr(), payload(V{"age_over_18": "true"}, nil), false), expect("age_over_18")),
		bad("phone_not_e164", sign(hdr(), payload(V{"phone": "99112233"}, nil), false), expect("phone")),
		bad("birth_date_invalid", sign(hdr(), payload(V{"birth_date": "2004-02-30"}, nil), false), expect("birth_date")),
		bad("full_name_missing_given", sign(hdr(), payload(V{"full_name": V{"surname": "Батболд"}}, nil), false), expect("full_name")),
		bad("no_sub", sign(hdr(), with(age, "sub", nil), false), expect("age_over_18")),
		bad("iat_future", ageJWS, with(expect("age_over_18"), "now", iat-120)),
		bad("iat_too_old", ageJWS, with(expect("age_over_18"), "now", iat+601)),
		bad("exp_passed", sign(hdr(), with(age, "exp", iat-100), false), expect("age_over_18")),
	}
	out := V{
		"comment": "eID «Миний QR» cross-SDK vectors (Go/TS/.NET). Generated once; do not regenerate per SDK — copy this file. Rules: developer.eidmongolia.mn «Миний QR».",
		"version": 1, "maxAgeSeconds": 600, "clockSkewSeconds": 60,
		"attributes": []string{"age_over_18", "age_over_21", "full_name", "phone", "birth_date", "civil_id"},
		"jwks":       jwks, "parse": parse, "verify": verify,
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	os.Stdout.Write(append(b, '\n'))
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func splitJWS(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}
