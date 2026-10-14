//go:build js && wasm

// Command wasm — pades-ийг хөтөч/Node-д (GOOS=js GOARCH=wasm) globalThis.eidPades-ээр гаргана:
//
//	eidPades.prepare(pdf: Uint8Array, opts: object) → {dtbs, digest, state: Uint8Array, docId}
//	eidPades.complete(state, signature: Uint8Array, opts) → Promise<{pdf, cms: Uint8Array, docId, outSha256, inSha256,
//	    hasPage, pageSha256, revIndex, sigRevSha256, priorCmsSha256, signerCert}>
//	eidPades.verify(pdf, opts) → тайлан (object)
//	eidPades.version → "pades-client/1"
//
// Алдаа: prepare/verify нь throw, complete нь reject — {code, message}. TSA/OCSP/CRL-ийг net/http-ийн js fetch-ээр;
// AIA/CDP-ийн http:// нь зөвхөн eID-ийн allowlist host-д https болно (pades/fetch.go).
package main

import (
	"context"
	"encoding/json"
	"syscall/js"

	"github.com/gerege-systems/eid-mongolia-sdk-go/pades"
)

func toBytes(v js.Value) []byte {
	if v.IsUndefined() || v.IsNull() {
		return nil
	}
	b := make([]byte, v.Get("length").Int())
	js.CopyBytesToGo(b, v)
	return b
}

func toU8(b []byte) js.Value {
	a := js.Global().Get("Uint8Array").New(len(b))
	js.CopyBytesToJS(a, b)
	return a
}

func optsJSON(v js.Value) string {
	if v.IsUndefined() || v.IsNull() {
		return ""
	}
	return js.Global().Get("JSON").Call("stringify", v).String()
}

func jsErr(err error) js.Value {
	var o map[string]any
	_ = json.Unmarshal([]byte(pades.ErrorJSON(err)), &o)
	e := js.Global().Get("Error").New(o["message"])
	e.Set("code", o["code"])
	return e
}

func throw(err error) any { panic(js.ValueOf(jsErr(err))) }

func fromJSON(b []byte) js.Value { return js.Global().Get("JSON").Call("parse", string(b)) }

func main() {
	api := js.Global().Get("Object").New()
	api.Set("version", pades.ProfileVersion)
	api.Set("prepare", js.FuncOf(func(_ js.Value, a []js.Value) any {
		o, err := pades.ParsePrepareOptions(optsJSON(arg(a, 1)))
		if err != nil {
			return throw(err)
		}
		p, err := pades.Prepare(toBytes(arg(a, 0)), o)
		if err != nil {
			return throw(err)
		}
		r := js.Global().Get("Object").New()
		r.Set("dtbs", toU8(p.DTBS))
		r.Set("digest", toU8(p.Digest))
		r.Set("state", toU8(p.State))
		r.Set("docId", p.DocID)
		return r
	}))
	api.Set("complete", js.FuncOf(func(_ js.Value, a []js.Value) any {
		state, sig, opts := toBytes(arg(a, 0)), toBytes(arg(a, 1)), optsJSON(arg(a, 2))
		return js.Global().Get("Promise").New(js.FuncOf(func(_ js.Value, pr []js.Value) any {
			resolve, reject := pr[0], pr[1]
			go func() {
				o, err := pades.ParseCompleteOptions(opts)
				if err != nil {
					reject.Invoke(jsErr(err))
					return
				}
				c, err := pades.Complete(context.Background(), state, sig, o)
				if err != nil {
					reject.Invoke(jsErr(err))
					return
				}
				meta, _ := json.Marshal(c.Meta(false))
				r := fromJSON(meta)
				r.Set("pdf", toU8(c.PDF))
				r.Set("cms", toU8(c.CMS))
				r.Set("signerCert", toU8(c.SignerCert))
				resolve.Invoke(r)
			}()
			return nil
		}))
	}))
	api.Set("verify", js.FuncOf(func(_ js.Value, a []js.Value) any {
		o, err := pades.ParseVerifyOptions(optsJSON(arg(a, 1)))
		if err != nil {
			return throw(err)
		}
		r, err := pades.Verify(toBytes(arg(a, 0)), o)
		if err != nil {
			return throw(err)
		}
		b, _ := json.Marshal(r)
		return fromJSON(b)
	}))
	js.Global().Set("eidPades", api)
	select {}
}

func arg(a []js.Value, i int) js.Value {
	if i < len(a) {
		return a[i]
	}
	return js.Undefined()
}
