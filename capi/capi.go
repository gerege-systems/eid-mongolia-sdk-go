// Package main — pades-ийн C ABI (Windows DLL / .so / .dylib):
//
//	go build -buildmode=c-shared -o eidpades.dll ./capi
//
// Бүх функц 0 = амжилт, 1 = алдаа буцаана. Гаралтын буфер (out_*, err) нь C heap-д (malloc); дуудагч eid_free-ээр
// чөлөөлнө. Алдаа нь JSON {"code","message"} (*err). Глобал төлөвгүй — thread-safe.
package main

/*
#include <stdint.h>
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"encoding/json"
	"unsafe"

	"github.com/gerege-systems/eid-mongolia-sdk-go/pades"
)

func goBytes(p *C.uint8_t, n C.size_t) []byte {
	if p == nil || n == 0 {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(p), C.int(n))
}

func goString(p *C.char) string {
	if p == nil {
		return ""
	}
	return C.GoString(p)
}

func cBytes(b []byte, out **C.uint8_t, n *C.size_t) {
	*out = (*C.uint8_t)(C.CBytes(b))
	*n = C.size_t(len(b))
}

func fail(err error, errOut **C.char) C.int {
	if errOut != nil {
		*errOut = C.CString(pades.ErrorJSON(err))
	}
	return 1
}

// eid_pades_prepare — out_json = {"dtbs","digest","state","docId"} (base64).
//
//export eid_pades_prepare
func eid_pades_prepare(pdf *C.uint8_t, n C.size_t, optsJSON *C.char, outJSON **C.uint8_t, outN *C.size_t, errOut **C.char) C.int {
	o, err := pades.ParsePrepareOptions(goString(optsJSON))
	if err != nil {
		return fail(err, errOut)
	}
	p, err := pades.Prepare(goBytes(pdf, n), o)
	if err != nil {
		return fail(err, errOut)
	}
	b, err := json.Marshal(struct {
		DTBS   []byte `json:"dtbs"`
		Digest []byte `json:"digest"`
		State  []byte `json:"state"`
		DocID  string `json:"docId"`
	}{p.DTBS, p.Digest, p.State, p.DocID})
	if err != nil {
		return fail(err, errOut)
	}
	cBytes(b, outJSON, outN)
	return 0
}

// eid_pades_complete — out_pdf = гарын үсэгтэй PDF; out_meta_json = CompletedMeta (cms base64 дотор), NUL-төгсгөлтэй.
//
//export eid_pades_complete
func eid_pades_complete(state *C.uint8_t, stateN C.size_t, sig *C.uint8_t, sigN C.size_t, optsJSON *C.char,
	outPDF **C.uint8_t, outPDFN *C.size_t, outMeta **C.char, errOut **C.char) C.int {
	o, err := pades.ParseCompleteOptions(goString(optsJSON))
	if err != nil {
		return fail(err, errOut)
	}
	c, err := pades.Complete(context.Background(), goBytes(state, stateN), goBytes(sig, sigN), o)
	if err != nil {
		return fail(err, errOut)
	}
	meta, err := json.Marshal(c.Meta(true))
	if err != nil {
		return fail(err, errOut)
	}
	cBytes(c.PDF, outPDF, outPDFN)
	*outMeta = C.CString(string(meta))
	return 0
}

// eid_pades_verify — out_json = тайлан JSON.
//
//export eid_pades_verify
func eid_pades_verify(pdf *C.uint8_t, n C.size_t, optsJSON *C.char, outJSON **C.uint8_t, outN *C.size_t, errOut **C.char) C.int {
	o, err := pades.ParseVerifyOptions(goString(optsJSON))
	if err != nil {
		return fail(err, errOut)
	}
	r, err := pades.Verify(goBytes(pdf, n), o)
	if err != nil {
		return fail(err, errOut)
	}
	b, err := json.Marshal(r)
	if err != nil {
		return fail(err, errOut)
	}
	cBytes(b, outJSON, outN)
	return 0
}

// eid_pades_version — профайлын хувилбар (eid_free-ээр чөлөөлнө).
//
//export eid_pades_version
func eid_pades_version() *C.char { return C.CString(pades.ProfileVersion) }

// eid_free — энэ сангийн буцаасан буферийг чөлөөлнө.
//
//export eid_free
func eid_free(p unsafe.Pointer) { C.free(p) }

func main() {}
