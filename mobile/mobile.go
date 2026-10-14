// Package mobile — pades-ийн gomobile bind хил (iOS/macOS xcframework, Android AAR). Хил дээр зөвхөн []byte, string,
// error ба тэдгээрээс бүрдсэн struct; options/тайлан JSON. Алдааны Error() нь JSON {"code","message"}.
//
//	gomobile bind -target ios,macos -o EidPades.xcframework ./mobile
//	gomobile bind -target android -o eidpades.aar ./mobile
package mobile

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/gerege-systems/eid-mongolia-sdk-go/pades"
)

// PrepareResult — pades.Prepared.
type PrepareResult struct {
	DTBS   []byte
	Digest []byte
	State  []byte
	DocID  string
}

// CompleteResult — гарын үсэгтэй PDF, CMS ба бусад утга MetaJSON-д (docId, outSha256, inSha256, hasPage,
// pageSha256, revIndex, sigRevSha256, priorCmsSha256, signerCert).
type CompleteResult struct {
	PDF      []byte
	CMS      []byte
	MetaJSON string
}

type jsonError struct{ msg string }

func (e *jsonError) Error() string { return e.msg }

func wrap(err error) error {
	if err == nil {
		return nil
	}
	return &jsonError{msg: pades.ErrorJSON(err)}
}

// Prepare — pades.Prepare; optionsJSON нь PrepareOptions (signerCert base64 DER, …).
func Prepare(pdf []byte, optionsJSON string) (*PrepareResult, error) {
	o, err := pades.ParsePrepareOptions(optionsJSON)
	if err != nil {
		return nil, wrap(err)
	}
	p, err := pades.Prepare(pdf, o)
	if err != nil {
		return nil, wrap(err)
	}
	return &PrepareResult{DTBS: p.DTBS, Digest: p.Digest, State: p.State, DocID: p.DocID}, nil
}

// Complete — pades.Complete (сүлжээ: TSA, OCSP, CRL). optionsJSON: {"tsaUrl","roots"}.
func Complete(state, signature []byte, optionsJSON string) (*CompleteResult, error) {
	o, err := pades.ParseCompleteOptions(optionsJSON)
	if err != nil {
		return nil, wrap(err)
	}
	c, err := pades.Complete(context.Background(), state, signature, o)
	if err != nil {
		return nil, wrap(err)
	}
	meta, err := json.Marshal(c.Meta(false))
	if err != nil {
		return nil, wrap(err)
	}
	return &CompleteResult{PDF: c.PDF, CMS: c.CMS, MetaJSON: string(meta)}, nil
}

// Verify — pades.Verify; тайлан JSON.
func Verify(pdf []byte, optionsJSON string) (string, error) {
	o, err := pades.ParseVerifyOptions(optionsJSON)
	if err != nil {
		return "", wrap(err)
	}
	r, err := pades.Verify(pdf, o)
	if err != nil {
		return "", wrap(err)
	}
	b, err := json.Marshal(r)
	if err != nil {
		return "", wrap(errors.New("тайлан JSON"))
	}
	return string(b), nil
}

// Version — профайлын хувилбар (pades.ProfileVersion).
func Version() string { return pades.ProfileVersion }
