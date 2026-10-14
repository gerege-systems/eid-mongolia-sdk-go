package eid

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"
)

const (
	// DefaultServerPoll — серверийн нэг long-poll-ийн дээд хугацаа.
	DefaultServerPoll = 30 * time.Second
	// DefaultMaxWait — WaitForResult-ийн нийт хүлээх дээд хугацаа.
	DefaultMaxWait = 150 * time.Second
)

// SessionService — session poll (long-poll). RP-API нь serverPoll хүртэл хүлээгээд (эсвэл иргэн хариу өгмөгц)
// буцдаг тул хэдхэн дуудлагаар үр дүн авна.
type SessionService struct {
	h *httpDoer
}

// rawSession — GET /session/{id}-ийн wire хэлбэр.
type rawSession struct {
	State  string `json:"state"`
	Result struct {
		EndResult      string `json:"endResult"`
		DocumentNumber string `json:"documentNumber"`
	} `json:"result"`
	SignatureProtocol string `json:"signatureProtocol"`
	Signature         struct {
		Value                        string                        `json:"value"`
		SignatureAlgorithm           string                        `json:"signatureAlgorithm"`
		SignatureProtocol            string                        `json:"signatureProtocol"`
		ServerRandom                 string                        `json:"serverRandom"`
		UserChallenge                string                        `json:"userChallenge"`
		FlowType                     string                        `json:"flowType"`
		InitialCallbackURL           *string                       `json:"initialCallbackUrl"`
		SignatureAlgorithmParameters *SignatureAlgorithmParameters `json:"signatureAlgorithmParameters"`
	} `json:"signature"`
	Cert struct {
		Value            string `json:"value"`
		CertificateLevel string `json:"certificateLevel"`
	} `json:"cert"`
	InteractionTypeUsed string           `json:"interactionTypeUsed"`
	OnBehalfOf          *OrgResult       `json:"onBehalfOf"`
	PDF                 *PDFSessionBlock `json:"pdf"`
}

// ParseSessionResult — RP-API-ийн session JSON-ийг SessionResult болгон задална (хадгалсан хариуг дахин
// шалгах, тестэд).
func ParseSessionResult(raw []byte) (*SessionResult, error) {
	var r rawSession
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("eid: session JSON: %w", err)
	}
	return r.result(), nil
}

func (r *rawSession) result() *SessionResult {
	proto := r.SignatureProtocol
	if proto == "" {
		proto = r.Signature.SignatureProtocol
	}
	params := r.Signature.SignatureAlgorithmParameters
	if params != nil && params.HashAlgorithm == "" {
		params = nil
	}
	org := r.OnBehalfOf
	if org != nil && org.OrgEtsi == "" {
		org = nil
	}
	pdf := r.PDF
	if pdf != nil && pdf.DocID == "" {
		pdf = nil
	}
	if pdf != nil && pdf.Signer != nil && pdf.Signer.Etsi == "" {
		pdf.Signer = nil
	}
	if pdf != nil && pdf.Validation != nil && pdf.Validation.Indication == "" {
		pdf.Validation = nil
	}
	return &SessionResult{
		State:                        r.State,
		EndResult:                    r.Result.EndResult,
		DocumentNumber:               r.Result.DocumentNumber,
		CertificateDERB64:            r.Cert.Value,
		CertificateLevel:             r.Cert.CertificateLevel,
		SignatureValueB64:            r.Signature.Value,
		SignatureAlgorithm:           r.Signature.SignatureAlgorithm,
		SignatureProtocol:            proto,
		ServerRandom:                 r.Signature.ServerRandom,
		UserChallenge:                r.Signature.UserChallenge,
		FlowType:                     r.Signature.FlowType,
		InitialCallbackURL:           r.Signature.InitialCallbackURL,
		SignatureAlgorithmParameters: params,
		InteractionTypeUsed:          r.InteractionTypeUsed,
		OnBehalfOf:                   org,
		PDF:                          pdf,
	}
}

// Poll — нэг удаагийн long-poll; serverPoll ≤ 0 бол DefaultServerPoll. HTTP timeout = serverPoll + 10s.
func (s *SessionService) Poll(ctx context.Context, sessionID string, serverPoll time.Duration) (*SessionResult, error) {
	if serverPoll <= 0 {
		serverPoll = DefaultServerPoll
	}
	path := fmt.Sprintf("/session/%s?timeoutMs=%d", url.PathEscape(sessionID), serverPoll.Milliseconds())
	var r rawSession
	if err := s.h.getJSON(ctx, path, serverPoll+10*time.Second, &r); err != nil {
		return nil, err
	}
	return r.result(), nil
}

// WaitOptions — WaitForResult-ийн тохиргоо. Тэг утга = анхдагч.
type WaitOptions struct {
	// MaxWait — нийт хүлээх хугацаа (0 = DefaultMaxWait).
	MaxWait time.Duration
	// ServerPoll — нэг long-poll (0 = DefaultServerPoll).
	ServerPoll time.Duration
}

// WaitForResult — COMPLETE болтол poll хийнэ. MaxWait дуустал COMPLETE болоогүй бол сүүлчийн (RUNNING) үр дүнг
// алдаагүй буцаана — дуудагч EndResult == ""-ийг TIMEOUT мэт боловсруулна. ctx цуцлагдвал алдаа.
func (s *SessionService) WaitForResult(ctx context.Context, sessionID string, o *WaitOptions) (*SessionResult, error) {
	maxWait, poll := DefaultMaxWait, DefaultServerPoll
	if o != nil && o.MaxWait > 0 {
		maxWait = o.MaxWait
	}
	if o != nil && o.ServerPoll > 0 {
		poll = o.ServerPoll
	}
	deadline := time.Now().Add(maxWait)
	last := &SessionResult{State: StateRunning}
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return last, nil
		}
		r, err := s.Poll(ctx, sessionID, max(time.Second, min(poll, remaining)))
		if err != nil {
			return nil, err
		}
		last = r
		if r.State == StateComplete {
			return r, nil
		}
	}
}
