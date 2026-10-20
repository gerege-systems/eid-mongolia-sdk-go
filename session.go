package eid

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

const (
	// DefaultServerPoll — серверийн нэг long-poll-ийн дээд хугацаа.
	DefaultServerPoll = 30 * time.Second
	// DefaultMaxWait — WaitForResult-ийн нийт хүлээх хугацааны нөөц утга: MaxWait, ExpiresAt өгөөгүй, discovery-ийн
	// sessionTtl ч мэдэгдэхгүй үед (CA-ийн гарын үсгийн session-ий анхдагч 600 с-тэй ижил).
	DefaultMaxWait = 600 * time.Second
	// WaitGrace — ExpiresAt / discovery sessionTtl-ээс хойш нэмж хүлээх хугацаа: CA хугацаа дууссан session-ийг дараагийн
	// poll-д COMPLETE/TIMEOUT болгодог тул сүүлчийн poll нь дуусах мөчөөс хойш явагдаж, цагийн бага зөрүүг даана.
	WaitGrace = 15 * time.Second
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
	InteractionTypeUsed string                 `json:"interactionTypeUsed"`
	OnBehalfOf          *OrgResult             `json:"onBehalfOf"`
	Person              *Person                `json:"person"`
	TokenCertificate    *TokenCertSessionBlock `json:"tokenCertificate"`
}

// ParseSessionResult — RP-API-ийн session JSON-ийг SessionResult болгон задална (хадгалсан хариуг дахин
// шалгах, тестэд).
func ParseSessionResult(raw []byte) (*SessionResult, error) {
	var r rawSession
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("eid: session JSON: %w", err)
	}
	out := r.result()
	out.Raw = append(json.RawMessage(nil), raw...)
	return out, nil
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
	person := r.Person
	if person != nil && *person == (Person{}) {
		person = nil
	}
	tok := r.TokenCertificate
	if tok != nil && tok.Status == "" {
		tok = nil
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
		Person:                       person,
		TokenCertificate:             tok,
	}
}

// Poll — нэг удаагийн long-poll; serverPoll ≤ 0 бол DefaultServerPoll. HTTP timeout = serverPoll + 10s.
func (s *SessionService) Poll(ctx context.Context, sessionID string, serverPoll time.Duration) (*SessionResult, error) {
	if serverPoll <= 0 {
		serverPoll = DefaultServerPoll
	}
	path := fmt.Sprintf("%s?timeoutMs=%d", routeSession.expand(sessionID), serverPoll.Milliseconds())
	var raw json.RawMessage
	if err := s.h.getJSON(ctx, path, serverPoll+10*time.Second, &raw); err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return &SessionResult{}, nil
	}
	return ParseSessionResult(raw)
}

// WaitOptions — WaitForResult-ийн тохиргоо. Тэг утга = анхдагч.
type WaitOptions struct {
	// MaxWait — нийт хүлээх хугацаа. 0 бол ExpiresAt + WaitGrace; ExpiresAt тэг бол discovery-ийн sessionTtl
	// (max(auth, sign)) + WaitGrace; тэр нь ч мэдэгдэхгүй бол DefaultMaxWait. Өгвөл үүнийг л дагана.
	MaxWait time.Duration
	// ExpiresAt — session start хариуны ExpiresAt (NotificationSession / DeviceLinkSession.ExpiresAt). Өгвөл
	// discovery-г татахгүй.
	ExpiresAt time.Time
	// ServerPoll — нэг long-poll (0 = DefaultServerPoll).
	ServerPoll time.Duration
}

// WaitForResult — COMPLETE болтол poll хийнэ. Анхдагчаар session-ий амьдрах хугацаа дуустал (WaitOptions.MaxWait-ийг
// үз) хүлээнэ — CA хугацаа дууссан session-ийг COMPLETE/TIMEOUT болгодог тул ердийн үед тэр үр дүн ирнэ. Хугацаа дуустал
// COMPLETE болоогүй бол сүүлчийн (RUNNING) үр дүнг алдаагүй буцаана — дуудагч EndResult == ""-ийг TIMEOUT мэт
// боловсруулна. ctx цуцлагдвал алдаа.
func (s *SessionService) WaitForResult(ctx context.Context, sessionID string, o *WaitOptions) (*SessionResult, error) {
	if o == nil {
		o = &WaitOptions{}
	}
	poll := DefaultServerPoll
	if o.ServerPoll > 0 {
		poll = o.ServerPoll
	}
	deadline := s.waitDeadline(ctx, o)
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

// waitDeadline — WaitForResult-ийн дуусах мөч: MaxWait > ExpiresAt > discovery sessionTtl > DefaultMaxWait.
func (s *SessionService) waitDeadline(ctx context.Context, o *WaitOptions) time.Time {
	now := time.Now()
	switch {
	case o.MaxWait > 0:
		return now.Add(o.MaxWait)
	case !o.ExpiresAt.IsZero():
		// Хугацаа аль хэдийн өнгөрсөн ч нэг poll хийнэ — CA-ийн COMPLETE/TIMEOUT-ийг авна.
		if d := o.ExpiresAt.Add(WaitGrace); d.After(now.Add(time.Second)) {
			return d
		}
		return now.Add(time.Second)
	}
	// Session-ий төрөл (auth / sign) энд мэдэгдэхгүй — урт нь аюулгүй: CA хугацаа дууссан session-ийг өөрөө TIMEOUT
	// болгоно. Discovery татагдахгүй бол нөөц утга (алдаа биш).
	if st, err := fetchSessionTTL(ctx, s.h); err == nil {
		if d := max(st.Auth, st.Sign); d > 0 {
			return now.Add(d + WaitGrace)
		}
	}
	return now.Add(DefaultMaxWait)
}
