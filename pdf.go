package eid

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net/textproto"
	"net/url"
	"strings"
	"time"
)

// PDFSignerRef — гарын үсэг зурагч: яг нэг талбар бөглөнө.
type PDFSignerRef struct {
	Etsi                       string `json:"etsi,omitempty"`
	DocumentNumber             string `json:"documentNumber,omitempty"`
	CertificateChoiceSessionID string `json:"certificateChoiceSessionId,omitempty"`
}

// PDF урсгал.
const (
	PDFFlowNotification = "notification"
	PDFFlowDeviceLink   = "device-link"
)

// PDFPrepareInput — POST /pdf/sign/prepare-ийн оролт.
type PDFPrepareInput struct {
	// PDF — эх PDF (≤ 10 223 616 байт — /.well-known/eid pdfSigning.maxInputBytes).
	PDF []byte
	// FileName — баримтын нэр (≤ 120 тэмдэгт) — /verify хуудас, иргэний түүхэнд харагдана.
	FileName string
	Signer   PDFSignerRef
	// Flow — PDFFlowNotification (анхдагч) эсвэл PDFFlowDeviceLink (QR/Web2App/App2App).
	Flow             string
	CertificateLevel CertificateLevel
	// InitialCallbackURL — device-link Web2App/App2App буцах URL.
	InitialCallbackURL string
	// DocID — олон гарын үсэгтэй баримтад хүлээж буй docID (заавал биш).
	DocID string
	// OnBehalfOf — байгууллагын нэрийн өмнөөс (NTRMN-<бүртгэл>). Татгалзвал ForbiddenError/APIError.Code.
	OnBehalfOf string
}

// PDFPrepareSession — prepare-ийн хариу.
type PDFPrepareSession struct {
	SessionID string `json:"sessionId"`
	DocID     string `json:"docId"`
	// VC — иргэнд ХАРУУЛАХ баталгаажуулах код (ПИН биш).
	VC string `json:"vc"`
	// Digest — CA-ийн зуруулах digest (base64) ба Interactions (base64 мөр) — хоёр урсгалд (notification,
	// device-link) хариунаас. Хариунд байхгүй бол "".
	Digest       string `json:"digest"`
	Interactions string `json:"interactions"`
	// DeviceLink — device-link урсгалд л (BuildDeviceLink-д Digest/Interactions-ийг ЯГ ХЭВЭЭР өгнө).
	DeviceLink *PDFDeviceLink `json:"deviceLink,omitempty"`
	// ReceivedAt — хариу хүлээн авсан мөч (QR-ийн DeviceLinkInput.ReceivedAt).
	ReceivedAt time.Time `json:"receivedAt"`
}

// PDFDeviceLink — device-link урсгалын холбоосын материал. SessionSecret зөвхөн backend-д.
type PDFDeviceLink struct {
	SessionToken   string `json:"sessionToken"`
	SessionSecret  string `json:"sessionSecret"`
	DeviceLinkBase string `json:"deviceLinkBase"`
	Digest         string `json:"digest"`
	Interactions   string `json:"interactions"`
}

// PDFService — PAdES гарын үсэг (CA угсарна): RP эх PDF-ээ илгээж, иргэн PIN2-оор зурсны дараа CA
// PAdES-BASELINE-LT гарын үсэгтэй PDF буцаана. Урсгал: Prepare → Session.WaitForResult (pdf.DocumentStatus=READY)
// → Document → DocumentVerified.
type PDFService struct {
	h     *httpDoer
	creds Credentials
	level CertificateLevel
}

type pdfPrepareRequest struct {
	RelyingPartyUUID   string           `json:"relyingPartyUUID"`
	RelyingPartyName   string           `json:"relyingPartyName"`
	CertificateLevel   CertificateLevel `json:"certificateLevel"`
	Signer             PDFSignerRef     `json:"signer"`
	Flow               string           `json:"flow"`
	FileName           string           `json:"fileName"`
	InitialCallbackURL string           `json:"initialCallbackUrl,omitempty"`
	DocID              string           `json:"docID,omitempty"`
	OnBehalfOf         string           `json:"onBehalfOf,omitempty"`
}

// Prepare — POST /pdf/sign/prepare (multipart: request JSON + pdf). SIGN эрх шаардана.
func (p *PDFService) Prepare(ctx context.Context, in PDFPrepareInput) (*PDFPrepareSession, error) {
	if len(in.PDF) == 0 {
		return nil, errors.New("eid: PDF хоосон")
	}
	flow := in.Flow
	if flow == "" {
		flow = PDFFlowNotification
	}
	reqJSON, err := json.Marshal(pdfPrepareRequest{
		RelyingPartyUUID:   p.creds.RPUUID,
		RelyingPartyName:   p.creds.RPName,
		CertificateLevel:   orDefault(in.CertificateLevel, p.level),
		Signer:             in.Signer,
		Flow:               flow,
		FileName:           in.FileName,
		InitialCallbackURL: strings.TrimSpace(in.InitialCallbackURL),
		DocID:              strings.TrimSpace(in.DocID),
		OnBehalfOf:         strings.TrimSpace(in.OnBehalfOf),
	})
	if err != nil {
		return nil, fmt.Errorf("eid: pdf request encode: %w", err)
	}
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := writePart(mw, `form-data; name="request"`, "application/json", reqJSON); err != nil {
		return nil, err
	}
	disp := fmt.Sprintf(`form-data; name="pdf"; filename="%s"`, quoteEscaper.Replace(in.FileName))
	if err := writePart(mw, disp, "application/pdf", in.PDF); err != nil {
		return nil, err
	}
	if err := mw.Close(); err != nil {
		return nil, fmt.Errorf("eid: multipart: %w", err)
	}

	var r struct {
		SessionID    string         `json:"sessionID"`
		DocID        string         `json:"docID"`
		VC           vcValue        `json:"vc"`
		Digest       string         `json:"digest"`
		Interactions string         `json:"interactions"`
		DeviceLink   *PDFDeviceLink `json:"deviceLink"`
	}
	if err := p.h.doJSON(ctx, "POST", "/pdf/sign/prepare", &body, mw.FormDataContentType(), pdfTimeout, &r); err != nil {
		return nil, err
	}
	s := &PDFPrepareSession{
		SessionID:    r.SessionID,
		DocID:        r.DocID,
		VC:           string(r.VC),
		Digest:       r.Digest,
		Interactions: r.Interactions,
		ReceivedAt:   time.Now(),
	}
	if r.DeviceLink != nil && r.DeviceLink.SessionToken != "" {
		s.DeviceLink = r.DeviceLink
		if s.Digest == "" {
			s.Digest = r.DeviceLink.Digest
		}
		if s.Interactions == "" {
			s.Interactions = r.DeviceLink.Interactions
		}
	}
	return s, nil
}

// Document — GET /pdf/sign/{sessionID}/document: гарын үсэгтэй PDF (READY-ээс хойш 30 мин). Татсан байтыг
// DocumentVerified-аар session-ий pdf.OutSHA256-тай заавал тулга. Эрх хасагдсан бол
// ForbiddenError.Code = CodeRepresentationRevoked.
func (p *PDFService) Document(ctx context.Context, sessionID string) ([]byte, error) {
	return p.h.getBytes(ctx, "/pdf/sign/"+url.PathEscape(sessionID)+"/document", pdfTimeout)
}

// DocumentVerified — татсан PDF-ийн SHA-256 нь session-ий pdf.OutSHA256-тай таарч, баримт READY бол true.
// false бол файлд ИТГЭХГҮЙ (дахин татна эсвэл алдаа).
func DocumentVerified(signedPDF []byte, pdf *PDFSessionBlock) bool {
	if pdf == nil || pdf.DocumentStatus != PDFReady || pdf.OutSHA256 == "" || len(signedPDF) == 0 {
		return false
	}
	want, err := hex.DecodeString(strings.TrimSpace(pdf.OutSHA256))
	if err != nil || len(want) != sha256.Size {
		return false
	}
	got := sha256.Sum256(signedPDF)
	return subtle.ConstantTimeCompare(got[:], want) == 1
}

var quoteEscaper = strings.NewReplacer("\\", "\\\\", `"`, "\\\"", "\r", "", "\n", "")

func writePart(mw *multipart.Writer, disposition, ctype string, data []byte) error {
	h := textproto.MIMEHeader{}
	h.Set("Content-Disposition", disposition)
	h.Set("Content-Type", ctype)
	w, err := mw.CreatePart(h)
	if err != nil {
		return fmt.Errorf("eid: multipart: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("eid: multipart: %w", err)
	}
	return nil
}
