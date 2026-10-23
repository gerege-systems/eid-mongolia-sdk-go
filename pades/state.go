package pades

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"

	eid "github.com/gerege-systems/eid-mongolia-sdk-go"
)

// stateMagic — State-ийн толгой (хувилбартай). Формат: magic ‖ uint32 BE толгойн урт ‖ JSON толгой ‖ prepared PDF
// (CA-ийн pades_codec.go-тэй ижил санаа: PDF-ийг base64 болгохгүй).
var stateMagic = []byte("EIDPADES1")

type prepState struct {
	DocID       string   `json:"docId"`
	SignerCert  []byte   `json:"signerCert"`
	Chain       [][]byte `json:"chain"`
	SignedAttrs []byte   `json:"signedAttrs"`
	ByteRange   [4]int64 `json:"byteRange"`
	RevIndex    int      `json:"revIndex"`
	InSHA256    string   `json:"inSha256"`
	HasPage     bool     `json:"hasPage"`
	PageSHA256  string   `json:"pageSha256,omitempty"`
	ClaimedRole string   `json:"claimedRole,omitempty"`
	FileName    string   `json:"fileName,omitempty"` // цэвэрлэсэн (CA бүртгэлд)
	// Images — харагдах дүрслэлд шигтгэсэн зургийн PNG sha256 (Completed.Images → бүртгэл).
	Images []eid.PDFSignatureImage `json:"images,omitempty"`
	// PreparedSHA256 — prepared PDF-ийн sha256 (state эвдэрснийг Complete-д илрүүлнэ).
	PreparedSHA256 string `json:"preparedSha256"`
	PDF            []byte `json:"-"`
}

func (s *prepState) encode() ([]byte, error) {
	head, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(stateMagic)+4+len(head)+len(s.PDF))
	out = append(out, stateMagic...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(head))) // #nosec G115 -- толгой хэдэн KB
	out = append(out, head...)
	return append(out, s.PDF...), nil
}

func decodeState(b []byte) (*prepState, error) {
	if !bytes.HasPrefix(b, stateMagic) || len(b) < len(stateMagic)+4 {
		return nil, errors.New("state-ийн толгой танигдсангүй")
	}
	b = b[len(stateMagic):]
	n := binary.BigEndian.Uint32(b[:4])
	if uint64(n) > uint64(len(b)-4) {
		return nil, errors.New("state таслагдсан")
	}
	var s prepState
	if err := json.Unmarshal(b[4:4+n], &s); err != nil {
		return nil, err
	}
	s.PDF = bytes.Clone(b[4+n:])
	if sha256Hex(s.PDF) != s.PreparedSHA256 {
		return nil, errors.New("prepared PDF-ийн hash таарахгүй")
	}
	if len(s.SignedAttrs) == 0 || len(s.SignerCert) == 0 || len(s.PDF) == 0 || s.RevIndex < 1 {
		return nil, errors.New("state дутуу")
	}
	return &s, nil
}
