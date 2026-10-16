package validate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// EID_VALIDATE_CORPUS=<dir> үед тест бүрийн Extract-ийн оролт/гаралтыг <dir>-д бичнэ (TS SDK-ийн differential corpus;
// pades/testdata/validate/README.md).
func init() {
	dir := os.Getenv("EID_VALIDATE_CORPUS")
	if dir == "" {
		return
	}
	CorpusHook = CorpusWriter(dir)
}

// CorpusEntry — corpus-ийн нэг бичлэг (<sha>-<profile>.json).
type CorpusEntry struct {
	Profile    string            `json:"profile"`
	Error      string            `json:"error,omitempty"`
	DocID      string            `json:"docId"`
	Metas      map[int]SigMeta   `json:"metas,omitempty"`
	Signatures []CorpusSignature `json:"signatures"`
}

// CorpusSignature — RawSignature + экспортлогдоогүй objNum/byteRange (байт талбаруудыг sha256-аар).
type CorpusSignature struct {
	RawSignature
	ObjNum    int     `json:"obj_num"`
	ByteRange []int64 `json:"byte_range"`
}

var corpusMu sync.Mutex

// CorpusWriter — CorpusHook-ийн хэрэгжүүлэлт (pades багцын тест ч ашиглана).
func CorpusWriter(dir string) func([]byte, bool, []RawSignature, map[int]SigMeta, string, error) {
	return func(doc []byte, broad bool, sigs []RawSignature, metas map[int]SigMeta, docID string, err error) {
		corpusMu.Lock()
		defer corpusMu.Unlock()
		_ = os.MkdirAll(dir, 0o755)
		sum := sha256.Sum256(doc)
		name := hex.EncodeToString(sum[:8])
		prof := "own"
		if broad {
			prof = "broad"
		}
		e := CorpusEntry{Profile: prof, DocID: docID, Metas: metas, Signatures: []CorpusSignature{}}
		switch err {
		case nil:
		case ErrNoSignature:
			e.Error = "no_signature"
		case ErrTooMany:
			e.Error = "too_many"
		default:
			e.Error = "not_pdf"
		}
		for _, s := range sigs {
			e.Signatures = append(e.Signatures, CorpusSignature{RawSignature: s, ObjNum: s.ObjNum(), ByteRange: s.ByteRange()})
		}
		b, _ := json.MarshalIndent(e, "", " ")
		_ = os.WriteFile(filepath.Join(dir, name+".pdf"), doc, 0o644)
		_ = os.WriteFile(filepath.Join(dir, name+"-"+prof+".json"), b, 0o644)
	}
}

// TestCorpusGolden — EID_VALIDATE_CORPUS үед pades golden-ийн оролт/гаралтыг (бодит PAdES бичигчийн хэлбэр) corpus-д нэмнэ.
func TestCorpusGolden(t *testing.T) {
	if CorpusHook == nil {
		t.Skip("EID_VALIDATE_CORPUS алга")
	}
	files, _ := filepath.Glob("../../testdata/golden/*/*.pdf")
	for _, f := range files {
		doc, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = Extract(doc)
		_, _ = extractWith(doc, profileBroad)
	}
}
