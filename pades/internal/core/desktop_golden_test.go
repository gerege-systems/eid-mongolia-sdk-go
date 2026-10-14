package core

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/pdf"
)

// desktopDir — eid-desktop-ийн Swift port-ын golden (pades/testdata/golden/desktop/README.md). Swift нь CA-ийн
// Go-той байт-ижил гэж баталгаажсан тул энэ port ч тэдгээртэй байт-ижил байх ёстой.
var desktopDir = filepath.Join("..", "..", "testdata", "golden", "desktop")

func readDesktop(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(desktopDir, rel)) // #nosec G304 -- тест
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// lastSig — doc-ийн "Signature n" талбарын Sig толь.
func lastSig(t *testing.T, doc []byte, n int) pdf.Value {
	t.Helper()
	r, err := pdf.NewReader(bytes.NewReader(doc), int64(len(doc)))
	if err != nil {
		t.Fatal(err)
	}
	fields := r.Trailer().Key("Root").Key("AcroForm").Key("Fields")
	for i := range fields.Len() {
		f := fields.Index(i)
		if f.Key("T").Text() == "Signature "+string(rune('0'+n)) {
			return f.Key("V")
		}
	}
	t.Fatalf("Signature %d алга", n)
	return pdf.Value{}
}

func parseM(t *testing.T, s string) time.Time {
	t.Helper()
	// D:YYYYMMDDHHmmSS+HH'mm'
	s = strings.TrimPrefix(s, "D:")
	tm, err := time.Parse("20060102150405-07'00'", s)
	if err != nil {
		t.Fatal(err)
	}
	return tm
}

// vriItems — doc-ийн DSS /VRI-ийн sigContents-д харгалзах Cert/OCSP/CRL stream-уудын агуулга (дарааллаар).
func vriItems(t *testing.T, doc []byte, key string) DSS {
	t.Helper()
	r, err := pdf.NewReader(bytes.NewReader(doc), int64(len(doc)))
	if err != nil {
		t.Fatal(err)
	}
	e := r.Trailer().Key("Root").Key("DSS").Key("VRI").Key(key)
	if e.IsNull() {
		t.Fatalf("VRI %s алга", key)
	}
	read := func(name string) [][]byte {
		var out [][]byte
		a := e.Key(name)
		for i := range a.Len() {
			b, err := io.ReadAll(a.Index(i).Reader())
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, b)
		}
		return out
	}
	return DSS{Certs: read("Cert"), OCSPs: read("OCSP"), CRLs: read("CRL")}
}

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// TestDesktopGolden — desktop-ийн оролтоос алхам бүрийг (гарын үсэг → DSS → 2 дахь гарын үсэг → DSS) энэ core-оор
// давтаж, гаралт бүрийг файлтай байт-түвшинд тулгана. CMS нь desktop-ийн *.p7s (openssl), /M /Name /Reason нь
// хүлээгдэж буй файлаас.
func TestDesktopGolden(t *testing.T) {
	for _, kind := range []string{"quartz", "objstm"} {
		t.Run(kind, func(t *testing.T) {
			cur := readDesktop(t, "input/base-"+kind+".pdf")
			for n := 1; n <= 2; n++ {
				want := readDesktop(t, "output/"+kind+"-"+string(rune('0'+n))+".pdf")
				sig := lastSig(t, want, n)
				prep, err := PrepareSignatureWithReason(cur, parseM(t, sig.Key("M").Text()), sig.Key("Name").Text(), sig.Key("Reason").Text())
				if err != nil {
					t.Fatal(err)
				}
				signed, err := EmbedCMS(prep.PDF, prep.ByteRange, readDesktop(t, "output/"+kind+"-"+string(rune('0'+n))+".p7s"))
				if err != nil {
					t.Fatal(err)
				}
				if !sameDoc(t, signed, want) {
					t.Fatalf("%s-%d.pdf зөрөв: авсан %s, хүлээсэн %s", kind, n, sha(signed), sha(want))
				}
				signed = want // xref stream-ийн zlib-ийн ялгааг дараагийн алхамд дамжуулахгүй
				wantDSS := readDesktop(t, "output/"+kind+"-"+string(rune('0'+n))+"-dss.pdf")
				contents, err := SignatureContents(signed, prep.ByteRange)
				if err != nil {
					t.Fatal(err)
				}
				h := sha1Upper(contents)
				d := vriItems(t, wantDSS, h)
				d.Contents = contents
				out, err := AppendDSS(signed, d)
				if err != nil {
					t.Fatal(err)
				}
				if !sameDoc(t, out, wantDSS) {
					t.Fatalf("%s-%d-dss.pdf зөрөв: авсан %s, хүлээсэн %s", kind, n, sha(out), sha(wantDSS))
				}
				// xref stream-ийн zlib нь Swift (Compression.framework) ба Go-д өөр байт өгдөг тул дараагийн алхмыг
				// хүлээгдэж буй файлаас эхлүүлнэ (classic xref-д ижил).
				cur = wantDSS
			}
		})
	}
}

func sha1Upper(b []byte) string {
	s := sha1.Sum(b) // #nosec G401 -- VRI түлхүүр
	return strings.ToUpper(hex.EncodeToString(s[:]))
}

var byteRangeTail = regexp.MustCompile(`(/ByteRange \[0 \d+ \d+ )\d+\]`)

var xrefLen = regexp.MustCompile(`/Type /XRef /Length (\d+)( /Filter /FlateDecode)?`)

// normXref — xref stream бүрийн өгөгдлийг (FlateDecode бол задалж) түүхийгээр, /Length ба /Filter-ийг арилгана.
// Профайл pades-client/1-д xref stream шахалтгүй, desktop-ийн хуучин гаралт FlateDecode-той.
func normXref(t *testing.T, doc []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	rest := doc
	for {
		m := xrefLen.FindSubmatchIndex(rest)
		if m == nil {
			out.Write(rest)
			return out.Bytes()
		}
		n, _ := strconv.Atoi(string(rest[m[2]:m[3]]))
		flate := m[4] >= 0
		out.Write(rest[:m[2]])
		out.WriteString("*")
		rest = rest[m[1]:]
		i := bytes.Index(rest, []byte(">>\nstream\n"))
		if i < 0 || i+10+n > len(rest) {
			t.Fatal("xref stream задарсангүй")
		}
		out.Write(rest[:i+10])
		raw := rest[i+10 : i+10+n]
		if flate {
			zr, err := zlib.NewReader(bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			if raw, err = io.ReadAll(zr); err != nil {
				t.Fatal(err)
			}
		}
		out.Write(raw)
		rest = rest[i+10+n:]
	}
}

func sameDoc(t *testing.T, got, want []byte) bool {
	t.Helper()
	if bytes.Equal(got, want) {
		return true
	}
	// ByteRange-ийн 4 дэх тоо (төгсгөл хүртэлх урт) нь xref stream-ийн шахсан уртаас хамаарна.
	norm := func(b []byte) []byte { return byteRangeTail.ReplaceAll(normXref(t, b), []byte("$1*]")) }
	return bytes.Equal(norm(got), norm(want))
}
