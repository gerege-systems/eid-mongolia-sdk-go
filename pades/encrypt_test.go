package pades

import (
	"bytes"
	"compress/zlib"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/validate"
)

// trailerPDF — сонгодог xref-тэй жижиг PDF (Catalog + хоосон Pages), trailer-т extra нэмнэ.
func trailerPDF(extra string) []byte {
	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n%" + strings.Repeat("x", 300) + "\n")
	off1 := b.Len()
	b.WriteString("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
	off2 := b.Len()
	b.WriteString("2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n")
	xref := b.Len()
	fmt.Fprintf(&b, "xref\n0 3\n0000000000 65535 f \n%010d 00000 n \n%010d 00000 n \n", off1, off2)
	fmt.Fprintf(&b, "trailer\n<< /Size 3 /Root 1 0 R %s>>\nstartxref\n%d\n%%%%EOF\n", extra, xref)
	return b.Bytes()
}

// TestEncryptDirectDict — trailer-ийн /Encrypt нь лавлагаа биш шууд толь (`/Encrypt << … >>`, `/Encrypt<<`) байсан ч
// PDF_ENCRYPTED (CA !382-тэй ижил); /EncryptMetadata нь шифрлэлт биш.
func TestEncryptDirectDict(t *testing.T) {
	const u = "<" + "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" + ">"
	for _, tc := range []struct {
		name  string
		extra string
		enc   bool
	}{
		{"AES-256 шууд толь", "/Encrypt << /Filter /Standard /V 5 /R 6 /Length 256 /P -1 /O " + u + " /U " + u +
			" /OE " + u + " /UE " + u + " /Perms <00112233445566778899aabbccddeeff> /CF << /StdCF << /CFM /AESV3 /Length 32 >> >> /StmF /StdCF /StrF /StdCF >> ", true},
		{"RC4 шууд толь, зайгүй", "/Encrypt<< /Filter /Standard /V 2 /R 3 /Length 128 /P -1 /O " + u + " /U " + u + " >> ", true},
		{"лавлагаа", "/Encrypt 9 0 R ", true},
		{"/EncryptMetadata (шифрлэлт биш)", "/X << /EncryptMetadata false >> ", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := trailerPDF(tc.extra)
			if got := encrypted(doc); got != tc.enc {
				t.Fatalf("encrypted = %v", got)
			}
			_, err := ValidatePDF(context.Background(), doc, ValidateOptions{Offline: true})
			if (ErrorCode(err) == CodePDFEncrypted) != tc.enc {
				t.Fatalf("ValidatePDF: %v", err)
			}
		})
	}
}

// TestEncryptedObjStm — бодит шифрлэгдсэн, ObjStm-тэй баримт (qpdf 12.4.2 `--object-streams=generate --encrypt`, эх нь
// testdata/objstm/qpdf-chrome.pdf; хэрэглэгчийн нууц үг хоосон): CheckStructure ObjStm-ийн ciphertext-ийг шалгаад
// хуурамч татгалзалт өгөхгүй; ValidatePDF / Prepare / SuggestPlacement нь PDF_ENCRYPTED.
func TestEncryptedObjStm(t *testing.T) {
	p := loadOrCreatePKI(t)
	files, err := filepath.Glob(filepath.Join("testdata", "encrypted-objstm", "*.pdf"))
	if err != nil || len(files) != 4 {
		t.Fatalf("%v %v", files, err)
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			doc, err := os.ReadFile(f) // #nosec G304 -- тест
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(doc, []byte("/ObjStm")) || !bytes.Contains(doc, []byte("/Encrypt")) {
				t.Fatal("ObjStm / Encrypt алга — тестийн өгөгдөл буруу")
			}
			if err := validate.CheckStructure(doc); err != nil {
				t.Fatalf("CheckStructure: %v", err)
			}
			if _, err := ValidatePDF(context.Background(), doc, ValidateOptions{Offline: true}); ErrorCode(err) != CodePDFEncrypted {
				t.Fatalf("ValidatePDF: %v", err)
			}
			// AES-128: encrypted() /Encrypt-ийг resolve хийж panic → false болдог байсан (v0.21.0 хүртэл PDF_INVALID,
			// тайлсан ObjStm-ийг scanSignatures задалдаг — zip bomb); одоо Keys()-ээр → PDF_ENCRYPTED.
			if !encrypted(doc) {
				t.Fatal("encrypted = false")
			}
			if _, err := Prepare(doc, testOpts(p, p.citizen.cert)); ErrorCode(err) != CodePDFEncrypted {
				t.Fatalf("Prepare: %v", err)
			}
			if _, err := SuggestPlacement(doc, Appearance{}); ErrorCode(err) != CodePDFEncrypted {
				t.Fatalf("SuggestPlacement: %v", err)
			}
		})
	}
}

// TestZipBombObjStmFakeEncryptComment — `% /Encrypt <<` тайлбар ObjStm-ийн zip bomb хамгаалалтыг унтраадаг байсан
// (v0.21.1-ээс өмнө): одоо ValidatePDF / Prepare нь PDF_INVALID (ErrPDFStructure). Баримт нь хамгаалалтгүйгээр
// digitorus-аар задрах зөв xref-тэй (obj 3 = ObjStm).
func TestZipBombObjStmFakeEncryptComment(t *testing.T) {
	var z bytes.Buffer
	zw, _ := zlib.NewWriterLevel(&z, zlib.BestCompression)
	_, _ = zw.Write([]byte("4 0 "))
	_, _ = zw.Write(bytes.Repeat([]byte{' '}, 33<<20)) // > validate.maxObjStmBytes (32 MiB)
	_ = zw.Close()
	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n% /Encrypt <<\n")
	offs := []int{b.Len()}
	b.WriteString("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
	offs = append(offs, b.Len())
	b.WriteString("2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n")
	offs = append(offs, b.Len())
	fmt.Fprintf(&b, "3 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode /Length %d >>\nstream\n", z.Len())
	b.Write(z.Bytes())
	b.WriteString("\nendstream\nendobj\n")
	x := b.Len()
	b.WriteString("xref\n0 4\n0000000000 65535 f \n")
	for _, o := range offs {
		fmt.Fprintf(&b, "%010d 00000 n \n", o)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", x)
	doc := b.Bytes()
	if _, err := ValidatePDF(context.Background(), doc, ValidateOptions{Offline: true}); ErrorCode(err) != CodePDFInvalid || !errors.Is(err, ErrPDFStructure) {
		t.Fatalf("ValidatePDF: %v", err)
	}
	p := loadOrCreatePKI(t)
	if _, err := Prepare(doc, testOpts(p, p.citizen.cert)); ErrorCode(err) != CodePDFInvalid || !errors.Is(err, ErrPDFStructure) {
		t.Fatalf("Prepare: %v", err)
	}
}
