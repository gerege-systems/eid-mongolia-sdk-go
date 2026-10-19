package pades

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
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
