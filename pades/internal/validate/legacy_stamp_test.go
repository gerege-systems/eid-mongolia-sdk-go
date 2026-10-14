package validate

import (
	"bytes"
	"crypto/x509"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pdfcpuapi "github.com/pdfcpu/pdfcpu/pkg/api"

	pdfsign "github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/vpage"
)

// legacyWithPage — устсан stamp-ийн суурийн хэлбэр (pdfsign.BuildVerifiedPDF, 2026-10-13 хүртэл): гарын үсэг мэт
// объектгүй баримтын ард нэг хуудсыг pdfcpu merge-ээр нэмнэ (файлыг БҮТЭН дахин бичиж xref stream болгоно);
// гарын үсэгтэй баримтыг хөндөхгүй. Хуучин файлын «legacy own» хэлбэрийг шалгагч таньсаар байгааг батлахад.
func legacyWithPage(t *testing.T, doc []byte) []byte {
	t.Helper()
	signed, err := pdfsign.HasSignatureObjects(doc)
	if err != nil {
		t.Fatal(err)
	}
	if signed {
		return bytes.Clone(doc)
	}
	var out bytes.Buffer
	if err := pdfcpuapi.MergeRaw([]io.ReadSeeker{bytes.NewReader(doc), bytes.NewReader(minimalPDF(t))}, &out, false, nil); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// TestLegacyStampedPDFStillValidates — `POST /v3/signature/stamp` 2026-10-13-нд эх кодоос устсан ч тэрээр гаргасан
// файлууд шалгагдсаар байх ёстой (pdf_stamps + doc-signer, docs/PADES_SIGNING.md §10). testdata/legacy_stamp нь
// устгахаас өмнөх StampSignedDocument-оор (туршилтын PKI, 2126 он хүртэл хүчинтэй) хоёр удаа stamp хийсэн ХӨЛДӨӨСӨН
// файл — дахин үүсгэх боломжгүй, засахгүй. revisions.sha256 = stamp бүрийн гаралтын sha256 (pdf_stamps.out_sha256).
func TestLegacyStampedPDFStillValidates(t *testing.T) {
	dir := filepath.Join("testdata", "legacy_stamp")
	read := func(name string) []byte {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	cert := func(name string) *x509.Certificate {
		t.Helper()
		c, err := x509.ParseCertificate(read(name))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	root, issuing := cert("root.der"), cert("issuing.der")
	roots := x509.NewCertPool()
	roots.AddCert(root)
	v := &Validator{Roots: roots, Intermediates: []*x509.Certificate{issuing}, Issuers: []*x509.Certificate{issuing}, Status: good}

	rep := mustPDF(t, v, read("stamped.pdf"))
	outs := strings.Fields(string(read("revisions.sha256")))
	if rep.Indication != Valid || len(rep.Signatures) != 2 || len(outs) != 2 {
		t.Fatalf("indication=%s гарын үсэг=%d revision=%d", rep.Indication, len(rep.Signatures), len(outs))
	}
	for i, want := range []string{"BAT BOLD", "DORJ SUREN"} {
		s := rep.Signatures[i]
		if s.Indication != Valid || s.Certificate.Usage != "document_signer" || !s.Certificate.IssuedByEID {
			t.Fatalf("гарын үсэг %d: %s %v usage=%s ours=%v", i+1, s.Indication, s.Problems, s.Certificate.Usage, s.Certificate.IssuedByEID)
		}
		if s.SignerName != want || s.SignerNameSource != SignerNamePlatformAttested {
			t.Fatalf("гарын үсэг %d: signer_name=%q source=%q", i+1, s.SignerName, s.SignerNameSource)
		}
		// pdf_stamps-аас session олох түлхүүр: revision-ий sha256 == тухайн stamp-ийн гаралт.
		if s.RevisionSHA256 != outs[i] {
			t.Fatalf("гарын үсэг %d: revision sha256=%s, pdf_stamps out=%s", i+1, s.RevisionSHA256, outs[i])
		}
	}
	if !rep.Signatures[0].ExtendedBySignaturesOnly || !rep.Signatures[1].CoversWholeDocument {
		t.Fatalf("давхар stamp-ийн бүтэц: %+v", rep.Signatures)
	}
}
