package vpage

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"io"
	"os"
	"testing"
	"unicode/utf16"
)

// pageContent — PDF-ийн бүх zlib stream-ийг задалж нийлүүлнэ (content stream-д зурсан текстийг шалгахад).
func pageContent(t *testing.T, pdf []byte) []byte {
	t.Helper()
	var content []byte
	remaining := pdf
	for {
		start := bytes.Index(remaining, []byte("stream\n"))
		if start < 0 {
			return content
		}
		remaining = remaining[start+len("stream\n"):]
		end := bytes.Index(remaining, []byte("endstream"))
		if end < 0 {
			return content
		}
		if reader, err := zlib.NewReader(bytes.NewReader(remaining[:end])); err == nil {
			decoded, err := io.ReadAll(reader)
			reader.Close()
			if err != nil {
				t.Fatal(err)
			}
			content = append(content, decoded...)
		}
		remaining = remaining[end+len("endstream"):]
	}
}

// utf16be — fpdf UTF-8 font-ийн текстийг content stream-д Identity-H (UTF-16BE) хэлбэрээр бичдэг.
func utf16be(s string) []byte {
	var b []byte
	for _, u := range utf16.Encode([]rune(s)) {
		b = binary.BigEndian.AppendUint16(b, u)
	}
	return b
}

func testDocumentPage(fileName string) DocumentPage {
	return DocumentPage{Brand: "eID Mongolia", FileName: fileName,
		DocumentHash: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", FileSize: 245760,
		DocID: "3f0c2a8e-6b1d-4c55-9a77-0f6f4f1d2b11", VerifyURL: "https://ca.eidmongolia.mn/verify/3f0c2a8e-6b1d-4c55-9a77-0f6f4f1d2b11",
		TrustURL: "https://eidmongolia.mn/trust", CAName: "eID Mongolia Issuing CA",
		TSAName: "eID Mongolia TSA (tsa.timeserver.mn)", Provider: "ca.eidmongolia.mn"}
}

// Баталгаажуулалтын хуудас: хуучин web-sign хуудасны төрх, Кирилл (Й Өө Үү №) embedded Noto Sans-аар,
// зурагч/гарын үсгийн мэдээлэлгүй, эх баримтын ард.
func TestDocumentPage(t *testing.T) {
	p := testDocumentPage("ТЕХНИКИЙН ТОДОРХОЙЛОЛТ — Гэрээ №12, Өөрчлөлт, Үүрэг.pdf")
	page, err := BuildDocumentPage(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(page, []byte("/BaseFont /utf8notosans")) || !bytes.Contains(page, []byte("/FontFile2")) {
		t.Fatal("Noto Sans embed хийгдээгүй")
	}
	if out := os.Getenv("PADES_PAGE_OUT"); out != "" { // гар шалгалт: PDF-ийг хадгална
		_ = os.WriteFile(out, page, 0o600)
	}
	content := pageContent(t, page)
	for _, want := range []string{
		"ТЕХНИКИЙН ТОДОРХОЙЛОЛТ", "Electronically signed document", "DOCUMENT", "FILE NAME", "HASH ALGORITHM",
		"DOCUMENT HASH", "DOCUMENT ID", "VERIFICATION", "Scan to verify", "Adobe Acrobat: trust the Mongolian National Root CA",
		"https://eidmongolia.mn/trust", "240.0 KB",
		// footer; «(» «)»-ийг content stream-д escape хийдэг тул хаалтгүй хэсгүүдээр.
		"CA: eID Mongolia Issuing CA  |  TSA: eID Mongolia TSA ", "tsa.timeserver.mn", "  |  Provider: ca.eidmongolia.mn",
	} {
		if !bytes.Contains(content, utf16be(want)) {
			t.Errorf("хуудсанд %q алга", want)
		}
	}
	// Courier (ASCII) талбарууд.
	for _, want := range []string{p.DocumentHash, p.DocID} {
		if !bytes.Contains(content, []byte(want)) {
			t.Errorf("хуудсанд %q алга", want)
		}
	}
	// Хуудас гарын үсгээс өмнө үүснэ: зурагч/гарын үсгийн хэсэг, «VERIFIED» баталгаа байх ёсгүй.
	for _, bad := range []string{"SIGNER", "SIGNATURE", "TIMESTAMP", "VERIFIED", "valid"} {
		if bytes.Contains(content, utf16be(bad)) || bytes.Contains(content, []byte(bad)) {
			t.Errorf("хуудсанд %q байна", bad)
		}
	}
	merged, err := AppendDocumentPage(minimalPDF(t), p)
	if err != nil {
		t.Fatal(err)
	}
	if signed, err := HasSignatureObjects(merged); err != nil || signed {
		t.Fatalf("merge: %v %v", signed, err)
	}
	if _, err := BuildDocumentPage(DocumentPage{}); err == nil {
		t.Fatal("docID-гүй хуудас үүсгэв")
	}
}
