package pades

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	eid "github.com/gerege-systems/eid-mongolia-sdk-go"
	"github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/core"
	"github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/validate"
)

// SealPDF → Completed.SealRegistration → CA-ийн POST /seal/{orgEtsi}/registrations-ийн дүрэм (ca-eidmongolia-mn main
// 70c0e09c, server/internal/service/memory/pades_seal_register.go RegisterSealSignature + handlers_seal_register.go).

// docSealer — fakeSealer + DocumentSealer: нөөцийг (docId, revIndex) тэмдэглэнэ.
type docSealer struct {
	fakeSealer
	docID    string
	revIndex int
	reserved int
}

func (d *docSealer) SealForDocument(ctx context.Context, org string, digest []byte, docID string, revIndex int) (*eid.SealResult, error) {
	d.docID, d.revIndex = docID, revIndex
	d.reserved++
	return d.Seal(ctx, org, digest, eid.SHA256)
}

// caSealRegisterBody — CA dto.SealRegisterRequest (JSON tag ЯГ ижил; handler DisallowUnknownFields).
type caSealRegisterBody struct {
	DocID               string   `json:"docID"`
	RevIndex            int      `json:"revIndex"`
	CMS                 string   `json:"cms"`
	FileName            string   `json:"fileName,omitempty"`
	InSHA256            string   `json:"inSha256"`
	SigRevSHA256        string   `json:"sigRevSha256"`
	OutSHA256           string   `json:"outSha256"`
	PriorCMSSHA256      []string `json:"priorCmsSha256,omitempty"`
	PriorRevisionSHA256 []string `json:"priorRevisionSha256,omitempty"`
}

// caAcceptsSealRegistration — CA-ийн шалгалтыг (сүлжээ, DB, TSA-гүй хэсэг) SDK-ийн гаралт дээр давтана:
//   - handler: JSON ≤ 64 KiB, DisallowUnknownFields;
//   - normalizeSealRegister: docID жижиг UUID, revIndex 1–16, fileName ≤ 120, hash 64 жижиг hex, prior тоо = revIndex − 1,
//     cms base64 DER ≤ 28 672;
//   - ParseCMS + SignedAttributesWithRole(messageDigest, cert, role) байт-ижил (claimedRole 0) → SHA-256(signedAttrs) =
//     org_seal_ops-ийн digest (энэ RP-ийн тамгалсан digest — sealed);
//   - sealOpFor: нөөц байвал docId/revIndex бүртгэлийнхтэй ижил (SEAL_DOC_MISMATCH);
//   - registerSealCert: organizationIdentifier = orgEtsi (SIGNER_MISMATCH), e-Seal профайл;
//   - мэдүүлгийн hash-ууд нь файлын нотолгоо (CA validate.SignatureProof): cms_sha256 = /Contents CMS DER-ийн sha256,
//     sigRevSha256 = sha256(doc[:ByteRange end]), outSha256 = sha256(файл), inSha256 = sha256(оролт), prior = өмнөх
//     гарын үсгүүдийн cms_sha256 файл дахь дарааллаар.
func caAcceptsSealRegistration(t *testing.T, reg *eid.SealRegistration, in, out []byte, sealed []byte, reservedDoc string, reservedRev int) {
	t.Helper()
	if reg == nil {
		t.Fatal("SealRegistration nil")
	}
	raw, err := json.Marshal(reg)
	if err != nil || len(raw) > 64<<10 {
		t.Fatalf("JSON %d байт: %v", len(raw), err)
	}
	var b caSealRegisterBody
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil || dec.More() {
		t.Fatalf("CA DisallowUnknownFields: %v %s", err, raw)
	}
	if err := reg.Validate(); err != nil {
		t.Fatalf("normalizeSealRegister: %v", err)
	}
	cms, err := base64.StdEncoding.DecodeString(b.CMS)
	if err != nil || len(cms) == 0 || len(cms) > 28672 {
		t.Fatalf("cms: %d %v", len(cms), err)
	}
	sigs, err := validate.Extract(out)
	if err != nil || len(sigs) != b.RevIndex {
		t.Fatalf("Extract: %d гарын үсэг, revIndex %d: %v", len(sigs), b.RevIndex, err)
	}
	last := sigs[len(sigs)-1]
	cmsSum := sha256.Sum256(cms)
	if last.CMSSHA256 != hex.EncodeToString(cmsSum[:]) {
		t.Fatalf("cms_sha256 %s ≠ /Contents %s", hex.EncodeToString(cmsSum[:]), last.CMSSHA256)
	}
	for i, h := range b.PriorCMSSHA256 {
		if sigs[i].CMSSHA256 != h {
			t.Fatalf("priorCmsSha256[%d] %s ≠ файл %s", i, h, sigs[i].CMSSHA256)
		}
	}
	sum := func(p []byte) string { s := sha256.Sum256(p); return hex.EncodeToString(s[:]) }
	if b.InSHA256 != sum(in) || b.OutSHA256 != sum(out) || b.SigRevSHA256 != sum(out[:last.SignedEnd]) {
		t.Fatalf("hash: in %v out %v sigRev %v", b.InSHA256 == sum(in), b.OutSHA256 == sum(out), b.SigRevSHA256 == sum(out[:last.SignedEnd]))
	}
	// CA: SignedAttributesWithRole(messageDigest, signer, role) байт-ижил, SHA-256(signedAttrs) = тамгалсан digest.
	md, _ := hex.DecodeString(last.MessageDigest)
	cert, err := x509.ParseCertificate(last.Leaf)
	if err != nil {
		t.Fatal(err)
	}
	if !eid.IsSealCertificate(cert) || len(last.ClaimedRoles) != 0 {
		t.Fatalf("e-Seal %v, claimedRole %v", eid.IsSealCertificate(cert), last.ClaimedRoles)
	}
	attrs, err := core.SignedAttributesWithRole(md, cert, "")
	if err != nil || !bytes.Equal(core.DTBS(attrs), sealed) {
		t.Fatalf("SHA-256(signedAttrs) ≠ тамгалсан digest (CA SEAL_NOT_FOUND): %v", err)
	}
	if reservedDoc != "" && (reservedDoc != b.DocID || reservedRev != b.RevIndex) {
		t.Fatalf("нөөц %s/%d ≠ бүртгэл %s/%d (CA SEAL_DOC_MISMATCH)", reservedDoc, reservedRev, b.DocID, b.RevIndex)
	}
}

const sealRegDocID = "7a1b2c3d-4e5f-4a6b-8c7d-8e9f0a1b2c3d"

func TestSealPDFRegistrationQRless(t *testing.T) {
	p := loadOrCreatePKI(t)
	key, leaf := sealLeaf(t, p, x509.KeyUsageContentCommitment, 88101)
	in := readInput(t, "quartz-pdf13.pdf")
	s := &docSealer{fakeSealer: fakeSealer{cert: leaf.Raw, key: key}}
	o := sealOpts(p, leaf)
	o.FileName = " Нэхэмжлэх.pdf "
	res, err := SealPDF(context.Background(), s, "NTRMN-6235972", in, o)
	if err != nil {
		t.Fatal(err)
	}
	if s.reserved != 0 {
		t.Fatal("QR-гүй тамга docId нөөцлөх ёсгүй")
	}
	if res.SealRegistration == nil || res.SealRegistration.FileName != "Нэхэмжлэх.pdf" || res.SealRegistration.DocID != res.DocID ||
		res.SealRegistration.RevIndex != 1 || len(res.SealRegistration.PriorCMSSHA256) != 0 {
		t.Fatalf("%+v", res.SealRegistration)
	}
	caAcceptsSealRegistration(t, res.SealRegistration, in, res.PDF, s.digest, "", 0)
	if bytes.Contains(res.PDF, []byte("/EIDVerify")) {
		t.Fatal("QR-гүй дардас маркертай")
	}
	// Хэт урт нэр → REQUEST_INVALID (CA cleanFileName ≤ 120).
	o.FileName = strings.Repeat("а", 121)
	if _, err := SealPDF(context.Background(), s, "NTRMN-6235972", in, o); ErrorCode(err) != CodeRequestInvalid {
		t.Fatalf("fileName: %v", err)
	}
}

// TestSealPDFRegistrationQR — QR-тэй тамга: нөөц (docId, revIndex) = дардасны QR = бүртгэлийн бие; иргэний (verify
// хуудастай) баримтын дараа docId хуудаснаас, revIndex 2, prior = иргэний CMS.
func TestSealPDFRegistrationQR(t *testing.T) {
	p := loadOrCreatePKI(t)
	key, leaf := sealLeaf(t, p, x509.KeyUsageContentCommitment, 88102)
	marker := func(doc string, rev int) []byte {
		return []byte("/EIDVerify <</URL (https://ca.eidmongolia.mn/verify/" + doc + "/" + string(rune('0'+rev)) + ")>> BDC")
	}

	in := readInput(t, "quartz-pdf13.pdf")
	s := &docSealer{fakeSealer: fakeSealer{cert: leaf.Raw, key: key}}
	o := sealOpts(p, leaf)
	o.QR, o.DocID = true, sealRegDocID
	res, err := SealPDF(context.Background(), s, "NTRMN-6235972", in, o)
	if err != nil {
		t.Fatal(err)
	}
	if s.reserved != 1 || s.docID != sealRegDocID || s.revIndex != 1 || res.DocID != sealRegDocID || res.Placement == nil ||
		!bytes.Contains(res.PDF, marker(sealRegDocID, 1)) {
		t.Fatalf("нөөц %d %s/%d, docId %s, placement %+v", s.reserved, s.docID, s.revIndex, res.DocID, res.Placement)
	}
	caAcceptsSealRegistration(t, res.SealRegistration, in, res.PDF, s.digest, s.docID, s.revIndex)
	rep, err := Verify(res.PDF, VerifyOptions{Roots: [][]byte{p.root.cert.Raw}, Issuers: [][]byte{p.ca04.cert.Raw}, Time: goldenNow})
	if err != nil || rep.Indication != Valid || rep.Signatures[0].Certificate.Usage != "seal" || !rep.Signatures[0].Visible {
		b, _ := json.Marshal(rep)
		t.Fatalf("%v %s", err, b)
	}

	signed := citizenSign(t, p, readInput(t, "quartz-pdf13.pdf"))
	s2 := &docSealer{fakeSealer: fakeSealer{cert: leaf.Raw, key: key}}
	o2 := sealOpts(p, leaf)
	o2.QR = true
	res2, err := SealPDF(context.Background(), s2, "NTRMN-6235972", signed.PDF, o2)
	if err != nil {
		t.Fatal(err)
	}
	if s2.docID != signed.DocID || s2.revIndex != 2 || !bytes.Contains(res2.PDF[len(signed.PDF):], marker(signed.DocID, 2)) ||
		res2.SealRegistration == nil || len(res2.SealRegistration.PriorSignatures) != 1 {
		t.Fatalf("citizen-then-seal-qr: %s/%d %+v", s2.docID, s2.revIndex, res2.SealRegistration)
	}
	caAcceptsSealRegistration(t, res2.SealRegistration, signed.PDF, res2.PDF, s2.digest, s2.docID, s2.revIndex)
	cmsSum := sha256.Sum256(signed.CMS)
	if res2.SealRegistration.PriorCMSSHA256[0] != hex.EncodeToString(cmsSum[:]) {
		t.Fatal("prior ≠ иргэний CMS")
	}
}

// TestSealPDFRegistrationRejects — QR-д DocumentSealer заавал, Invisible-тэй хамт болохгүй, гарын үсэгтэй (docId олдохгүй)
// баримтад DocID заавал; QR-гүй тамга тэр үед бүртгэлгүй (SealRegistration nil) эсвэл SealOptions.DocID-оор.
func TestSealPDFRegistrationRejects(t *testing.T) {
	p := loadOrCreatePKI(t)
	key, leaf := sealLeaf(t, p, x509.KeyUsageContentCommitment, 88103)
	in := readInput(t, "quartz-pdf13.pdf")
	o := sealOpts(p, leaf)
	o.QR = true
	plain := &fakeSealer{cert: leaf.Raw, key: key}
	if _, err := SealPDF(context.Background(), plain, "NTRMN-6235972", in, o); ErrorCode(err) != CodeRequestInvalid || plain.digest != nil {
		t.Fatalf("QR + Sealer (нөөцгүй): %v", err)
	}
	s := &docSealer{fakeSealer: fakeSealer{cert: leaf.Raw, key: key}}
	o.Invisible = true
	if _, err := SealPDF(context.Background(), s, "NTRMN-6235972", in, o); ErrorCode(err) != CodeRequestInvalid || s.digest != nil {
		t.Fatalf("QR + Invisible: %v", err)
	}

	// QR-гүй, үл харагдах тамгатай баримт (verify хуудас, маркер алга) → дараагийн тамгын docId олдохгүй.
	inv := sealOpts(p, leaf)
	inv.Invisible = true
	first, err := SealPDF(context.Background(), s, "NTRMN-6235972", in, inv)
	if err != nil {
		t.Fatal(err)
	}
	second, err := SealPDF(context.Background(), s, "NTRMN-6235972", first.PDF, sealOpts(p, leaf))
	if err != nil || second.DocID != "" || second.SealRegistration != nil {
		t.Fatalf("docId-гүй: %v %q %+v", err, second.DocID, second.SealRegistration)
	}
	if _, err := SealRegistration(second); ErrorCode(err) != CodeRequestInvalid {
		t.Fatalf("SealRegistration docId-гүй: %v", err)
	}
	qr := sealOpts(p, leaf)
	qr.QR = true
	n := s.reserved
	if _, err := SealPDF(context.Background(), s, "NTRMN-6235972", first.PDF, qr); ErrorCode(err) != CodeRequestInvalid || s.reserved != n {
		t.Fatalf("QR, docId-гүй: %v", err)
	}
	withID := sealOpts(p, leaf)
	withID.DocID = first.DocID
	third, err := SealPDF(context.Background(), s, "NTRMN-6235972", first.PDF, withID)
	if err != nil || third.SealRegistration == nil || third.SealRegistration.RevIndex != 2 {
		t.Fatalf("SealOptions.DocID: %v %+v", err, third)
	}
	caAcceptsSealRegistration(t, third.SealRegistration, first.PDF, third.PDF, s.digest, "", 0)

	// Иргэний Completed → SealRegistration REQUEST_INVALID (Registration ашиглана).
	if _, err := SealRegistration(citizenSign(t, p, in)); ErrorCode(err) != CodeRequestInvalid {
		t.Fatalf("иргэн: %v", err)
	}
	if _, err := SealRegistration(nil); ErrorCode(err) != CodeRequestInvalid {
		t.Fatal(err)
	}
}

// TestSealPDFQRMatchesGolden — SealOptions.QR нь golden v13-ийн `seal-qr-visible` / `seal-qr-visible-en`-ийн DTBS-тэй
// байт-ижил (prepared PDF + signedAttrs; дотоод sealQR-тэй ижил зам — шинэ golden байт үгүй), нөөц = (golden docId, 1).
func TestSealPDFQRMatchesGolden(t *testing.T) {
	p := loadOrCreatePKI(t)
	var m goldenManifest
	if err := json.Unmarshal(readTestdata(t, "golden/manifest.json"), &m); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{}
	for _, c := range m.Cases {
		want[c.Name] = c.Expect.DTBS
	}
	chain := [][]byte{p.ca04.cert.Raw, p.ca03.cert.Raw, p.ca02.cert.Raw}
	for _, c := range []struct {
		golden, input string
		o             SealOptions
	}{
		{"seal-qr-visible", "libreoffice-contract.pdf", SealOptions{Reason: "Нэхэмжлэх", DocID: qrSealDocID,
			Appearance: &Appearance{X: 356, Y: 36, Width: 220, Height: 64}}},
		{"seal-qr-visible-en", "quartz-pdf13.pdf", SealOptions{DocID: "9d0e1f2a-3b4c-4d5e-9f6a-7b8c9d0e1f2a",
			Appearance: &Appearance{X: 340, Y: 36, Width: 220, Height: 64, Lang: "en"}}},
	} {
		s := &docDTBSSealer{dtbsSealer: dtbsSealer{cert: p.seal.cert.Raw}}
		c.o.SigningTime, c.o.Chain, c.o.QR = goldenTime, chain, true
		if _, err := SealPDF(context.Background(), s, "NTRMN-0000000", readInput(t, c.input), c.o); !errors.Is(err, errSealStop) {
			t.Fatalf("%s: %v", c.golden, err)
		}
		if got := hex.EncodeToString(s.digest); want[c.golden] == "" || got != want[c.golden] {
			t.Errorf("%s: SealPDF(QR) DTBS %s ≠ golden %s", c.golden, got, want[c.golden])
		}
		if s.docID != c.o.DocID || s.revIndex != 1 {
			t.Errorf("%s: нөөц %s/%d", c.golden, s.docID, s.revIndex)
		}
	}
}

type docDTBSSealer struct {
	dtbsSealer
	docID    string
	revIndex int
}

func (d *docDTBSSealer) SealForDocument(ctx context.Context, org string, digest []byte, docID string, revIndex int) (*eid.SealResult, error) {
	d.docID, d.revIndex = docID, revIndex
	return d.Seal(ctx, org, digest, eid.SHA256)
}
