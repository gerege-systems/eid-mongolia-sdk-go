package validate

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"testing"
)

// citizenTmpl — иргэний SIGN (PIN2) профайл: contentCommitment, нэр нь GIVENNAME + SURNAME.
func citizenTmpl(given, surname string) *x509.Certificate {
	return &x509.Certificate{
		Subject: pkix.Name{
			CommonName: surname + "," + given, SerialNumber: "PNOMN-1234567890",
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier{2, 5, 4, 42}, Value: given},
				{Type: asn1.ObjectIdentifier{2, 5, 4, 4}, Value: surname},
			},
		},
		KeyUsage: x509.KeyUsageContentCommitment | x509.KeyUsageDigitalSignature,
	}
}

func wantName(t *testing.T, s SignatureReport, name, claimed, source string) {
	t.Helper()
	if s.SignerName != name || s.ClaimedName != claimed || s.SignerNameSource != source {
		t.Fatalf("signer_name=%q claimed_name=%q source=%q; хүлээсэн %q / %q / %q (%s %v)",
			s.SignerName, s.ClaimedName, s.SignerNameSource, name, claimed, source, s.Indication, s.Problems)
	}
}

// (a) Иргэн өөрийн SIGN гэрчилгээгээр жинхэнэ PAdES гарын үсэг угсарч, /Name-д өөр хүний нэр бичсэн:
// signer_name нь PDF-ийн текст БИШ, гэрчилгээний нэр байх ёстой. signPDF /Name-д «Бат Болд» бичдэг.
func TestSignerNameCitizenCertIgnoresClaimedName(t *testing.T) {
	p := newPKI(t)
	citizen := issue(t, p.issuing, citizenTmpl("DORJ", "ATTACKER"))
	s := only(t, mustPDF(t, p.validator(good), signPDF(t, minimalPDF(t), citizen, []*x509.Certificate{p.issuing.cert}, "")))
	if s.Indication != Valid || !s.ChainTrusted || s.Certificate.Usage != "sign" {
		t.Fatalf("урьдчилсан нөхцөл: %s %v usage=%s", s.Indication, s.Problems, s.Certificate.Usage)
	}
	wantName(t, s, "DORJ ATTACKER", "Бат Болд", SignerNameCertificate)
}

// GIVENNAME/SURNAME-гүй гэрчилгээ (тамга г.м.) → CommonName.
func TestSignerNameFallsBackToCommonName(t *testing.T) {
	p := newPKI(t)
	seal := issue(t, p.issuing, &x509.Certificate{Subject: pkix.Name{CommonName: "Org Seal LLC"}, KeyUsage: x509.KeyUsageContentCommitment})
	s := only(t, mustPDF(t, p.validator(good), signPDF(t, minimalPDF(t), seal, []*x509.Certificate{p.issuing.cert}, "")))
	wantName(t, s, "Org Seal LLC", "Бат Болд", SignerNameCertificate)
}

// (b) Манай issuing CA-аас гарсан doc-signer профайл: /Name-ийг зөвхөн платформ бичдэг → platform_attested.
func TestSignerNamePlatformAttested(t *testing.T) {
	p := newPKI(t)
	s := only(t, mustPDF(t, p.validator(good), signPDF(t, minimalPDF(t), p.leaf, []*x509.Certificate{p.issuing.cert}, "")))
	if s.Indication != Valid {
		t.Fatalf("урьдчилсан нөхцөл: %s %v", s.Indication, s.Problems)
	}
	wantName(t, s, "Бат Болд", "Бат Болд", SignerNamePlatformAttested)
}

// (c) documentSigning EKU-тэй ч манай issuing CA-аас гараагүй / гинж нь итгэмжлэгдээгүй → platform_attested БИШ.
func TestSignerNameDocSigningEKUNotOursIsNotAttested(t *testing.T) {
	p := newPKI(t)
	docTmpl := func() *x509.Certificate {
		return &x509.Certificate{
			Subject: pkix.Name{CommonName: "Fake Document Signer"}, KeyUsage: x509.KeyUsageDigitalSignature,
			UnknownExtKeyUsage: []asn1.ObjectIdentifier{oidEKUDocumentSigning},
		}
	}
	t.Run("үндэсний root-ийн дор, өөр sub-CA", func(t *testing.T) {
		otherCA := issue(t, p.root, caTmpl("Other Provider CA"))
		signer := issue(t, otherCA, docTmpl())
		s := only(t, mustPDF(t, p.validator(good), signPDF(t, minimalPDF(t), signer, []*x509.Certificate{otherCA.cert}, "")))
		if !s.ChainTrusted || s.Certificate.Usage != "document_signer" || s.Certificate.IssuedByEID {
			t.Fatalf("урьдчилсан нөхцөл: %+v", s)
		}
		wantName(t, s, "Fake Document Signer", "Бат Болд", SignerNameCertificate)
	})
	t.Run("гадны root (итгэмжлэгдээгүй гинж), манай issuing CA-ийн нэртэй", func(t *testing.T) {
		foreign := newPKI(t) // CA-ийн subject нь манайхтай ижил, түлхүүр өөр
		s := only(t, mustPDF(t, p.validator(good), signPDF(t, minimalPDF(t), foreign.leaf, []*x509.Certificate{foreign.issuing.cert}, "")))
		if s.ChainTrusted {
			t.Fatalf("урьдчилсан нөхцөл: гинж итгэмжлэгдсэн гэж гарлаа")
		}
		wantName(t, s, "eID Mongolia Document Signer", "Бат Болд", SignerNameCertificate)
	})
	t.Run("self-signed doc-signer", func(t *testing.T) {
		self := issue(t, nil, docTmpl())
		s := only(t, mustPDF(t, p.validator(good), signPDF(t, minimalPDF(t), self, nil, "")))
		wantName(t, s, "Fake Document Signer", "Бат Болд", SignerNameCertificate)
	})
}

// (d) Бүрэн бүтэн байдал нь эвдэрсэн doc-signer гарын үсэг → platform_attested БИШ.
func TestSignerNameIntegrityBrokenIsNotAttested(t *testing.T) {
	p := newPKI(t)
	signed := signPDF(t, minimalPDF(t), p.leaf, []*x509.Certificate{p.issuing.cert}, "")
	i := bytes.Index(signed, []byte("Validate test content"))
	if i < 0 {
		t.Fatal("тестийн текст олдсонгүй")
	}
	signed[i] ^= 0x01
	s := only(t, mustPDF(t, p.validator(good), signed))
	if s.Indication != Invalid {
		t.Fatalf("урьдчилсан нөхцөл: %s %v", s.Indication, s.Problems)
	}
	wantName(t, s, "eID Mongolia Document Signer", "Бат Болд", SignerNameCertificate)
}

// Цуцлагдсан (түлхүүр алдагдсан байж болох) doc-signer-ийн /Name-ийг платформын баталгаа гэж үзэхгүй.
func TestSignerNameRevokedDocSignerIsNotAttested(t *testing.T) {
	p := newPKI(t)
	signed := signPDF(t, minimalPDF(t), p.leaf, []*x509.Certificate{p.issuing.cert}, "")
	s := only(t, mustPDF(t, p.validator(fakeStatus{st: CertStatus{Issued: true, Revoked: true}}), signed))
	wantName(t, s, "eID Mongolia Document Signer", "Бат Болд", SignerNameCertificate)
}

// Бүтэц эвдэрсэн / гэрчилгээ задраагүй → signer_name хоосон, unverified; claimed_name түүхий текстээр.
func TestSignerNameMalformedIsUnverified(t *testing.T) {
	p := newPKI(t)
	v := p.validator(good)
	wantName(t, v.evaluateSignature(RawSignature{SignerName: "Victim", Malformed: true}), "", "Victim", SignerNameUnverified)
	wantName(t, v.evaluateSignature(RawSignature{SignerName: "Victim", Integrity: true, Leaf: []byte("der биш")}), "", "Victim", SignerNameUnverified)
}

// JSON гэрээ: signer_name хэвээр, шинэ талбарууд нэмэгдсэн.
func TestSignerNameJSONFields(t *testing.T) {
	p := newPKI(t)
	rep := mustPDF(t, p.validator(good), signPDF(t, minimalPDF(t), p.leaf, []*x509.Certificate{p.issuing.cert}, ""))
	raw, err := json.Marshal(rep.Signatures[0])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m["signer_name"] != "Бат Болд" || m["claimed_name"] != "Бат Болд" || m["signer_name_source"] != "platform_attested" {
		t.Fatalf("JSON: %s", raw)
	}
}

// civil_id — файл дахь иргэний гэрчилгээний SERIALNUMBER (PNOMN-…)-ээс бүтнээр; иргэний биш гэрчилгээ (тамга,
// doc-signer) → талбар огт гарахгүй.
func TestSignatureCivilIDFromFileCertificate(t *testing.T) {
	p := newPKI(t)
	citizen := issue(t, p.issuing, citizenTmpl("DORJ", "BAT"))
	s := only(t, mustPDF(t, p.validator(good), signPDF(t, minimalPDF(t), citizen, []*x509.Certificate{p.issuing.cert}, "")))
	if s.CivilID != "1234567890" {
		t.Fatalf("civil_id %q", s.CivilID)
	}
	raw, _ := json.Marshal(s)
	if !bytes.Contains(raw, []byte(`"civil_id":"1234567890"`)) {
		t.Fatalf("JSON: %s", raw)
	}
	seal := issue(t, p.issuing, &x509.Certificate{Subject: pkix.Name{CommonName: "Org Seal LLC", SerialNumber: "NTRMN-1234567"}, KeyUsage: x509.KeyUsageContentCommitment})
	s = only(t, mustPDF(t, p.validator(good), signPDF(t, minimalPDF(t), seal, []*x509.Certificate{p.issuing.cert}, "")))
	if raw, _ := json.Marshal(s); s.CivilID != "" || bytes.Contains(raw, []byte("civil_id")) {
		t.Fatalf("иргэний биш гэрчилгээнд civil_id: %s", raw)
	}
}
