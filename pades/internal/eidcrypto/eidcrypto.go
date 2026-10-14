// Package eidcrypto — CA-ийн server/internal/crypto-оос PAdES-д хэрэгтэй хэсэг (TSA EKU профайл, хүнд харуулах нэр).
// Эх: ca-eidmongolia-mn server/internal/crypto/{ca_profile_tsa.go,subject_name.go} — өөрчлөлтгүй.
package eidcrypto

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"strings"
)

var (
	oidExtExtKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidKPTimeStamping = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidGivenName      = asn1.ObjectIdentifier{2, 5, 4, 42}
	oidSurname        = asn1.ObjectIdentifier{2, 5, 4, 4}
)

// TSAEKUExtension — critical ExtendedKeyUsage { id-kp-timeStamping } (RFC 3161 §2.3).
func TSAEKUExtension() pkix.Extension {
	// SEQUENCE { OID 1.3.6.1.5.5.7.3.8 } — тогтмол DER; asn1.Marshal энд унах боломжгүй.
	val, _ := asn1.Marshal([]asn1.ObjectIdentifier{oidKPTimeStamping})
	return pkix.Extension{Id: oidExtExtKeyUsage, Critical: true, Value: val}
}

// IsTSASigningCert — RFC 3161 §2.3: TSA-ийн гарын үсгийн cert-ийн EKU extension ЗААВАЛ байх, critical,
// агуулга нь яг { id-kp-timeStamping }. Go-ийн Verify(KeyUsages: timeStamping) нь EKU extension-гүй
// leaf-ийг «бүх хэрэглээнд» гэж үзэж хүлээн авдаг — тиймээс гинжийн шалгалтын ДЭЭР үүнийг шаардана.
func IsTSASigningCert(c *x509.Certificate) bool {
	n := 0
	for _, e := range c.Extensions {
		if !e.Id.Equal(oidExtExtKeyUsage) {
			continue
		}
		n++
		var oids []asn1.ObjectIdentifier
		if rest, err := asn1.Unmarshal(e.Value, &oids); err != nil || len(rest) != 0 || !e.Critical ||
			len(oids) != 1 || !oids[0].Equal(oidKPTimeStamping) {
			return false
		}
	}
	return n == 1
}

// SubjectDisplayName — гэрчилгээний subject-ээс хүнд харуулах нэр: GIVENNAME + SURNAME, аль аль нь
// байхгүй бол CommonName.
func SubjectDisplayName(cert *x509.Certificate) string {
	given, surname := SubjectNames(cert)
	if name := strings.TrimSpace(given + " " + surname); name != "" {
		return name
	}
	return cert.Subject.CommonName
}

// SubjectNames — subject-ийн GIVENNAME (2.5.4.42) ба SURNAME (2.5.4.4).
func SubjectNames(cert *x509.Certificate) (given, surname string) {
	for _, n := range cert.Subject.Names {
		switch {
		case n.Type.Equal(oidGivenName):
			given, _ = n.Value.(string)
		case n.Type.Equal(oidSurname):
			surname, _ = n.Value.(string)
		}
	}
	return given, surname
}
