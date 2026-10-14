package eid

import (
	"crypto/x509"
	"encoding/asn1"
)

// Subject — иргэний гэрчилгээний subject-ийн талбарууд (RFC 5280 / ETSI EN 319 412-2).
type Subject struct {
	// GivenName — GIVENNAME (2.5.4.42), латин (ICAO, том үсэг).
	GivenName string
	// Surname — SURNAME (2.5.4.4), эцэг/эхийн нэр, латин.
	Surname string
	// CommonName — CN.
	CommonName string
	// SerialNumber — SERIALNUMBER (2.5.4.5): ETSI таних тэмдэг, ж: PNOMN-<иргэний дугаар> / NTRMN-<бүртгэл>.
	SerialNumber string
	// Country — C (ж: MN).
	Country string
}

var (
	oidGivenName = asn1.ObjectIdentifier{2, 5, 4, 42}
	oidSurname   = asn1.ObjectIdentifier{2, 5, 4, 4}
)

// ParseSubject — гэрчилгээний subject-оос нэр, ETSI дугаар, улсыг задална. Олон утгатай атрибутаас эхнийхийг авна.
func ParseSubject(cert *x509.Certificate) Subject {
	if cert == nil {
		return Subject{}
	}
	s := Subject{CommonName: cert.Subject.CommonName, SerialNumber: cert.Subject.SerialNumber}
	if len(cert.Subject.Country) > 0 {
		s.Country = cert.Subject.Country[0]
	}
	for _, a := range cert.Subject.Names {
		v, ok := a.Value.(string)
		if !ok {
			continue
		}
		switch {
		case a.Type.Equal(oidGivenName) && s.GivenName == "":
			s.GivenName = v
		case a.Type.Equal(oidSurname) && s.Surname == "":
			s.Surname = v
		}
	}
	return s
}
