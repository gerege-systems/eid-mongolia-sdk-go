package core

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
	"unicode/utf8"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// CMS SignedData (CAdES baseline, detached) — §4.2. encoding/asn1-ийн оронд cryptobyte: signedAttrs-ийн
// DER (SET OF эрэмбэ) болон [0]/[1] IMPLICIT tag-ийг байт түвшинд хянах.

var (
	oidData              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidContentType       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningCertV2     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
	oidTimeStampToken    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}
	oidSHA256            = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA256WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidECDSAWithSHA256   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	errUnsupportedSigner = errors.New("pades: гарын үсгийн түлхүүрийн төрөл дэмжигдэхгүй (RSA эсвэл ECDSA P-256)")
)

var (
	// OIDSignerAttrV2 — CAdES signer-attributes-v2 (ETSI EN 319 122-1 §5.2.6.1, id-aa-ets-signerAttrV2).
	OIDSignerAttrV2 = asn1.ObjectIdentifier{0, 4, 0, 19122, 1, 1}
	// OIDRole — X.520 id-at-role: claimedAttributes-ийн төрөл (EU DSS-ийн бичдэгтэй ижил, утга нь UTF8String).
	OIDRole = asn1.ObjectIdentifier{2, 5, 4, 72}
)

// SignedAttributes — DER SET OF Attribute (tag 0x31): contentType = id-data, messageDigest = digest,
// signingCertificateV2 (ESSCertIDv2: certHash = SHA-256(cert), issuerSerial; hashAlgorithm анхдагч тул
// орхино). signingTime БАЙХГҮЙ (PAdES baseline — цаг /M ба timestamp-д). Утас зурах DTBS = SHA-256(үүний).
func SignedAttributes(messageDigest []byte, signer *x509.Certificate) ([]byte, error) {
	return SignedAttributesWithRole(messageDigest, signer, "")
}

// ClaimedRoleMaxRunes — мэдүүлсэн үүргийн (claimed role) дээд урт, тэмдэгтээр (албан тушаал ≤ 255 + нэр ≤ 512 +
// NTRMN-… — pdf_signatures.claimed_role varchar(900)).
const ClaimedRoleMaxRunes = 900

// SignedAttributesWithRole — SignedAttributes + claimedRole хоосон биш бол signer-attributes-v2:
//
//	SignerAttributeV2 ::= SEQUENCE { claimedAttributes [0] EXPLICIT SEQUENCE OF Attribute }
//	Attribute ::= SEQUENCE { type id-at-role (2.5.4.72), values SET { UTF8String } }
//
// EU DSS (CAdESLevelBaselineB.addSignerAttribute) яг ийм бүтэцтэй бичиж, CAdESSignature.getClaimedSignerRoles нь
// ASN1String утгыг «ClaimedRole» болгон харуулдаг. Үүрэг нь гарын үсэг зурагчийн мэдүүлэг (CMS-д гарын үсэгтэй);
// eID нь prepare болон finalize-д бүртгэлээр шалгасан (docs/PADES_SIGNING.md §16).
func SignedAttributesWithRole(messageDigest []byte, signer *x509.Certificate, claimedRole string) ([]byte, error) {
	if len(messageDigest) != sha256.Size {
		return nil, errors.New("pades: messageDigest SHA-256 биш")
	}
	if claimedRole != "" && (!utf8.ValidString(claimedRole) || utf8.RuneCountInString(claimedRole) > ClaimedRoleMaxRunes) {
		return nil, errors.New("pades: claimed role буруу эсвэл хэт урт")
	}
	certHash := sha256.Sum256(signer.Raw)
	type attr struct {
		oid asn1.ObjectIdentifier
		val func(*cryptobyte.Builder)
	}
	extra := []attr{}
	if claimedRole != "" {
		extra = append(extra, attr{OIDSignerAttrV2, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // SignerAttributeV2
				b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) { // [0] EXPLICIT
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // ClaimedAttributes
						b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // Attribute
							b.AddASN1ObjectIdentifier(OIDRole)
							b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
								b.AddASN1(cbasn1.UTF8String, func(b *cryptobyte.Builder) { b.AddBytes([]byte(claimedRole)) })
							})
						})
					})
				})
			})
		}})
	}
	attrs := make([][]byte, 0, 4)
	for _, a := range append([]attr{
		{oidContentType, func(b *cryptobyte.Builder) { b.AddASN1ObjectIdentifier(oidData) }},
		{oidMessageDigest, func(b *cryptobyte.Builder) { b.AddASN1OctetString(messageDigest) }},
		{oidSigningCertV2, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // SigningCertificateV2
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // certs SEQUENCE OF ESSCertIDv2
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // ESSCertIDv2
						b.AddASN1OctetString(certHash[:])
						b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // IssuerSerial
							b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // GeneralNames
								// directoryName [4] EXPLICIT Name
								b.AddASN1(cbasn1.Tag(4).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
									b.AddBytes(signer.RawIssuer)
								})
							})
							b.AddASN1BigInt(signer.SerialNumber)
						})
					})
				})
			})
		}},
	}, extra...) {
		var b cryptobyte.Builder
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(a.oid)
			b.AddASN1(cbasn1.SET, a.val)
		})
		der, err := b.Bytes()
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, der)
	}
	// DER SET OF — элементийг кодчилсон байтаар өсөхөөр эрэмбэлнэ (X.690 §11.6).
	slices.SortFunc(attrs, bytes.Compare)
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
		for _, a := range attrs {
			b.AddBytes(a)
		}
	})
	return b.Bytes()
}

// DTBS — утсанд зурагдах 32 байт: SHA-256(DER(signedAttrs) SET OF tag-тай) (RFC 5652 §5.4).
func DTBS(signedAttrs []byte) []byte {
	s := sha256.Sum256(signedAttrs)
	return s[:]
}

// SignatureAlgorithmFor — SignerInfo.signatureAlgorithm-ийн нэр (session-д): RSA → sha256WithRSAEncryption
// (PKCS#1 v1.5, §4.2 яагаад PSS биш), ECDSA (legacy threshold) → ecdsa-with-SHA256.
func SignatureAlgorithmFor(cert *x509.Certificate) (string, error) {
	switch cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "sha256WithRSAEncryption", nil
	case *ecdsa.PublicKey:
		return "ecdsa-with-SHA256", nil
	}
	return "", errUnsupportedSigner
}

// AssembleCMS — ContentInfo{SignedData} угсарна: certificates = signer + chain (root-гүй), SignerInfo
// (issuerAndSerialNumber, SHA-256, signedAttrs [0], алгоритм, гарын үсэг, unsignedAttrs [1] =
// signatureTimeStampToken). tst хоосон бол unsignedAttrs-гүй (зөвхөн тест/хэмжилтэд — prod TSA заавал).
func AssembleCMS(signedAttrs []byte, signer *x509.Certificate, chain []*x509.Certificate, signature, tst []byte) ([]byte, error) {
	if len(signedAttrs) < 2 || signedAttrs[0] != 0x31 {
		return nil, errors.New("pades: signedAttrs нь DER SET биш")
	}
	var sigAlg asn1.ObjectIdentifier
	switch signer.PublicKey.(type) {
	case *rsa.PublicKey:
		sigAlg = oidSHA256WithRSA
	case *ecdsa.PublicKey:
		sigAlg = oidECDSAWithSHA256
	default:
		return nil, errUnsupportedSigner
	}
	// [0] IMPLICIT SET OF Attribute: SET tag-ийг 0xA0 болгоно (агуулга нь ижил).
	implicitAttrs := bytes.Clone(signedAttrs)
	implicitAttrs[0] = 0xA0

	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // ContentInfo
		b.AddASN1ObjectIdentifier(oidSignedData)
		b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // SignedData
				b.AddASN1Int64(1)
				b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
					addAlgID(b, oidSHA256, false)
				})
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // EncapsulatedContentInfo (detached)
					b.AddASN1ObjectIdentifier(oidData)
				})
				// certificates [0] IMPLICIT SET OF — DER: кодчилсон байтаар өсөхөөр (X.690 §11.6).
				certs := [][]byte{signer.Raw}
				for _, c := range chain {
					if !c.Equal(signer) {
						certs = append(certs, c.Raw)
					}
				}
				slices.SortFunc(certs, bytes.Compare)
				b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) { // certificates
					for _, c := range certs {
						b.AddBytes(c)
					}
				})
				b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) { // signerInfos
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // SignerInfo
						b.AddASN1Int64(1)
						b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // IssuerAndSerialNumber
							b.AddBytes(signer.RawIssuer)
							b.AddASN1BigInt(signer.SerialNumber)
						})
						addAlgID(b, oidSHA256, false)
						b.AddBytes(implicitAttrs)
						addAlgID(b, sigAlg, sigAlg.Equal(oidSHA256WithRSA))
						b.AddASN1OctetString(signature)
						if len(tst) > 0 {
							b.AddASN1(cbasn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
								b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
									b.AddASN1ObjectIdentifier(oidTimeStampToken)
									b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) { b.AddBytes(tst) })
								})
							})
						}
					})
				})
			})
		})
	})
	out, err := b.Bytes()
	if err != nil {
		return nil, fmt.Errorf("pades: CMS угсрах: %w", err)
	}
	return out, nil
}

// addAlgID — AlgorithmIdentifier; nullParams — RSA PKCS#1 алгоритмд NULL параметр (RFC 4055 §5).
func addAlgID(b *cryptobyte.Builder, oid asn1.ObjectIdentifier, nullParams bool) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oid)
		if nullParams {
			b.AddASN1NULL()
		}
	})
}
