package eidcrypto

import (
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"fmt"
)

// Нийтийн PKI гинж (ca-eidmongolia-mn pki/chain, 2026-09-28-ийн 04/05). Итгэлийн тулгуур нь зөвхөн 01; бусад нь
// гинж бүтээх завсрын CA.
var (
	//go:embed chain/01-mongolian-national-root-ca.pem
	root01 []byte
	//go:embed chain/02-mongolian-national-issuing-ca-mddc.pem
	ca02 []byte
	//go:embed chain/03-gerege-issuing-ca.pem
	ca03 []byte
	//go:embed chain/04-eid-mongolia-issuing-ca.pem
	ca04 []byte
	//go:embed chain/05-eid-mongolia-org-issuing-ca.pem
	ca05 []byte
)

func mustCert(p []byte) *x509.Certificate {
	b, _ := pem.Decode(p)
	if b == nil {
		panic("eidcrypto: шигтгэсэн PEM задарсангүй")
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		panic(fmt.Sprintf("eidcrypto: шигтгэсэн гэрчилгээ: %v", err))
	}
	return c
}

// NationalRoot — Mongolian National Root CA (01).
func NationalRoot() *x509.Certificate { return mustCert(root01) }

// Intermediates — 02, 03, 04, 05.
func Intermediates() []*x509.Certificate {
	return []*x509.Certificate{mustCert(ca02), mustCert(ca03), mustCert(ca04), mustCert(ca05)}
}

// Issuers — eID-ийн иргэн/байгууллагын гэрчилгээ олгогч CA (04, 05).
func Issuers() []*x509.Certificate { return []*x509.Certificate{mustCert(ca04), mustCert(ca05)} }
