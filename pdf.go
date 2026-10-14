package eid

import "time"

// PDFService — клиент талын PAdES-ийн CA-ийн хэсэг: PDF eID-ийн сервер рүү ОЧИХГҮЙ. RP PDF-ээ өөрөө угсарна
// (pades.Prepare → Sign.DigestForSigner / DeviceLinkForSigner-ээр DTBS-д гарын үсэг → pades.Complete), дараа нь
// RegisterSignature-аар CA-ийн бүртгэлд (docID, /verify) оруулна.
type PDFService struct {
	h       *httpDoer
	timeout time.Duration
}
