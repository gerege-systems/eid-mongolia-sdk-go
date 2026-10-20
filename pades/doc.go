// Package pades — клиент талын PAdES (PDF гарын үсэг): PDF eID-ийн серверт очихгүй; CA зөвхөн hash (DTBS) зурна.
// Client-side PAdES baseline B-LT for eID Mongolia: the PDF never leaves the caller; the CA signs only a 32-byte hash.
//
// Гурван алхам:
//
//	p, err := pades.Prepare(pdf, pades.PrepareOptions{SignerCert: cert, VerifyPage: true, FileName: "Гэрээ.pdf"})
//	// p.DTBS (32 байт) → RP-API RAW_DIGEST_SIGNATURE session (утас) эсвэл токены C_Sign; p.State-ийг хадгална
//	c, err := pades.Complete(ctx, p.State, signature, pades.CompleteOptions{})
//	// c.PDF — PAdES-BASELINE-LT; c.CMS, c.DocID, c.RevIndex … — CA-ийн бүртгэлд (POST /pdf/signatures)
//	rep, err := pades.ValidatePDF(ctx, c.PDF, pades.ValidateOptions{}) // Verify — Deprecated
//
// Complete: гарын үсгийг DTBS дээр шалгана (RSA PKCS#1 v1.5, ECDSA r‖s эсвэл DER) → RFC 3161 timestamp
// (DefaultTSAURL) → CMS → placeholder-т бичнэ → OCSP/CRL-ийг гэрчилгээний AIA/CDP-ээс (иргэн, TSA-ийн OCSP нь
// genTime-аас хожуу) → DSS revision → CA-ийн нийтийн шалгагчийн кодоор self-validation. Аль нэг алхам унавал файл
// буцаахгүй (*Error, Code-оор).
//
// Профайл (pades-client/1) нь ca-eidmongolia-mn-ийн server/internal/pdfsign/pades бичигчийн 1:1 extract — ижил
// оролтод CA-тай ижил байт; гинжийн итгэлийн тулгуур нь зөвхөн Mongolian National Root CA (шигтгэсэн 01; 02–05 нь
// завсрын). Golden vector: testdata/golden.
package pades
