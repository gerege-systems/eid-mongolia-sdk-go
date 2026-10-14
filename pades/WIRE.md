# Сүлжээний хүсэлтийн байт (pades-client/1)

Golden-ийн HTTP fixture түлхүүр = `"<METHOD> <URL> <hex(SHA-256(body))[0:16]>"` (GET-д body хоосон →
`e3b0c44298fc1c14`) тул хүсэлтийн БАЙТ нь гэрээний нэг хэсэг. Reference: `pades/tsa.go` (`digitorus/timestamp`
`Request.Marshal`), `pades/ltv.go` (`x/crypto/ocsp CreateRequest`).

## 1. RFC 3161 TSA

`POST <tsaUrl>` (анхдагч `https://tsa.timeserver.mn/`), `Content-Type: application/timestamp-query`, body:

```
TimeStampReq ::= SEQUENCE {
  version        INTEGER 1                                    02 01 01
  messageImprint SEQUENCE {
    hashAlgorithm SEQUENCE { OID sha256, NULL }              30 0d 06 09 608648016503040201 05 00
    hashedMessage OCTET STRING (32) = SHA-256(SignerInfo.signature)   04 20 …
  }
  -- reqPolicy байхгүй
  nonce          INTEGER (64 бит, DER хамгийн богино)
  certReq        BOOLEAN TRUE                                 01 01 ff
}
```

- `signature` = CMS SignerInfo-д бичигдэх байт (RSA хэвээр; ECDSA — DER).
- nonce = эх үүсвэрээс 8 байт уншаад big-endian эерэг бүхэл: DER INTEGER — эхний тэг байтуудыг хасна, дээд бит 1 бол
  `00` угтвар (`02 09 00 …`), 0 бол `02 01 00`. Production-д криптограф санамсаргүй; golden-д §3.
- Хариу `application/timestamp-reply`, ≤ 4 MiB, HTTP 200. Шалгах: status granted, token-ийн nonce = хүсэлтийнх,
  imprint SHA-256 таарна, TSA signer cert: EKU extension яг `{timeStamping}` ба critical, гинж roots-д (token-ийн бусад
  cert = intermediate) genTime-д хүчинтэй; `|now − genTime| ≤ 10 мин`; token-д гэрчилгээ байх. Унавал `TSA_UNAVAILABLE`.

Жишээ (signature = ASCII `example signature bytes`, nonce = `9817c2613697bd4d`):

```
3044 020101 3031 300d0609608648016503040201 0500 0420 9a68ee19b28bcddef1da4964977ae0a070eafb5ccfcbb300b03d4fb9f1ebbfd6
     0209 009817c2613697bd4d 0101ff
nonce 8001020304050607 → 0209 008001020304050607 ;  nonce 0000010203040506 → 0206 010203040506 (дараалсан 3041…)
```

## 2. OCSP (RFC 6960, RFC 5019 профайл)

`POST <AIA OCSP URL>` (гэрчилгээний AIA-д бичигдсэн дарааллаар), `Content-Type: application/ocsp-request`, body:

```
OCSPRequest ::= SEQUENCE { tbsRequest SEQUENCE { requestList SEQUENCE OF { Request SEQUENCE {
  reqCert CertID SEQUENCE {
    hashAlgorithm  SEQUENCE { OID sha1 1.3.14.3.2.26, NULL }  300906052b0e03021a0500
    issuerNameHash OCTET STRING SHA-1(issuer.subject Name DER)
    issuerKeyHash  OCTET STRING SHA-1(issuer SubjectPublicKeyInfo-ийн subjectPublicKey BIT STRING-ийн агуулга)
    serialNumber   INTEGER (cert serial, DER)
  } } } } }
-- version, requestorName, extensions (nonce) БАЙХГҮЙ; optionalSignature үгүй
```

Жишээ (golden тестийн иргэн, serial 0x03ED, олгогч = `pki/04.pem`):

```
3043 3041 303f 303d 303b 300906052b0e03021a0500
  0414 66d7a67d8f5b73eb50670437691b40eaf94c3b86
  0414 1722dd2dafa7e06b2a74a1c92a1d0ba6da740df9
  020203ed
```

## 3. CRL

`GET <CDP URL>` (гэрчилгээний CDP-д бичигдсэн дарааллаар; header нэмэхгүй; ижил URL-ийг нэг Complete дотор нэг удаа),
хариу DER CRL, ≤ 4 MiB, HTTP 200.

**Үндэсний CRL-ийн толин хуулбар (бүх платформд, тогтмол map):** CDP URL яг тэнцүү бол дараах URL-ээр татна —

| CDP (гэрчилгээнд) | татах URL |
|---|---|
| `http://esign.gov.mn/MNICA-2022.crl` (03-ийн CDP, олгогч 02) | `https://crl.eidmongolia.mn/MNICA-2022.crl` |
| `http://esign.gov.mn/MNRCA-2021.crl` (02-ийн CDP, олгогч 01) | `https://crl.eidmongolia.mn/MNRCA-2021.crl` |

Бусад URL-ийг буулгахгүй. CRL-ийн гарын үсгийг олгогчоор (02/01) шалгадаг тул толинд итгэх шаардлагагүй (CA !352;
2026-10-14 шалгасан: 200, `Access-Control-Allow-Origin: *`). Fixture түлхүүр нь **татсан** URL-ээр.

## 4. Golden-ийн nonce

`seed = UTF-8("golden-nonce:" + caseName)`; блок k (0, 1, …) = `SHA-256(prev ‖ byte(k))`, `prev` = эхэндээ seed, дараа
нь өмнөх блок; уншсан байт = блокуудын залгаас. Nonce = эхний 8 байт = `SHA-256(seed ‖ 0x00)[0:8]`. Native SDK-ууд
тестэд nonce эх үүсвэрийг (эсвэл 8 байтыг) inject хийнэ.

## 5. HTTP

Анхдагч client: timeout 10 с, redirect дагахгүй, зөвхөн `http`/`https`, хариу ≤ 4 MiB. Хөтөч: (§3-ийн толины дараа) AIA/CDP-ийн
`http://`-ийг зөвхөн `ocsp.eidmongolia.mn`, `crl.eidmongolia.mn`, `tsa.timeserver.mn`-д `https://` болгоно, бусдыг
татахгүй (docs/PADES_CLIENT_SIDE.md §8.4) — Go reference backend-д ажиллах тул энэ upgrade-гүй.
