### Fixed — USB токены AUTH гэрчилгээ QUALIFIED (CA !472-тэй нийцэл)

- **Юу:** `eid.CertificateLevelOf(c, "ACSP_V2")` qcStatements-гүй нэвтрэлтийн гэрчилгээнд KeyUsage `keyEncipherment`
  (утасны P-CITIZEN-AUTH)-аас гадна **EKU clientAuth + emailProtection ба certificatePolicies-д үндэсний OID
  `2.16.496.1.101.1.2.8`** (токены P-CITIZEN-AUTH-TOKEN — EC тул KE үгүй) байвал `QUALIFIED` буцаана; өмнө нь `ADVANCED`.
  Бусад (policy-гүй, emailProtection-гүй) нэвтрэлтийн гэрчилгээ `ADVANCED` хэвээр; гарын үсгийн дүрэм (qcStatements)
  өөрчлөгдөөгүй.
- **Яагаад:** CA !472 (2026-11-06) токены AUTH/SIGN мөрийг `QUALIFIED` болгосон тул session-ий хариу токены AUTH-д
  `certificateLevel: QUALIFIED` зарлана — хуучин дүрмээр SDK «гэрчилгээнээс (ADVANCED) өндөр» гэж татгалздаг байв.
  Өмнө олгосон токены AUTH гэрчилгээ ижил агуулгатай; CA тэдгээрийг `ADVANCED` гэж зарласаар байгаа бөгөөд хариуны бага
  түвшин хүчинтэй (`effectiveLevel`) тул RP-д `ADVANCED` хэвээр.
- **Хаана:** `validator.go` (`CertificateLevelOf`, `isCitizenAuthToken`, `oidNationalPolicy`), README §Validator 3,
  `pades/internal/validate/validate.go` (тайлбар); тест `chain_test.go` (`TestCertificateLevelFromCertificate` — токены
  AUTH fixture: KU DS, EKU clientAuth+emailProtection, үндэсний policy, EC P-256 → QUALIFIED; policy-гүй /
  emailProtection-гүй → ADVANCED). TS SDK 0.40.3-тай ижил дүрэм.
- **Шалгасан:** `go test ./...`, `go vet ./...`, gofmt, `GOOS=linux GOARCH=amd64 go build ./...`.
