### Added — `TokenCertStart.Supersedes`, `TokenCertInfo.PersonalAutoSupersede`

- **Юу:** `IssueCertificate`-ийн хариунд `Supersedes []TokenSupersede{TokenSerial}` — хувийн хязгаар хүрсэн үед олголт
  амжилттай болоход superseded (4)-оор цуцлагдах өмнөх хувийн токенууд (бусад үед nil). Discovery
  `TokenCertInfo.PersonalAutoSupersede` (хуучин CA-д false). 409 `TOKEN_LIMIT_REACHED` `kind=PERSONAL` одоо зөвхөн `limit=0`.
- **Яагаад:** CA !392 (прод b09b755e) хувийн токены автомат солилт; RP PIN2-оос өмнө иргэнд анхааруулах ёстой.
- **Хаана:** `token.go`, README §3.7, `portal_gaps_test.go`, `contract_test.go` (`personalAutoSupersede: true`).
- **Шалгасан:** `gofmt`, `go vet`, `go test ./...`, contract тест live discovery-д.
