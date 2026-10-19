### Added — `PersonCertificate.TokenSerial`

- **Юу:** `c.Person.Certificates`-ийн `KeyMedium == "TOKEN"` мөрөнд гэрчилгээ олгогдсон USB токены серийн дугаар
  (`json:"tokenSerial,omitempty"`; CA `GET /v3/certificates/etsi/{personEtsi}`, 2026-10-19). MOBILE/HSM болон хуучин CA-д `""`.
- **Яагаад:** нэг токены AUTH + SIGN-ийг байгууллага + олгосон цагаар таамаглахгүй, токеноор нь бүлэглэх.
- **Хаана:** `person.go`, README §3.6, `share_test.go` (`TestPersonCertificateTokenSerial`).
- **Шалгасан:** `gofmt`, `go vet`, `go test ./...`.
