### Added — `TokenCertInput.AppTransaction`, `CodeAppAttestationInvalid`

- **Юу:** `POST /token/certificate`-д заавал биш `appTransaction` (StoreKit 2 AppTransaction JWS, ≤ 16 KiB;
  `json:"appTransaction,omitempty"`). `MaxAppTransactionBytes`-аас их бол илгээхгүй — `ErrAppTransactionTooLarge`.
  400 `CodeAppAttestationInvalid` (`APP_ATTESTATION_INVALID`) тогтмол. Discovery `TokenCertInfo.AppTransaction`
  (`"optional"`; хуучин CA-д `""`).
- **Яагаад:** CA (MR !390) macOS App Store build-ийн апп баталгааг токены олголтод нэмсэн; SDK-ийн хүсэлтийн бүтэц
  талбаргүй байсан тул портал дамжуулж чадахгүй байв.
- **Хаана:** `token.go`, README §3.7, `portal_gaps_test.go` (`TestTokenCertificateAppTransaction`,
  `TestTokenCertificateInfo`), `contract_test.go` (`TestContractTokenCertificate` — `appTransaction: "optional"`).
- **Шалгасан:** `gofmt`, `go vet`, `go test ./...`, `go test -tags contract -run ContractTokenCertificate` (live
  discovery), `GOOS=linux go build`.
