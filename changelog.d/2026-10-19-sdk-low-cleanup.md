### Changed — 10-15 SDK аудитын Low олдворууд: PII-гүй алдаа, https BaseURL, CI-ийн staticcheck/govulncheck/fuzz, devicelink golden drift

- **Юу:**
  - `maskPath` нь `/linked/{documentNumber}`-ийг ч нууна (`/signature/notification/linked/…`) — өмнө нь баримтын
    дугаар `NetworkError.Op` / `ResponseTooLargeError` / алдааны текстэд орж болдог байв.
  - `pades.Complete`-ийн LTV/цуцлалтын алдааны текст иргэний гэрчилгээний CN (овог, нэр)-ийн оронд `serial <hex>`-ээр
    заана (`pades/ltv.go` `certRef`).
  - **Зан төлөвийн өөрчлөлт:** `ResolveBaseURL` / `NewClient` нь `http://`-ийг зөвхөн `localhost` / loopback IP
    (127.0.0.0/8, ::1)-д зөвшөөрнө; бусад `http://` → алдаа (API secret сүлжээгээр нээлттэй явахгүй).
  - CI: `lint` job (`staticcheck@v0.8.2`, `govulncheck@v1.8.0`, Go stable) ба `fuzz` job (`FuzzValidatePDF`, 30 с).
    staticcheck-ийн өмнөх 9 олдвор засагдсан (ашиглагдаагүй талбар, `t.Fatal(fmt.Sprintf)`, deprecated
    `timestamp.CreateResponse` → `CreateResponseWithOpts(…, crypto.SHA256)` (байт-ижил), тестийн U+202E/U+200E →
    escape, `Catalog` алдааны мөрөнд `//lint:ignore ST1005`).
  - `testdata/devicelink_golden.json`-ийн sha256-ийг pin хийсэн (`TestDeviceLinkGoldenPinned`); `EID_CA_REPO` (CA
    репогийн локал clone) өгвөл canonical файлтай байт-ижил эсэхийг мөн шалгана (CA репо private тул CI-д алгасна).
  - `FuzzValidatePDF` (`pades/fuzz_test.go`): ValidatePDF (offline) + Verify; seed = репогийн бүх тестийн PDF + олдсон
    crash (`pades/testdata/fuzz/`). Seed-үүд энгийн `go test`-д ажиллана.
- **Яагаад:** 10-15 SDK аудитын Low олдворууд.
- **Хаана:** `errors.go`, `client.go`, `pades/ltv.go`, `.github/workflows/ci.yml`, `devicelink_test.go`,
  `pades/fuzz_test.go`; тест: `TestMaskPathAllRoutes`, `TestResolveBaseURL`, `TestCompleteRevokedIsHardFailure` /
  `TestCollectLTVRejectsForeignEvidence` (`noSubjectCN`), `TestDeviceLinkGoldenPinned`.
- **Шалгасан:** gofmt, `go vet`, `go test -race ./...`, `GOOS=linux GOARCH=amd64 go build`, staticcheck v0.8.2 (0),
  govulncheck v1.8.0 Go 1.27.2-оор (0 дуудагдах эмзэг байдал), fuzz нийт ~10 мин (засварын дараа олдворгүй).
