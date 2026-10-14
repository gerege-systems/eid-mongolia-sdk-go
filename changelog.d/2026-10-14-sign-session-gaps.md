- **Sign session-ий дутуу хэсгүүд (client-side PAdES)** — зориулсан хувилбар v0.2.x (release-ийг координатор
  дараалуулна; tag энэ PR-д үгүй). Портал HASH sign (RAW_DIGEST_SIGNATURE, digest = 32 байт DTBS)-д олсон дутуу:
  - **Device-link sign:** `Sign.DeviceLinkByEtsi` / `DeviceLinkByDocument` (`POST /signature/device-link/{etsi|document}/…`)
    — `initialCallbackUrl`, `interactions`, `fileName`, `onBehalfOf`, RAW_DIGEST параметрүүд. `DeviceLinkSession.LinkInput`
    — auth/sign/cert холбоосын `BuildDeviceLink` оролтыг session-оос угсарна. `SignContext` (`NotificationSession.Sign`,
    `DeviceLinkSession.Sign`) — илгээсэн digest/hash/алгоритм/interactions/callback.
  - **Certificate-choice:** `Sign.CertificateChoiceByEtsi`, `Sign.CertificateChoiceDeviceLink` (зөвхөн QR — CA-ийн хүсэлт
    callback авдаггүй), `Validator.ValidateCertificateChoice` → `Signer{Certificate, DocumentNumber, CertChoiceSessionID}`.
  - **Signer-ээр зурах:** `Sign.DigestForSigner` (`/signature/notification/linked/{documentNumber}` +
    `linkedSessionID`, cert choice-гүй бол `/notification/document/…`), `Sign.DeviceLinkForSigner`
    (`/signature/device-link/document/…`). Олон утастай иргэнд etsi-ээр эхлүүлбэл өөр утас зурж CMS эвдэрдэг тул
    documentNumber-аар л. Анхдагч `sha256WithRSAEncryption` + SHA-256; digest-ийн уртыг хүсэлтээс өмнө шалгана.
  - **`ValidateSignOptions.ExpectedAlgorithm`** — хүссэн RSA алгоритмаас өөр хариу (ж: PKCS#1 хүссэнд rsassa-pss) →
    `*ValidationError`; CA-ийн хуучин threshold-ECDSA credential-ийн `ecdsa-with-SHA256`-ийг зөвхөн EC P-256 + SHA-256
    үед. **`ExpectedCertificate`** — certificate-choice-ийн гэрчилгээнээс өөрөөр зурсан бол татгалзана.
  - **`ExpiresAt`** — CA session start хариунд хугацаа буцаадаггүй (`sessionID`/`vc`, device-link-д token/secret) тул
    sign / cert-choice session-д хүсэлтээс өмнөх цаг + `Config.SignSessionTTL` (анхдагч `DefaultSignSessionTTL` = 600с
    = CA `EID_SIGN_SESSION_TTL_SECONDS`; CA админ 60–1800с болгож болно). `SessionExpiry` туслах.
  - 5 шинэ зам `rpRoutes`-д (live `/.well-known/eid`-д бүгд бий).
  - Хаана: `sign.go`, `certchoice.go`, `validator.go` (precheck → `sessionDone` + `leafOf`), `devicelink.go`, `types.go`,
    `routes.go`, `client.go`, README §3.3.
- Шалгасан: `sign_gaps_test.go` (device-link body/зам/LinkInput байт-ижил, ExpiresAt, cert choice body түлхүүрүүд,
  ValidateCertificateChoice, DigestForSigner linked/document/device-link + буруу оролтод хүсэлт явахгүй,
  ExpectedAlgorithm/ExpectedCertificate). `gofmt`, `go vet ./...`, `go test -race ./...`, `go test -tags contract`
  (live discovery), `GOOS=linux GOARCH=amd64 go build ./...`.
