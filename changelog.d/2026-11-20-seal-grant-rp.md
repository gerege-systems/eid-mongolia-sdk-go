### Added — RP-ийн санаачилсан тамганы эрхийн хүсэлт (`Seal.RequestGrant`, `GrantStatus`, `WaitForGrant`, `Organization.SealGrants`)

- **Юу:** CA V156-ийн (ca-eidmongolia-mn PR #62) замууд:
  - `c.Seal.RequestGrant(ctx, orgEtsi, sessionID)` — `POST /seal/grants {orgEtsi, sessionId}` → 202 `*SealGrant`
    (`GrantID`, `OrgEtsi`, `Status`, `ExpiresAt`, `ApprovedAt?`, `RevokedAt?`, `Failure?`); хоосон оролт сүлжээнд гарахгүй.
  - `c.Seal.GrantStatus(ctx, grantID)` — `GET /seal/grants/{grantId}`.
  - `c.Seal.WaitForGrant(ctx, grantID, *SealWaitOptions)` — APPROVED хүртэл; REJECTED / EXPIRED / FAILED / REVOKED /
    хугацаа → `*SealGrantError` (`Outcome`, `Failure`; `SealGrantTimeout`); Retry-After-ийг дагана (`WaitForCertificate`-тэй ижил).
  - `c.Organization.SealGrants(ctx, personEtsi)` — `GET /organization/seal-grants/etsi/{personEtsi}` (PKI_READ) →
    `*OrgSealGrantsResponse` (байгууллага бүр + `OrgSealGrant`: RP нэр/домэйн, төлөв, огноо, батлагч, тамгалалтын тоо;
    статистик боломжгүй үед `SealCount`/`SealCount30d` nil).
  - Алдааны sentinel-ууд: `ErrRPNotRegistered`, `ErrNotOrgCEO` (403 `*ForbiddenError`), `ErrAuthSessionNotFound`,
    `ErrOrgNotFound`, `ErrAuthSessionWrongFlow`, `ErrAuthSessionNotCompleted`, `ErrAuthSessionTooOld`,
    `ErrAuthSessionAlreadyUsed`, `ErrRPNotActive`, `ErrSealGrantAlreadyApproved`, `ErrRPPermissionsFull`,
    `ErrSealGrantNotFound` (`*APIError`); `SealGrantErrorCodes`. `maskPath` нь `/seal/grants/{id}`-г нууна.
- **Яагаад:** RP (эхний хэрэглэгч — eidmongolia.mn портал) байгууллагын тамганы эрхийг операторгүйгээр, Гүйцэтгэх
  захирлын PIN2 зөвшөөрлөөр авах.
- **Хаана:** `seal_grant.go`, `errors.go` (`APIError.Is`, `ForbiddenError.Is`, `identifierInPath`), `routes.go`, `README.md`
  §3.10; тест `seal_grant_test.go` (fake сервер: биеийн талбар DisallowUnknownFields, код бүрийн sentinel/төрөл, 429
  Retry-After, wait-ийн төгсгөлийн төлвүүд, timeout/cancel, null/дутуу статистик).
- **Шалгалт:** PR-ийн CI (go test -race, vet, staticcheck, govulncheck, contract — шинэ 3 зам live discovery-д бий).
