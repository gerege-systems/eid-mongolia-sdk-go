- **v0.3.2 — `eidlogin`: регистрийн oracle хаалт (decoy + PushFloor), OCSP цуцлалт, аудитын hook (TS 0.15.2-тэй ижил).**
  - **G1 (Critical) — бүртгэлийн oracle.** Push start eID-ийн татгалзалд (танихгүй дугаар) 502, бүртгэлтэйд 200 өгдөг,
    хугацааны доод хязгааргүй байсан — нэвтрээгүй хэн ч регистр eID-д бүртгэлтэй эсэхийг шалгаж болох байв. Одоо eID-ийн
    өөрийн JSON 4xx (401/403/429-ээс бусад) → decoy session: бодит хариутай ижил `{mode, vc (5 оронтой), expiresIn}`,
    ижил cookie, `status` нь eID-ээс асуулгүй `Poll`-ын хугацаанд барьж PENDING → TTL-ийн дараа EXPIRED. Push start-ийн
    хариу бүр (бодит, decoy, 502) ≥ `PushFloor` (анхдагч 1 с, ctx тасарвал зогсоно). 5xx / холболт / JSON бус 4xx (proxy)
    / 401 / 403 → 502, 429 → 429 (eID порталын `HandleEIDStartByNationalID`-тэй ижил: тасалдлыг нуухгүй, дугаараас
    хамааралгүй). Хязгаар decoy-д ч үйлчилнэ. Push-ийн CA `TIMEOUT` → `EXPIRED` (decoy-той ижил төгсгөл). Унтраах: `DisableDecoy`, `DisablePushFloor` (анхааруулгатай).
  - **G2 (High) — цуцлалт.** `finish` нь `ValidateAuth`-ийн дараа гэрчилгээг AIA OCSP-оор шалгана (`Config.Revocation`,
    nil = шинэ `eid.NewOCSPChecker`). revoked / unknown → FAILED `VALIDATION` (500 биш); хариугүй → soft-fail
    (порталын `EID_OCSP=soft`: зөвшөөрч Warn, `Identity.Revocation = unchecked`), `RevocationMode: eid.RevocationHardFail`
    → FAILED. `DisableRevocation` — унтраана. Шинэ: `eid.NewOCSPChecker` (олгогч/OCSPSigning responder-ийн гарын үсэг,
    serial, thisUpdate [−48ц, +5мин], nextUpdate, 2 с timeout, redirect-гүй, 16 KiB, good-ийг 5 мин кэш),
    `Validator.CheckRevocationWith`, `Identity.Revocation`.
  - **G3 (Medium) — аудит.** `Config.OnEvent(ctx, kind, sessionID, meta)`: `push_sent` (meta `decoy`), `push_limited`,
    `refused`, `expired`, `unverified` (`reason`), `flow_refused`, `success` (`flow`, `revocation`), `failed`
    (`endResult`). Регистрийн дугаар биш `pushKey` = HMAC-SHA256(`AuditKey`, дугаар); токен/нууц орохгүй.
- Хаана: `ocsp.go`, `validator.go`, `eidlogin/eidlogin.go`, `eidlogin/security_test.go`, `ocsp_test.go`,
  `eidlogin/eidlogin_test.go` (хуурмаг цаг, event бүртгэл), `README.md` §2, §4.
- Шалгасан: `TestPushDecoyIndistinguishable` (талбар, vc хэлбэр, floor 1 с хуурмаг цагаар, decoy poll eID-ээс асуухгүй,
  EXPIRED, event-д decoy, meta-д регистр алга), `TestPushOutageNotDecoy` (500/proxy400/401 → 502), `TestDecoyAndFloorOptOut`,
  `TestDecoyRateLimited`, `TestRevocation` (revoked/checker алдаа/hard-fail → FAILED VALIDATION; анхдагч soft → unchecked;
  good; disabled), `TestEvents`, `TestOCSPChecker` (good/revoked/unknown, delegated responder, хуучин thisUpdate, 5xx,
  буруу issuer, кэш); `gofmt`, `go vet`, `go test -race ./...`, `GOOS=linux GOARCH=amd64 go build ./...`.
