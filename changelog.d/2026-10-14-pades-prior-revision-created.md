- **PAdES бүртгэл: горим A-ийн өмнөх гарын үсэгтэй баримт + `Created`.**
  - Юу: горим A-аар (CA угсарсан) эхэлж зурагдсан баримтад нэмж зурахад `RegisterSignature` 409 `PRIOR_MISMATCH` авдаг
    байв — `pades.Registration` бүх өмнөх мөрийг CMS-ээр илгээж, `PriorRevisionSHA256`-г дуудагчид гараар ангилуулдаг. CA
    өмнөх мөр бүрийг өөрийнх нь түлхүүрээр таньдаг (клиент — `cms_sha256`, горим A — `sig_rev_sha256` = `sha256(doc[0 :
    ByteRange[2]+ByteRange[3]])`; CA `persistence/models.go` `PDFPrior.Covers`, `pades_finalize.go` `sha256(signed)`), файлаас
    ялгах боломжгүй (профайл 1:1).
  - Засвар: `pades.Registration` → `PriorSignatures []eid.PDFPriorSignature` (`json:"-"`, CA руу илгээхгүй);
    `RegisterSignature` эхлээд CMS-ээр, `PRIOR_MISMATCH` бол эхний k-г revision-оор (k = 1…n), n ≤ 4 бол бүх хослол
    (`priorSplits`, TS-тэй ижил дараалал). `PriorRevisionSHA256` гараар өгвөл хуучин зан.
  - `PDFSignatureRegistered.Created` — 201 → true, 200 (давталт) → false (`httpDoer.postJSONStatus`).
- Хаана: `pdfregister.go`, `client.go`, `pades/register.go`, README.
- Шалгасан: `TestRegisterSignatureReplayAndPriorMismatch`, `TestPriorSplits`, `TestRegisterSignature` (Created),
  `pades` 2 дахь гарын үсэг: `PriorRevisionSHA256[0] == эхнийх SigRevSHA256`, `PriorSignatures`; gofmt, vet,
  `go test -race ./...`, `GOOS=linux GOARCH=amd64 go build ./...`.
- Үлдсэн: native SDK (Swift/Kotlin/.NET)-д ижил засвар тусдаа.
