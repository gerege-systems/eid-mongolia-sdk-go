### Fixed — `pades`: trailer-ийн шууд `/Encrypt << … >>` толь `PDF_ENCRYPTED`

- **Юу:** digitorus баримтыг нээж чадахгүй үед (ж: AES-256, буруу /U) хэрэглэдэг байт-regex нь зөвхөн `/Encrypt N G R`
  лавлагааг таньдаг байсан тул шууд толь (`/Encrypt << … >>`, `/Encrypt<<`)-той баримт `PDF_INVALID` болдог байв —
  одоо `PDF_ENCRYPTED`. Regex `/Encrypt(?:\s+\d+\s+\d+\s+R|\s*<<)` (CA !382-тэй ижил); `/EncryptMetadata` тооцогдохгүй.
- **Хаана:** `pades/prepare.go` (`encryptKey`), `pades/internal/validate/extract.go` (`encryptRef`), `pades/PRECHECKS.md` #4.
- **Шалгасан:** `TestEncryptDirectDict` (AES-256 шууд толь, RC4 `/Encrypt<<`, лавлагаа, `/EncryptMetadata` → encrypted
  биш) — хуучин regex-ээр AES-256/RC4 тохиолдол унахыг баталсан.
