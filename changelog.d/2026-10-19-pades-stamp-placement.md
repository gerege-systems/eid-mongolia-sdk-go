### Changed — `pades`: the visible stamp avoids existing page content (PLACEMENT_SPEC.md)

- **What:** `Appearance.X/Y` is now the preferred spot. Before writing the widget, the target page is scanned
  (content stream text/paths/images/forms/inline images + annotation `/Rect`s, no rendering, no font files) and, when
  the requested rect (+4 pt) overlaps something, the stamp moves to the first free candidate: mirrored column at the
  same height (bottom-right → bottom-left), then up the requested column in 12 pt steps, then up the mirrored column.
  Nothing free → requested spot. New `Prepared.Placement` (`page, x, y, width, height, status`:
  `requested | moved | overlap | unscanned`).
- **Why:** prod 2026-10-19 — on a LibreOffice-converted Word contract the stamp covered the last-page footer.
- **Where:** `pades/internal/core/occupancy.go` (scanner), `placement.go` (candidates), `signature.go`
  (`Visible.Avoid`, `Prepared.Placement`), `pades/prepare.go`, spec `pades/PLACEMENT_SPEC.md`, APPEARANCE_SPEC §1,
  README §7.1. Golden v5: 6 new cases (`libreoffice-contract-visible`, `…-second`, `table-bottom-visible`,
  `rotated90-footer-visible`, `quartz-pdf13-visible-third`, `full-page-visible`), `expect.placement` on all visible
  cases; scanner vectors `pades/testdata/golden/placement/`. CI fuzz job also runs `FuzzOccupancy`.
- **Verified:** all v3/v4 golden outputs byte-identical (only `expect.placement: requested` added to the manifest);
  `go test -race ./...`, `go vet`, `gofmt`, staticcheck, govulncheck, `FuzzOccupancy` 60 s locally; before/after
  renders with pdftoppm.
- **Remaining:** TS / Swift / Kotlin / .NET ports (byte-identical to golden v5) and the `pades-golden-v5` tag at
  release.
