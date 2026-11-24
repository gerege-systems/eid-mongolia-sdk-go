### Fixed — §6.6 step 2.2 (`docIDFromStamps`) no longer depends on xref order for malformed objects

- What: Go now matches the TypeScript port. The lookup first counts widgets per verified e-Seal signature (raw `/V`
  reference compared with the verified set, never resolved; count + first widget, O(xref objects)), then reads only
  the stamps of single-widget signatures. Only a single-widget candidate's own `/AP`, `/N`, `/Length` and stream reads
  (including an indirect `/DecodeParms`) → `PDF_INVALID`; unreadable objects elsewhere in the walk (indirect `/FT`, a
  non-seal `/V`, the first widget of a signature with 2+ widgets) are skipped. Before, Go returned `PDF_INVALID` for
  these depending on where they sat in the xref.
- Why: two conforming ports must never disagree, and the result must not depend on xref order. Counting without
  resolving `/V` also keeps the work linear when an appended update adds many widgets pointing at a large signature.
- Where: `pades/verify.go` (`docIDFromStamps`, `readStamp`); APPEARANCE_SPEC §6.6 step 2.2 (failure rule, order,
  note that the marker is read from the latest xref and is not tied to the e-Seal's signed revision).
- Tests: `TestDocIDFromStampsMalformed` (each case with the malformed objects before and after the valid candidate),
  `TestDocIDFromStampsManyWidgets` (200 000 appended widgets). No golden/testdata change; validator and `SealPDF`
  untouched. Verified in CI.
