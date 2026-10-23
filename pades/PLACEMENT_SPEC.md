# Visible stamp placement — PLACEMENT_SPEC (pades-client/1)

Reference implementation: `pades/internal/core/occupancy.go` (`Occupancy`), `pades/internal/core/placement.go`
(`PlaceCandidates`, `PlaceVisible`), wired in `core/signature.go` (`prepareSignature`, `Visible.Avoid`) and
`pades/prepare.go` (`Prepared.Placement`). Conformance: `pades/testdata/golden/placement/vectors.json` (occupancy box
list + chosen position, box-for-box) and the pades golden cases listed in §8. Every native SDK (TS, Swift, Kotlin, C#)
ports this document 1:1 and must reproduce both exactly.

The stamp itself (form XObject, widget, `/Rect` mapping) is unchanged — [APPEARANCE_SPEC.md](APPEARANCE_SPEC.md). This
document only decides **where** the stamp goes: `appearance.{x, y}` is now the *preferred* spot. Before the widget is
written, the target page is scanned for content, and when the preferred rect would overlap something the stamp moves to
the first free spot in a fixed order. When the preferred rect is free, the output is byte-identical to before.

## 1. Scope and result

- Runs whenever `appearance` is given. `appearance.exact = true` (§6a) keeps the scan but never moves the stamp. Inputs: the target page dictionary (APPEARANCE_SPEC §1: `page`
  resolved, CropBox/MediaBox `box` in h100, `rot`), and the requested `x, y, w, h` (h100, visible space). The request is
  validated exactly as before (APPEARANCE_SPEC §1) **before** placement — an invalid request is still `REQUEST_INVALID`.
- Output: the final `(x, y)` (h100, visible space) and a status:

  | status | meaning | position |
  |---|---|---|
  | `requested` | the requested rect is free | requested |
  | `moved` | requested rect overlaps content; a free candidate was found (never with `exact`) | that candidate |
  | `overlap` | no candidate is free (`exact`: the requested rect is not free) | requested (drawn over content) |
  | `unscanned` | the page could not be scanned (§5) | requested |

- `Prepared.placement = { page, x, y, width, height, status }` — `x, y, width, height` in pt (`h100 / 100`), `page` the
  1-based page the stamp is on. Callers should surface `overlap` / `unscanned` (e.g. a notice) — the signature is valid
  either way. The final position only changes the widget `/Rect`; the appearance stream depends on `w, h, rot` only.

### 1a. Default page (`page` 0 / absent)

`appearance.page` 1…N is used as given (even when it is a verify page). `page` 0 or absent selects **the last page of the
input that is not an eID verify page** — the verify pages added by earlier revisions are skipped exactly like the
verify page this Prepare adds is not counted. Pages are taken in `/Pages` tree order (APPEARANCE_SPEC §1: `/Kids`
order, depth ≤ 32, at most 65 537 pages); scan from the last page backwards and pick the first page that is not a
verify page; when every page is a verify page, the last page.

**Verify page** (structural, no text recognition): a page whose `/Annots` (an array; its first 10 000 elements) contains
a dictionary with `/Subtype /Link` and `/A` a dictionary with `/S /URI` and `/URI` a string **byte-equal** to
`https://ca.eidmongolia.mn/verify/` + `docId`, where `docId` is the document id this Prepare uses (the one written on
the first eID signature's verify page, `Prepared.docId`). The verify page carries that link (PAGE_SPEC §6, the
`VerifyURL` link), and it is the same link from which later signers read `docId` (so any document whose `docId` comes
from its page has it); a visible stamp has no Link annotation, and its QR URL (`…/verify/<docId>/<rev>`) is not byte-equal anyway.
Annotation entries may be direct or indirect; anything else (a non-dictionary entry, `/A` missing, another `/S`, a
`/URI` that differs in any byte, a page that cannot be read) does not make a verify page.

**Object generations.** References resolve by object number *and* generation: `N G R` reads the xref entry of `N` only
when that entry records generation `G` (an object in an object stream has generation 0); otherwise the reference is
null. The `docId` scan (the first `/Subtype /Link` whose `/A /URI` is `https://ca.eidmongolia.mn/verify/` + a lowercase
UUID, Prepare and §6b) walks the xref in object-number order and reads each in-use object with **the generation its xref
entry records** — never an assumed generation 0. A verify page, its `/Annots`, Link or `/A` with a non-zero generation is
therefore found exactly like a generation-0 one. Golden v8 (`input/verify-gen1.pdf`: verify page `6 1 obj`, Link
`7 1 obj`, URI action `8 2 obj`): `verify-gen1` (first signature, invisible), `page0-verify-gen1` (2nd signer, page 0
→ docId from the generation-1 Link, page 1), `page-explicit-verify-gen1` (`page: 2` → the widget is added to the
generation-1 page, rewritten as `6 1 obj`).

The rule errs towards *content*: a page that only looks like a verify page (another `docId`, a different host, a
`/rev` suffix, text without the link) is a content page — the stamp may then land on it, which is the pre-v6 behaviour
and harmless; a real content page is never skipped unless it links to this document's own verify URL. No marker is
added to new verify pages: the link already identifies them, in old files as well.

Golden v6 (`manifest.json`): `page0-after-verify` (2nd signer, page 0 on content + verify → page 1),
`page0-after-verify-second` (3rd signer → page 1, moved past the 2nd stamp), `page0-two-verify`
(`input/two-verify.pdf`: 1 content + 2 verify pages → page 1), `page-explicit-verify` (`page: 2` = the verify page →
kept), `page0-fake-verify` (`input/fake-verify.pdf`: last page links to another docId and to `…/<docId>/1` → content,
page 2).

Units: h100 = 1/100 pt integers (APPEARANCE_SPEC §1). All scanner arithmetic is IEEE-754 binary64 (§2).

### 1b. Page numbers and `verifyPagePosition` (golden v9)

Page numbers in `appearance.page`, `Prepared.placement.page` and `suggestPlacement` (`page`, `pageCount`, `pages`)
always count **the pages of the input document as given**: the verify page this Prepare adds (PAGE_SPEC §8a) is never
counted, whatever its position. With `verifyPagePosition = "first"` the verify page becomes page 1 of the output, so
the SDK draws the stamp on output page `page + 1` while `placement.page` still reports `page`; with `"last"` (default)
input and output numbering coincide. `page` is validated against the input's page count (`page > N` →
`REQUEST_INVALID`), and page 0 (§1a) is resolved on the input before the page is added. A UI that previews the input
PDF can therefore pass its own page index unchanged.

Second and later signers: a verify page added in front by an earlier revision is an ordinary page of *their* input
(explicit `page` counts it); page 0 skips it like any verify page (§1a — the scan goes from the last page backwards, so
a verify page at the front is only reached when every later page is a verify page too).

## 2. Arithmetic (determinism)

- Numbers from content streams and PDF objects are parsed to binary64 with correct rounding (Go `strconv.ParseFloat`,
  JS `Number`, Kotlin `toDouble`, Swift `Double(String)`, .NET `double.Parse(…, InvariantCulture)` — all correctly
  rounded for the token grammar of §3.1).
- Only `+ − × ÷`, `min`, `max`, `abs`, `floor`, `ceil` are used — no `sqrt`, trig or `pow`.
- **No fused multiply-add.** Each product is rounded on its own, then the terms are added **left to right** in the order
  written below. (Go needs explicit `float64(a*b)` conversions to stop the compiler from fusing on arm64; JS, JVM, .NET
  and Swift do not fuse by default — do not enable fast-math / `-ffp-contract=fast`.)
- Matrix product `m × n` (row vector convention, ISO 32000-1 §8.3.4), `m = [a b c d e f]`:
  ```
  [ m.a·n.a + m.b·n.c,   m.a·n.b + m.b·n.d,
    m.c·n.a + m.d·n.c,   m.c·n.b + m.d·n.d,
    m.e·n.a + m.f·n.c + n.e,   m.e·n.b + m.f·n.d + n.f ]
  ```
  Point transform `(x, y) × m = (a·x + c·y + e,  b·x + d·y + f)`.
- **float → integer is saturating, truncating toward zero**: NaN → 0; a value ≥ 2^63 or +∞ → 2^63 − 1; a value
  < −2^63 or −∞ → −2^63; otherwise the integer part. This applies to every conversion in this document (`/W` CIDs,
  `/FirstChar`, quantising, `Round100`). Go's plain `int(f)` is **not** conformant — out of range it is
  platform-dependent (amd64 gives −2^63, arm64 saturates; `/W [0 1e20 100]` assigned nothing on amd64 and every CID on
  arm64) — the reference uses `SatInt`. JS/Kotlin/Swift/.NET: clamp before converting (Kotlin `toLong()` saturates;
  Swift `Int(f)` traps out of range; C# `(long)f` is unspecified out of range). Ports that keep the value as a double
  (JS) must still compare and index with the saturated value. Vector `int-saturate` (§8).
- **Quantising a box** (float pt → h100 integer box): clamp each coordinate to `[−1e7, 1e7]`, then
  `x0 = floor(minx × 100)`, `y0 = floor(miny × 100)`, `x1 = ceil(maxx × 100)`, `y1 = ceil(maxy × 100)` (outward, so it
  is conservative). A NaN coordinate → unscannable (§5). (Values stay within ±1e9, safe as JS numbers and 32-bit-safe
  after the clamp.)

## 3. Occupancy scan

`Occupancy(page, box)` → ordered list of h100 boxes `[x0 y0 x1 y1]` in the page's **default user space** (the same space
as `/Rect`), or *unscannable*. Order = emission order: content stream (§3.2–§3.6) in execution order, then annotations
(§3.7) in `/Annots` order. Boxes are not clipped, merged or sorted.

### 3.1 Content bytes and tokens

- `/Contents` absent/null → empty content. A stream → its decoded bytes. An array → each element's decoded bytes, joined
  with one LF (`0x0A`) between elements. Any other kind, or an array element that is not a stream → unscannable.
- **Stream decoding**: `/Filter` absent with `/DecodeParms` absent; or `/Filter /FlateDecode` with `/DecodeParms` absent;
  or `/Filter [/FlateDecode]` with `/DecodeParms` absent or `[null]`. Anything else (other filters, predictors, filter
  chains) → unscannable. FlateDecode = zlib (RFC 1950):
  - header: CM = 8, `(CMF·256 + FLG) mod 31 = 0`. **FDICT**: when set, the 4-byte DICTID follows; DICTID = 1 (the
    Adler-32 of the empty dictionary) is accepted and inflation proceeds with no dictionary; any other DICTID →
    unscannable (vectors `zlib-fdict-empty`, `zlib-fdict-other`).
  - raw deflate up to its final block, then the 4-byte Adler-32 of the decoded bytes must be present and match. A
    truncated stream — deflate data ending before the final block, or fewer than 4 checksum bytes — and a wrong
    Adler-32 → unscannable; bytes after the checksum are ignored (vectors `zlib-truncated-data`, `zlib-no-adler`,
    `zlib-bad-adler`, `zlib-trailing`).
  - A decoder that silently accepts truncated input (e.g. .NET `ZLibStream`/`DeflateStream`, which do not report a
    missing final block or checksum) is not conformant on its own: check the header, that the final block was reached
    and the Adler-32 yourself.
  Any inflate/header/checksum error → unscannable. Stream data = `/Length` bytes after `stream` EOL (as the
  SDK's object reader already does).
- **Byte budget**: the sum of decoded bytes of every stream decoded during the scan (page contents + every form
  *execution*, re-counted when the same form runs again) must stay ≤ 4 194 304 (4 MiB); otherwise unscannable.
- Lexer (ISO 32000-1 §7.2, simplified — this grammar is normative):
  - whitespace: `00 09 0A 0C 0D 20`; delimiters: `( ) < > [ ] { } / %`; `%` starts a comment up to (not including) the
    next CR or LF.
  - `(` literal string: nested balanced parentheses; escapes `\n \r \t \b \f`, `\(` `\)` `\\`, `\ddd` (1–3 octal digits,
    value mod 256), `\` + CR, `\` + CR LF, `\` + LF = line continuation (no byte), `\` + any other byte = that byte. EOF
    ends the string (what was read is kept).
  - `<<` / `>>` dictionary open / close; `<` hex string: hex digits (either case) pair into bytes, every other byte is
    skipped, `>` or EOF ends it, an odd final nibble is padded with 0.
  - `[` / `]` array open / close; `/` name: following regular bytes, `#xx` (two hex digits) decoded.
  - `)` `{` `}`, a `>` not followed by `>`, a `]` or `>>` with nothing open → skipped.
  - Any other run of regular bytes is a **number** iff it matches `[+-]?([0-9]+(\.[0-9]*)?|\.[0-9]+)` and is ≤ 32 bytes;
    otherwise `true` / `false` / `null` are operand objects and everything else is an **operator keyword**. (`1e5`,
    `--5`, `1.2.3` and 33-byte digit strings are keywords.)
  - Inside an open array or dictionary every token is an element (keywords become opaque elements); arrays keep their
    elements (TJ needs them), dictionaries are opaque. EOF inside an open array/dictionary ends the content (the pending
    operands are dropped). Nesting deeper than 32 → unscannable.
  - Operand stack: operands accumulate until an operator keyword; each operator consumes the whole stack (it is cleared
    whether or not the operator used it). More than 65 536 pending operand objects (array elements count) →
    unscannable.
- Operator count: every operator keyword executed (page + forms, including unknown ones and `BI`) counts; more than
  100 000 → unscannable.
- **Operand rule**: an operator below acts only when the stack holds *exactly* the listed operands with the listed types
  (`n` = number, `s` = string, `/` = name, `[]` = array); otherwise it is ignored (no state change). Unknown operators
  are ignored.

### 3.2 Graphics state

Per content stream run: `CTM` (initial: identity for the page, §3.5 for forms), line width `lw = 1`, `fillWhite =
false`, `strokeWhite = false`, text state `Tc = 0, Tw = 0, Th = 1, TL = 0, Tfs = 0, Trise = 0, font = default` (§3.4).
All of these are saved by `q` and restored by `Q`.

| operator | operands | effect |
|---|---|---|
| `q` | — | push; more than 64 saved states in one stream → unscannable |
| `Q` | — | pop (ignored when the stack is empty) |
| `cm` | n×6 | `CTM = [a b c d e f] × CTM`; any non-finite component → unscannable |
| `w` | n | `lw = n` |
| `g` / `G` | n | `fillWhite` / `strokeWhite = (n ≥ 1)` |
| `rg` / `RG` | n×3 | `… = (all three ≥ 1)` |
| `k` / `K` | n×4 | `… = (all four ≤ 0)` |
| `cs` `sc` `scn` | any | `fillWhite = false` |
| `CS` `SC` `SCN` | any | `strokeWhite = false` |

`gs`, `d`, `J`, `j`, `M`, `ri`, `i`, `BDC`/`BMC`/`EMC`/`MP`/`DP`, `BX`/`EX`, `d0`/`d1`, `Tr` and `sh` (shadings —
background gradients are not occupancy) have no effect. Text render mode is ignored: invisible text (`3 Tr`) counts too.

### 3.3 Paths

Points are transformed by the CTM **when the construction operator runs**; all path data below is in user space.
A path is a list of subpaths; each subpath has a start point, a current point, a bounding box of every point added
(control points included) and a list of segment boxes.

| operator | operands | effect |
|---|---|---|
| `m` | n×2 | new subpath at `P = (x,y)×CTM`; bbox = P |
| `l` | n×2 | needs a subpath, else ignored; segment box = bbox{current, P}; current = P |
| `c` | n×6 | segment box = bbox{current, P1, P2, P3}; current = P3 |
| `v` / `y` | n×4 | segment box = bbox{current, P1, P2}; current = P2 |
| `h` | — | needs a subpath; segment box = bbox{current, start}; current = start |
| `re` | n×4 `x y w h` | new subpath: points `(x,y)`, `(x+w,y)`, `(x+w,y+h)`, `(x,y+h)` (each `×CTM`; `x+w`, `y+h` computed before transforming), segments between consecutive points, then closed as `h` |

The subpath bbox also absorbs every point. `W`, `W*` have no effect (clipping is ignored — conservative).

Painting operators (operands: none, else ignored; the path is cleared after a painting operator that acted):

- `s`, `b`, `b*` first close the last subpath (as `h`).
- **fill** (`f F f* B B* b b*`), only when `fillWhite = false`: for each subpath, quantise its bbox; skip it when
  `2 × area(bbox ∩ box) ≥ area(box)` (`box` = the page's CropBox/MediaBox in h100, integer arithmetic; `area` of an
  empty intersection = 0) — a page background; else emit it.
- **stroke** (`S s B B* b b*`), only when `strokeWhite = false`: `hw = |lw| / 2`,
  `ex = hw·|CTM.a| + hw·|CTM.c|`, `ey = hw·|CTM.b| + hw·|CTM.d|` (the CTM *at the painting operator*); for every segment
  box of every subpath emit `quantise([x0 − ex, y0 − ey, x1 + ex, y1 + ey])`.
- `B B* b b*`: fill boxes first, then stroke boxes. `n`: nothing.

### 3.4 Fonts and widths

`Tf /Name size` (`/` + n): `font = resolve(/Resources /Font /Name)` (missing → *default*), `Tfs = size`.

**Font cache** (fixed behaviour of the reference, not an accident to fix): a font's metrics (the table below) are read
once per scan and cached under the object number of the **indirect object that contains the font dictionary** — the
font's own object when `/F1 5 0 R`, otherwise the object the direct dictionary is written in (digitorus `GetPtr`). So
two fonts written directly inside the same object (e.g. `/Font << /A << … >> /B << … >> >>` inside the page object)
share one entry: whichever is used first defines the metrics for both. Object number 0 (no containing object) is not
cached. Vector `fonts-direct` (§8). Kinds:

| font dict | codes | `w0(code)` (glyph units, 1/1000 em) |
|---|---|---|
| `/Subtype /Type0`, `/Encoding /Identity-H` or `/Identity-V` (a name) | 2-byte big-endian; an odd final byte is dropped | `/DescendantFonts[0] /W` lookup, else `/DW` (number), else 1000 |
| `/Subtype /Type0`, any other encoding | 1 byte each | 1000 |
| `/Subtype /Type3`, no font, unresolvable font | 1 byte each | 1000 |
| anything else (Type1, TrueType, MMType1, …) | 1 byte each | `/Widths[code − /FirstChar]` when that index is in range and the element is a number; else `/FontDescriptor /MissingWidth` when it is a number > 0; else 1000 |

- `/FirstChar` default 0; only the first 256 `/Widths` elements are read.
- `/W` is read entry by entry over its first 65 536 elements: `c [w…]` assigns `c, c+1, …` (first 65 536 elements of
  the inner array; non-number elements are skipped but keep their position); `c1 c2 w` assigns `max(c1, 0) … c2`
  (nothing when `c2 < max(c1,0)`), stopping at 65535; CIDs outside 0…65535 are ignored; **the first assignment of a CID
  wins**; any other shape (a non-number where `c` is expected, a missing element) stops the reading — what was read
  so far stays. CID numbers are converted saturating toward zero (§2); `c + i` past 2^63 − 1 is out of range. Every attempted assignment (inner-array number or range CID,
  assigned or not, in range or not) costs 1 from a budget of 262 144; when it runs out the reading stops.
- Word spacing applies to the 1-byte code 32 of every 1-byte font **except** the "Type0, other encoding" row.
- No font program, cmap or system font is ever consulted. Identity-V text is measured as horizontal (documented
  limitation).

### 3.5 Text

State: `Tm`, `Tlm` — identity at the start of every content stream run and at every `BT`. (`ET` has no effect; text
operators outside `BT…ET` still act.)

| operator | operands | effect |
|---|---|---|
| `Tc` `Tw` `TL` `Ts` | n | set `Tc` / `Tw` / `TL` / `Trise` |
| `Tz` | n | `Th = n / 100` |
| `Td` | n×2 | `Tlm = [1 0 0 1 tx ty] × Tlm; Tm = Tlm` |
| `TD` | n×2 | `TL = −ty`, then `Td` |
| `T*` | — | `Td 0 −TL` |
| `Tm` | n×6 | `Tm = Tlm = [a b c d e f]` |
| `Tj` | s | show [s] |
| `'` | s | `T*`, show [s] |
| `"` | n n s | `Tw = aw`, `Tc = ac`, `T*`, show [s] |
| `TJ` | [] | show the array's elements (strings and numbers; other kinds skipped) |

`BT` takes no operands (otherwise ignored). After every `Tlm` update (`Td TD T* ' "`) a non-finite component →
unscannable.

**show(items)** — `x = 0`, extent = none. For each item:
- number `n`: `x = x − (n / 1000 · Tfs) · Th`;
- string: for each code (§3.4): `gw = (w0 / 1000 · Tfs) · Th`; extent ∪= `[min(x, x+gw), max(x, x+gw)]`;
  `adv = (w0 / 1000 · Tfs) + Tc (+ Tw for a word-space code)`; `x = x + adv · Th`.
  (Evaluation order exactly as written: `w0 / 1000`, then `· Tfs`, then `· Th`.)

If an extent exists: `ya = Trise + Tfs · (−0.3)`, `yb = Trise + Tfs`; the four corners `(xmin, ya) (xmax, ya)
(xmin, yb) (xmax, yb)` are transformed by `Tm`, then by the CTM; their bbox is emitted (quantised). Then
`Tm = [1 0 0 1 x 0] × Tm` (non-finite → unscannable). No extent (empty strings) → no box, `Tm` still advances.
The glyph box is the advance width × [−0.3, 1.0] em — no font bounding boxes, no kerning beyond `TJ`.

### 3.6 XObjects and inline images

- `Do /Name`: `x = /Resources /XObject /Name`.
  - `/Subtype /Image`: emit the bbox of the unit square's four corners `(0,0) (1,0) (0,1) (1,1)` × CTM.
  - `/Subtype /Form` (a stream): if the current depth + 1 > 8 → unscannable (page content is depth 0). Else
    `M = /Matrix` (6 numbers; otherwise identity), `CTM' = M × CTM` (non-finite → unscannable), resources = the form's
    `/Resources` if it is a dictionary, else the caller's. Decode the form stream (§3.1, same filter rules and budget)
    and run it as a new content stream at depth + 1 with initial state = the caller's current graphics state but
    `CTM = CTM'`, empty path, empty operand stack, empty `q` stack, `Tm = Tlm = identity`. After it, the caller's state
    (graphics, path, text) is exactly as before `Do`. `/BBox` is not used (no clipping).
  - Anything else (missing, PS, not a stream for Form): ignored.
- `BI` (always acts, whatever the operand stack holds): tokens are read until the keyword `ID` — objects are
  completed (arrays/dictionaries) and dropped, other keywords are skipped and are **not** counted as operators; EOF
  first → content ends. Then one whitespace byte after `ID` is skipped if present. The data ends at the first `EI` (bytes `45 49`) whose
  preceding byte is whitespace and which is followed by whitespace or the end of the content; lexing resumes after it
  and the unit-square box × CTM is emitted. No such `EI` → the content ends with no box.

### 3.7 Annotations

After the content, `/Annots` of the page (array; other kinds → none; more than 10 000 entries → unscannable). Each
element that is a dictionary, except `/Subtype /Popup` and those whose `/F` (integer) has bit 2 (Hidden, value 2) or
bit 6 (NoView, value 32) set, with `/Rect` = 4 numbers whose x's differ and y's differ: emit
`quantise([min x, min y, max x, max y])`. Zero-area rects (invisible signature widgets `[0 0 0 0]`) are skipped.
Existing visible eID stamps are widgets, so a second signer never covers the first.

## 4. What is deliberately ignored (and why)

| content | rule | reason |
|---|---|---|
| white fill/stroke via `g/rg/k` (`G/RG/K`) | not occupied | page-colour boxes and cell backgrounds from Word/LibreOffice; the stamp is transparent but drawn over white is fine |
| colour set via `cs/sc/scn` | occupied | colour space unknown without resolving it — conservative |
| a filled subpath covering ≥ 50 % of the page box | not occupied | page backgrounds / full-page shading rects |
| a stroked frame around the page | only its edges | strokes count per segment, so a border does not block the inside |
| images (any size, incl. full-page scans) | occupied | a scan is content; scanned pages therefore end in `overlap` (same position as before, flagged) |
| clipping (`W`, form `/BBox`) | ignored | over-counts clipped-away content — conservative |
| `sh` | ignored | shadings paint within the clip; usually decorative backgrounds |
| invisible text (`3 Tr`) | occupied | simpler; OCR layers lie under an image anyway |
| Type3 / no metrics | 1000 units per glyph | over-estimates width — conservative |

## 5. Limits → `unscannable`

4 MiB decoded bytes · 100 000 operators · form depth 8 · `q` depth 64 · operand objects 65 536 · array/dict nesting 32 ·
10 000 annotations · unsupported filter or broken stream · `/Contents` of the wrong kind · non-finite matrix · NaN box.
On any of these the whole scan is discarded and the stamp stays at the requested spot (`status = unscannable`). The
scanner never throws to the caller: a parse failure of a referenced object is also *unscannable* (Go recovers the
reader's panics). Malformed *tokens* are not failures — §3.1 defines what they mean.

## 6. Candidates and choice

`vw, vh` = visible page size (APPEARANCE_SPEC §1: `(bw, bh)`, swapped for rot 90/270). Request `x, y, w, h` (h100).
Constants: `pad = 400` (4 pt), `step = 1200` (12 pt), `kmax = 100`.

1. `xl = vw − x − w` (the mirror of the requested column; for the portal's bottom-right request this is the bottom-left
   with the same margin). Columns = `[x]`, plus `[xl]` when `xl ≠ x`.
2. Candidates in trial order:
   `(x, y)`, `(xl, y)` [if `xl ≠ x`], then `(x, y + k·step)` for `k = 1, 2, …` while `k ≤ kmax` and
   `y + k·step + h ≤ vh − y`, then the same `k` run for `(xl, …)` [if `xl ≠ x`].
   (The top margin equals the bottom margin `y`; every candidate is inside the page because the request is.)
3. For each candidate: `r = VisibleRect(box, rot, cx, cy, w, h)` (APPEARANCE_SPEC §1, user space h100);
   `e = [r0 − pad, r1 − pad, r2 + pad, r3 + pad]`. It is **free** iff no occupied box `b` satisfies
   `b0 < e2 ∧ e0 < b2 ∧ b1 < e3 ∧ e1 < b3` (strict: touching edges are free).
4. The first free candidate wins: status `requested` if it is the first candidate, else `moved`. None free → requested
   position, status `overlap`.

Fallback choice (`overlap` / `unscannable` → requested spot): it keeps today's behaviour and the signer's chosen layout;
adding a page would change the page count (and break the visible-signature validation of earlier signers), and shrinking
the stamp would need a different appearance stream. The status makes the overlap visible to the caller.

## 6a. Exact placement (`appearance.exact`)

For a position the signer chose (a UI where the citizen drags the stamp on the page preview), `appearance.exact = true`
(default `false`; JSON `exact`, TS `exact?: boolean`, Go `Exact`, .NET `Exact`, Swift/Kotlin `exact`):

- Validation is unchanged (APPEARANCE_SPEC §1): the rect must lie fully inside the page's visible box
  (`x + w ≤ vw`, `y + h ≤ vh`, `w, h > 0`) — otherwise `REQUEST_INVALID`, never clamped. `page` 0 resolves as in §1a.
- The page is scanned (§3) and the requested rect is the **only** candidate: status `requested` when it is free (§6
  step 3, with the same 4 pt `pad`), `overlap` when it is not, `unscanned` when the page cannot be scanned (§5). The
  stamp is drawn at the requested rect in every case; status is never `moved`.
- The output is the one of the non-exact request whose result is that same rect: an exact request at a free spot is
  byte-identical to an auto placement that lands there (golden `exact-free` = `table-bottom-visible`,
  `exact-page0-after-verify` = `page0-after-verify` — same `preparedSha256`). `exact` is not written into the PDF.
- `exact = false` (or absent) is byte-identical to golden v6.

## 6b. Suggestion without signing (`suggestPlacement`)

`suggestPlacement(pdf, appearance)` (TS `suggestPlacement`, Go `pades.SuggestPlacement`, .NET
`Pades.SuggestPlacement`, Swift `PAdES.suggestPlacement`, Kotlin `Pades.suggestPlacement`) runs §1a + §3–§6a on the
input **without** a certificate, signing or network, so a UI can show the default stamp position before signing and map
coordinates. Result (pt):

```
{ page,                    // 1-based, resolved (page 0 → §1a)
  x, y, width, height,     // = Prepared.placement for the same pdf + appearance
  status,                  // requested | moved | overlap | unscanned (never moved with exact)
  pageWidth, pageHeight,   // visible size of `page` (CropBox, else MediaBox; after /Rotate)
  pageCount,               // pages in /Pages tree order (§1a)
  pages: [{width, height}] // visible size of every page, index 0 = page 1; {0, 0} = geometry unreadable }
```

- Coordinates are the appearance space (APPEARANCE_SPEC §1): origin at the visible lower-left, x right, y up. A UI that
  renders page `p` at `s` px/pt with a top-left origin maps `left = x·s`, `top = (pageHeight − y − height)·s`; back:
  `x = left/s`, `y = pageHeight − top/s − height`, then pass `exact: true` so the stamp stays where the user put it.
  `pages[i]` sizes = `round100(box)/100` with the §1 box rules — viewers that intersect CropBox with MediaBox may differ
  only on malformed pages.
- Page sizes cost one walk of the page tree (no content is read except the target page's scan), so they are always
  returned.
- Checks, in order: input size (`PDF_TOO_LARGE`), `%PDF-` header and structure (`PDF_INVALID`), the appearance values
  (APPEARANCE_SPEC §1, `REQUEST_INVALID`), encryption (`PDF_ENCRYPTED`), page > page count / box / `/Rotate` / rect
  outside the page (`REQUEST_INVALID`). **Not** checked (Prepare does): prior signatures (`PDF_FOREIGN_SIGNATURE`,
  `PDF_PRIOR_SIGNATURE_INVALID`, `PDF_LOCKED`, `PDF_TOO_MANY_SIGNATURES`), the signer certificate, `docId`, and whether
  the name/role fit the stamp size (APPEARANCE_SPEC §3 — depends on the signer).
- `docId` for §1a: a document that already has signatures (any `/ByteRange` + `/Contents` dictionary, PRECHECKS) uses the
  `docId` read from its verify page link (the first `/Subtype /Link` whose `/URI` is `https://ca.eidmongolia.mn/verify/`
  + a lowercase UUID, as Prepare reads it); an unsigned document skips no page (Prepare uses the caller's or a fresh
  random `docId` there). Hence the result equals `Prepared.placement` except for an unsigned input that already carries
  verify pages of the `docId` the caller passes to Prepare (golden `page0-two-verify`, synthetic).
- Golden v7: every visible case carries `expect.suggestion` (the full object above, for that case's input) and
  `exact-out-of-bounds` carries `expect.suggestionError` = `REQUEST_INVALID`; ports compare field-for-field (numbers as
  JSON numbers) and assert `suggestion ⊇ placement` for every case except `page0-two-verify`.

## 6c. Images (golden v10)

With `signatureImage` / `stampImage` (APPEARANCE_SPEC §6) nothing in §1–§6b changes: the request `w, h` is the **whole
widget rect** — for a stamp image it is the box plus the stamp's overflow above it (the union), so the candidate rects,
the 4 pt `pad` test and the `/Rect` all use the union and the overflow never lands on content. `width = height = 0`
selects the default size by the image flags — 220 × 64 (none), 220 × 110 (signature image), 240 × 147.5 (stamp image,
with or without a signature image) — in Prepare and in `suggestPlacement` alike (pass the same `appearance`, images
included, to get the right size; `suggestion.width/height` report it). Image input errors are `REQUEST_INVALID` in
`suggestPlacement` too; the `claimedRole` requirement of `stampImage` is checked by Prepare only.

## 7. Compatibility

- Pages where the requested rect is free give byte-identical output (same `/Rect`, same objects) — all golden v3/v4
  outputs are unchanged; their manifest entries only gain `expect.placement` with `status: "requested"`.
- The validator (APPEARANCE_SPEC §5, CA `server/internal/validate`) is unaffected: it reconstructs the stamp from the
  widget's `/Rect`, wherever that is.

## 8. Conformance data

- `pades/testdata/golden/placement/vectors.json` — list of `{name, input, page, request: [x y w h] pt, expect: {box,
  rotate, boxes, x, y, status}}`; `input` is relative to `pades/testdata/golden/`; `boxes` is the exact §3 emission list
  (`null` when unscannable); `x, y` the chosen position (h100). Inputs: the golden inputs plus
  `placement/input/*.pdf` — one per rule (text state, fonts, paths, XObjects/inline image, annotations,
  Flate + Contents array + CropBox + /Rotate 180, /Rotate 270, unsupported filter, form depth, q depth, malformed tokens,
  2 000 operators; zlib trailing bytes / truncated data / missing or wrong Adler-32 / FDICT 1 and other, direct fonts
  sharing the cache entry, saturating float → int). Ports must match `boxes` element-for-element.
- Pades golden (`manifest.json`, `output/`): every visible case has `expect.placement`. New cases (golden v5):

  | case | input | request | result |
  |---|---|---|---|
  | `libreoffice-contract-visible` | `input/libreoffice-contract.pdf` (LibreOffice-converted Word contract; last-page footer under the default spot — the prod case of 2026-10-19) | 340, 36, 220×64 | moved → 340, 60 |
  | `libreoffice-contract-visible-second` | previous output, page 2, second signer | 340, 36, 220×64 | moved → 340, 132 (above the first stamp) |
  | `table-bottom-visible` | `input/table-bottom.pdf` (A4, full-width table y 40…160) | 340, 36, 220×64 | moved → 340, 168 |
  | `rotated90-footer-visible` | `input/rotated90-footer.pdf` (`/Rotate 90`, footer across the visible bottom) | 536, 36, 220×64 | moved → 536, 60 |
  | `quartz-pdf13-visible-third` | `quartz-pdf13-visible-second` output (stamp at the bottom-right) | 340, 36, 220×64 | moved → 52, 36 (bottom-left) |
  | `full-page-visible` | `input/full-page.pdf` (text on every line) | 340, 36, 220×64 | overlap → 340, 36 |

- Golden v7 (`appearance.exact`, §6a/§6b):

  | case | input | request | result |
  |---|---|---|---|
  | `exact-on-content` | `input/table-bottom.pdf` | 340, 36, 220×64, exact | overlap → 340, 36 (not moved; `table-bottom-visible` moves to 340, 168) |
  | `exact-free` | `input/table-bottom.pdf` | 340, 168, 220×64, exact | requested; `preparedSha256` = `table-bottom-visible` |
  | `exact-rotated90-on-footer` | `input/rotated90-footer.pdf` | 536, 36, 220×64, exact | overlap → 536, 36 |
  | `exact-page0-after-verify` | `case:quartz-pdf13` (page 0) | 340, 36, 220×64, exact | requested, page 1; `preparedSha256` = `page0-after-verify` |
  | `exact-out-of-bounds` | `input/table-bottom.pdf` | 400, 36, 220×64, exact (400 + 220 > 595.28) | `REQUEST_INVALID` (prepare and suggestion) |

- Regenerate: `go test ./pades/internal/core -run Placement -update-placement` (synthetic inputs + vectors), then
  `go test ./pades -run TestGolden -update` (golden cases; existing TSA fixtures are replayed so older outputs stay
  byte-identical).

## 9. Porting checklist

1. Content lexer (§3.1) — the SDK already parses PDF objects; the content lexer is a separate, smaller tokenizer.
2. zlib inflate with header (incl. FDICT/DICTID), truncation and Adler-32 checks (§3.1; platform inflaters:
   `DecompressionStream('deflate')`/pako, `Inflater`; .NET `ZLibStream` and Swift's `Compression` (raw deflate) do not
   detect truncation or check the trailer — do it yourself).
2a. float → int saturating (§2) everywhere; font cache keyed by the containing object (§3.4).
3. Interpreter (§3.2–§3.6) with the exact evaluation order of §2; fonts (§3.4); annotations (§3.7).
4. Candidates (§6) reuse the existing `VisibleRect`.
5. `Prepared.placement` in the public result; `Appearance.exact` (§6a); `suggestPlacement` (§6b) sharing the same code
   path as Prepare (resolve page → geometry → `VisibleRect` → scan → choose).
6. Tests: `placement/vectors.json` box-for-box, golden v7 byte-for-byte plus `expect.suggestion` / `suggestionError`, a fuzz/property test that the scanner never
   throws on arbitrary content bytes.
