# v4 (clap) and v5 (grid) post-mortem — both runs were NULL

Artifacts pulled 2026-11-21 (nightly.link, no PAT). Run 41375453560 (v4-clap) and
41376244745 (v5-grid) both report `success` but did no work.

## Hard evidence
- v4: probe 52/52 `IMG=nil`, every battery run 6 ms. v5: 13/13 `IMG=nil`, 6–12 ms, all "clean".
- Gate bug: workflow greps `IMG=` — which also matches `IMG=nil`. Gate can never fail.

## v4 root cause (fatal, upstream of clap)
The templates used are header-only fragments: `triage-units/v2.2/oom-*` are 427–465 B,
**0 of 4 contain `mdat`**, 2 of 4 do not even contain `iloc`. No pixel data exists, so
CGImageSource returns nil before any aperture math. Clap can never be exercised on them.
(They can still OOM because the thumbnail path allocates from `ispe` before reading data.)

## v5 root cause (9 authoring bugs in gen_grid.py)
1. `iloc` field-size header written as two bytes (`04 04`) — spec packs them as 4-bit
   nibbles (`0x44`).
2. `iloc` v1 field order wrong: `extent_count` must come **after** `base_offset`.
3. Box sizes stale on `iinf`, `ipco`, `iloc` — all built with `box()` then `+=`.
4. Base offset computed before `iloc` was inserted into `meta` (self-referential shift).
5. Grid item data placed at the end of `mdat` instead of an `idat` box.
6. Grid payload `flags` = 0 → parser reads 16-bit dims while 32-bit dims were written.
7. No `ipma` entries for tile items → tiles had neither `ispe` nor `hvcC`.
8. Grid item wrongly associated with `hvcC`.
9. `parse_iloc` ignored `base_offset`/`construction_method` → “tile payload” was bytes
   sliced from file offset 0 (i.e. the `ftyp` box).

## Verification (libheif 1.23.6 + pillow_heif, local)
Fixed generator (`gen_v6_grid.py`) produces a grid that decodes: 8/12 cases decode,
including baseline 512×512, 1×1, 3×3, 4×1, 1×4, 8×8. The 4 lie cases fail with
`Grid tiles do not cover whole image` (libheif is strict; Apple's tolerance is the open
question worth testing) and `0xFFFFFFFF` collapses to 0×0.

## Actions
- New `detonate-v6-grid.yml` with a **strict gate** (`IMG=<digits>x<digits>`) and a
  NODECODE counter in the summary.
- v4 lane must be re-based on decodable HEICs (sips output, or libheif `clap_cropped.heic`)
  before clap authoring is retried.
