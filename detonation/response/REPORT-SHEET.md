# RESPONSE SHEET — outcome-labelled battery

Each unit has a designed, distinguishable outcome. Send as DOCUMENT, tap, then tick what you actually saw.
If observed ≠ expected, that is itself the finding (iOS 27 changed behaviour).

| # | file | expected outcome | observed (tick one) |
|---|------|------------------|---------------------|
| R0 | image/R0_control_ok.heic | normal preview, fast | fast / slow / blank / error / crash |
| R1 | image/R1_stall_bomb.heic | long spinner then image | fast / slow(s) / blank / error / crash |
| R2 | image/R2_blank_canvas.heic | blank preview, no error | fast / slow / blank / error / crash |
| R3 | image/R3_fail_dimg_short.heic | decode error / "cannot load" | fast / slow / blank / error / crash |
| R4 | image/R4_fail_mixed_lie.heic | decode error / "cannot load" | fast / slow / blank / error / crash |
| R5 | image/R5_fail_tile0.heic | decode error / "cannot load" | fast / slow / blank / error / crash |
| P0 | pdf/P0_control_valid.pdf | renders preview | ok / blank / error / crash |
| P1 | pdf/P1_trunc_60pct.pdf | error or partial render | ok / blank / error / crash |
| P2 | pdf/P2_garbage_tail.pdf | error | ok / blank / error / crash |
| P3 | pdf/P3_noxref.pdf | error (broken xref) | ok / blank / error / crash |

Notes per unit: seconds, WA restart?, screen state after.

## Why this matters
- A **blank** where a normal render is expected, or an **error** on a structurally legal file, proves the compositor path is being reached on 27 and tells us which invariant Apple enforces.
- A **crash** on any unit is an immediate candidate bug.
- If R3/R4/R5 render fine on 27 (they nil on 26), Apple loosened validation → new leniency = new attack surface, and we rebuild the matrix around it.
