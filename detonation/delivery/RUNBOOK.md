# FIELD RUNBOOK — iPhone 11 (A13, iOS 26.6)

Two independent lanes. **Image first, PDF last** (PDF failures crash WhatsApp and poison timings).

Baseline before anything: send an ordinary 400 KB photo, time preview. Everything is relative to that.

## Lane A — image bomb (no version gate, survives 26.7.1+)
File: `image/WA_bomb_65k.heic` (472 KB, 65,025 tiles, 512 canvas). CI: 6.0–7.4 s on M-series.

A1. Send as **image** message. Time Android→preview. (Tests the 0-click pipeline; recompression risk.)
A2. Send as **document**. Tap. Time to first frame and to full. WA alive? chat scrolls?
A3. 3 documents, open sequentially, times.
A4. 5 documents back-to-back, cumulative?
A5. A2 in Low Power Mode at ≤20 % battery.
A6. A2 during a voice call.

Integrity once, on A2: share → Save to Files → `shasum -a 256` via Shortcuts → send hex. Compare to `MANIFEST.sha256`.

## Lane B — PDF (CVE-2026-86950, GATED: iOS < 26.7.1 only)
Files: `pdf/P1_trigger.pdf` (known-crash PoC), then `P2_oracle_wild.pdf`, `P3_b32760.pdf`.
Delivery: document → tap → wait. 1-click.

B1. P1: crash to springboard? respring? blank preview? seconds.
B2. P2 same. B3. P3 same.
After each: Analytics Data screenshot for `WhatsApp-*` / `.ips` / `JetsamEvent`.

## Record per case
seconds, crash vs hang, blank preview/spinner, WA restart, chat scroll after, battery %, thermal, iOS + WA version, screenshots, hash.

Abort rule: max 2 attempts per case; a cold device beats a warm one.
