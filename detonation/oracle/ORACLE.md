# ASLR CRASH-ORACLE — DESIGN (RIP phase, option 2)
Status: DESIGN v1 (2026-10-15) — mrrobot/OMEGA-7. Feeds the real-target lane (WA delivery).

## 1. PROBLEM
Relative-write primitive only: strike lands at x27+64L (x27 = accumulator base, ASLR-random).
PC control needs an ABSOLUTE write (corrupt dp+0x48/0x50/0x60 fn-ptrs or release-chain blocks —
all ~25MB from the zone). Missing: victim's x27 (34 bits of ASLR) + heap region layout.
CI cannot demo full RCE because CI gives us lldb (we KNOW the layout) — the oracle matters
for the REAL TARGET where the only feedback = crash vs no-crash (1 bit).

## 2. CHANNEL MODEL (real target)
- Send crafted PDF (font with leaf-line at L) via WA auto-download (0-click ingest — the
  ImageIO parse happens on arrival, no tap).
- Feedback signals (in order of reliability):
  a. App death/restart visible via WhatsApp online-status / delivery-receipt timing gap
  b. Tracker canary: beacon server hit BEFORE crash (if the payload fetches a URL? no —
     ImageIO parse is offline; canary only confirms delivery, not state)
  c. Follow-up probe deliverability (crashed app = messages queue, receipts lag)
- Rate limit: ~1 probe per message; throttle to stay invisible (1/min proven in testpack
  protocol). Budget: hundreds of probes OK across days.

## 3. WHAT THE ORACLE CAN LEAK (1-bit per probe)
The corrupted-node walk derefs pattern-addresses = (real-high-bytes | our-low-halfwords).
L3-class patterns (0x136ffff0e) RETAIN real region prefix bits. Key consequence:
  fault/no-fault of a probe = f(region-prefix-bits ∧ our-pattern)
=> probe classes:
  A. REGION-SIZE LEAK: pattern = (correct-prefix, offset o). Victim faults iff o walks off
     the region's mapped span. Binary-search o => region span + alignment (structural,
     CI-verifiable first).
  B. PREFIX BRUTE: pattern = (guess-prefix, safe-low-offset). No-fault => guess CORRECT
     (walk continued into mapped memory) OR walk exited gracefully. Distinguish via
     double-probe (follow-up L that crashes ONLY if walk entered mapped memory).
     Search space: observed large-malloc region prefixes on runners: 0x100..0x15B (≈1.5GB
     span, 4MB granularity => ~384 candidates). At 1 probe/min = 6.4h worst case; binary
     tricks (structure of macOS libmalloc region placement = mmapped clusters, valleys)
     cut it to ~10 bits entropy => ~2-3h.
  C. x27-ZONE LOCALIZATION: strike L far-bands (crash windows) = zone-internal => no base
     info. BUT the node-arena tail behavior at band edges (rc=1 graceful at ≥32770) =
     zone-END detector: the graceful-exit boundary = (zone_end − x27) => 1-bit binary
     search on the zone's tail length => x27's offset WITHIN its region => combined with
     B => full base.

## 4. CI-SIMULATED ORACLE (validation harness — build FIRST)
Black-box wrapper: `probe.sh L` → runs render4 with font(L) → prints ONLY "0" (survive)
or "1" (crash). NO lldb in the loop.
  - Inference engine (python): consumes bits, maintains posterior over (region-prefix,
    x27-offset), chooses next L (adaptive binary search).
  - Ground truth: lldb pre-pass records actual x27/region for the SAME deterministic
    layout (ASLR-off multi-launch) => validate inference error rate.
  - Success metric: oracle infers x27-region within N probes; N < budget.
  NOTE: CI layout ≠ victim layout (different malloc history) — the ALGORITHM is what
  transfers, plus the structural constants (zone size 8MB, sub-region 64KB, band edges).

## 5. DELIVERY-LANE INTEGRATION (later)
- testpack_v1 SEND-PROTOCOL.md already defines 1/min cadence + logging.
- Oracle probes = PDFs with fonts at oracle-chosen L — same generator (gen_k2), zero new
  payload surface.
- Victim-side gate: macOS 26.6.2 confirmed vulnerable; trigger portable 14/15/26.

## 6. OPEN QUESTIONS
- Does the real target's ImageIO parse thumbnail path EXACTLY match render4's
  (CGImageSourceCreateThumbnailAtIndex 256px)? — CI = same API call = yes by construction
  IF WA uses the same thumbnail path (WA iOS renders PDF thumbs ~similar path — testpack
  PROBE results will confirm by parity of behavior).
- Crash visibility latency on target (WA restart ~seconds) — bounds probe rate.
- Region-prefix entropy on real devices (different malloc history than CI!) — the
  algorithm must be entropy-robust (posterior over wide priors).

## 7. NEXT CONCRETE STEPS
1. RIP-7 pattern-map (running) → identifies canonical-pattern Ls = oracle probe shapes.
2. Build probe.sh + inference engine skeleton (oracle/ dir).
3. CI validation campaign: 50-probe inference vs lldb ground truth ×5 layouts.
4. THEN wire to testpack lane when Djouss provides the sender number + target version.
