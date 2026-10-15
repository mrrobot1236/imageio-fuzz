# RIP-30: CALL-SITE CENSUS — disassemble aa_cache_render, find every blr/blraaz,
# bp them, capture target registers + source memory. The systematic consumer hunt.
import os, sys, struct, subprocess, time
import lldb
t = lldb.debugger.GetSelectedTarget()
CWD = os.getcwd()
CVE = os.path.dirname(CWD) + "/cve-2026-86950"
TRACE = open(os.path.join(CWD, "rip30_trace.txt"), "a")
def T(s): print(s, flush=True); TRACE.write(s+"\n"); TRACE.flush()
err = lldb.SBError()

def fresh():
    old = t.GetProcess()
    if old and old.IsValid() and old.GetState() in (lldb.eStateRunning, lldb.eStateStopped, lldb.eStateSuspended):
        old.Kill(); time.sleep(0.2)

def wait_stop(p, budget=25):
    p.Continue()
    st = p.GetState()
    t0 = time.time()
    while st == lldb.eStateRunning:
        if time.time() - t0 > budget:
            try: p.Stop(); time.sleep(0.5); st = p.GetState()
            except Exception: pass
            if st == lldb.eStateRunning:
                try: p.Kill()
                except Exception: pass
                return lldb.eStateKilled
            return st
        time.sleep(0.05); st = p.GetState()
    return st

def killp(p):
    try:
        if p and p.IsValid() and p.GetState() in (lldb.eStateRunning, lldb.eStateStopped, lldb.eStateSuspended):
            p.Kill()
    except Exception: pass

def safe_pc_addr(fr):
    try:
        a = fr.GetPCAddress().GetLoadAddress(t)
        if a is None or a < 0 or a >= (1 << 48): return None
        return a
    except Exception: return None

def pcoff(fr):
    a = safe_pc_addr(fr)
    try:
        if fr.GetSymbol() and a:
            return a - fr.GetSymbol().GetStartAddress().GetLoadAddress(t)
    except Exception: pass
    return -1

def reg(fr, name):
    r = fr.FindRegister(name)
    return r.GetValueAsUnsigned() if r and r.IsValid() else 0

def disasm_func(entry_addr, count=1400):
    out = []
    try:
        insts = t.ReadInstructions(lldb.SBAddress(entry_addr, t), count)
        for ins in insts:
            m = ins.GetMnemonic(target=t)
            if m.startswith("blr"):
                out.append((ins.GetAddress().GetLoadAddress(t) - entry_addr, m,
                            ins.GetOperands(target=t)))
    except Exception as e:
        T("disasm err: %s" % e)
    return out

# ---- PHASE-A: census ----
fresh()
be = t.BreakpointCreateByName("aa_cache_render"); be.SetOneShot(True)
p = t.LaunchSimple(["k2_d31472.pdf", "r.png"], None, CVE)
blr_sites = []
if p and p.IsValid():
    th = p.GetSelectedThread()
    pc0 = safe_pc_addr(th.GetSelectedFrame())
    if pc0:
        blr_sites = disasm_func(pc0, 1400)
        T("A blr-sites(%d): %s" % (len(blr_sites), [(hex(o), m, ops) for o, m, ops in blr_sites[:20]]))
    killp(p)
t.BreakpointDelete(be.GetID())
if not blr_sites:
    T("RIP-30 ABORT: no blr found"); TRACE.close(); sys.exit(0)

# ---- PHASE-B: bp the first N distinct blr sites, capture targets ----
NBP = 8
chosen = blr_sites[:NBP]
bps = {}
fresh()
be = t.BreakpointCreateByName("aa_cache_render"); be.SetOneShot(True)
p = t.LaunchSimple(["k2_d31472.pdf", "r.png"], None, CVE)
if p and p.IsValid():
    th = p.GetSelectedThread()
    pc0 = safe_pc_addr(th.GetSelectedFrame())
    if pc0:
        for off, m, ops in chosen:
            bps[off] = t.BreakpointCreateByAddress(pc0 + off)
        hits = {}
        x27 = 0
        for i in range(500):
            st = wait_stop(p)
            if st != lldb.eStateStopped: break
            fr = p.GetSelectedThread().GetSelectedFrame()
            off = pcoff(fr)
            if off in bps:
                hits[off] = hits.get(off, 0) + 1
                if hits[off] <= 3:
                    regs = {("x%d" % k): reg(fr, "x%d" % k) for k in range(18)}
                    nz = {k: hex(v) for k, v in regs.items() if v}
                    if not x27: x27 = reg(fr, "x27")
                    T("B blr+%d hit#%d regs: %s" % (off, hits[off], nz))
                p.Continue()
            else:
                p.Continue()
        killp(p)
        T("B blr-hit-counts: %s" % {hex(k): v for k, v in hits.items()})
for b in list(bps.values()): t.BreakpointDelete(b.GetID())
t.BreakpointDelete(be.GetID())
T("RIP-30 DONE")
TRACE.close()
