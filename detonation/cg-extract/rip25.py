# RIP-25: SLOT-RANGE SWEEP — walk the wild-write strike INTO the dispatch-table
# slot zone (page+0x810..0x910 class). Per-L process, self-calibrating:
# walk#2 -> scan for densest code-ptr page near x27 -> dump slots (record run
# offset in page) -> guard page -> delete walk bp -> continue -> record strike
# (fa, site, code, delta, INSIDE/BELOW/ABOVE slot range).
import os, sys, struct, subprocess, time
import lldb
t = lldb.debugger.GetSelectedTarget()
CWD = os.getcwd()
TRACE = open(os.path.join(CWD, "rip25_trace.txt"), "a")
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
            # find dense run start (>=6 codeish within 32 qwords window)
            off = -1
            for j in range(len(qs) - 8):
                w = qs[j:j+16]
                if sum(1 for q in w if codeish(q)) >= 8:
                    off = j*8; break
            bestn = n; best = page; bestoff = off
    return best, bestn, bestoff

RESULTS = {}
for L in [30400, 30464, 30528, 30592, 30656, 30720, 30784, 30848, 30912, 30976, 31040, 31104]:
    f = "k2_e%d.ttf" % L; pdf = "k2_e%d.pdf" % L
    if not os.path.exists(pdf):
        r = subprocess.run(['./venv/bin/python','-c',
            "import sys; sys.path.insert(0,'.'); from gen_k2 import build_font; build_font('%s', %d)" % (f, L)], capture_output=True)
        if r.returncode != 0:
            T("L=%d fontfail" % L); continue
        subprocess.run(['./venv/bin/python','gen_pdf.py', pdf, f], capture_output=True)
    fresh()
    be = t.BreakpointCreateByName("aa_cache_render"); be.SetOneShot(True)
    p = t.LaunchSimple([pdf, "r.png"], None, CWD)
    if not p or not p.IsValid():
        T("L=%d launchfail" % L); continue
    th = p.GetSelectedThread()
    pc0 = safe_pc_addr(th.GetSelectedFrame())
    if not pc0:
        T("L=%d noentry" % L); killp(p); continue
    bw = t.BreakpointCreateByAddress(pc0 + 1804)
    x27 = 0; wh = 0; slots = None; done = False
    for i in range(40):
        st = wait_stop(p)
        if st != lldb.eStateStopped: break
        fr = p.GetSelectedThread().GetSelectedFrame()
        off = -1
        try:
            a = safe_pc_addr(fr)
            if fr.GetSymbol() and a:
                off = a - fr.GetSymbol().GetStartAddress().GetLoadAddress(t)
        except Exception: pass
        if off == 1804:
            wh += 1
            x27 = fr.FindRegister("x27").GetValueAsUnsigned()
            if wh == 2:
                tp, n, soff = find_table(p, x27)
                if not tp or soff < 0:
                    T("L=%d no-table(n=%d off=%d)" % (L, n, soff)); break
                slots = qwords(p, tp + soff, 24)
                T("L=%d table=%x slots@+%x (n=%d): %s" % (L, tp, soff, n, [hex(q) for q in (slots or [])][:8]))
                tp = tp & ~0xFFF
                v = t.EvaluateExpression('(int)mprotect((void*)%d, 4096, 1)' % tp)
                T("L=%d guard %x mprot=%d" % (L, tp, v.GetValueAsSigned()))
                t.BreakpointDelete(bw.GetID())
            p.Continue()
        else:
            desc = p.GetSelectedThread().GetStopDescription(300) or ""
            fa = 0
            if "address=" in desc:
                try: fa = int(desc.split("address=")[1].split(")")[0], 16)
                except Exception: pass
            a = safe_pc_addr(fr); symoff = -1
            try:
                if fr.GetSymbol() and a: symoff = a - fr.GetSymbol().GetStartAddress().GetLoadAddress(t)
            except Exception: pass
            if x27 and slots:
                d = fa - x27
                slot_lo = (tp & ~0xFFF) + soff; slot_hi = slot_lo + 24*8
                zone = "INSIDE" if slot_lo <= fa < slot_hi else ("BELOW" if fa < slot_lo else "ABOVE")
                x0 = fr.FindRegister("x0").GetValueAsUnsigned()
                T("L=%d STRIKE site+%d code=%s fa=%x delta=%d zone=%s [slots %x..%x] x0=%x" %
                  (L, symoff, desc.split("(")[1][:4] if "(" in desc else "?", fa, d, zone, slot_lo, slot_hi, x0))
                RESULTS[L] = (symoff, fa, d, zone)
            else:
                T("L=%d early-stop %s" % (L, desc[:60]))
            killp(p); done = True; break
    if not done:
        T("L=%d rc=%s (no strike)" % (L, p.GetExitStatus() if p.IsValid() else -1))
        killp(p)
    for b in (be, bw):
        if b: t.BreakpointDelete(b.GetID())
T("RIP-25 strikes: %s" % RESULTS)
inside = {L: v for L, v in RESULTS.items() if v[3] == "INSIDE"}
T("RIP-25 INSIDE-SLOT Ls: %s" % inside)
TRACE.close()
