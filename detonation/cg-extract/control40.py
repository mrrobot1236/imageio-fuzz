# RIP-40 control: lldb anchor (x27 @ +1804) + crash fa capture for ONE probe L.
# writes: X27=<hex> FA=<hex> DESC=<stop desc> to rip40_control.txt
import os, time, re
import lldb
t = lldb.debugger.GetSelectedTarget()
CWD = os.getcwd()
OUT = open(os.path.join(CWD, "rip40_control.txt"), "w")
def T(s):
    print(s, flush=True); OUT.write(s + "\n"); OUT.flush()
err = lldb.SBBroadcaster  # placeholder
sberr = lldb.SBError()

pdf = os.environ.get("RIP40_PDF", "probe_31000.pdf")
p = t.LaunchSimple([pdf, "ctl_out.png"], None, CWD)
if not (p and p.IsValid()):
    T("LAUNCH-FAIL"); OUT.close(); raise SystemExit

# entry bp at aa_cache_render (one-shot)
b1 = t.BreakpointCreateByName("aa_cache_render")
b1.SetOneShot(True)

def wait_stop(budget=40):
    st = p.GetState(); t0 = time.time()
    while st == lldb.eStateRunning:
        if time.time() - t0 > budget:
            try: p.Stop(); time.sleep(0.4); st = p.GetState()
            except Exception: return lldb.eStateKilled
            if st == lldb.eStateRunning:
                try: p.Kill()
                except Exception: pass
                return lldb.eStateKilled
            return st
        time.sleep(0.05); st = p.GetState()
    return st

st = wait_stop()
ok27 = None; fa = None; desc = ""
if st == lldb.eStateStopped:
    th = p.GetSelectedThread(); fr = th.GetSelectedFrame()
    try:
        sym = fr.GetSymbol()
        a0 = fr.GetPCAddress().GetLoadAddress(t)
        base = sym.GetStartAddress().GetLoadAddress(t)
        T("ENTRY off=%d sym=%s" % (a0 - base, sym.GetName()))
        b2 = t.BreakpointCreateByAddress(base + 1804)
        p.Continue()
        st = wait_stop()
        if st == lldb.eStateStopped:
            fr = p.GetSelectedThread().GetSelectedFrame()
            r = fr.FindRegister("x27")
            ok27 = r.GetValueAsUnsigned() if r and r.IsValid() else None
            T("X27=%x" % (ok27 or 0))
            try: t.BreakpointDelete(b2.GetID())
            except Exception: pass
        p.Continue()
        st = wait_stop(60)
    except Exception as e:
        T("CTL-EXC %s" % e)

if st == lldb.eStateStopped:
    desc = p.GetSelectedThread().GetStopDescription(400) or ""
    T("STOP-DESC=%s" % desc[:160])
    m = re.search(r"address=0x([0-9a-fA-F]+)", desc)
    if m: fa = int(m.group(1), 16)
    try: p.Kill()
    except Exception: pass
else:
    T("ENDED st=%s rc=%s" % (st, p.GetExitStatus() if p.IsValid() else -1))
T("FA=%s" % (hex(fa) if fa else "none"))
T("CONTROL-DONE")
OUT.close()
