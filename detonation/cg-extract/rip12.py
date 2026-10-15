# RIP-12: guard-page wild-write proof. mprotect(x27-DELTA_page, 4096, PROT_READ)
# at the walk site -> continue -> SIGSEGV at +1868/+2396 = WRITE SITE CONFIRMED.
import os, sys, time
import lldb
def out(s): print(s); sys.stdout.flush()
t = lldb.debugger.GetSelectedTarget()
CWD = os.getcwd()
TRACE = open(os.path.join(CWD, "rip12_trace.txt"), "a")
def T(s): out(s); TRACE.write(s+"\n"); TRACE.flush()

PLAN = [(28928, 0x13000), (31344, 0x1f000), (31472, 0x13000), (28928, 0x46000), (31344, 0x12000)]
for L, DELTA in PLAN:
    T("[rip12] === L=%d guard=x27-%#x ===" % (L, DELTA))
    # clean any live process
    old = t.GetProcess()
    if old and old.IsValid() and old.GetState() in (lldb.eStateRunning, lldb.eStateStopped, lldb.eStateSuspended):
        old.Kill(); time.sleep(0.4)
    bpe = t.BreakpointCreateByName("aa_cache_render")
    p = t.LaunchSimple([f"k2_d{L}.pdf", "g.png"], None, CWD)
    if not p or not p.IsValid():
        T("[rip12] launch fail"); continue
    th = p.GetSelectedThread()
    if p.GetState() != lldb.eStateStopped:
        T("[rip12] no entry stop (state=%d)" % p.GetState()); continue
    pc = th.GetSelectedFrame().GetPCAddress().GetLoadAddress(t)
    bpw = t.BreakpointCreateByAddress(pc + 1804)
    p.Continue()
    if p.GetState() != lldb.eStateStopped:
        T("[rip12] no walk stop"); continue
    x27 = th.GetSelectedFrame().FindRegister("x27").GetValueAsUnsigned()
    page = (x27 - DELTA) & ~0xFFF
    T("[rip12] x27=%x guardpage=%x" % (x27, page))
    # mprotect via expression (returns 0 on success)
    expr = '(int)mprotect((void*)%d, 4096, 1)' % page   # PROT_READ=1
    val = lldb.SBCommandReturnObject()
    t.GetProcess().GetSelectedTarget().EvaluateExpression(expr, val)
    res = val.GetOutput() or val.GetError() or ""
    T("[rip12] mprotect -> %s" % (res.strip().splitlines()[-1] if res.strip() else "?"))
    t.BreakpointDelete(bpw.GetID()); t.BreakpointDelete(bpe.GetID())
    p.Continue()
    st = p.GetState()
    while st == lldb.eStateRunning: time.sleep(0.15); st = p.GetState()
    if st == lldb.eStateStopped:
        d = p.GetStopDescription(200)
        th2 = p.GetSelectedFrame() and p.GetSelectedThread()
        fr = p.GetSelectedThread().GetSelectedFrame()
        off = fr.GetPCAddress().GetLoadAddress(t) - fr.GetCompileUnit() and 0
        T("[rip12] *** STOPPED: %s | frame=%s+%.0s" % (d[:120], fr.GetDisplayFunctionName() or "?", ""))
        # get pc offset within aa_cache_render if applicable
        sym = fr.GetSymbol()
        if sym:
            start = sym.GetStartAddress().GetLoadAddress(t)
            pcaddr = fr.GetPCAddress().GetLoadAddress(t)
            T("[rip12] pc-offset: +%d in %s" % (pcaddr - start, sym.GetName()))
        p.Continue()
        while p.GetState() == lldb.eStateRunning: time.sleep(0.15); st = p.GetState()
    rc = p.GetExitStatus()
    T("[rip12] L=%d guard=%#x rc=%s" % (L, DELTA, rc))
TRACE.close()
