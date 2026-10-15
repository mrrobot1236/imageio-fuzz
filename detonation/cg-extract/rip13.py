# RIP-13: mapped-guard wild-write proof. Probe mprotect until MAPPED page found
# (the -1/0 boundary = in-lldb oracle), guard it read-only, continue -> SIGSEGV
# at aa_cache_render+write-offset = WILD WRITE SITE CONFIRMED.
import os, sys, time
import lldb
t = lldb.debugger.GetSelectedTarget()
CWD = os.getcwd()
TRACE = open(os.path.join(CWD, "rip13_trace.txt"), "a")
def T(s): print(s); TRACE.write(s+"\n"); TRACE.flush()

CONFIGS = [
    (28928, [0x12000, 0x10000, 0x14000, 0x18000, 0x0c000]),
    (31344, [0x1f000, 0x20000, 0x1e000, 0x22000, 0x18000]),
    (31472, [0x1f000, 0x20000, 0x1e000, 0x12000, 0x26000]),
]
for L, DELTAS in CONFIGS:
    T("[rip13] === L=%d probing %s ===" % (L, [hex(d) for d in DELTAS]))
    old = t.GetProcess()
    if old and old.IsValid() and old.GetState() in (lldb.eStateRunning, lldb.eStateStopped, lldb.eStateSuspended):
        old.Kill(); time.sleep(0.4)
    bpe = t.BreakpointCreateByName("aa_cache_render")
    p = t.LaunchSimple([f"k2_d{L}.pdf", "g.png"], None, CWD)
    if not p or not p.IsValid():
        T("[rip13] launch fail"); continue
    th = p.GetSelectedThread()
    if p.GetState() != lldb.eStateStopped:
        T("[rip13] no entry stop"); continue
    pc = th.GetSelectedFrame().GetPCAddress().GetLoadAddress(t)
    bpw = t.BreakpointCreateByAddress(pc + 1804)
    p.Continue()
    if p.GetState() != lldb.eStateStopped:
        T("[rip13] no walk stop"); continue
    x27 = th.GetSelectedFrame().FindRegister("x27").GetValueAsUnsigned()
    guard, gdelta = None, None
    for D in DELTAS:
        page = (x27 - D) & ~0xFFF
        v = t.EvaluateExpression('(int)mprotect((void*)%d, 4096, 1)' % page)
        r = v.GetValueAsSigned()
        T("[rip13] x27=%x delta=%#x page=%x mprotect=%d" % (x27, D, page, r))
        if r == 0:
            guard, gdelta = page, D
            break
    if not guard:
        T("[rip13] no mapped page found in list"); continue
    t.BreakpointDelete(bpw.GetID()); t.BreakpointDelete(bpe.GetID())
    p.Continue()
    st = p.GetState()
    while st == lldb.eStateRunning:
        time.sleep(0.15); st = p.GetState()
    if st == lldb.eStateStopped:
        th2 = p.GetSelectedThread()
        T("[rip13] *** STOPPED: %s" % (th2.GetStopDescription(200) or "?")[:120])
        fr = th2.GetSelectedFrame()
        sym = fr.GetSymbol()
        if sym:
            start = sym.GetStartAddress().GetLoadAddress(t)
            T("[rip13] pc-offset: +%d in %s" % (fr.GetPCAddress().GetLoadAddress(t) - start, sym.GetName()))
        p.Continue()
        while p.GetState() == lldb.eStateRunning:
            time.sleep(0.15); st = p.GetState()
    T("[rip13] L=%d guard-delta=%s rc=%s" % (L, hex(gdelta) if gdelta else "?", p.GetExitStatus()))
TRACE.close()
