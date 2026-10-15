# RIP-14: mapped-guard proof v2 — one-shot walk bp, guard mprotect, single continue,
# proper exit wait. SIGSEGV at write-offset = WILD WRITE CONFIRMED.
import os, sys, time
import lldb
t = lldb.debugger.GetSelectedTarget()
CWD = os.getcwd()
TRACE = open(os.path.join(CWD, "rip14_trace.txt"), "a")
def T(s): print(s); TRACE.write(s+"\n"); TRACE.flush()

CONFIGS = [
    (28928, [0x8000, 0x4000, 0x6000, 0xa000, 0x2000]),
    (31344, [0x1e000, 0x14000, 0x18000, 0x16000]),
    (31472, [0x1f000, 0x14000, 0x18000, 0x16000]),
]
for L, DELTAS in CONFIGS:
    T("[rip14] === L=%d ===" % L)
    old = t.GetProcess()
    if old and old.IsValid() and old.GetState() in (lldb.eStateRunning, lldb.eStateStopped, lldb.eStateSuspended):
        old.Kill(); time.sleep(0.4)
    bpe = t.BreakpointCreateByName("aa_cache_render")
    p = t.LaunchSimple([f"k2_d{L}.pdf", "g.png"], None, CWD)
    if not p or not p.IsValid():
        T("[rip14] launch fail"); continue
    th = p.GetSelectedThread()
    if p.GetState() != lldb.eStateStopped:
        T("[rip14] no entry stop"); continue
    pc = th.GetSelectedFrame().GetPCAddress().GetLoadAddress(t)
    bpw = t.BreakpointCreateByAddress(pc + 1804)
    bpw.SetOneShot(True)
    x27, guard, gdelta = 0, None, None
    # walk may need a few glyph iterations before accumulator assign; one-shot handles it
    for attempt in range(4):
        p.Continue()
        st = p.GetState()
        while st == lldb.eStateRunning:
            time.sleep(0.12); st = p.GetState()
        if st != lldb.eStateStopped:
            break
        x27 = p.GetSelectedThread().GetSelectedFrame().FindRegister("x27").GetValueAsUnsigned()
        if x27:
            T("[rip14] x27=%x (walk stop %d)" % (x27, attempt))
            break
    if not x27:
        T("[rip14] no x27"); continue
    for D in DELTAS:
        page = (x27 - D) & ~0xFFF
        v = t.EvaluateExpression('(int)mprotect((void*)%d, 4096, 1)' % page)
        r = v.GetValueAsSigned()
        T("[rip14] delta=%#x page=%x mprotect=%d" % (D, page, r))
        if r == 0:
            guard, gdelta = page, D
            break
    if not guard:
        T("[rip14] no mapped page in list"); continue
    p.Continue()   # single continue with guard armed
    st = p.GetState()
    while st in (lldb.eStateRunning,):
        time.sleep(0.12); st = p.GetState()
    if st == lldb.eStateStopped:
        th2 = p.GetSelectedThread()
        T("[rip14] *** SIGSEGV/STOP: %s" % (th2.GetStopDescription(200) or "?")[:120])
        fr = th2.GetSelectedFrame()
        sym = fr.GetSymbol()
        if sym:
            start = sym.GetStartAddress().GetLoadAddress(t)
            T("[rip14] *** pc-offset: +%d in %s" % (fr.GetPCAddress().GetLoadAddress(t) - start, sym.GetName()))
        p.Kill()
    T("[rip14] L=%d guard-delta=%s final=%s" % (L, hex(gdelta), p.GetExitStatus()))
TRACE.close()
