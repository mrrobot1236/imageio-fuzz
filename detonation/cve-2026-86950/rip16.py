# RIP-16: two-glyph cascade baseline. Trace walk stops (x27/x16 per +1804 hit)
# across glyph A (L=31472) and glyph B (L=29840) in ONE decode; then guard-runs:
# mprotect glyph-A strike page + glyph-B strike page -> per-glyph strike counts.
import os, sys, time
import lldb
t = lldb.debugger.GetSelectedTarget()
CWD = os.getcwd()
TRACE = open(os.path.join(CWD, "rip16_trace.txt"), "a")
def T(s): print(s); TRACE.write(s+"\n"); TRACE.flush()

L1, L2 = 31472, 29840
PDF = "k3_pair.pdf"

def fresh():
    old = t.GetProcess()
    if old and old.IsValid() and old.GetState() in (lldb.eStateRunning, lldb.eStateStopped, lldb.eStateSuspended):
        old.Kill(); time.sleep(0.25)
    bpe = t.BreakpointCreateByName("aa_cache_render")
    p = t.LaunchSimple([PDF, "c.png"], None, CWD)
    return bpe, p

# RUN-1: walk-stop trace (bp +1804, keep hitting)
bpe, p = fresh()
th = p.GetSelectedThread()
pc = th.GetSelectedFrame().GetPCAddress().GetLoadAddress(t)
bpw = t.BreakpointCreateByAddress(pc + 1804)
seq = []
for i in range(24):
    p.Continue()
    st = p.GetState()
    while st == lldb.eStateRunning:
        time.sleep(0.1); st = p.GetState()
    if st != lldb.eStateStopped: break
    fr = p.GetSelectedThread().GetSelectedFrame()
    x27 = fr.FindRegister("x27").GetValueAsUnsigned()
    x16 = fr.FindRegister("x16").GetValueAsUnsigned()
    seq.append((i, x27, x16))
    T("stop%02d x27=%x x16=%x x27-x16=%x" % (i, x27, x16, (x27 - x16) & 0xFFFFFFFFFFFF))
    if x27 and i == 0:
        x27_first = x27
p.Kill(); t.BreakpointDelete(bpw.GetID()); t.BreakpointDelete(bpe.GetID())
T("RUN-1 stops: %d" % len(seq))
if seq:
    x27s = [s[1] for s in seq]
    T("x27 drift: min=%x max=%x span=%x" % (min(x27s), max(x27s), max(x27s) - min(x27s)))

# RUN-2: guard glyph-A strike page (x27_first - 0x19000), count SIGSEGVs in decode
if seq:
    bpe, p = fresh()
    th = p.GetSelectedThread()
    pc = th.GetSelectedFrame().GetPCAddress().GetLoadAddress(t)
    bpw = t.BreakpointCreateByAddress(pc + 1804); bpw.SetOneShot(True)
    p.Continue()
    st = p.GetState()
    while st == lldb.eStateRunning: time.sleep(0.1); st = p.GetState()
    x27 = p.GetSelectedThread().GetSelectedFrame().FindRegister("x27").GetValueAsUnsigned()
    t.BreakpointDelete(bpw.GetID())
    hits = 0
    for D in (0x19000, 0x1a000):
        page = (x27 - D) & ~0xFFF
        v = t.EvaluateExpression('(int)mprotect((void*)%d, 4096, 1)' % page)
        if v.GetValueAsSigned() != 0:
            T("run2 guard d=%#x unmapped" % D); continue
        p.Continue()
        st = p.GetState()
        while st == lldb.eStateRunning: time.sleep(0.1); st = p.GetState()
        if st == lldb.eStateStopped:
            th2 = p.GetSelectedThread()
            T("run2 STRIKE d=%#x : %s" % (D, (th2.GetStopDescription(200) or "?")[:100]))
            hits += 1
            p.Kill()
            bpe2, p = fresh()   # fresh process for next guard
            th = p.GetSelectedThread()
            pc = th.GetSelectedFrame().GetPCAddress().GetLoadAddress(t)
            bpw = t.BreakpointCreateByAddress(pc + 1804); bpw.SetOneShot(True)
            p.Continue()
            st = p.GetState()
            while st == lldb.eStateRunning: time.sleep(0.1); st = p.GetState()
            x27 = p.GetSelectedThread().GetSelectedFrame().FindRegister("x27").GetValueAsUnsigned()
            t.BreakpointDelete(bpw.GetID())
        else:
            T("run2 d=%#x survive" % D)
    T("RUN-2 glyph-A strikes: %d" % hits)

# RUN-3: guard glyph-B strike page (x27 - 0x4c000, from L=29840 canonical delta)
bpe, p = fresh()
th = p.GetSelectedThread()
pc = th.GetSelectedFrame().GetPCAddress().GetLoadAddress(t)
bpw = t.BreakpointCreateByAddress(pc + 1804); bpw.SetOneShot(True)
p.Continue()
st = p.GetState()
while st == lldb.eStateRunning: time.sleep(0.1); st = p.GetState()
x27 = p.GetSelectedThread().GetSelectedFrame().FindRegister("x27").GetValueAsUnsigned()
t.BreakpointDelete(bpw.GetID())
# glyph B walks AFTER glyph A: x27 by then may differ; probe both current-x27 far deltas
for D in (0x4c000, 0x4a000, 0x48000):
    page = (x27 - D) & ~0xFFF
    v = t.EvaluateExpression('(int)mprotect((void*)%d, 4096, 1)' % page)
    r = v.GetValueAsSigned()
    T("run3 probe d=%#x -> %d" % (D, r))
    if r == 0:
        p.Continue()
        st = p.GetState()
        while st == lldb.eStateRunning: time.sleep(0.1); st = p.GetState()
        if st == lldb.eStateStopped:
            th2 = p.GetSelectedThread()
            fr = th2.GetSelectedFrame()
            off = -1
            if fr.GetSymbol():
                off = fr.GetPCAddress().GetLoadAddress(t) - fr.GetSymbol().GetStartAddress().GetLoadAddress(t)
            T("run3 STRIKE d=%#x +%d : %s" % (D, off, (th2.GetStopDescription(200) or "?")[:100]))
            p.Kill()
        else:
            T("run3 d=%#x survive" % D)
        break
p.Kill()
T("RIP-16 DONE")
TRACE.close()
