# RIP-11: wild-write proof — survivor-L trace: x27 @+1804 -> snapshot below-pool pages
# -> bp rel_cb (post-decode) -> re-snapshot -> DIFF = wild-write footprint.
import os, sys, struct, time
import lldb

def out(s): print(s); sys.stdout.flush()
t = lldb.debugger.GetSelectedTarget()
CWD = os.getcwd()
TRACE = open(os.path.join(CWD, "rip11_trace.txt"), "a")
def T(s): out(s); TRACE.write(s+"\n"); TRACE.flush()

OFFS = [0x48000, 0x40000, 0x38000, 0x30000, 0x28000, 0x20000, 0x18000, 0x10000, 0x8000]
def snapshot(p, x27):
    pages = {}
    err = lldb.SBError()
    for o in OFFS:
        m = p.ReadMemory(x27 - o, 512, err)
        pages[o] = m if err.Success() else None
    return pages

def diff(pre, post, x27):
    n = 0
    for o in OFFS:
        a, b = pre.get(o), post.get(o)
        if a and b and a != b:
            for i in range(0, len(a), 8):
                if a[i:i+8] != b[i:i+8]:
                    v = struct.unpack('<Q', b[i:i+8])[0]
                    T("  WILD-WRITE x27-%#x+%#x = %016x" % (o, i, v))
                    n += 1
    return n

for L in (28928, 31344, 31472):
    T("[rip11] === survivor L=%d ===" % L)
    bpe = t.BreakpointCreateByName("aa_cache_render")
    p = t.LaunchSimple([f"k2_d{L}.pdf", "w.png", ], None, CWD)
    if not p or not p.IsValid():
        T("[rip11] launch fail (render4 takes 2 args!)"); break
    th = p.GetSelectedThread()
    if p.GetState() != lldb.eStateStopped:
        T("[rip11] no entry stop"); t.BreakpointDelete(bpe.GetID()); continue
    pc = th.GetSelectedFrame().GetPCAddress().GetLoadAddress(t)
    bpw = t.BreakpointCreateByAddress(pc + 1804)
    p.Continue()
    x27 = th.GetSelectedFrame().FindRegister("x27").GetValueAsUnsigned()
    T("[rip11] x27=%x" % x27)
    t.BreakpointDelete(bpw.GetID()); t.BreakpointDelete(bpe.GetID())
    pre = snapshot(p, x27)
    bpr = t.BreakpointCreateByName("rel_cb")
    p.Continue()
    st = p.GetState()
    if st == lldb.eStateStopped:
        post = snapshot(p, x27)
        n = diff(pre, post, x27)
        T("[rip11] L=%d rel_cb stop; wild-write qwords: %d" % (L, n))
        p.Continue()
        while p.GetState() == lldb.eStateRunning: time.sleep(0.15)
    else:
        T("[rip11] L=%d no rel_cb stop (state=%d)" % (L, st))
    T("[rip11] L=%d final rc=%s" % (L, p.GetExitStatus()))
TRACE.close()
