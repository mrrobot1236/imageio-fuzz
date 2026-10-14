# K1a map mode: walk the node list at loop head, dump nodes + accumulator, ASLR off
import os, sys, struct, lldb
def out(s):
    print(s); sys.stdout.flush()
t = lldb.debugger.GetSelectedTarget()
p = t.GetProcess()
th = p.GetSelectedThread()
fr = th.GetSelectedFrame()
base = fr.GetPCAddress().GetLoadAddress(t)
mode = os.environ.get('JMODE', 'map')
out("[k1] base=0x%x mode=%s" % (base, mode))
if base in (0, 0xffffffffffffffff):
    out("[k1] bad base"); sys.exit(0)
def rd(addr, n):
    err = lldb.SBError()
    m = p.ReadMemory(addr, n, err)
    return m if err.Success() else None
# bp loop head +1804, fault +1828
for bp in list(t.breakpoint_iter()):
    t.BreakpointDelete(bp.GetID())
t.BreakpointCreateByAddress(base + 1804)   # loop head (byte offsets!)
t.BreakpointCreateByAddress(base + 1828)   # fault read
t.BreakpointCreateByAddress(base + 1984)   # vertical write
t.BreakpointCreateByAddress(base + 2396)   # bilinear write
t.BreakpointCreateByAddress(base + 2496)   # span write
out("[k1] bps armed (BYTE offsets): 1804 1828 1984 2396 2496")
hits = 0
first_chain_done = False
while hits < 500:
    p.Continue()
    st = p.GetState()
    if st != 5:
        out("[k1] state=%d hits=%d" % (st, hits)); break
    fr = th.GetSelectedFrame()
    desc = th.GetStopDescription(200)
    off = fr.GetPCAddress().GetLoadAddress(t) - base
    def r(n):
        v = fr.FindRegister(n)
        return v.GetValueAsUnsigned() if v else 0
    if off == 1804:  # loop head
        x22, x9, x25, x27, x19 = r('x22'), r('x9'), r('x25'), r('x27'), r('x19')
        if hits == 0:
            out("[k1] FIRST HEAD: x22=0x%x x9=0x%x x25=0x%x x27=0x%x x19=0x%x" % (x22, x9, x25, x27, x19))
        # node chain from x9 (active list) and x22 head
        for lname, start in (('x22head', x22), ('x9chain', x9)):
            seen = set()
            cur = start
            chain = []
            for i in range(24):
                if cur in seen or not cur or cur in (0, 0xffffffffffffffff): break
                seen.add(cur)
                m = rd(cur, 0x30)
                if not m: break
                nxt, = struct.unpack_from('<Q', m, 0)
                f10, f14, f18, f1c, f20, f24, f2c = struct.unpack_from('<7I', m, 0x10)
                chain.append("%d:0x%x[nx=0x%x x10=%08x x14=%08x x18=%08x x1c=%08x x20=%08x x24=%08x x2c=%04x]" % (
                    i, cur, nxt, f10, f14, f18, f1c, f20, f24, f2c & 0xffff))
                if nxt in seen: break
                cur = nxt
            out("[chain %s] %s" % (lname, ' '.join(chain) if chain else '(empty)'))
        # accumulator around x27
        m = rd(x27 - 0x10, 0x60)
        if m:
            out("[acc x27=0x%x] %s" % (x27, ' '.join('%08x' % v for v in struct.unpack('<24I', m))))
        hits += 1
    elif off in (1984, 2396, 2496):  # write sites
        out("[W +%d] x27=0x%x x13=0x%x x14=0x%x x16=0x%x x2=0x%x x17=0x%x x9=0x%x x11=0x%x w12=%d w13=%d w14=%d w15=%d" % (
            off, r('x27'), r('x13'), r('x14'), r('x16'), r('x2'), r('x17'), r('x9'), r('x11'),
            r('w12') if r('w12')<2**31 else r('w12')-2**32,
            r('w13') if r('w13')<2**31 else r('w13')-2**32,
            r('w14') if r('w14')<2**31 else r('w14')-2**32,
            r('w15') if r('w15')<2**31 else r('w15')-2**32))
        hits += 1
    elif off == 1828:  # fault site
        out("[k1] FAULT-STOP: %s" % desc)
        out("[k1] x9=0x%x x11=0x%x x16=0x%x x22=0x%x x27=0x%x x25=0x%x x19=0x%x" % (
            r('x9'), r('x11'), r('x16'), r('x22'), r('x27'), r('x25'), r('x19')))
        for name, addr, cnt in (('x16-0x30', r('x16')-0x30, 12), ('x27', r('x27'), 16)):
            if addr:
                m = rd(addr, cnt*8)
                out("[mem %s @0x%x] %s" % (name, addr, ' '.join('%016x' % v for v in struct.unpack('<%dQ' % cnt, m)) if m else 'unreadable'))
        break
    else:
        hits += 1
out("[k1] done hits=%d" % hits)
