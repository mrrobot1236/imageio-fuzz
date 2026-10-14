# K1b calibration tracer v4: head chains (first 2), ALL write-site events, BAD_ACCESS forensics
import os, sys, struct, lldb
def out(s):
    print(s); sys.stdout.flush()
t = lldb.debugger.GetSelectedTarget()
p = t.GetProcess()
th = p.GetSelectedThread()
fr = th.GetSelectedFrame()
base = fr.GetPCAddress().GetLoadAddress(t)
out("[cal] base=0x%x" % base)
if base in (0, 0xffffffffffffffff):
    out("[cal] bad base"); sys.exit(0)
for bp in list(t.breakpoint_iter()):
    t.BreakpointDelete(bp.GetID())
for off in (1804, 1984, 2396, 2496):
    t.BreakpointCreateByAddress(base + off)
out("[cal] bps: 1804 1984 2396 2496")
def rd(addr, n):
    err = lldb.SBError()
    m = p.ReadMemory(addr, n, err)
    return m if err.Success() else None
def regs(fr):
    def r(n):
        v = fr.FindRegister(n)
        return v.GetValueAsUnsigned() if v else 0
    return r
heads = wev = stops = 0
while stops < 1200 and wev < 40:
    p.Continue()
    st = p.GetState()
    if st != 5:
        out("[cal] state=%d heads=%d wev=%d" % (st, heads, wev)); break
    fr = th.GetSelectedFrame()
    desc = th.GetStopDescription(200)
    off = fr.GetPCAddress().GetLoadAddress(t) - base
    r = regs(fr)
    if 'BAD_ACCESS' in desc:
        out("[cal] FAULT: %s" % desc)
        out("[cal] x9=0x%x x11=0x%x x16=0x%x x22=0x%x x25=0x%x x27=0x%x x19=0x%x" % (
            r('x9'), r('x11'), r('x16'), r('x22'), r('x25'), r('x27'), r('x19')))
        for name, addr, cnt in (('x11-0x30', r('x11')-0x30, 12), ('x16-0x30', r('x16')-0x30, 12)):
            if addr:
                m = rd(addr, cnt*8)
                out("[mem %s @0x%x] %s" % (name, addr, ' '.join('%016x' % v for v in struct.unpack('<%dQ' % cnt, m)) if m else 'unreadable'))
        break
    if off == 1804:
        heads += 1
        if heads <= 2:
            out("[head %d] x22=0x%x x9=0x%x x25=0x%x x27=0x%x x19=0x%x" % (heads, r('x22'), r('x9'), r('x25'), r('x27'), r('x19')))
            for lname, start in (('x22', r('x22')), ('x9', r('x9'))):
                seen = set(); cur = start; chain = []
                for i in range(20):
                    if not cur or cur in seen or cur == 0xffffffffffffffff: break
                    seen.add(cur)
                    m = rd(cur, 0x30)
                    if not m: break
                    nxt, = struct.unpack_from('<Q', m, 0)
                    f = struct.unpack_from('<7I', m, 0x10)
                    chain.append("%d:0x%x[nx=0x%x F=%s]" % (i, cur, nxt, ' '.join('%08x' % v for v in f)))
                    if nxt in seen: break
                    cur = nxt
                out("[chain %s] %s" % (lname, ' '.join(chain) if chain else '(empty)'))
            m = rd(r('x27'), 0x40)
            if m:
                out("[acc] %s" % ' '.join('%08x' % v for v in struct.unpack('<16I', m)))
    elif off in (1984, 2396, 2496):
        wev += 1
        sgn = lambda v: v - 2**32 if v >= 2**31 else v
        out("[W +%d] x27=0x%x x13=0x%x x14=0x%x x16=0x%x x2=0x%x x17=0x%x w12=%d w13=%d w14=%d w15=%d" % (
            off, r('x27'), r('x13'), r('x14'), r('x16'), r('x2'), r('x17'),
            sgn(r('w12')), sgn(r('w13')), sgn(r('w14')), sgn(r('w15'))))
    stops += 1
out("[cal] done stops=%d heads=%d wev=%d" % (stops, heads, wev))
