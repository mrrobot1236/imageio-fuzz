# K2 aim-verifier: BEFORE snapshot at loop head, target+AFTER at write sites, fault forensics
import os, sys, struct, lldb
def out(s):
    print(s); sys.stdout.flush()
t = lldb.debugger.GetSelectedTarget()
p = t.GetProcess()
th = p.GetSelectedThread()
fr = th.GetSelectedFrame()
base = fr.GetPCAddress().GetLoadAddress(t)
out("[l2] base=0x%x" % base)
if base in (0, 0xffffffffffffffff):
    out("[l2] bad base"); sys.exit(0)
for bp in list(t.breakpoint_iter()):
    t.BreakpointDelete(bp.GetID())
for off in (1804, 1984, 2396, 2496):
    t.BreakpointCreateByAddress(base + off)
out("[l2] bps 1804/1984/2396/2496")
def rd(addr, n):
    err = lldb.SBError()
    m = p.ReadMemory(addr, n, err)
    return m if err.Success() else None
def snap(tag, x27):
    m = rd(x27 - 0x80, 0xE0)
    if m:
        out("[%s @x27-0x80..+0x60]" % tag + ' ' + ' '.join('%016x' % v for v in struct.unpack('<28Q', m)))
    else:
        out("[%s] unreadable" % tag)
heads = wev = stops = 0
while stops < 6000 and wev < 300:
    p.Continue()
    st = p.GetState()
    if st != 5:
        out("[l2] state=%d heads=%d wev=%d" % (st, heads, wev)); break
    fr = th.GetSelectedFrame()
    desc = th.GetStopDescription(200)
    off = fr.GetPCAddress().GetLoadAddress(t) - base
    def r(n):
        v = fr.FindRegister(n)
        return v.GetValueAsUnsigned() if v else 0
    if 'BAD_ACCESS' in desc:
        out("[l2] FAULT: %s" % desc)
        m = rd(r('x22') - 0x40, 0x200)
        out("[POOLF @x22-0x40]" + (' ' + ' '.join('%016x' % v for v in struct.unpack('<64Q', m)) if m else ' unreadable'))
        err = lldb.SBError()
        n0 = struct.unpack('<Q', p.ReadMemory(r('x22'), 8, err))[0] if err.Success() else 0
        out("[ARENAF] node0=0x%x" % n0)
        if n0:
            m = rd(n0 - 0xC0, 0x300)
            out("[ARENAMEM-F node0-0xC0]" + (' ' + ' '.join('%016x' % v for v in struct.unpack('<96Q', m)) if m else ' unreadable'))
        out("[l2] x9=0x%x x11=0x%x x13=0x%x x16=0x%x x22=0x%x x25=0x%x x27=0x%x" % (
            r('x9'), r('x11'), r('x13'), r('x16'), r('x22'), r('x25'), r('x27')))
        snap('FAULTMEM', r('x27'))
        break
    if off == 1804:
        heads += 1
        if heads == 1:
            for reg in ('x27','x22'):
                ri = p.GetMemoryRegionInfo(r(reg))
                if ri.IsValid():
                    out("[REGION %s] 0x%x-0x%x %s" % (reg, ri.GetRegionBase(), ri.GetRegionEnd(), (ri.GetName() or '?').strip()))
                else:
                    out("[REGION %s] invalid" % reg)
            m = rd(r('x22') - 0x40, 0x200)
            out("[POOL0 @x22-0x40]" + (' ' + ' '.join('%016x' % v for v in struct.unpack('<64Q', m)) if m else ' unreadable'))
            err = lldb.SBError()
            n0 = struct.unpack('<Q', p.ReadMemory(r('x22'), 8, err))[0] if err.Success() else 0
            out("[ARENA0] node0=0x%x" % n0)
            if n0:
                m = rd(n0 - 0xC0, 0x300)
                out("[ARENAMEM node0-0xC0]" + (' ' + ' '.join('%016x' % v for v in struct.unpack('<96Q', m)) if m else ' unreadable'))
        if heads <= 3:
            out("[head %d] x27=0x%x x22=0x%x x9=0x%x x25=0x%x" % (heads, r('x27'), r('x22'), r('x9'), r('x25')))
            snap('BEFORE-h%d' % heads, r('x27'))
    elif off in (1984, 2396, 2496):
        wev += 1
        out("[W +%d] x27=0x%x x13=0x%x x14=0x%x x16=0x%x x2=0x%x x17=0x%x x22=0x%x poold=%d" % (
            off, r('x27'), r('x13'), r('x14'), r('x16'), r('x2'), r('x17'), r('x22'), r('x13') - r('x22')))
        snap('AFTER-w%d' % wev, r('x27'))
    stops += 1
out("[l2] done stops=%d heads=%d wev=%d" % (stops, heads, wev))
