# lldb python v3: stopped at aa_cache_render entry. Trace write-path offsets; dump memory at fault.
import os, struct, lldb
t = lldb.debugger.GetSelectedTarget()
p = t.GetProcess()
th = p.GetSelectedThread()
fr = th.GetSelectedFrame()
base = fr.GetFunction().GetStartAddress().GetLoadAddress(t)
mode = os.environ.get('JMODE', 'survive')
print("[j2] base=0x%x mode=%s" % (base, mode))
if base == 0xffffffffffffffff:
    print("[j2] no valid frame, abort"); os._exit(0)
WATCH = (1868, 1884, 2396, 2404, 2408)
for off in WATCH:
    t.BreakpointCreateByAddress(base + off*4)
hits = printed = 0
while hits < 600 and printed < 80:
    lldb.debugger.HandleCommand("continue")
    st = p.GetState()
    if st != 5:
        print("[j2] state=%d at hit %d" % (st, hits)); break
    fr = th.GetSelectedFrame()
    desc = p.GetStopDescription(200)
    off = fr.GetPCAddress().GetLoadAddress(t) - base
    def r(n):
        v = fr.FindRegister(n)
        return v.GetValueAsUnsigned() if v else 0
    if off in WATCH:
        print("[hit %3d +%d] x9=0x%x x11=0x%x x13=0x%x x16=0x%x w12=%08x w13=%08x w14=%08x%s" % (
            hits, off, r('x9'), r('x11'), r('x13'), r('x16'), r('w12'), r('w13'), r('w14'),
            "  <<WRITE@0x%x" % r('x16') if off in (1868, 2396, 2404, 2408) else ""))
        printed += 1
    if 'BAD_ACCESS' in desc:
        print("[j2] FAULT: %s" % desc)
        for name, addr, cnt in (('x22', r('x22'), 8), ('x9-0x100', r('x9')-0x100, 12),
                                 ('x16-0x40', r('x16')-0x40, 12), ('x25', r('x25'), 16), ('x19', r('x19'), 8)):
            if addr and addr != 0xffffffffffffffff:
                err = lldb.SBError()
                mem = p.ReadMemory(addr, cnt*8, err)
                if err.Success():
                    vals = struct.unpack('<%dQ' % cnt, mem)
                    print("[mem %s @0x%x] %s" % (name, addr, ' '.join('%016x' % v for v in vals)))
                else:
                    print("[mem %s @0x%x] read failed" % (name, addr))
        break
    hits += 1
print("[j2] done hits=%d printed=%d" % (hits, printed))
