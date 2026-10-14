# lldb python v4: SBProcess.Continue() API (no HandleCommand re-entry deadlock)
import os, sys, struct, lldb
def out(s):
    print(s); sys.stdout.flush()
t = lldb.debugger.GetSelectedTarget()
p = t.GetProcess()
th = p.GetSelectedThread()
fr = th.GetSelectedFrame()
base = fr.GetFunction().GetStartAddress().GetLoadAddress(t)
mode = os.environ.get('JMODE', 'survive')
out("[j3] base=0x%x mode=%s" % (base, mode))
WATCH = (1868, 1884, 2396, 2404, 2408)
for off in WATCH:
    t.BreakpointCreateByAddress(base + off*4)
out("[j3] write-path breakpoints armed")
hits = printed = 0
while hits < 900 and printed < 70:
    p.Continue()
    st = p.GetState()
    if st != 5:
        out("[j3] state=%d (exit/crash-done) hits=%d" % (st, hits)); break
    fr = th.GetSelectedFrame()
    desc = p.GetStopDescription(200)
    off = fr.GetPCAddress().GetLoadAddress(t) - base
    def r(n):
        v = fr.FindRegister(n)
        return v.GetValueAsUnsigned() if v else 0
    if off in WATCH:
        out("[hit %3d +%d] x9=0x%x x11=0x%x x13=0x%x x16=0x%x w12=%08x w13=%08x w14=%08x%s" % (
            hits, off, r('x9'), r('x11'), r('x13'), r('x16'), r('w12'), r('w13'), r('w14'),
            "  <<WRITE@0x%x" % r('x16') if off in (1868, 2396, 2404, 2408) else ""))
        printed += 1
    if 'BAD_ACCESS' in desc:
        out("[j3] FAULT: %s" % desc)
        for name, addr, cnt in (('x22', r('x22'), 8), ('x9-0x100', r('x9')-0x100, 12),
                                 ('x16-0x40', r('x16')-0x40, 12), ('x25', r('x25'), 16), ('x19', r('x19'), 8)):
            if addr:
                err = lldb.SBError()
                mem = p.ReadMemory(addr, cnt*8, err)
                if err.Success():
                    vals = struct.unpack('<%dQ' % cnt, mem)
                    out("[mem %s @0x%x] %s" % (name, addr, ' '.join('%016x' % v for v in vals)))
                else:
                    out("[mem %s @0x%x] unreadable" % (name, addr))
        break
    hits += 1
out("[j3] done hits=%d printed=%d" % (hits, printed))
