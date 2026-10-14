# lldb python v2: called while STOPPED at aa_cache_render entry.
# Sets offset breakpoints, continues, logs write-path events. JMODE=crash -> dumps memory at fault.
import os, lldb
t = lldb.debugger.GetSelectedTarget()
p = t.GetProcess()
th = p.GetSelectedThread()
fr = th.GetSelectedFrame()
base = fr.GetFunction().GetStartAddress().GetLoadAddress(t)
mode = os.environ.get('JMODE', 'survive')
print("[j2] base=0x%x mode=%s" % (base, mode))
for off in (1868, 1884, 2396, 2404, 2408):
    t.BreakpointCreateByAddress(base + off*4)
hits = 0
while hits < 120:
    lldb.debugger.HandleCommand("continue")
    st = p.GetState()
    if st != 5:
        print("[j2] process state=%d (exited/crashed) at hit %d" % (st, hits))
        break
    fr = th.GetSelectedFrame()
    stopdesc = p.GetStopDescription(160)
    off = fr.GetPCAddress().GetLoadAddress(t) - base
    def r(n):
        v = fr.FindRegister(n)
        return v.GetValueAsUnsigned() if v else 0
    line = "[hit %2d +%-5d] x9=0x%x x11=0x%x x13=0x%x x16=0x%x w12=%08x w13=%08x w14=%08x" % (
        hits, off, r('x9'), r('x11'), r('x13'), r('x16'), r('w12'), r('w13'), r('w14'))
    if off in (1868, 2396, 2404, 2408):
        line += "  <<WRITE@0x%x" % r('x16')
    if 'BAD_ACCESS' in stopdesc or 'fault' in stopdesc.lower():
        line += "  FAULT: " + stopdesc
    print(line)
    hits += 1
    if mode == 'crash' and 'BAD_ACCESS' in stopdesc:
        for name, addr, cnt in (('x22-area', r('x22'), 8), ('x9-0x100', r('x9')-0x100, 12),
                                 ('x16-0x40', r('x16')-0x40, 12), ('x25', r('x25'), 16), ('x19', r('x19'), 8)):
            if addr:
                err = lldb.SBError()
                mem = p.ReadMemory(addr, cnt*8, err)
                if err.Success():
                    import struct
                    vals = struct.unpack('<%dQ' % cnt, mem)
                    print("[mem %s @0x%x] %s" % (name, addr, ' '.join('%016x' % v for v in vals)))
                else:
                    print("[mem %s @0x%x] read failed: %s" % (name, addr, err.GetCString()))
print("[j2] done hits=%d" % hits)
