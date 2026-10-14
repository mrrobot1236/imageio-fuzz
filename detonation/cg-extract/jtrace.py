# lldb python: trace aa_cache_render write sites (+1868 str, +2396/2404/2408 strh)
import lldb, sys
t = lldb.debugger.GetSelectedTarget()
p = t.GetProcess()
th = p.GetSelectedThread()
fr = th.GetSelectedFrame()
fn = fr.GetFunction()
base = fn.GetStartAddress().GetLoadAddress(t)
print("[jtrace] fn base=0x%x" % base)
bps = {}
for off in (1868, 2396, 2404, 2408, 1884, 1992):
    bp = t.BreakpointCreateByAddress(base + off*4)
    bps[bp.GetID()] = off
print("[jtrace] bps set: %s" % bps)
hits = 0
while hits < 60:
    lldb.debugger.HandleCommand("continue")
    if p.GetState() != 5:  # eStopped
        print("[jtrace] state=%d exit" % p.GetState())
        break
    fr = th.GetSelectedFrame()
    off = fr.GetPCAddress().GetLoadAddress(t) - base
    r = lambda n: fr.FindRegister(n).GetValueAsUnsigned()
    line = "[hit +%d] x16=0x%x x11=0x%x x9=0x%x x13=0x%x w12=%d w13=%d w14=%d" % (
        off, r('x16'), r('x11'), r('x9'), r('x13'), r('w12') & 0xffffffff, r('w13') & 0xffffffff, r('w14') & 0xffffffff)
    if off in (2396, 2404, 2408, 1868):
        line += " WRITE@0x%x" % r('x16')
    print(line)
    hits += 1
print("[jtrace] done, hits=%d" % hits)
