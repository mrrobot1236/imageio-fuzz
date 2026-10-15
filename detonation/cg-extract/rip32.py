# RIP-32: PARENT-FRAME CALL CENSUS + LDR PROVENANCE.
# A: at walk stop: full backtrace (symbols+offsets) -> disassemble parent frames
#    -> census blr/blraa in parents -> bp them.
# B: at each parent-blr hit: target reg + disasm-backwards to find the ldr that
#    loaded it -> resolve the SLOT ADDRESS (base+imm) -> report provenance.
import os, sys, struct, time
import lldb
t = lldb.debugger.GetSelectedTarget()
CWD = os.getcwd()
CVE = os.path.dirname(CWD) + "/cve-2026-86950"
TRACE = open(os.path.join(CWD, "rip32_trace.txt"), "a")
def T(s): print(s, flush=True); TRACE.write(s+"\n"); TRACE.flush()
err = lldb.SBError()

def fresh():
    old = t.GetProcess()
    if old and old.IsValid() and old.GetState() in (lldb.eStateRunning, lldb.eStateStopped, lldb.eStateSuspended):
        old.Kill(); time.sleep(0.5)

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
        time.sleep(0.05); st = p.GetState()
    return st

def killp(p):
    try:
        if p and p.IsValid() and p.GetState() in (lldb.eStateRunning, lldb.eStateStopped, lldb.eStateSuspended):
            p.Kill()
    except Exception: pass

def safe_pc_addr(fr):
    try:
        a = fr.GetPCAddress().GetLoadAddress(t)
        if a is None or a < 0 or a >= (1 << 48): return None
        return a
    except Exception: return None

def pcoff(fr):
    a = safe_pc_addr(fr)
    try:
        if fr.GetSymbol() and a:
            return a - fr.GetSymbol().GetStartAddress().GetLoadAddress(t)
    except Exception: pass
    return -1

def reg(fr, name):
    r = fr.FindRegister(name)
    return r.GetValueAsUnsigned() if r and r.IsValid() else 0

def symname(fr):
    try: return fr.GetSymbol().GetName() or "?"
    except Exception: return "?"

def disasm_blrs(start_addr, count):
    out = []
    try:
        ilist = t.ReadInstructions(lldb.SBAddress(start_addr, t), count)
        for ins in ilist:
            m = ins.GetMnemonic(target=t)
            if m.startswith("blr"):
                out.append((ins.GetAddress().GetLoadAddress(t), m, ins.GetOperands(target=t)))
    except Exception as e:
        T("disasm err %s" % e)
    return out

def backtrace_at(fr, depth=6):
    th = fr.GetThread()
    out = []
    for i in range(min(depth, th.GetNumFrames())):
        f = th.GetFrameAtIndex(i)
        a = safe_pc_addr(f)
        try:
            so = a - f.GetSymbol().GetStartAddress().GetLoadAddress(t) if (a and f.GetSymbol()) else -1
        except Exception: so = -1
        out.append((i, symname(f), so, a))
    return out

def find_ldr_source(p, fr, pc):
    # disasm backwards from pc: find ldr xN, [xM, #imm] where xN == call reg
    try:
        ilist = t.ReadInstructions(lldb.SBAddress(pc - 32, t), 10)
        prev = None
        for ins in ilist:
            m = ins.GetMnemonic(target=t)
            ops = ins.GetOperands(target=t)
            if m.startswith("ldr"):
                return (ins.GetAddress().GetLoadAddress(t) - pc, m, ops)
        return None
    except Exception as e:
        return None

fresh()
be = t.BreakpointCreateByName("aa_cache_render"); be.SetOneShot(True)
p = t.LaunchSimple(["k2_d31472.pdf", "r.png"], None, CVE)
parent_blrs = {}; bt_info = None; x27 = 0
if p and p.IsValid():
    th = p.GetSelectedThread()
    pc0 = safe_pc_addr(th.GetSelectedFrame())
    if pc0:
        t.BreakpointCreateByAddress(pc0 + 1804)
        wh = 0
        for i in range(300):
            st = wait_stop(p)
            if st != lldb.eStateStopped: break
            fr = p.GetSelectedThread().GetSelectedFrame()
            off = pcoff(fr)
            if off == 1804:
                wh += 1
                if wh == 2:
                    bt = backtrace_at(fr, 6)
                    bt_info = bt
                    T("A backtrace: %s" % [(i, nm, hex(so) if so >= 0 else "?") for i, nm, so, a in bt])
                    # census blrs in parents (frames 1..3): disasm from their frame start
                    for fi, nm, so, a in bt[1:4]:
                        if a and so >= 0:
                            fstart = a - so
                            blrs = disasm_blrs(fstart, 1600)
                            T("A parent[%d] %s start=%x blrs(%d): %s" % (fi, nm, fstart, len(blrs), [(hex(ba - fstart), m, ops) for ba, m, ops in blrs[:12]]))
                            for ba, m, ops in blrs[:10]:
                                parent_blrs[ba] = (fi, nm, ops.split(",")[0].strip())
                    # bp the census'd sites
                    for ba, (fi, nm, rn) in list(parent_blrs.items())[:10]:
                        t.BreakpointCreateByAddress(ba)
                    t.BreakpointDelete(t.GetBreakpointAtIndex(t.GetNumBreakpoints() - 1).GetID()) if False else None
                if wh == 2:
                    pass  # keep walk bp for subsequent stops? delete to speed up
                    # keep it: cheap
                p.Continue()
            elif off != 1804 and off >= 0 and off != -1 and pcoff(fr) in [b for b in []]:
                p.Continue()
            else:
                # possible parent-blr hit: check symbol+pc match
                pc = safe_pc_addr(fr)
                if pc in parent_blrs:
                    fi, nm, rn = parent_blrs[pc]
                    tgt = reg(fr, rn)
                    ld = find_ldr_source(p, fr, pc)
                    if parent_blrs.get('__count__%d' % fi, 0) < 3:
                        parent_blrs['__count__%d' % fi] = parent_blrs.get('__count__%d' % fi, 0) + 1
                        T("B parent[%d] %s blr %s=%x ldr=%s x27=%x" % (fi, nm, rn, tgt, ld, x27))
                        # resolve ldr slot: parse [xM, #imm]
                        if ld:
                            ops = ld[2]
                            try:
                                base = ops.split("[")[1].split(",")[0].strip()
                                imm = 0
                                if "#" in ops.split("[")[1]:
                                    imm = int(ops.split("[")[1].split("#")[1].rstrip("]"), 0)
                                bval = reg(fr, base)
                                T("B SLOT: %s+%d = %x  (value=%x)" % (base, imm, bval + imm, tgt))
                            except Exception as e:
                                T("B slot-parse err %s" % e)
                p.Continue()
    killp(p)
t.BreakpointDelete(be.GetID())
for bp in list(t.breakpoint_iter()):
    t.BreakpointDelete(bp.GetID())
T("RIP-32 DONE")
TRACE.close()
