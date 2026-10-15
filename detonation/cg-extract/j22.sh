#!/bin/bash
# M4b: gap sweep for subtle corruption (byte-exfil hunt) + M5 edge micro-map
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
for L in (18000, 19000, 20000, 21000, 21500, 22000, 22500, 23000, 23500,
          32752, 32760, 32764, 32766, 32770, 32772):
    build_font(f"k2_g{L}.ttf", L)
print("gen done: 15")
PYEOF
for L in 18000 19000 20000 21000 21500 22000 22500 23000 23500 32752 32760 32764 32766 32770 32772; do
  ./venv/bin/python gen_pdf.py k2_g${L}.pdf k2_g${L}.ttf
  ./render k2_g${L}.pdf >/dev/null 2>&1; RC=$?
  ./render2 k2_g${L}.pdf gpng_${L}.png >/dev/null 2>&1; RC2=$?
  MD5=$(md5 -q gpng_${L}.png 2>/dev/null || echo nopng)
  echo "gap L=$L rc=$RC rc2=$RC2 md5=$MD5" >> gap_map.txt
done
# stability retest of the anomaly L=32768 (rc=1) x3 + value-curve points 26000/27000
for R in 1 2 3; do
  ./render k2_g32768.pdf >/dev/null 2>&1; echo "edge retest $R rc=$?" >> gap_map.txt
done
cat gap_map.txt
cd ../..
mkdir -p findings && cp detonation/cve-2026-86950/{gap_map.txt,gpng_*.png} findings/ 2>/dev/null
ls findings/ | wc -l
