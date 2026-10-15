#!/bin/bash
# RIP-16: two-glyph cascade baseline (L1=31472, L2=29840, one decode)
set -x
cd detonation/cve-2026-86950
clang -O2 -g -o render4 render4.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation || exit 9
[ -x venv/bin/python ] || python3 -m venv venv
./venv/bin/pip -q install fonttools
./venv/bin/python gen_k3.py k3_pair.ttf 31472 29840
./venv/bin/python gen_pdf2.py k3_pair.pdf k3_pair.ttf
rm -f rip16_trace.txt
lldb -b ./render4 -o "command script import $PWD/../cg-extract/rip16.py" > rip16_session.txt 2>&1 || true
cd ../..
mkdir -p findings
cp detonation/cve-2026-86950/{rip16_trace.txt,rip16_session.txt} findings/ 2>/dev/null
ls findings/ | wc -l
cat detonation/cve-2026-86950/rip16_trace.txt | head -50
