#!/bin/bash
# RIP-32: parent-frame call census + ldr provenance
set -x
cd detonation/cve-2026-86950
clang -O2 -g -o render4 render4.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation || exit 9
[ -x venv/bin/python ] || python3 -m venv venv
./venv/bin/pip -q install fonttools
./venv/bin/python -c "import sys; sys.path.insert(0,'.'); from gen_k2 import build_font; build_font('k2_d31472.ttf', 31472)"
./venv/bin/python gen_pdf.py k2_d31472.pdf k2_d31472.ttf
rm -f rip32_trace.txt
lldb -b ./render4 -o "command script import $PWD/../cg-extract/rip32.py" > rip32_session.txt 2>&1 || true
cd ../..
mkdir -p findings
cp detonation/cve-2026-86950/{rip32_trace.txt,rip32_session.txt} findings/ 2>/dev/null
ls findings/ | wc -l
cat detonation/cve-2026-86950/rip32_trace.txt
