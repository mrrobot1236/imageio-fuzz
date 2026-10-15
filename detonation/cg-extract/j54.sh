#!/bin/bash
# RIP-27: 48-leaf dense sweep + interpolation + armed verification
set -x
cd detonation/cve-2026-86950
clang -O2 -g -o render4 render4.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation || exit 9
[ -x venv/bin/python ] || python3 -m venv venv
./venv/bin/pip -q install fonttools
rm -f rip27_trace.txt
lldb -b ./render4 -o "command script import $PWD/../cg-extract/rip27.py" > rip27_session.txt 2>&1 || true
cd ../..
mkdir -p findings
cp detonation/cve-2026-86950/{rip27_trace.txt,rip27_session.txt} findings/ 2>/dev/null
ls findings/ | wc -l
cat detonation/cve-2026-86950/rip27_trace.txt
