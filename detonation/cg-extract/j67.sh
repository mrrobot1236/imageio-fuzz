#!/bin/bash
# RIP-39 gadget stage ONLY (bash watchdog; macOS has no GNU timeout)
set -x
date +%T start-gadget
cd detonation/cve-2026-86950
clang -O0 -g -o render7 render7.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation || exit 9
# --- robust python env (venv or --user fallback), fail loudly ---
rm -rf venv
PY=""
if python3 -m venv venv 2>/dev/null && ./venv/bin/pip install -q fonttools 2>/dev/null && ./venv/bin/python -c "import fontTools" 2>/dev/null; then
  PY="$PWD/venv/bin/python"
else
  python3 -m pip install -q --user fonttools 2>/dev/null || pip3 install -q --user fonttools 2>/dev/null
  PY=python3
fi
"$PY" -c "import fontTools; print('fonttools OK via', '$PY')" || { echo "ENV-FAIL no fonttools"; exit 9; }
$PY -c "import sys; sys.path.insert(0,'.'); from gen_k2 import build_font; build_font('k2_s1000.ttf', 1000)"
$PY gen_pdf.py k2_s1000.pdf k2_s1000.ttf
$PY -c "import sys; sys.path.insert(0,'.'); from gen_k2 import build_font; build_font('k2_d31472.ttf', 31472)"
$PY gen_pdf.py k2_d31472.pdf k2_d31472.ttf
date +%T fonts-done
rm -f /tmp/rip39_id.txt rip39_trace.txt
lldb -b ./render7 -o "command script import $PWD/../cg-extract/rip39.py" > rip39_session.txt 2>&1 &
LPID=$!
( sleep 600; kill -9 $LPID 2>/dev/null; echo "WATCHDOG-FIRED" >> rip39_session.txt ) &
WPID=$!
wait $LPID; RC=$?
kill $WPID 2>/dev/null; wait $WPID 2>/dev/null
date +%T lldb-done rc=$RC
echo "=== /tmp/rip39_id.txt ===" >> rip39_trace.txt
cat /tmp/rip39_id.txt >> rip39_trace.txt 2>/dev/null || echo "NO-FILE" >> rip39_trace.txt
cd ../..
mkdir -p findings
cp detonation/cve-2026-86950/{rip39_trace.txt,rip39_session.txt} findings/ 2>/dev/null
date +%T done
echo "=== RIP-39 TRACE ==="; cat detonation/cve-2026-86950/rip39_trace.txt
