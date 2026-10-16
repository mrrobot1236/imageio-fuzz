#!/bin/bash
# RIP-40: ASLR-delta leak (crash-report fa) + control anchors (watchdogged)
set -x
date +%T start-aslr
cd detonation/cve-2026-86950
clang -O0 -g -o render7 render7.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation || exit 9
# --- robust python env ---
rm -rf venv
PY=""
if python3 -m venv venv 2>/dev/null && ./venv/bin/pip install -q fonttools 2>/dev/null && ./venv/bin/python -c "import fontTools" 2>/dev/null; then
  PY="$PWD/venv/bin/python"
else
  python3 -m pip install -q --user fonttools 2>/dev/null || pip3 install -q --user fonttools 2>/dev/null
  PY=python3
fi
"$PY" -c "import fontTools; print('fonttools OK')" || { echo "ENV-FAIL"; exit 9; }
export RIP40_PY="$PY"
date +%T env-ready
rm -f rip40_trace.txt rip40_run.log
./venv/bin/python ../cg-extract/rip40.py > rip40_run.log 2>&1 || true
[ "$PY" = "python3" ] && python3 ../cg-extract/rip40.py > rip40_run.log 2>&1 || true
date +%T aslr-done
cd ../..
mkdir -p findings
cp detonation/cve-2026-86950/{rip40_trace.txt,rip40_run.log,rip40_control.txt} findings/ 2>/dev/null
date +%T done
echo "=== RIP-40 TRACE ==="; cat detonation/cve-2026-86950/rip40_trace.txt 2>/dev/null
