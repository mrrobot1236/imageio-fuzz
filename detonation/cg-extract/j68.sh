#!/bin/bash
# RIP-38 blind oracle ONLY (watchdogged)
set -x
date +%T start-oracle
cd detonation/cve-2026-86950
clang -O0 -g -o render7 render7.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation || exit 9
[ -x venv/bin/python ] || python3 -m venv venv
./venv/bin/pip -q install fonttools
date +%T env-ready
rm -f rip38_trace.txt
timeout -k 30 1500 ../cg-extract/venv-x 2>/dev/null; ./venv/bin/python ../cg-extract/rip38.py > rip38_run.log 2>&1 || echo "oracle-watchdog rc=$?"
date +%T oracle-done
cd ../..
mkdir -p findings
cp detonation/cve-2026-86950/{rip38_trace.txt,rip38_run.log} findings/ 2>/dev/null
date +%T done
echo "=== RIP-38 TRACE ==="; cat detonation/cve-2026-86950/rip38_trace.txt 2>/dev/null
echo "=== RUN LOG TAIL ==="; tail -40 detonation/cve-2026-86950/rip38_run.log 2>/dev/null
