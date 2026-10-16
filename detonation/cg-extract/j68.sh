#!/bin/bash
# RIP-38 blind oracle ONLY (bash watchdog)
set -x
date +%T start-oracle
cd detonation/cve-2026-86950
clang -O0 -g -o render7 render7.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation || exit 9
[ -x venv/bin/python ] || python3 -m venv venv
./venv/bin/pip -q install fonttools
date +%T env-ready
rm -f rip38_trace.txt rip38_run.log
./venv/bin/python ../cg-extract/rip38.py > rip38_run.log 2>&1 &
OPID=$!
( sleep 1200; kill -9 $OPID 2>/dev/null; echo "WATCHDOG-FIRED" >> rip38_run.log ) &
WPID=$!
wait $OPID; RC=$?
kill $WPID 2>/dev/null; wait $WPID 2>/dev/null
date +%T oracle-done rc=$RC
cd ../..
mkdir -p findings
cp detonation/cve-2026-86950/{rip38_trace.txt,rip38_run.log} findings/ 2>/dev/null
date +%T done
echo "=== RIP-38 TRACE ==="; cat detonation/cve-2026-86950/rip38_trace.txt 2>/dev/null
