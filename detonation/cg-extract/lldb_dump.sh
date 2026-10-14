#!/bin/bash
# v2: -k commands = executed exactly when the process crashes
set -x
cd detonation/cve-2026-86950
clang -O2 -g -o render render.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation
lldb -b \
  -k "thread backtrace all" \
  -k "register read" \
  -k "disassemble --frame" \
  -k "disassemble --frame --count 1600" \
  -k "settings set target.disable-aslr true" \
  -k "quit" \
  -o "settings set target.disable-aslr true" \
  -o "run -- trigger.pdf" \
  ./render > lldb_dump.txt 2>&1
wc -c lldb_dump.txt
tail -5 lldb_dump.txt
cd ../..
mkdir -p findings
cp detonation/cve-2026-86950/lldb_dump.txt findings/
