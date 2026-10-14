#!/bin/bash
# Pure-command lldb trace: bp at write offsets via symbol arithmetic; fixed continue/read cycles
set -x
cd detonation/cve-2026-86950
clang -O2 -g -o render render.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation
ls j1.pdf || { python3 -m venv venv; ./venv/bin/pip -q install fonttools; ./venv/bin/python gen_j1.py; }
LL=( lldb -b \
  -o "breakpoint set -n aa_cache_render" \
  -o "process launch -- j1.pdf" \
  -o "breakpoint set -a $pc+7472" \
  -o "breakpoint set -a $pc+9584" \
  -o "breakpoint set -a $pc+9616" \
  -o "breakpoint set -a $pc+9632" \
  -o "breakpoint delete 1" )
for i in $(seq 1 40); do
  LL+=(-o "continue" -o "register read x9 x11 x13 x16 w12 w13 w14")
done
LL+=(-o "detach" -o "quit")
"${LL[@]}" ./render > j4_survive.txt 2>&1 || true
grep -cE "stop reason = breakpoint" j4_survive.txt || echo 0
# crash session: same but fault expected
LC=( lldb -b \
  -o "breakpoint set -n aa_cache_render" \
  -o "process launch -- trigger.pdf" \
  -o "breakpoint set -a $pc+7472" \
  -o "breakpoint set -a $pc+9584" \
  -o "breakpoint delete 1" )
for i in $(seq 1 30); do
  LC+=(-o "continue" -o "register read x9 x11 x13 x16 w12 w13 w14")
done
LC+=(-o "detach" -o "quit")
"${LC[@]}" ./render > j4_crash.txt 2>&1 || true
cd ../..
mkdir -p findings && cp detonation/cve-2026-86950/j4_*.txt findings/
ls -la findings/
