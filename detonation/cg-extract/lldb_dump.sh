#!/bin/bash
# Catch the CVE-2026-86950 SIGSEGV under lldb and dump full context + function disassembly
set -x
cd detonation/cve-2026-86950
clang -O2 -g -o render render.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation
lldb -b -o "settings set target.disable-aslr false" \
  -o "process launch -- trigger.pdf" \
  -o "thread backtrace" \
  -o "register read" \
  -o "disassemble --frame" \
  -o "disassemble -n aa_cache_render" \
  -o "disassemble -r '.*GlyphBitmapCreate.*'" \
  -o "image lookup -va" \
  ./render > lldb_dump.txt 2>&1
tail -30 lldb_dump.txt
mkdir -p ../../findings 2>/dev/null; cd ../..
mkdir -p findings
cp detonation/cve-2026-86950/lldb_dump.txt findings/ 2>/dev/null || true
ls -la findings/
