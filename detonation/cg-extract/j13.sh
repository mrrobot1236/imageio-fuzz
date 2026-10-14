#!/bin/bash
set -x
cd detonation/cve-2026-86950
clang -O2 -g -o render render.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation
clang -O2 -g -o render2 render2.c -framework ImageIO -framework CoreGraphics -framework CoreFoundation
[ -x venv/bin/python ] || python3 -m venv venv
./venv/bin/pip -q install fonttools
./venv/bin/python gen_k2.py
for TAG in m256 m64 z0 p64 p1k p4k p8k; do ./venv/bin/python gen_pdf.py k2_${TAG}.pdf k2_${TAG}.ttf; done
./venv/bin/python - << 'PYEOF'
import sys; sys.path.insert(0, '.')
from gen_k2 import build_font
for tag, L in (("p4k", 4096), ("p8k", 8192)):
    build_font(f"k2_{tag}.ttf", L); print(tag, L)
PYEOF
for TAG in p4k p8k; do ./venv/bin/python gen_pdf.py k2_${TAG}.pdf k2_${TAG}.ttf; done
# crash check (plain)
for TAG in m256 m64 z0 p64 p1k p4k p8k wild; do
  ./render k2_${TAG}.pdf >/dev/null 2>&1; echo "plain $TAG rc=$?" >> sweep_summary.txt
done
# traced runs on surviving variants: catch the line-write among W events
for TAG in m256 z0 p64 p1k p4k; do
  lldb -b \
    -o "breakpoint set -n aa_cache_render" \
    -o "process launch -- k2_${TAG}.pdf" \
    -o "command script import $PWD/../cg-extract/jtrace5.py" \
    -o "detach" -o "quit" \
    ./render > k2t_${TAG}.txt 2>&1 || true
  echo "--- k2t_$TAG: $(grep -cE '\[W ' k2t_${TAG}.txt) W-events"
done
cat sweep_summary.txt
cd ../..
mkdir -p findings
cp detonation/cve-2026-86950/k2t_*.txt detonation/cve-2026-86950/sweep_summary.txt findings/
ls findings/ | wc -l
