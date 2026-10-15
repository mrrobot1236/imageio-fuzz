#!/bin/bash
# BLACK-BOX ORACLE PROBE — returns ONLY the 1-bit channel: 0=survive, 1=crash.
# Usage: probe.sh <L> [workdir]. NO lldb, NO memory reads — mimics the real-target
# feedback channel (crash vs no-crash) for inference-engine development.
L=$1
CD=${2:-$(dirname "$0")/../cve-2026-86950}
cd "$CD" || exit 2
TTF=k2_o${L}.ttf; PDF=k2_o${L}.pdf
[ -f "$PDF" ] || {
  ./venv/bin/python -c "import sys; sys.path.insert(0,'.'); from gen_k2 import build_font; build_font('$TTF', $L)" || exit 2
  ./venv/bin/python gen_pdf.py $PDF $TTF || exit 2
}
./render4 $PDF o.png >/dev/null 2>&1
RC=$?
[ $RC -eq 0 ] && echo 0 || echo 1
