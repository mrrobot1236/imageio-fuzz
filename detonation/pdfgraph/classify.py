#!/usr/bin/env python3
"""Classify a directory of units with the oracle harness. usage: classify.py <dir> <outdir> [skip]"""
import glob, subprocess, os, shutil, sys
d, out = sys.argv[1], sys.argv[2]
skip = sys.argv[3] if len(sys.argv) > 3 else None
os.makedirs(out, exist_ok=True)
crash=blank=painted=fail=0
for f in sorted(glob.glob(os.path.join(d, '*.pdf'))):
    if skip and f.endswith('/' + skip): continue
    try: p = subprocess.run(['/tmp/hash', f], capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        print('TIMEOUT', os.path.basename(f)); shutil.copyfile(f, os.path.join(out, 'TIMEOUT_' + os.path.basename(f))); continue
    e = p.stderr or ''
    if 'AddressSanitizer' in e or 'SEGV' in e or 'deadly signal' in e or 'runtime error' in e:
        crash += 1; print('CRASH', os.path.basename(f)); print(e[:500]); shutil.copyfile(f, os.path.join(out, 'CRASH_' + os.path.basename(f)))
    elif p.returncode != 0 or not (p.stdout or '').strip():
        fail += 1; print('fail', os.path.basename(f), (e.strip().splitlines() or [''])[-1][:80])
    elif (p.stdout or '').startswith('BLANK'):
        blank += 1; print('blank', os.path.basename(f), p.stdout.strip())
    else:
        painted += 1; print('painted', os.path.basename(f), p.stdout.strip())
print(f'=== RESULT: {painted} painted / {blank} blank / {fail} fail / {crash} crash')
