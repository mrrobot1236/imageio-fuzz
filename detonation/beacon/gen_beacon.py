#!/usr/bin/env python3
"""Wrap a page into a beacon PDF: visible label + full-page link annotation to BASE/b/<unit>."""
import sys
BASE, UNIT, OUT = sys.argv[1], sys.argv[2], sys.argv[3]
url = f"{BASE}/b/{UNIT}"
def obj(n, body): return f'{n} 0 obj\n{body}\nendobj\n'.encode('latin1')
out = b'%PDF-1.7\n'
out += obj(1, '<< /Type /Catalog /Pages 2 0 R >>')
out += obj(2, '<< /Type /Pages /Kids [3 0 R] /Count 1 >>')
out += obj(3, '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] '
              '/Annots [5 0 R] /Contents 4 0 R >>')
c = ('BT /F1 26 Tf 60 760 Td (REPORT: ' + UNIT + ') Tj ET '
     'BT /F1 16 Tf 60 720 Td (tap anywhere to log this unit) Tj ET').encode('latin1')
out += obj(4, f'<< /Length {len(c)} >>\nstream\n'.encode()+c+b'\nendstream')
out += obj(5, '<< /Type /Annot /Subtype /Link /Rect [0 0 595 842] /Border [0 0 0] '
              f'/A << /S /URI /URI ({url}) >> >>')
# xref
start = len(out)
offs = []; p = 9
for chunk in out[9:].split(b'endobj\n')[:-1]:
    offs.append(p); p += len(chunk) + 7
x = b'xref\n0 %d\n0000000000 65535 f \n' % (len(offs)+1)
for o in offs: x += b'%010d 00000 n \n' % o
out += x + b'trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n' % (len(offs)+1, start)
open(OUT, 'wb').write(out)
print(OUT, len(out), url)
