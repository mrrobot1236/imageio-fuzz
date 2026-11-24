#!/usr/bin/env python3
"""Structural (object-graph) PDF cases: one graph-level lie each.
Complements pdf-lies (field-level). Offsets are correct unless the case is about offsets."""
import sys, os, zlib
OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
os.makedirs(OUT, exist_ok=True)
W = H = 64
RAW = bytes(((x*4) & 255) ^ ((y*3) & 255) for y in range(H) for x in range(W) for _ in range(3))

def doc(objs, trailer=b'/Root 1 0 R', size_lie=0, xref_ok=True, extra_tail=b''):
    out = b'%PDF-1.7\n'; offs = []
    for i, body in enumerate(objs, 1):
        offs.append(len(out)); out += b'%d 0 obj\n' % i + body + b'\nendobj\n'
    start = len(out)
    if xref_ok:
        out += b'xref\n0 %d\n0000000000 65535 f \n' % (len(objs)+1)
        for o in offs: out += b'%010d 00000 n \n' % o
    out += b'trailer\n<< /Size %d ' % (len(objs)+1+size_lie) + trailer + b' >>\nstartxref\n%d\n%%%%EOF\n' % start + extra_tail
    return out

def ib(extra=b'', data=None):
    d = RAW if data is None else data
    return (b'<< /Type /XObject /Subtype /Image /Width 64 /Height 64 /BitsPerComponent 8 /ColorSpace /DeviceRGB '
            + extra + b'/Length %d >>\nstream\n' % len(d) + d + b'\nendstream')

def stream(data, extra=b''):
    return b'<< /Length %d %s>>\nstream\n' % (len(data), extra) + data + b'\nendstream'

def base(imgextra=b'', content=b'q 200 0 0 200 50 50 cm /Im0 Do Q', pageextra=b'', imgbody=None, extra_objs=None):
    img = imgbody if imgbody is not None else ib(imgextra)
    objs = [b'<< /Type /Catalog /Pages 2 0 R >>',
            b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
            b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] /Resources << /XObject << /Im0 4 0 R >> >> /Contents 5 0 R ' + pageextra + b'>>',
            img, stream(content)]
    if extra_objs: objs += extra_objs
    return objs

C = {}
C['ok'] = lambda: doc(base())
# --- offset / xref lies ---
def startxref_lie(delta):
    d = doc(base()); i = d.rfind(b'startxref'); j = d.find(b'\n', i+10)
    n = int(d[i+10:j]); return d[:i+10] + b'%d' % (n+delta) + d[j:]
C['sx_minus40'] = lambda: startxref_lie(-40)
C['sx_plus40'] = lambda: startxref_lie(40)
C['sx_zero'] = lambda: startxref_lie(-999999) if False else doc(base()).replace(b'startxref\n', b'startxref\n0')
C['xref_off_by_8'] = lambda: doc(base()).replace(b'\n000000', b'\n000000', 1)  # placeholder
C['xref_missing'] = lambda: doc(base(), xref_ok=False)
C['size_lie_big'] = lambda: doc(base(), size_lie=1000)
C['size_lie_neg'] = lambda: doc(base(), size_lie=-3)
C['no_eof'] = lambda: doc(base()).replace(b'%%EOF\n', b'')
C['xref_free_reuse'] = lambda: doc(base()).replace(b'0000000000 65535 f', b'0000000000 65535 f', 1).replace(b'\n0000000', b'\n0000000')
# --- reference graph lies ---
C['dangling_contents'] = lambda: doc([b'<< /Type /Catalog /Pages 2 0 R >>', b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>', b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] /Resources << >> /Contents 99 0 R >>'])
C['pages_self'] = lambda: doc([b'<< /Type /Catalog /Pages 2 0 R >>', b'<< /Type /Pages /Kids [2 0 R] /Count 1 >>'])
C['page_self_parent'] = lambda: doc([b'<< /Type /Catalog /Pages 2 0 R >>', b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>', b'<< /Type /Page /Parent 3 0 R /MediaBox [0 0 300 300] /Contents 4 0 R >>', stream(b'')])
C['kids_dup_1000'] = lambda: doc([b'<< /Type /Catalog /Pages 2 0 R >>', b'<< /Type /Pages /Kids [' + b' '.join([b'3 0 R']*1000) + b'] /Count 1000 >>', b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] /Contents 4 0 R >>', stream(b'')])
C['xref_to_midstring'] = lambda: doc(base()).replace(b'\n000000', b'\n000000', 1)
C['root_is_page'] = lambda: doc([b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 10 10] /Contents 3 0 R >>', b'<< /Type /Pages /Kids [] /Count 0 >>', stream(b'')])
# --- content / operator depth ---
C['q_depth_100k'] = lambda: doc([b'<< /Type /Catalog /Pages 2 0 R >>', b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>', b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] /Contents 4 0 R >>', stream(b'q '*100000)])
C['q_unbalanced_close'] = lambda: doc([b'<< /Type /Catalog /Pages 2 0 R >>', b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>', b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] /Contents 4 0 R >>', stream(b'Q '*100000)])
C['truncated_op'] = lambda: doc([b'<< /Type /Catalog /Pages 2 0 R >>', b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>', b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] /Contents 4 0 R >>', stream(b'q 200 0 0 200 50 50 cm /Im0 D')])
C['content_len_huge'] = lambda: doc([b'<< /Type /Catalog /Pages 2 0 R >>', b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>', b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] /Contents 4 0 R >>', b'<< /Length 10000000 >>\nstream\nq Q\nendstream'])
# --- filter chain graph ---
C['filter_arr_10'] = lambda: doc(base(imgextra=b'/Filter [/FlateDecode /FlateDecode /FlateDecode /FlateDecode /FlateDecode /FlateDecode /FlateDecode /FlateDecode /FlateDecode /FlateDecode] ', imgbody=ib(extra=b'/Filter [/FlateDecode /FlateDecode /FlateDecode /FlateDecode /FlateDecode /FlateDecode /FlateDecode /FlateDecode /FlateDecode /FlateDecode] ', data=zlib.compress(RAW))))
C['filter_arr_empty'] = lambda: doc(base(imgbody=ib(extra=b'/Filter [] ')))
C['dp_type_mismatch'] = lambda: doc(base(imgbody=ib(extra=b'/Filter /FlateDecode /DecodeParms [<< /Predictor 12 >>] ', data=zlib.compress(RAW))))
C['dp_dict_for_single'] = lambda: doc(base(imgbody=ib(extra=b'/Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 192 >> ', data=zlib.compress(RAW))))
# --- form / xobject graph ---
C['form_self_recursive'] = lambda: doc([b'<< /Type /Catalog /Pages 2 0 R >>', b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>', b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] /Resources << /XObject << /Fm0 4 0 R >> >> /Contents 5 0 R >>', b'<< /Type /XObject /Subtype /Form /BBox [0 0 100 100] /Resources << /XObject << /Fm0 4 0 R >> >> /Length 10 >>\nstream\n/Fm0 Do Q\nendstream', stream(b'q /Fm0 Do Q')])
C['form_chain_64'] = lambda: doc([b'<< /Type /Catalog /Pages 2 0 R >>', b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>', b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] /Resources << /XObject << /Fm0 4 0 R >> >> /Contents 70 0 R >>'] + [b'<< /Type /XObject /Subtype /Form /BBox [0 0 100 100] /Resources << /XObject << /Fm%d 4 0 R >> >> /Length 9 >>\nstream\n/Fm%d Do \nendstream' % (i+1, i+1) for i in range(64)] + [stream(b'q /Fm0 Do Q')])
C['xobj_as_page_content'] = lambda: doc([b'<< /Type /Catalog /Pages 2 0 R >>', b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>', b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] /Resources << /XObject << /Im0 4 0 R >> >> /Contents 4 0 R >>', stream(b'q 10 0 0 10 0 0 cm /Im0 Do Q')])
C['subtype_missing_img'] = lambda: doc(base(imgbody=b'<< /Type /XObject /Width 64 /Height 64 /BitsPerComponent 8 /ColorSpace /DeviceRGB /Length %d >>\nstream\n' % len(RAW) + RAW + b'\nendstream'))
# --- nesting / array depth ---
C['nested_arr_500'] = lambda: doc(base(imgextra=b'/Decode [' + b'['*500 + b'0 1' + b']'*500 + b'] '))
C['nested_dict_200'] = lambda: doc(base(imgextra=b'/Foo ' + b'<< /A '*200 + b'1' + b' >>'*200 + b' '))
C['name_escape_weird'] = lambda: doc(base(imgextra=b'/Foo#20Bar#2Fbaz#00x 1 '))
C['huge_number'] = lambda: doc(base(imgextra=b'/Foo 999999999999999999999999999999999999999 '))
C['real_precision'] = lambda: doc(base(imgextra=b'/Foo 0.1000000000000000000001 '))

# --- objstm / xref stream builders ---
def objstm_doc(wrong_n=False, first_lie=0, short_payload=False):
    objs = [b'<< /Type /Catalog /Pages 2 0 R >>',
            b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
            b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] /Resources << /XObject << /Im0 4 0 R >> >> /Contents 5 0 R >>']
    hdr = []; body = b''; num = 4
    for payload in [b'<< /Type /XObject /Subtype /Image /Width 64 /Height 64 /BitsPerComponent 8 /ColorSpace /DeviceRGB /Length %d >>\nstream\n' % len(RAW) + RAW + b'\nendstream',
                    b'<< /Length 25 >>\nstream\nq 200 0 0 200 50 50 cm /Im0 Do Q\nendstream']:
        hdr.append(b'%d %d' % (num, len(body))); body += payload + b'\n'; num += 1
    n = 99 if wrong_n else 2
    first = len(b' '.join(hdr)) + 1 + first_lie
    stm = b' '.join(hdr) + b'\n' + (body[:-40] if short_payload else body)
    out = b'%PDF-1.7\n'
    offs = []
    for i, o in enumerate(objs, 1):
        offs.append(len(out)); out += b'%d 0 obj\n' % i + o + b'\nendobj\n'
    so = len(out); out += b'6 0 obj\n<< /Type /ObjStm /N %d /First %d /Length %d >>\nstream\n' % (n, first, len(stm)) + stm + b'\nendstream\nendobj\n'
    # xref stream: W [1 4 2], entries for 0..6 + objstm 7
    rows = [(0,0,65535),(0,offs[0],0),(0,offs[1],0),(0,offs[2],0),(2,6,0),(2,6,1),(1,so,0)]
    x = b''.join(bytes([t]) + i.to_bytes(4,'big') + g.to_bytes(2,'big') for t,i,g in rows)
    xo = len(out)
    out += b'7 0 obj\n<< /Type /XRef /Size 8 /W [1 4 2] /Root 1 0 R /Length %d >>\nstream\n' % len(x) + x + b'\nendstream\nendobj\n'
    out += b'startxref\n%d\n%%%%EOF\n' % xo
    return out
C['objstm_ok'] = lambda: objstm_doc()
C['objstm_n_lie'] = lambda: objstm_doc(wrong_n=True)
C['objstm_first_lie'] = lambda: objstm_doc(first_lie=17)
C['objstm_short'] = lambda: objstm_doc(short_payload=True)

# --- incremental update chain ---
def incr(revs=1, junk=False):
    d = doc(base()).replace(b'%%%%EOF\n', b'')
    prev = d.rfind(b'startxref'); prevoff = int(d[prev+10:].split(b'\n')[0])
    for k in range(revs):
        o = len(d)
        d += b'4 0 obj\n<< /Type /XObject /Subtype /Image /Width 64 /Height 64 /BitsPerComponent 8 /ColorSpace /DeviceRGB /Length %d >>\nstream\n' % len(RAW) + RAW + b'\nendstream\nendobj\n'
        xs = len(d); d += b'xref\n4 1\n%010d 00000 n \n' % o + b'trailer\n<< /Size 6 /Root 1 0 R /Prev %d >>\nstartxref\n%d\n%%%%EOF\n' % (prevoff, xs)
        prevoff = xs
        if junk: d += b'%' + b'x'*200 + b'\n'
    return d
C['incr_1'] = lambda: incr(1)
C['incr_20'] = lambda: incr(20)
C['incr_200'] = lambda: incr(200)
C['incr_junk'] = lambda: incr(3, junk=True)

for n, f in C.items():
    open(os.path.join(OUT, n + '.pdf'), 'wb').write(f())
print('emitted', len(C))
