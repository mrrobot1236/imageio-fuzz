#!/usr/bin/env python3
"""Structurally valid PDFs, one lying field each, aimed at CG image-XObject decode paths."""
import sys, os, zlib
OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
os.makedirs(OUT, exist_ok=True)
W = H = 64
RAW = bytes(((x*4) & 255) ^ ((y*3) & 255) for y in range(H) for x in range(W) for _ in range(3))

def doc(objs, extra_trailer=b''):
    out = b'%PDF-1.7\n'
    offs = []
    for i, body in enumerate(objs, 1):
        offs.append(len(out))
        out += f'{i} 0 obj\n'.encode() + body + b'\nendobj\n'
    start = len(out)
    out += b'xref\n0 %d\n0000000000 65535 f \n' % (len(objs)+1)
    for o in offs: out += b'%010d 00000 n \n' % o
    out += b'trailer\n<< /Size %d /Root 1 0 R ' % (len(objs)+1) + extra_trailer + b'>>\nstartxref\n%d\n%%%%EOF\n' % start
    return out

def stream(data, decl_len=None, extra=b''):
    n = len(data) if decl_len is None else decl_len
    return b'<< /Length %d %s>>\nstream\n' % (n, extra) + data + b'\nendstream'

def build(imgdict, content=b'q 200 0 0 200 50 50 cm /Im0 Do Q', res_extra=b'', objs_extra=None, stream_kw=None):
    objs = [
        b'<< /Type /Catalog /Pages 2 0 R >>',
        b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
        b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] /Resources << /XObject << /Im0 4 0 R >> ' + res_extra + b'>> /Contents 5 0 R >>',
        imgdict,
        b'<< /Length %d >>\nstream\n' % len(content) + content + b'\nendstream',
    ]
    if objs_extra: objs += objs_extra
    return doc(objs)

def img(w=W, h=H, bpc=8, cs=b'/DeviceRGB', data=None, decl_len=None, extra=b''):
    d = RAW if data is None else data
    head = (b'<< /Type /XObject /Subtype /Image /Width %d /Height %d /BitsPerComponent %d /ColorSpace %s ' % (w, h, bpc, cs)) + extra
    return head + stream(d, decl_len)

CASES = {
 'ok':                 lambda: build(img()),
 'w0':                 lambda: build(img(w=0)),
 'w1':                 lambda: build(img(w=1)),
 'wmax':               lambda: build(img(w=0x7fffffff)),
 'hmax':               lambda: build(img(h=0x7fffffff)),
 'whmax':              lambda: build(img(w=0x7fffffff, h=0x7fffffff)),
 'w65535':             lambda: build(img(w=65535)),
 'bpc1':               lambda: build(img(bpc=1)),
 'bpc16':              lambda: build(img(bpc=16)),
 'bpc3':               lambda: build(img(bpc=3)),
 'bpc0':               lambda: build(img(bpc=0)),
 'len_small':          lambda: build(img(decl_len=1)),
 'len_zero':           lambda: build(img(decl_len=0)),
 'len_big':            lambda: build(img(decl_len=10**7)),
 'gray_rgbdata':       lambda: build(img(cs=b'/DeviceGray')),
 'decode_big':         lambda: build(img(extra=b'/Decode [0 65535 0 65535 0 65535] ')),
 'interp_wmax':        lambda: build(img(w=0x7fffffff, extra=b'/Interpolate true ')),
 'short_data':         lambda: build(img(data=RAW[:100])),
 'long_data':          lambda: build(img(h=1)),
 'smask_1x1':          lambda: build(img(w=0x7fffffff), objs_extra=[
                          b'<< /Type /XObject /Subtype /Image /Width 1 /Height 1 /BitsPerComponent 8 /ColorSpace /DeviceGray ' + stream(b'\x80') + b' >>']),
 'form_bbox_inv':      lambda: build(img(w=0x7fffffff, h=0x7fffffff),
                          content=b'q /Fm0 Do Q',
                          res_extra=b'/XObject << /Im0 4 0 R /Fm0 6 0 R >> ',
                          objs_extra=[b'<< /Type /XObject /Subtype /Form /BBox [100 100 0 0] /Length 0 >>\nstream\n\nendstream']),
 'pattern_huge':       lambda: build(img(w=0x7fffffff, h=0x7fffffff),
                          content=b'/Pattern cs /P0 scn 0 0 300 300 re f',
                          res_extra=b'/Pattern << /P0 6 0 R >> ',
                          objs_extra=[b'<< /Type /Pattern /PatternType 1 /PaintType 1 /TilingType 1 /BBox [0 0 1 1] /XStep 1000000 /YStep 1000000 /Resources << /XObject << /Im0 4 0 R >> >> /Length 12 >>\nstream\nq 1 0 0 1 0 0 cm /Im0 Do Q\nendstream']),
 'inline_wmax':        lambda: build(b'<< /Type /XObject /Subtype /Image /Width 1 /Height 1 /BitsPerComponent 8 /ColorSpace /DeviceRGB /Length 3 >>\nstream\nabc\nendstream',
                          content=b'q 100 0 0 100 0 0 cm BI /W 2147483647 /H 2147483647 /BPC 8 /CS /RGB ID ' + RAW[:64] + b' EI Q'),
}

CASES2 = {
 'big4k_short':        lambda: build(img(w=4096, h=4096, data=RAW[:4096])),
 'big8k_short':        lambda: build(img(w=8192, h=8192, data=RAW[:2048])),
 'h4k_short':          lambda: build(img(h=4096, data=RAW[:512])),
 'bpc16_4k_short':     lambda: build(img(w=4096, h=4096, bpc=16, data=RAW[:1024])),
 'smask_4k_empty':     lambda: build(img(w=4096, h=4096, data=RAW[:256]), objs_extra=[
                          b'<< /Type /XObject /Subtype /Image /Width 4096 /Height 4096 /BitsPerComponent 8 /ColorSpace /DeviceGray /Length 0 >>\nstream\n\nendstream']),
 'mask_array_huge':    lambda: build(img(w=4096, h=4096, data=RAW[:64], extra=b'/Mask [0 1 0 1 0 1] ')),
 'imagemask_wmax':     lambda: build(img(w=0x7fffffff, h=4096, bpc=1, data=b'\xff'*64, extra=b'/ImageMask true ')),
 'indexed_short':      lambda: build(img(cs=b'[/Indexed /DeviceRGB 255 <000000ffffff>]', data=b'\x00\x01\x02'*10)),
 'decode_2elem':       lambda: build(img(extra=b'/Decode [0 1] ')),
 'cs_bpc_mismatch4':   lambda: build(img(bpc=4, cs=b'/DeviceRGB')),
}
CASES.update(CASES2)

for n, f in CASES.items():
    open(f'{OUT}/{n}.pdf', 'wb').write(f())
print('emitted', len(CASES))
