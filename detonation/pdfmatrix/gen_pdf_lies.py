#!/usr/bin/env python3
"""Structurally valid PDFs, one lying field each, aimed at CG image-XObject decode paths."""
import sys, os, zlib, base64
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
                          objs_extra=[b'<< /Type /Pattern /PatternType 1 /PaintType 1 /TilingType 1 /BBox [0 0 1 1] /XStep 1000000 /YStep 1000000 /Resources << /XObject << /Im0 4 0 R >> >> /Length 27 >>\nstream\nq 1 0 0 1 0 0 cm /Im0 Do Q\nendstream']),
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

JPEG1 = bytes.fromhex("ffd8ffe000104a46494600010100000100010000ffdb0043000a07070807060a0808080b0a0a0b0e18100e0d0d0e1d15161118231f2524221f2221262b372f26293429212230413134393b3e3e3e252e4449433c48373d3e3bffdb0043010a0b0b0e0d0e1c10101c3b2822283b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3bffc00011080040004003012200021101031101ffc4001f0000010501010101010100000000000000000102030405060708090a0bffc400b5100002010303020403050504040000017d01020300041105122131410613516107227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a3435363738393a434445464748494a535455565758595a636465666768696a737475767778797a838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9faffc4001f0100030101010101010101010000000000000102030405060708090a0bffc400b51100020102040403040705040400010277000102031104052131061241510761711322328108144291a1b1c109233352f0156272d10a162434e125f11718191a262728292a35363738393a434445464748494a535455565758595a636465666768696a737475767778797a82838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae2e3e4e5e6e7e8e9eaf2f3f4f5f6f7f8f9faffda000c03010002110311003f00f2d48aa748aa448aa748bdabea65333a150624553a455224556122ae794cf6a8542348aac2454f48aac2455cd299ecd0a8469155848aa448aa748ab9a533daa150e5522ab09153d22ab091576ca67e4542a11a4556122a9122a9d22ae794cf6a854189154e915489155848ab9a533d9a1508d22ab09153d22ab091573ca67b542a1caa4553a455224556122aed94cfc8a8542348aac2454f48aac2455cd299ed50a8469155848aa448aa748ab9e533d9a150624553a455224556122ae694cf6a85439448aac2454f48aac2455db299f9150a846917b55848aa448aa748ab9a533d9a150624553a455224556122f6ae794cf6a8542348aac2454f48aac2455cd299ed50a87fffd9")
Z = zlib.compress(RAW)
def flt(name, data, params=b''):
    return img(w=4096, h=4096, data=b'', extra=b'/Filter /%s ' % name.encode() + params) [:0] or img(w=4096, h=4096, extra=b'/Filter /%s ' % name.encode() + params, data=data)
CASES3 = {
 'flate_trunc':        lambda: img(w=4096, h=4096, extra=b'/Filter /FlateDecode ', data=Z[:40]),
 'flate_short_out':    lambda: img(w=4096, h=4096, extra=b'/Filter /FlateDecode ', data=zlib.compress(b'\x00')),
 'flate_garbage':      lambda: img(w=4096, h=4096, extra=b'/Filter /FlateDecode ', data=b'\x78\x9c'+b'\xff'*40),
 'flate_len_lie':      lambda: img(w=4096, h=4096, extra=b'/Filter /FlateDecode ', data=Z, decl_len=32),
 'dct_big_dict':       lambda: img(w=4096, h=4096, extra=b'/Filter /DCTDecode ', data=JPEG1),
 'dct_dict_1x1':       lambda: img(w=1, h=1, extra=b'/Filter /DCTDecode ', data=JPEG1),
 'dct_trunc':          lambda: img(w=1, h=1, extra=b'/Filter /DCTDecode ', data=JPEG1[:60]),
 'lzw_garbage':        lambda: img(w=4096, h=4096, extra=b'/Filter /LZWDecode ', data=b'\x80\x0b\x60\x50\x22\x0c\x0c\x85\x01'),
 'rle_overrun':        lambda: img(w=4096, h=4096, extra=b'/Filter /RunLengthDecode ', data=b'\xff\x01\x02'),
 'rle_eod_only':       lambda: img(w=4096, h=4096, extra=b'/Filter /RunLengthDecode ', data=b'\x80'),
 'ccitt_short':        lambda: img(w=4096, h=4096, bpc=1, cs=b'/DeviceGray', extra=b'/Filter /CCITTFaxDecode ', data=b'\x00'*10),
 'ccitt_k_neg':        lambda: img(w=4096, h=4096, bpc=1, cs=b'/DeviceGray', extra=b'/Filter /CCITTFaxDecode /DecodeParms << /K -1 /Columns 4096 /Rows 4096 >> ', data=b'\x00'*10),
 'ccitt_k_pos_huge':   lambda: img(w=0x7fffffff, h=4096, bpc=1, cs=b'/DeviceGray', extra=b'/Filter /CCITTFaxDecode /DecodeParms << /K 1 /Columns 2147483647 /Rows 4096 >> ', data=b'\x00'*32),
 'pred12_cols0':       lambda: img(w=4096, h=4096, extra=b'/Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 0 >> ', data=Z),
 'pred15_cols_huge':   lambda: img(w=4096, h=4096, extra=b'/Filter /FlateDecode /DecodeParms << /Predictor 15 /Columns 100000 >> ', data=Z),
 'pred10_bpc16':       lambda: img(w=4096, h=4096, extra=b'/Filter /FlateDecode /DecodeParms << /Predictor 10 /Columns 12288 /Colors 3 /BitsPerComponent 16 >> ', data=Z),
 'mask_ccitt_mismatch':lambda: img(w=4096, h=4096, extra=b'/ImageMask true /Filter /CCITTFaxDecode /DecodeParms << /Columns 1 >> ', bpc=1, cs=b'/DeviceGray', data=b'\x00'*4),
 'two_filter_chain':   lambda: img(w=4096, h=4096, extra=b'/Filter [/ASCII85Decode /FlateDecode] ', data=base64.a85encode(Z)),
}
CASES.update(CASES3)

Z64 = zlib.compress(RAW)
CASES3.update({
 'flate_ok64':        lambda: img(w=64, h=64, extra=b'/Filter /FlateDecode ', data=Z64),
 'flate_trunc64':     lambda: img(w=64, h=64, extra=b'/Filter /FlateDecode ', data=Z64[:40]),
 'pred12_ok64':       lambda: img(w=64, h=64, extra=b'/Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 192 >> ', data=Z64),
 'pred15_ok64':       lambda: img(w=64, h=64, extra=b'/Filter /FlateDecode /DecodeParms << /Predictor 15 /Columns 192 >> ', data=Z64),
 'pred12_cols0_64':   lambda: img(w=64, h=64, extra=b'/Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 0 >> ', data=Z64),
 'ccitt_64':          lambda: img(w=64, h=64, bpc=1, cs=b'/DeviceGray', extra=b'/Filter /CCITTFaxDecode /DecodeParms << /K 0 /Columns 64 /Rows 64 >> ', data=b'\x98'*120),
 'ccitt_short64':     lambda: img(w=64, h=64, bpc=1, cs=b'/DeviceGray', extra=b'/Filter /CCITTFaxDecode /DecodeParms << /K 0 /Columns 64 /Rows 64 >> ', data=b'\x98'*3),
 'dct_4096dims':      lambda: img(w=4096, h=4096, extra=b'/Filter /DCTDecode ', data=JPEG1),
 'dct_ok64':          lambda: img(w=64, h=64, extra=b'/Filter /DCTDecode ', data=JPEG1),
})

for n, f in CASES.items():
    open(f'{OUT}/{n}.pdf', 'wb').write(f())
print('emitted', len(CASES))
