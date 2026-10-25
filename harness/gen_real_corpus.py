#!/usr/bin/env python3
"""gen_real_corpus.py — real decodable image corpus generator (runs on macOS runner).

Generates gradient PNGs at int-overflow boundary dimensions, then fans them
out to real JPEG/TIFF/GIF/BMP/JP2/HEIC via sips. Unlike synthetic boundary
seeds, these actually decode — they carry the fuzzer through the real
decoder paths instead of dying at format sniffing.
"""
import os, sys, zlib, struct, subprocess

OUT = sys.argv[1] if len(sys.argv) > 1 else "real"
os.makedirs(OUT, exist_ok=True)

def png_chunk(t, d):
    return struct.pack('>I', len(d)) + t + d + struct.pack('>I', zlib.crc32(t + d) & 0xffffffff)

def write_png(path, w, h):
    with open(path, 'wb') as f:
        f.write(b'\x89PNG\r\n\x1a\n')
        f.write(png_chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0)))
        raw = b''.join(bytes([0]) + bytes(((x * 7 + y * 13) & 0xff) for x in range(w * 3)) for y in range(h))
        f.write(png_chunk(b'IDAT', zlib.compress(raw, 6)))
        f.write(png_chunk(b'IEND', b''))

DIMS = [(1,1),(2,2),(3,3),(4,4),(7,7),(8,8),(15,15),(16,16),(31,31),(32,32),
        (63,63),(64,64),(127,127),(128,128),(255,255),(256,256),(257,257),
        (511,511),(512,512),(1023,1023),(1024,1024),(1027,3),(3,1027),
        (2048,8),(8,2048),(2048,2048),(4096,4096)]

EXT = {'jpeg':'jpg','tiff':'tif','bmp':'bmp','jp2':'jp2','heic':'heic','gif':'gif'}

def sips(src, dst, fmt):
    try:
        r = subprocess.run(['sips','-s','format',fmt,src,'--out',dst],
                           capture_output=True, timeout=300)
        if r.returncode == 0 and os.path.exists(dst) and os.path.getsize(dst) > 0:
            return True
    except Exception as e:
        print(f'sips {fmt} {src}: {e}')
    if os.path.exists(dst):
        os.remove(dst)
    print(f'sips {fmt} {src}: skipped')
    return False

n = 0
for w, h in DIMS:
    p = os.path.join(OUT, f'base_{w}x{h}.png')
    write_png(p, w, h)
    n += 1
    fmts = ['jpeg','tiff','gif','bmp','jp2','heic'] if w * h <= 1024 * 1024 else ['jpeg','jp2','heic']
    for fmt in fmts:
        dp = os.path.join(OUT, f'real_{w}x{h}.{EXT[fmt]}')
        if sips(p, dp, fmt):
            n += 1

print(f'generated {n} files in {OUT}')
