// imageio_fuzz.m — libFuzzer harness for ImageIO decode paths (ASan+UBSan)
#import <CoreFoundation/CoreFoundation.h>
#import <ImageIO/ImageIO.h>
#import <CoreGraphics/CoreGraphics.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>


static void draw_guarded(CGImageRef img, size_t w, size_t h, CGColorSpaceRef cs) {
    CGContextRef probe = CGBitmapContextCreate(NULL, w, h, 8, 0, cs,
        kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Host);
    if (!probe) return;
    size_t rb = CGBitmapContextGetBytesPerRow(probe);
    CGContextRelease(probe);
    if (!rb) return;
    size_t need = rb * h;
    size_t pg = (size_t)sysconf(_SC_PAGESIZE);
    size_t pages = (need + pg - 1) / pg;
    size_t total = (pages + 1) * pg;
    void *base = mmap(NULL, total, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) return;
    mprotect((char *)base + pages * pg, pg, PROT_NONE);
    void *data = (char *)base + (pages * pg - need);
    CGContextRef ctx = CGBitmapContextCreate(data, w, h, 8, rb, cs,
        kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Host);
    if (ctx) {
        memset(data, 0xAA, need);
        fprintf(stderr, "DRAW w=%zu h=%zu rb=%zu need=%zu\n", w, h, rb, need);
        CGContextDrawImage(ctx, CGRectMake(0, 0, (CGFloat)w, (CGFloat)h), img);
        size_t painted = 0, scan = need < 4096 ? need : 4096;
        const unsigned char *u = (const unsigned char *)data;
        for (size_t i = 0; i < scan; i++) if (u[i] != 0xAA) painted++;
        fprintf(stderr, "DRAWN painted=%zu/%zu\n", painted, scan);
        CGContextRelease(ctx);
    } else {
        fprintf(stderr, "DRAWCTXFAIL w=%zu h=%zu rb=%zu\n", w, h, rb);
    }
    munmap(base, total);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8 || size > 16*1024*1024) return 0;
    CFDataRef cfdata = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, data, (CFIndex)size, kCFAllocatorNull);
    CGDataProviderRef provider = CGDataProviderCreateWithCFData(cfdata);
    CGImageSourceRef src = CGImageSourceCreateWithDataProvider(provider, NULL);
    if (src) {
        CGImageRef img = CGImageSourceCreateImageAtIndex(src, 0, NULL);
        if (img) {
            // GUARDED FULL-RASTER DRAW (model-B detector).
            // Buffer is sized from the DECLARED dims; the tile compositor writes into it.
            // A PROT_NONE page sits flush behind the last buffer byte, so a single byte
            // of overrun faults (ASan cannot see uninstrumented framework writes).
            size_t w = CGImageGetWidth(img), h = CGImageGetHeight(img);
            if (w && h && (w * h) <= (size_t)64*1024*1024) {
                CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
                if (cs) draw_guarded(img, w, h, cs);
                if (cs) CGColorSpaceRelease(cs);
            }
            CGImageRelease(img);
        }
        CGImageSourceCopyPropertiesAtIndex(src, 0, NULL);
        CGImageSourceCreateThumbnailAtIndex(src, 0, NULL);
        CFRelease(src);
    }
    CGDataProviderRelease(provider);
    CFRelease(cfdata);
    return 0;
}
