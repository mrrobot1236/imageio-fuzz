// imageio_probe.m — reports what the decoder ACTUALLY produced (no fuzzing).
// Purpose: prove/disprove that ispe/pixi/hvcC lies change the raster geometry
// and bytes-per-pixel. Prints one PROBE line per input.
#import <CoreFoundation/CoreFoundation.h>
#import <ImageIO/ImageIO.h>
#import <CoreGraphics/CoreGraphics.h>
#include <stdio.h>

int main(int argc, char **argv) {
    for (int a = 1; a < argc; a++) {
        FILE *f = fopen(argv[a], "rb"); if (!f) continue;
        fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
        void *buf = malloc(n); if (fread(buf, 1, n, f) != (size_t)n) { fclose(f); free(buf); continue; }
        fclose(f);
        CFDataRef cd = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, buf, n, kCFAllocatorNull);
        CGDataProviderRef p = CGDataProviderCreateWithCFData(cd);
        CGImageSourceRef s = CGImageSourceCreateWithDataProvider(p, NULL);
        printf("PROBE %s", argv[a]);
        if (!s) { printf(" SRC=nil\n"); goto done; }
        CFDictionaryRef props = CGImageSourceCopyPropertiesAtIndex(s, 0, NULL);
        if (props) {
            CFNumberRef pw = CFDictionaryGetValue(props, kCGImagePropertyPixelWidth);
            CFNumberRef ph = CFDictionaryGetValue(props, kCGImagePropertyPixelHeight);
            long w = -1, h = -1;
            if (pw) CFNumberGetValue(pw, kCFNumberLongType, &w);
            if (ph) CFNumberGetValue(ph, kCFNumberLongType, &h);
            printf(" props=%ldx%ld", w, h);
            CFRelease(props);
        }
        CGImageRef img = CGImageSourceCreateImageAtIndex(s, 0, NULL);
        if (!img) { printf(" IMG=nil\n"); }
        else {
            printf(" IMG=%zux%zu bpc=%zu bpp=%zu rowbytes=%zu\n",
                   CGImageGetWidth(img), CGImageGetHeight(img),
                   CGImageGetBitsPerComponent(img), CGImageGetBitsPerPixel(img),
                   CGImageGetBytesPerRow(img));
            CGImageRelease(img);
        }
        CFRelease(s);
    done:
        CGDataProviderRelease(p); CFRelease(cd); free(buf);
    }
    return 0;
}
