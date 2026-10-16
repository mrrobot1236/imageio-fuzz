// ORACLE-SCAN: pure receiver-side thumbnail ingest (WA-equivalent path).
// CGImageSource -> CreateThumbnailAtIndex. Exit 0 = survive (bit 0).
// Crash/signal = bit 1. No lldb, no patching -- exactly what iOS does.
#include <ImageIO/ImageIO.h>
#include <CoreGraphics/CoreGraphics.h>
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "oracle.pdf";
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8*)path, strlen(path), false);
    CGImageSourceRef src = CGImageSourceCreateWithURL(url, NULL);
    if (!src) { fprintf(stderr, "SRC-FAIL\n"); return 2; }
    CFDictionaryRef opts = (__bridge CFDictionaryRef)@{ (__bridge NSString*)kCGImageSourceCreateThumbnailFromDocument: @YES,
                                                        (__bridge NSString*)kCGImageSourceThumbnailMaxPixelSize: @320 };
    CGImageRef img = CGImageSourceCreateThumbnailAtIndex(src, 0, opts);
    (void)@{}; // keep ARC quiet under plain clang via -fobjc-arc
    if (!img) { fprintf(stderr, "THUMB-NULL\n"); return 3; }
    fprintf(stderr, "SURVIVE %zux%zu\n", (size_t)CGImageGetWidth(img), (size_t)CGImageGetHeight(img));
    CGImageRelease(img); CFRelease(src);
    return 0;
}
