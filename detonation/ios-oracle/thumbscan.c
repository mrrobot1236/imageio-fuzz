// ORACLE-SCAN: pure receiver-side thumbnail ingest (WA-equivalent path).
// CGImageSource -> CreateThumbnailAtIndex. Exit 0 = survive (bit 0).
// Crash/signal = bit 1. Pure C, no ObjC.
#include <ImageIO/ImageIO.h>
#include <CoreGraphics/CoreGraphics.h>
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "oracle.pdf";
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8*)path, strlen(path), false);
    CGImageSourceRef src = CGImageSourceCreateWithURL(url, NULL);
    CFRelease(url);
    if (!src) { fprintf(stderr, "SRC-FAIL\n"); return 2; }
    int maxpx = 320;
    CFNumberRef num = CFNumberCreate(NULL, kCFNumberIntType, &maxpx);
    const void *keys2[] = { kCGImageSourceCreateThumbnailFromDocumentAbsolute, kCGImageSourceThumbnailMaxPixelSize };
    const void *vals2[] = { kCFBooleanTrue, num };
    CFDictionaryRef opts2 = CFDictionaryCreate(NULL, keys2, vals2, 2,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CGImageRef img = CGImageSourceCreateThumbnailAtIndex(src, 0, opts2);
    CFRelease(num); CFRelease(opts2);
    if (!img) { fprintf(stderr, "THUMB-NULL\n"); CFRelease(src); return 3; }
    fprintf(stderr, "SURVIVE %zux%zu\n", (size_t)CGImageGetWidth(img), (size_t)CGImageGetHeight(img));
    CGImageRelease(img); CFRelease(src);
    return 0;
}
