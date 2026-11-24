// Oracle harness: renders page 1 to a bitmap and reports a content fingerprint.
// Status classes: PARSE_FAIL / BLANK / PAINTED, plus FNV hash + painted count.
#include <CoreGraphics/CoreGraphics.h>
#include <stdio.h>
#include <stdint.h>
int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "x.pdf";
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)path, strlen(path), false);
    CGPDFDocumentRef doc = CGPDFDocumentCreateWithURL(url);
    CFRelease(url);
    if (!doc) { fprintf(stderr, "PARSE_FAIL nil_doc\n"); return 1; }
    size_t n = CGPDFDocumentGetNumberOfPages(doc);
    if (n < 1) { fprintf(stderr, "PARSE_FAIL no_pages\n"); return 1; }
    CGPDFPageRef page = CGPDFDocumentGetPage(doc, 1);
    CGRect box = CGPDFPageGetBoxRect(page, kCGPDFMediaBox);
    int w = (int)box.size.width, h = (int)box.size.height;
    if (w < 1 || w > 4096) w = 512; if (h < 1 || h > 4096) h = 512;
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGContextRef ctx = CGBitmapContextCreate(NULL, w, h, 8, 0, cs, kCGImageAlphaPremultipliedLast);
    if (!ctx) { fprintf(stderr, "PARSE_FAIL no_ctx\n"); return 1; }
    CGContextSetRGBFillColor(ctx, 1, 1, 1, 1);
    CGContextFillRect(ctx, CGRectMake(0, 0, w, h));
    CGContextDrawPDFPage(ctx, page);
    unsigned char *p = CGBitmapContextGetData(ctx);
    size_t stride = CGBitmapContextGetBytesPerRow(ctx);
    uint64_t fnv = 1469598103934665603ULL; size_t painted = 0;
    for (int y = 0; y < h; y++) for (int x = 0; x < w; x++) {
        unsigned char *q = p + y*stride + x*4;
        fnv = (fnv ^ q[0]) * 1099511628211ULL; fnv = (fnv ^ q[1]) * 1099511628211ULL; fnv = (fnv ^ q[2]) * 1099511628211ULL;
        if (q[0] != 255 || q[1] != 255 || q[2] != 255) painted++;
    }
    printf("%s %dx%d %zu %016llx\n", painted ? "PAINTED" : "BLANK", w, h, painted, (unsigned long long)fnv);
    return 0;
}
