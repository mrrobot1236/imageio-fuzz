// Draw-path harness: CGPDFDocument -> CGBitmapContext 1:1, forces real raster work.
#include <CoreGraphics/CoreGraphics.h>
#include <stdio.h>
int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "x.pdf";
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)path, strlen(path), false);
    CGPDFDocumentRef doc = CGPDFDocumentCreateWithURL(url);
    CFRelease(url);
    if (!doc || CGPDFDocumentGetNumberOfPages(doc) < 1) { fprintf(stderr, "no page\n"); return 1; }
    CGPDFPageRef page = CGPDFDocumentGetPage(doc, 1);
    CGRect box = CGPDFPageGetBoxRect(page, kCGPDFMediaBox);
    if (box.size.width < 1 || box.size.width > 16384) box.size.width = 1024;
    if (box.size.height < 1 || box.size.height > 16384) box.size.height = 1024;
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGContextRef ctx = CGBitmapContextCreate(NULL, (size_t)box.size.width, (size_t)box.size.height, 8, 0, cs, kCGImageAlphaPremultipliedLast);
    fprintf(stderr, "drawing %gx%g...\n", box.size.width, box.size.height);
    CGContextDrawPDFPage(ctx, page);
    fprintf(stderr, "drawn\n");
    return 0;
}
