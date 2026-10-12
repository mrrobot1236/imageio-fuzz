// imageio_fuzz.m — libFuzzer harness for ImageIO decode paths (ASan+UBSan)
#import <CoreFoundation/CoreFoundation.h>
#import <ImageIO/ImageIO.h>
#import <CoreGraphics/CoreGraphics.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8 || size > 16*1024*1024) return 0;
    CFDataRef cfdata = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, data, (CFIndex)size, kCFAllocatorNull);
    CGDataProviderRef provider = CGDataProviderCreateWithCFData(cfdata);
    CGImageSourceRef src = CGImageSourceCreateWithDataProvider(provider, NULL);
    if (src) {
        CGImageRef img = CGImageSourceCreateImageAtIndex(src, 0, NULL);
        if (img) { CGImageRelease(img); }
        CGImageSourceCopyPropertiesAtIndex(src, 0, NULL);
        CGImageSourceCreateThumbnailAtIndex(src, 0, NULL);
        CFRelease(src);
    }
    CGDataProviderRelease(provider);
    CFRelease(cfdata);
    return 0;
}
