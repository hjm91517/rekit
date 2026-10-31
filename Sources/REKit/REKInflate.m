#import "REKInflate.h"
#import <zlib.h>

NSData *REKInflateRaw(NSData *src, NSUInteger expectedSize) {
    if (src.length == 0) return [NSData data];
    z_stream zs;
    memset(&zs, 0, sizeof(zs));
    if (inflateInit2(&zs, -MAX_WBITS) != Z_OK) return nil;

    NSUInteger cap = expectedSize > 0 ? expectedSize : MAX(src.length * 4, 64 * 1024);
    NSMutableData *out = [NSMutableData dataWithLength:cap];
    zs.next_in = (Bytef *)src.bytes;
    zs.avail_in = (uInt)src.length;
    NSInteger written = 0;

    int status = Z_OK;
    while (status == Z_OK) {
        if (written == (NSInteger)out.length) {
            [out increaseLengthBy:MAX(out.length, 64 * 1024)];
        }
        zs.next_out = (Bytef *)out.mutableBytes + written;
        zs.avail_out = (uInt)(out.length - (NSUInteger)written);
        status = inflate(&zs, Z_NO_FLUSH);
        written = (NSInteger)out.length - (NSInteger)zs.avail_out;
        if (status == Z_STREAM_END) break;
        if (status != Z_OK && status != Z_BUF_ERROR) { inflateEnd(&zs); return nil; }
        if (status == Z_BUF_ERROR && zs.avail_in == 0) { inflateEnd(&zs); break; }
    }
    inflateEnd(&zs);
    if (status != Z_STREAM_END && written == 0) return nil;
    [out setLength:(NSUInteger)MAX(written, 0)];
    return out;
}
