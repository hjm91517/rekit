#import <Foundation/Foundation.h>

/// Raw-deflate (RFC1951, windowBits = -15) inflate. Returns nil on failure.
NSData *_Nullable REKInflateRaw(NSData *src, NSUInteger expectedSize);
