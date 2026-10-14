#!/bin/bash
set -x
CACHE="/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e"
ls -la /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/ | head -20
U="/Applications/Xcode_15.4.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/dyld_shared_cache_util"
ls -la "$U" || U=$(find /Applications/Xcode*.app -name dyld_shared_cache_util 2>/dev/null | head -1)
echo "USING: $U"
"$U" 2>&1 | head -5
rm -rf xout && mkdir xout
"$U" -extract "$PWD/xout" "$CACHE" com.apple.CoreGraphics 2>&1 | tee util.log
ls -la xout/
"$U" -extract "$PWD/xout" "$CACHE" CoreGraphics 2>&1 | tee -a util.log
ls -la xout/
file xout/* 2>/dev/null
