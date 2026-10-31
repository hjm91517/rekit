#!/usr/bin/env bash
# Packages the built .app into an unsigned IPA and records what is inside.
set -euo pipefail

SRC="${1:-build/Build/Products/Release-iphoneos}"
OUT="${2:-artifacts}"
APP="$SRC/REKitApp.app"

if [ ! -d "$APP" ]; then
  echo "找不到 $APP" >&2
  exit 1
fi

rm -rf "$OUT/Payload"
mkdir -p "$OUT/Payload"
cp -R "$APP" "$OUT/Payload/"

# 顺手把框架里的 dylib 抽出来，方便直接做注入素材
mkdir -p "$OUT"
find "$APP/Frameworks" -name '*.dylib' -maxdepth 2 -exec cp {} "$OUT/" \; 2>/dev/null || true

(
  cd "$OUT"
  rm -f REKitApp.ipa
  zip -qry REKitApp.ipa Payload
)

{
  echo "app: $APP"
  echo "ipa: $OUT/REKitApp.ipa"
  echo "size: $(wc -c < "$OUT/REKitApp.ipa") bytes"
  echo "arch: $(lipo -archs "$APP/REKitApp" 2>/dev/null || echo unknown)"
  echo "frameworks:"
  ls -1 "$APP/Frameworks" 2>/dev/null || echo "  (none)"
  echo "signature: unsigned (CODE_SIGNING_ALLOWED=NO)"
} | tee "$OUT/manifest.txt"
