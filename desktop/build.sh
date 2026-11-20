#!/bin/sh
# Builds dist/EventSolutions-Setup.exe (works on Linux, Mac and Windows/WSL):
#  1. electron-builder packs the app into dist/win-unpacked (after-pack.js sets
#     the icon and version on EventSolutions.exe)
#  2. makensis (NSIS, downloaded by electron-builder) makes the installer
set -e
cd "$(dirname "$0")"
npx electron-builder --win dir --x64
NSIS=$(ls -d "${XDG_CACHE_HOME:-$HOME/.cache}"/electron-builder/nsis-3*/nsis-3* 2>/dev/null | head -1)
RES=$(ls -d "${XDG_CACHE_HOME:-$HOME/.cache}"/electron-builder/nsis-resources-*/nsis-resources-* 2>/dev/null | head -1)
if [ -z "$NSIS" ] || [ -z "$RES" ]; then
  # first build: let electron-builder download NSIS once (the nsis target itself may fail without 32-bit Wine)
  npx electron-builder --win nsis --x64 >/dev/null 2>&1 || true
  NSIS=$(ls -d "${XDG_CACHE_HOME:-$HOME/.cache}"/electron-builder/nsis-3*/nsis-3* | head -1)
  RES=$(ls -d "${XDG_CACHE_HOME:-$HOME/.cache}"/electron-builder/nsis-resources-*/nsis-resources-* | head -1)
fi
case "$(uname -s)" in Darwin) MK="$NSIS/mac/makensis" ;; Linux) MK="$NSIS/linux/makensis" ;; *) MK="$NSIS/Bin/makensis.exe" ;; esac
VERSION=$(node -p "require('./package.json').version")
NSISDIR="$NSIS" "$MK" -V2 -DVERSION="$VERSION" -DPLUGINS="$RES/plugins/x86-unicode" installer.nsi
ls -la dist/EventSolutions-Setup.exe
