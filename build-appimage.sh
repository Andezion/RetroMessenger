#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
APPDIR="$SCRIPT_DIR/AppDir"

echo "Building RetroMessenger"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

echo "Preparing AppDir"
rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin"
mkdir -p "$APPDIR/usr/share/applications"
mkdir -p "$APPDIR/usr/share/icons/hicolor/256x256/apps"

cp "$BUILD_DIR/RetroMessenger" "$APPDIR/usr/bin/"
cp "$SCRIPT_DIR/retromessenger.desktop" "$APPDIR/usr/share/applications/"

if [ ! -f "$SCRIPT_DIR/retromessenger.png" ]; then
    echo "No icon found, generating placeholder..."
    if command -v convert &> /dev/null; then
        convert -size 256x256 xc:'#2d2d2d' \
            -fill '#00ff88' -font Courier -pointsize 48 \
            -gravity center -annotate 0 'RM' \
            "$SCRIPT_DIR/retromessenger.png"
    else
        printf '\x89PNG\r\n\x1a\n' > "$SCRIPT_DIR/retromessenger.png"
        echo "Warning: ImageMagick not found. Please provide retromessenger.png (256x256)"
    fi
fi

cp "$SCRIPT_DIR/retromessenger.png" "$APPDIR/usr/share/icons/hicolor/256x256/apps/"

echo "Downloading linuxdeploy"
LINUXDEPLOY="$BUILD_DIR/linuxdeploy-x86_64.AppImage"
if [ ! -f "$LINUXDEPLOY" ]; then
    wget -q "https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage" \
        -O "$LINUXDEPLOY"
    chmod +x "$LINUXDEPLOY"
fi

echo "Creating AppImage"
"$LINUXDEPLOY" \
    --appdir "$APPDIR" \
    --desktop-file "$APPDIR/usr/share/applications/retromessenger.desktop" \
    --icon-file "$APPDIR/usr/share/icons/hicolor/256x256/apps/retromessenger.png" \
    --output appimage

echo ""
echo "Done!"
echo "AppImage created in: $(ls -1 "$SCRIPT_DIR"/RetroMessenger*.AppImage 2>/dev/null || echo "$BUILD_DIR")"
echo "Users can run it with: chmod +x RetroMessenger*.AppImage && ./RetroMessenger*.AppImage"
