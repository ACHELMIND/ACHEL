#!/bin/bash
set -e

# Release script for ANGEL Platform
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$ROOT_DIR/bin"
RELEASE_DIR="$ROOT_DIR/releases"

# Check for version tag
if [ -z "$1" ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 v1.0.0"
    exit 1
fi

VERSION="$1"
echo "=== ANGEL Platform Release $VERSION ==="

# Clean previous builds
echo "Cleaning previous builds..."
rm -rf "$BUILD_DIR" "$RELEASE_DIR"
mkdir -p "$BUILD_DIR" "$RELEASE_DIR"

# Run tests
echo "Running tests..."
cd "$ROOT_DIR"
go test -race ./...

# Build for Linux
echo "Building for Linux..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags "-X main.Version=$VERSION" \
    -o "$BUILD_DIR/angel-linux-amd64" ./cmd/teamserver/
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags "-X main.Version=$VERSION" \
    -o "$BUILD_DIR/angel-console-linux-amd64" ./cmd/console/

# Build for Windows
echo "Building for Windows..."
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build \
    -ldflags "-X main.Version=$VERSION" \
    -o "$BUILD_DIR/angel-windows-amd64.exe" ./cmd/teamserver/
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build \
    -ldflags "-X main.Version=$VERSION" \
    -o "$BUILD_DIR/angel-console-windows-amd64.exe" ./cmd/console/

# Build for macOS
echo "Building for macOS..."
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build \
    -ldflags "-X main.Version=$VERSION" \
    -o "$BUILD_DIR/angel-darwin-amd64" ./cmd/teamserver/
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build \
    -ldflags "-X main.Version=$VERSION" \
    -o "$BUILD_DIR/angel-darwin-arm64" ./cmd/teamserver/

# Create release archives
echo "Creating release archives..."
cd "$BUILD_DIR"

tar -czf "$RELEASE_DIR/angel-$VERSION-linux-amd64.tar.gz" angel-linux-amd64 angel-console-linux-amd64
tar -czf "$RELEASE_DIR/angel-$VERSION-windows-amd64.zip" angel-windows-amd64.exe angel-console-windows-amd64.exe
tar -czf "$RELEASE_DIR/angel-$VERSION-darwin-amd64.tar.gz" angel-darwin-amd64

# Generate checksums
echo "Generating checksums..."
cd "$RELEASE_DIR"
sha256sum *.tar.gz *.zip > checksums-$VERSION.txt

echo ""
echo "=== Release Complete ==="
echo "Release files: $RELEASE_DIR/"
ls -la "$RELEASE_DIR/"
