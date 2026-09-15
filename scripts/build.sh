#!/bin/bash
set -e

# Build script for ANGEL Platform
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$ROOT_DIR/bin"
VERSION=$(git -C "$ROOT_DIR" describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

echo "=== ANGEL Platform Build ==="
echo "Version: $VERSION"
echo "Build Time: $BUILD_TIME"
echo ""

# Create build directory
mkdir -p "$BUILD_DIR"

# Build binaries
echo "Building teamserver..."
cd "$ROOT_DIR"
go build -ldflags "-X main.Version=$VERSION -X main.BuildTime=$BUILD_TIME" \
    -o "$BUILD_DIR/angel" ./cmd/teamserver/

echo "Building console..."
go build -ldflags "-X main.Version=$VERSION -X main.BuildTime=$BUILD_TIME" \
    -o "$BUILD_DIR/angel-console" ./cmd/console/

echo "Building rules-loader..."
go build -ldflags "-X main.Version=$VERSION -X main.BuildTime=$BUILD_TIME" \
    -o "$BUILD_DIR/angel-rules" ./cmd/rules-loader/

echo ""
echo "=== Build Complete ==="
echo "Binaries: $BUILD_DIR/"
ls -la "$BUILD_DIR/"
