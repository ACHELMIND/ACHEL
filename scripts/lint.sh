#!/bin/bash
set -e

# Lint script for ANGEL Platform
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== ANGEL Platform Lint ==="

# Check if golangci-lint is installed
if ! command -v golangci-lint &> /dev/null; then
    echo "Installing golangci-lint..."
    go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
fi

# Run linter
echo "Running golangci-lint..."
cd "$ROOT_DIR"
golangci-lint run ./...

# Format code
echo "Formatting code..."
gofmt -s -w .

# Check for goimports
if command -v goimports &> /dev/null; then
    echo "Running goimports..."
    goimports -w .
fi

# Tidy modules
echo "Tidying modules..."
go mod tidy

echo ""
echo "=== Lint Complete ==="
