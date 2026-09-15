#!/bin/bash
set -e

# Test script for ANGEL Platform
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== ANGEL Platform Tests ==="

cd "$ROOT_DIR"

# Run unit tests
echo "Running unit tests..."
go test -v -race ./...

# Run tests with coverage
echo ""
echo "Running tests with coverage..."
go test -race -coverprofile=coverage.out ./...

# Generate coverage report
echo "Generating coverage report..."
go tool cover -html=coverage.out -o coverage.html
go tool cover -func=coverage.out

echo ""
echo "=== Tests Complete ==="
echo "Coverage report: coverage.html"
