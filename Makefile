.PHONY: build test lint clean release install dev

# Variables
APP_NAME := angel
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
GO_FLAGS := -ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)"
MODULE := github.com/angel-platform/angel

# Default target
all: lint test build

# Build all binaries
build:
	@echo "Building $(APP_NAME)..."
	@mkdir -p bin
	go build $(GO_FLAGS) -o bin/angel ./cmd/teamserver/
	go build $(GO_FLAGS) -o bin/angel-console ./cmd/console/
	go build $(GO_FLAGS) -o bin/angel-rules ./cmd/rules-loader/
	@echo "Build complete: bin/"

# Build for specific platform
build-linux:
	@echo "Building for Linux..."
	@mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(GO_FLAGS) -o bin/angel-linux-amd64 ./cmd/teamserver/
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(GO_FLAGS) -o bin/angel-console-linux-amd64 ./cmd/console/

build-windows:
	@echo "Building for Windows..."
	@mkdir -p bin
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(GO_FLAGS) -o bin/angel-windows-amd64.exe ./cmd/teamserver/
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(GO_FLAGS) -o bin/angel-console-windows-amd64.exe ./cmd/console/

build-darwin:
	@echo "Building for macOS..."
	@mkdir -p bin
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build $(GO_FLAGS) -o bin/angel-darwin-amd64 ./cmd/teamserver/
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(GO_FLAGS) -o bin/angel-darwin-arm64 ./cmd/teamserver/

# Build all platforms
build-all: build-linux build-windows build-darwin

# Run tests
test:
	@echo "Running tests..."
	go test -v -race -cover ./...

# Run tests with coverage report
test-coverage:
	@echo "Running tests with coverage..."
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Lint code
lint:
	@echo "Running linter..."
	@which golangci-lint > /dev/null 2>&1 || go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	golangci-lint run ./...

# Format code
fmt:
	@echo "Formatting code..."
	gofmt -s -w .
	goimports -w .

# Tidy modules
tidy:
	@echo "Tidying modules..."
	go mod tidy

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -rf bin/
	rm -f coverage.out coverage.html

# Install binaries
install:
	@echo "Installing binaries..."
	go install ./cmd/teamserver/
	go install ./cmd/console/
	go install ./cmd/rules-loader/

# Development mode
dev:
	@echo "Starting in development mode..."
	go run ./cmd/teamserver/ &

# Generate report
report:
	@echo "Generating report..."
	go run ./cmd/console/ report --format html --output report.html

# Run rules loader
rules:
	@echo "Loading rules..."
	go run ./cmd/rules-loader/

# Docker build
docker:
	@echo "Building Docker image..."
	docker build -t $(APP_NAME):$(VERSION) .

# Security scan
security:
	@echo "Running security scan..."
	@which gosec > /dev/null 2>&1 || go install github.com/securego/gosec/cmd/gosec@latest
	gosec ./...

# Dependency check
deps:
	@echo "Checking dependencies..."
	go mod verify
	go mod graph

# Help
help:
	@echo "Available targets:"
	@echo "  build        - Build all binaries"
	@echo "  build-linux  - Build for Linux"
	@echo "  build-windows- Build for Windows"
	@echo "  build-darwin - Build for macOS"
	@echo "  build-all    - Build for all platforms"
	@echo "  test         - Run tests"
	@echo "  test-coverage- Run tests with coverage"
	@echo "  lint         - Run linter"
	@echo "  fmt          - Format code"
	@echo "  tidy         - Tidy modules"
	@echo "  clean        - Clean build artifacts"
	@echo "  install      - Install binaries"
	@echo "  dev          - Start in development mode"
	@echo "  report       - Generate report"
	@echo "  rules        - Load rules"
	@echo "  docker       - Build Docker image"
	@echo "  security     - Run security scan"
	@echo "  deps         - Check dependencies"
	@echo "  help         - Show this help"
