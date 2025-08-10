# Makefile for opreturner - Bitcoin OP_RETURN CLI tool
# Builds for multiple platforms and architectures

# Binary name
BINARY_NAME=opreturner

# Version (can be overridden via VERSION=1.0.0 make build)
VERSION ?= 1.0.0

# Build directory
BUILD_DIR=build

# Go build flags
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -s -w"

# Platforms to build for
PLATFORMS=linux/amd64 linux/arm64 linux/386 linux/arm darwin/amd64 darwin/arm64 windows/amd64 windows/386

# Default target
.PHONY: all
all: clean build-all

# Clean build directory
.PHONY: clean
clean:
	@echo "Cleaning build directory..."
	@rm -rf $(BUILD_DIR)
	@mkdir -p $(BUILD_DIR)

# Build for current platform
.PHONY: build
build:
	@echo "Building for current platform..."
	@go build $(LDFLAGS) -o $(BINARY_NAME) main.go

# Build for all platforms
.PHONY: build-all
build-all: clean
	@echo "Building for all platforms..."
	@for platform in $(PLATFORMS); do \
		IFS='/' read -r GOOS GOARCH <<< "$$platform"; \
		echo "Building for $$GOOS/$$GOARCH..."; \
		GOOS=$$GOOS GOARCH=$$GOARCH go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-$$GOOS-$$GOARCH main.go; \
		if [ "$$GOOS" = "windows" ]; then \
			mv $(BUILD_DIR)/$(BINARY_NAME)-$$GOOS-$$GOARCH $(BUILD_DIR)/$(BINARY_NAME)-$$GOOS-$$GOARCH.exe; \
		fi; \
	done
	@echo "Build complete! Binaries are in $(BUILD_DIR)/"

# Build for specific platform
.PHONY: build-linux
build-linux:
	@echo "Building for Linux..."
	@GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 main.go
	@GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 main.go

# Build for macOS
.PHONY: build-darwin
build-darwin:
	@echo "Building for macOS..."
	@GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 main.go
	@GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 main.go

# Build for Windows
.PHONY: build-windows
build-windows:
	@echo "Building for Windows..."
	@GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe main.go
	@GOOS=windows GOARCH=386 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-386.exe main.go

# Build for ARM devices (Raspberry Pi, etc.)
.PHONY: build-arm
build-arm:
	@echo "Building for ARM devices..."
	@GOOS=linux GOARCH=arm go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm main.go
	@GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 main.go

# Build for specific architecture
.PHONY: build-amd64
build-amd64:
	@echo "Building for AMD64..."
	@GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 main.go
	@GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 main.go
	@GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe main.go

# Build for Apple Silicon (M1/M2)
.PHONY: build-apple-silicon
build-apple-silicon:
	@echo "Building for Apple Silicon (M1/M2)..."
	@GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 main.go

# Build for Intel Mac
.PHONY: build-intel-mac
build-intel-mac:
	@echo "Building for Intel Mac..."
	@GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 main.go

# Build for Raspberry Pi (32-bit)
.PHONY: build-raspberry-pi
build-raspberry-pi:
	@echo "Building for Raspberry Pi (32-bit)..."
	@GOOS=linux GOARCH=arm go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm main.go

# Build for Raspberry Pi (64-bit)
.PHONY: build-raspberry-pi64
build-raspberry-pi64:
	@echo "Building for Raspberry Pi (64-bit)..."
	@GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 main.go

# Build for servers (Linux AMD64)
.PHONY: build-server
build-server:
	@echo "Building for Linux servers..."
	@GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 main.go

# Build for development (current platform)
.PHONY: dev
dev:
	@echo "Building for development (current platform)..."
	@go build -o $(BINARY_NAME) main.go

# Install dependencies
.PHONY: deps
deps:
	@echo "Installing dependencies..."
	@go mod download
	@go mod tidy

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	@go test -v ./...

# Run with race detection
.PHONY: test-race
test-race:
	@echo "Running tests with race detection..."
	@go test -race -v ./...

# Format code
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	@go fmt ./...

# Run linter
.PHONY: lint
lint:
	@echo "Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not found. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

# Show build info
.PHONY: info
info:
	@echo "Build Information:"
	@echo "  Binary: $(BINARY_NAME)"
	@echo "  Version: $(VERSION)"
	@echo "  Go version: $(shell go version)"
	@echo "  Build directory: $(BUILD_DIR)"
	@echo "  Available platforms: $(PLATFORMS)"

# Show help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  all              - Clean and build for all platforms"
	@echo "  build            - Build for current platform"
	@echo "  build-all        - Build for all platforms"
	@echo "  build-linux      - Build for Linux (AMD64 + ARM64)"
	@echo "  build-darwin     - Build for macOS (Intel + Apple Silicon)"
	@echo "  build-windows    - Build for Windows (AMD64 + 386)"
	@echo "  build-arm        - Build for ARM devices"
	@echo "  build-amd64      - Build for AMD64 architecture"
	@echo "  build-apple-silicon - Build for Apple Silicon (M1/M2)"
	@echo "  build-intel-mac  - Build for Intel Mac"
	@echo "  build-raspberry-pi - Build for Raspberry Pi (32-bit)"
	@echo "  build-raspberry-pi64 - Build for Raspberry Pi (64-bit)"
	@echo "  build-server     - Build for Linux servers"
	@echo "  dev              - Build for development"
	@echo "  deps             - Install dependencies"
	@echo "  test             - Run tests"
	@echo "  test-race        - Run tests with race detection"
	@echo "  fmt              - Format code"
	@echo "  lint             - Run linter"
	@echo "  clean            - Clean build directory"
	@echo "  info             - Show build information"
	@echo "  help             - Show this help message"
	@echo ""
	@echo "Examples:"
	@echo "  make build-all                    # Build for all platforms"
	@echo "  make build-linux                  # Build for Linux only"
	@echo "  make build-apple-silicon          # Build for Apple Silicon Mac"
	@echo "  VERSION=2.0.0 make build-all     # Build with specific version"

# Default target
.DEFAULT_GOAL := help
