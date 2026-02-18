# Copyright (c) 2025 NetworkOps
# SPDX-License-Identifier: MPL-2.0

HOSTNAME=registry.terraform.io
NAMESPACE=networkops
NAME=networkops
BINARY=terraform-provider-${NAME}
VERSION=0.1.0
OS_ARCH=$(shell go env GOOS)_$(shell go env GOARCH)

default: install

.PHONY: build
build:
	go build -o ${BINARY}

.PHONY: install
install: build
	mkdir -p ~/.terraform.d/plugins/${HOSTNAME}/${NAMESPACE}/${NAME}/${VERSION}/${OS_ARCH}
	mv ${BINARY} ~/.terraform.d/plugins/${HOSTNAME}/${NAMESPACE}/${NAME}/${VERSION}/${OS_ARCH}

.PHONY: lint
lint:
	golangci-lint run ./...

.PHONY: fmt
fmt:
	go fmt ./...
	gofumpt -l -w .

.PHONY: test
test:
	go test -v -cover -timeout=120s -parallel=4 ./...

.PHONY: testacc
testacc:
	TF_ACC=1 go test -v -cover -timeout 120m ./...

.PHONY: generate
generate:
	go generate ./...

.PHONY: docs
docs:
	go generate ./...
	tfplugindocs generate

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: clean
clean:
	rm -f ${BINARY}
	rm -rf ~/.terraform.d/plugins/${HOSTNAME}/${NAMESPACE}/${NAME}

.PHONY: release
release:
	GOOS=darwin GOARCH=amd64 go build -o ./dist/${BINARY}_${VERSION}_darwin_amd64
	GOOS=darwin GOARCH=arm64 go build -o ./dist/${BINARY}_${VERSION}_darwin_arm64
	GOOS=linux GOARCH=amd64 go build -o ./dist/${BINARY}_${VERSION}_linux_amd64
	GOOS=linux GOARCH=arm64 go build -o ./dist/${BINARY}_${VERSION}_linux_arm64
	GOOS=windows GOARCH=amd64 go build -o ./dist/${BINARY}_${VERSION}_windows_amd64.exe

.PHONY: all
all: fmt lint test build

.PHONY: help
help:
	@echo "NetworkOps Terraform Provider"
	@echo ""
	@echo "Usage:"
	@echo "  make build    - Build the provider binary"
	@echo "  make install  - Build and install to local Terraform plugins"
	@echo "  make test     - Run unit tests"
	@echo "  make testacc  - Run acceptance tests"
	@echo "  make lint     - Run linter"
	@echo "  make fmt      - Format code"
	@echo "  make docs     - Generate documentation"
	@echo "  make clean    - Remove build artifacts"
	@echo "  make release  - Build for all platforms"
	@echo ""
