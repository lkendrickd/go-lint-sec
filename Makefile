BINARY     := go-sec-lint
MODULE     := github.com/dk/go-sec-lint
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE       ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS    := -s -w \
	-X 'main.version=$(VERSION)' \
	-X 'main.commit=$(COMMIT)' \
	-X 'main.date=$(DATE)'

GOPATH     ?= $(shell go env GOPATH)
GOBIN      := $(GOPATH)/bin

GOLANGCI_LINT_VERSION := v2.1.6
GOLANGCI_LINT         := $(shell command -v golangci-lint 2>/dev/null || echo "$(GOBIN)/golangci-lint")

.PHONY: all build lint lint-fix vet test clean install

all: lint build

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) .

install:
	go install -ldflags "$(LDFLAGS)" .

$(GOBIN)/golangci-lint:
	@echo "Installing golangci-lint $(GOLANGCI_LINT_VERSION)..."
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

lint: $(GOBIN)/golangci-lint
	$(GOLANGCI_LINT) run ./...

lint-fix: $(GOBIN)/golangci-lint
	$(GOLANGCI_LINT) run --fix ./...

vet:
	go vet ./...

test:
	go test -race ./...

clean:
	rm -f $(BINARY)
