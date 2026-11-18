PLUGIN_NAME ?= key-access
VERSION ?= 0.1.0
BUILD_DIR ?= dist
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
GO_LDFLAGS ?= -s -w -X main.pluginVersion=$(VERSION)

EXT_linux = so
EXT_freebsd = so
EXT_darwin = dylib
EXT_windows = dll
PLUGIN_EXT = $(or $(EXT_$(GOOS)),so)
PLUGIN_OUTPUT ?= $(BUILD_DIR)/$(PLUGIN_NAME).$(PLUGIN_EXT)
PLUGIN_HEADER = $(basename $(PLUGIN_OUTPUT)).h
CPA_DIR ?=

.PHONY: all build test vet check install clean

all: check build

build:
	mkdir -p $(dir $(PLUGIN_OUTPUT))
	CGO_ENABLED=1 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath -buildmode=c-shared -ldflags "$(GO_LDFLAGS)" -o $(PLUGIN_OUTPUT) .
	rm -f $(PLUGIN_HEADER)
	@echo "built $(PLUGIN_OUTPUT)"

test:
	go test ./...

vet:
	go vet ./...

test-page:
	node test/page/smoke.js

.PHONY: test-page e2e
e2e: build
	@test -n "$(CPA_HOST)" || (echo "usage: make e2e CPA_HOST=/path/to/cpa-binary"; exit 1)
	@D=$$(mktemp -d /tmp/ka-plugins.XXXXXX) && mkdir -p "$$D/$(GOOS)/$(GOARCH)" && cp $(PLUGIN_OUTPUT) "$$D/$(GOOS)/$(GOARCH)/$(PLUGIN_NAME).$(PLUGIN_EXT)" && bash test/e2e/run.sh "$(CPA_HOST)" "$$D"

check: test-page
	gofmt -l -w *.go
	go vet ./...
	go test -race ./...

install: build
	@test -n "$(CPA_DIR)" || (echo "usage: make install CPA_DIR=/path/to/CLIProxyAPI"; exit 1)
	@mkdir -p "$(CPA_DIR)/plugins/$(GOOS)/$(GOARCH)"
	cp $(PLUGIN_OUTPUT) "$(CPA_DIR)/plugins/$(GOOS)/$(GOARCH)/$(PLUGIN_NAME).$(PLUGIN_EXT)"
	@echo "installed to $(CPA_DIR)/plugins/$(GOOS)/$(GOARCH)/$(PLUGIN_NAME).$(PLUGIN_EXT)"

clean:
	rm -rf $(BUILD_DIR)
