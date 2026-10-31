# HELP
# This will output the help for each task
# thanks to https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html

.DEFAULT_GOAL := help
.PHONY: help all build examples stress release-notes install fmt fmt-check lint lint-ci vet vuln test test-race coverage cover bench fuzz generate generate-check check clean interop test-interop coverage-check cross e2e coverage-pkg-check

help: ## This help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Parent otfabric/go.work does not list this module; isolate toolchain commands.
export GOWORK := off

# CI formats and lints with the Go version from go.mod, not the toolchain
# installed here; gofmt's output changes between releases, so formatting is
# done with that version and fmt-check requires the local gofmt to agree too.
GO_MOD_VERSION := $(shell sed -nE 's/^go ([0-9]+\.[0-9]+).*/\1/p' go.mod | head -n1)
GOFMT_CI = $(shell GOTOOLCHAIN=go$(GO_MOD_VERSION).0 go env GOROOT)/bin/gofmt

BIN_DIR := bin
# The CLI is a nested module (ADR-0009): ./... of this module does not reach it.
CLI_DIR := cmd/otprobe
PKGS := $(shell go list ./...)
# Library packages for coverage (exclude the CLI, generators, test helpers and examples).
COVER_PKGS := $(shell go list ./... | grep -vE '/cmd/|/internal/cmd|/internal/testsrv|/internal/fuzzkit|/examples|/e2e' | paste -sd, -)
TEST_PKGS := $(shell go list ./... | grep -vE '/interop|/examples')
INTEROP_TAGS := interop

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
TAG := $(shell git describe --tags --exact-match 2>/dev/null || echo "")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE := $(shell date -u +%Y%m%d-%H:%M:%S)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.tag=$(TAG) -X main.commit=$(COMMIT) -X main.buildDate=$(BUILD_DATE)

all: build ## Default target: build the otprobe binary

build: ## Build the otprobe binary into ./bin
	@mkdir -p $(BIN_DIR)
	cd $(CLI_DIR) && go build -ldflags "$(LDFLAGS)" -o "$(CURDIR)/$(BIN_DIR)/otprobe" .

# The self-contained examples: each starts a demo device on loopback and exits.
RUN_EXAMPLES := quickstart identify sweep custom observe

examples: ## Run the self-contained examples (each must exit successfully)
	@for e in $(RUN_EXAMPLES); do \
		echo "Running example $$e"; \
		go run ./examples/$$e >/dev/null || { echo "example $$e failed"; exit 1; }; \
	done

install: ## Install otprobe to /usr/local/bin (may require sudo)
	sudo install -m 0755 $(BIN_DIR)/otprobe /usr/local/bin/otprobe

fmt: ## Format Go code with the gofmt of the Go version in go.mod (what CI uses)
	@echo "Running gofmt (go$(GO_MOD_VERSION))"
	@$(GOFMT_CI) -w .

fmt-check: ## Fail if the go.mod-version gofmt or the local gofmt would change any file
	@echo "Checking formatting (gofmt go$(GO_MOD_VERSION) and local $$(go env GOVERSION))"
	@ci="$$($(GOFMT_CI) -l .)"; loc="$$(gofmt -l .)"; \
	if [ -n "$$ci$$loc" ]; then \
		[ -z "$$ci" ] || { echo "Not formatted for gofmt go$(GO_MOD_VERSION) (CI):"; echo "$$ci"; }; \
		[ -z "$$loc" ] || { echo "Not formatted for the local gofmt:"; echo "$$loc"; }; \
		echo "Run 'make fmt'."; exit 1; \
	fi

lint: ## Run staticcheck
	@echo "Running staticcheck"
	@staticcheck ./...
	@cd $(CLI_DIR) && staticcheck ./...

lint-ci: ## Run golangci-lint
	@echo "Running golangci-lint"
	@golangci-lint run ./...
	@cd $(CLI_DIR) && golangci-lint run ./...

vet: ## Run go vet
	@echo "Running go vet"
	@go vet ./...
	@cd $(CLI_DIR) && go vet ./...

vuln: ## Run govulncheck
	@echo "Running govulncheck"
	@govulncheck ./...
	@cd $(CLI_DIR) && govulncheck ./...

test: ## Run the tests (no interop)
	@echo "Running tests"
	@go test -count=1 $(TEST_PKGS)
	@cd $(CLI_DIR) && go test -count=1 ./...

test-race: ## Run the tests with the race detector
	@echo "Running race tests"
	@go test -count=1 -race $(TEST_PKGS)
	@cd $(CLI_DIR) && go test -count=1 -race ./...

# Minimum library coverage; make coverage (and so make check) fails below it.
COVER_MIN ?= 90
# Per-package floor (TEST-012), checked by coverage-pkg-check. Lowest package
# measured: 92.6 % (protocols/openadr). See TESTING.md.
COVER_PKG_MIN := 90

coverage: ## Run tests with coverage across the library packages (writes coverage.out; fails below COVER_MIN%)
	@echo "Running coverage (minimum $(COVER_MIN)%)"
	@go test -count=1 -race -covermode=atomic -coverpkg=$(COVER_PKGS) -coverprofile=coverage.out $(TEST_PKGS)
	@total=$$(go tool cover -func=coverage.out | awk '/^total:/ {sub("%","",$$3); print $$3}'); \
	echo "total: $$total%"; \
	awk -v t="$$total" -v m="$(COVER_MIN)" 'BEGIN { if (t+0 < m+0) { print "coverage " t "% is below " m "%"; exit 1 } }'

coverage-pkg-check: coverage ## Fail when a package is below COVER_PKG_MIN (reads coverage.out)
	@awk -v m="$(COVER_PKG_MIN)" 'NR > 1 { n[$$1] = $$2; if ($$3 > 0) h[$$1] = 1 } \
	END { for (k in n) { p = k; sub(/\/[^\/]*$$/, "", p); s[p] += n[k]; if (k in h) c[p] += n[k] } \
	for (p in s) { v = 100 * c[p] / s[p]; printf "%s %.1f%%\n", p, v; if (v < m) { printf "  below COVER_PKG_MIN: %s: %.1f%% < %s%%\n", p, v, m; bad = 1 } } exit bad }' coverage.out

cover: coverage ## Open the coverage report in a browser
	@go tool cover -html=coverage.out

bench: ## Run the codec benchmarks
	@go test -count=1 -run='^$$' -bench=. -benchmem ./internal/... ./protocols/...

STRESS ?= 10
stress: ## Run every test STRESS times (default 10) with -race in shuffled order
	@echo "Stress: $(STRESS) shuffled race runs"
	@go test -race -count=$(STRESS) -shuffle=on -timeout=30m $(TEST_PKGS)

# Duration each fuzz target runs. Override with FUZZTIME=... (e.g. FUZZTIME=5m).
FUZZTIME ?= 20s
fuzz: ## Fuzz every parser for FUZZTIME each (default 20s)
	@echo "Fuzzing (FUZZTIME=$(FUZZTIME))"
	@for pkg in $$(go list ./... | grep -E '/protocols/|/internal/(iso|mbap)'); do \
		for fn in $$(go test -list '^Fuzz' $$pkg 2>/dev/null | grep '^Fuzz'); do \
			echo "  $$pkg $$fn"; \
			go test -run='^$$' -fuzz="^$$fn$$" -fuzztime=$(FUZZTIME) -parallel=4 $$pkg || exit 1; \
		done; \
	done

generate: ## Regenerate the CIP catalogue from go-ethernetip
	@go generate ./...

generate-check: ## Fail when the generated CIP catalogue is out of date
	@echo "Checking the generated CIP catalogue"
	@tmp=$$(mktemp); go run ./internal/cmd/gencip -out $$tmp && \
		diff -u protocols/enip/catalog.go $$tmp || { echo "Run 'make generate'."; rm -f $$tmp; exit 1; }; \
		rm -f $$tmp

coverpkg-check: ## Fail when CI's coverpkg (.github/workflows/ci.yml) is not COVER_PKGS
	@grep -qF -- "$(COVER_PKGS)" .github/workflows/ci.yml || { echo "coverpkg in .github/workflows/ci.yml must be: $(COVER_PKGS)"; exit 1; }

coverage-check: coverage ## Alias of coverage, which already fails below COVER_MIN

CROSS_PLATFORMS := linux/amd64 linux/arm64 linux/arm darwin/arm64 windows/amd64

cross: ## Cross-compile without cgo for the supported platforms
	@for p in $(CROSS_PLATFORMS); do \
		echo "Building for $$p"; \
		CGO_ENABLED=0 GOOS=$${p%/*} GOARCH=$${p#*/} go build ./... || exit 1; \
		(cd $(CLI_DIR) && CGO_ENABLED=0 GOOS=$${p%/*} GOARCH=$${p#*/} go build -o /dev/null ./...) || exit 1; \
	done

e2e: ## End-to-end suite: the public engine against scripted servers on loopback TCP
	@go test -count=1 -race ./e2e/...

check: coverpkg-check fmt fmt-check lint lint-ci vet vuln test-race coverage coverage-pkg-check examples ## Run format + lint + vet + vuln + tests

test-interop: ## Run the interop suite against the pinned reference servers (needs Docker)
	@echo "Running interop tests (go-<protocol> reference images)"
	@go test -tags=$(INTEROP_TAGS) -count=1 -timeout=20m ./interop/...

interop: test-interop ## Alias for test-interop

release-notes: ## Print the RELEASE.md section the release workflow will use for VERSION (e.g. VERSION=v0.1.0)
	@test -n "$(VERSION)" || { echo "usage: make release-notes VERSION=vX.Y.Z"; exit 1; }
	@out=$$(awk -v target="## $(VERSION)" '$$0 == target { found=1; next } found && /^---$$/ { exit } found { print }' RELEASE.md); \
	test -n "$$out" || { echo "RELEASE.md has no '## $(VERSION)' section: the release would fall back to a commit log"; exit 1; }; \
	echo "$$out"

clean: ## Remove generated binaries and coverage artifacts
	@rm -rf $(BIN_DIR) coverage.out coverage.html
