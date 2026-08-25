# Local equivalents of what CI runs, so a red build is not how we find out.
# Mirrors whydiff's `make check`.

VERSION := $(shell sed -n 's/^var Version = "\(.*\)"/\1/p' cmd/whatsrisky/main.go)
LDFLAGS := -s -w -X main.Version=$(VERSION)
PLATFORMS := darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 windows/amd64
PREFIX ?= $(HOME)/.local/bin

.PHONY: help check lint test test-all selfscan build build-all install uninstall print-version release-notes live-ai clean

help:
	@grep -E '^[a-z-]+:.*?##' $(MAKEFILE_LIST) | sed 's/:.*##/\t/' | expand -t22

check: lint test selfscan  ## lint + tests + the self-scan gate

lint:  ## gofmt + go vet
	@test -z "$$(gofmt -l cmd internal)" || (echo "gofmt:"; gofmt -l cmd internal; exit 1)
	go vet ./...

test:  ## the test suite, minus the parts that need scanner binaries
	go test ./... -short

test-all:  ## everything, including the integration tests
	go test ./...

# A stub cannot cover the real CLI's behaviour. Opt-in: it spends tokens.
live-ai:  ## run the AI pass against the real claude CLI
	WHATSRISKY_LIVE_AI=1 go test ./internal/runner/ -run Live -v -timeout 15m

build:  ## build the binary into dist/
	go build -ldflags '$(LDFLAGS)' -o dist/whatsrisky ./cmd/whatsrisky
	@./dist/whatsrisky --version

# The development install: build straight onto PATH, so the command is whatever is
# checked out. Re-run it after switching branches - unlike a Python editable
# install, a binary does not follow the source on its own.
install: | $(PREFIX)  ## build and put the binary on PATH (PREFIX=~/.local/bin)
	go build -ldflags '$(LDFLAGS)' -o $(PREFIX)/whatsrisky ./cmd/whatsrisky
	@echo "installed $$($(PREFIX)/whatsrisky --version) to $(PREFIX)/whatsrisky"
	@case ":$$PATH:" in *":$(PREFIX):"*) ;; *) echo "note: $(PREFIX) is not on your PATH" ;; esac

$(PREFIX):
	@mkdir -p $(PREFIX)

uninstall:  ## remove the installed binary
	rm -f $(PREFIX)/whatsrisky

# One binary per platform, which is the reason this is written in Go: the scanners
# it orchestrates are installed with a single curl, and so is this.
build-all:  ## cross-compile every release binary into dist/
	@rm -rf dist && mkdir -p dist
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; \
		name=whatsrisky_$(VERSION)_$${os}_$${arch}; \
		suffix=""; [ "$$os" = "windows" ] && suffix=".exe"; \
		echo "  $$name"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
			go build -trimpath -ldflags '$(LDFLAGS)' -o dist/$$name/whatsrisky$$suffix ./cmd/whatsrisky || exit 1; \
		tar -czf dist/$$name.tar.gz -C dist/$$name whatsrisky$$suffix; \
		rm -rf dist/$$name; \
	done
	@cd dist && shasum -a 256 *.tar.gz > checksums.txt
	@ls -la dist

selfscan: build  ## the gate CI runs: this repository must be clean at HIGH
	rm -rf whatsrisky-reports
	./dist/whatsrisky . --tools semgrep,gitleaks --semgrep-config p/security-audit \
		--format json --no-compare --fail-on high
	rm -rf whatsrisky-reports

print-version:  ## print the version the source declares
	@echo $(VERSION)

release-notes:  ## print the CHANGELOG section for the current version
	@awk '/^## \[$(VERSION)\]/{flag=1; next} /^## \[/{flag=0} flag' CHANGELOG.md

clean:  ## remove build and report artifacts
	rm -rf dist whatsrisky-reports
