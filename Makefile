# Local equivalents of what CI runs, so a red build is not how we find out.
# Mirrors whydiff's `make check`.

PY ?= python3

.PHONY: help check lint test test-all selfscan check-ci clean

help:
	@grep -E '^[a-z-]+:.*?##' $(MAKEFILE_LIST) | sed 's/:.*##/\t/' | expand -t22

check: lint test selfscan  ## lint + unit tests + the self-scan gate

lint:  ## pyflakes over the package and the tests
	$(PY) -m pyflakes whatsrisky tests

test:  ## unit tests only (no scanner binaries needed)
	$(PY) -m pytest tests -q -m "not integration"

test-all:  ## unit + integration (needs semgrep, trivy, gitleaks)
	$(PY) -m pytest tests -q

selfscan:  ## the gate CI runs: this repository must be clean at HIGH
	rm -rf whatsrisky-reports
	whatsrisky . --tools semgrep,gitleaks --semgrep-config p/security-audit \
		--format json --no-compare --fail-on high
	rm -rf whatsrisky-reports

# The CI failures so far were both about the runner's preconditions rather than
# the commands: a uv-managed interpreter, and a .venv that setup-uv had already
# created. This target reproduces both in a clean export of HEAD.
check-ci:  ## run the CI job steps against a clean export, with the runner's preconditions
	@set -e; \
	work=$$(mktemp -d); \
	git archive HEAD | tar -x -C $$work; \
	cd $$work; \
	uv venv --python 3.12 -q; \
	export VIRTUAL_ENV=$$work/.venv UV_PYTHON=3.12; \
	echo "-- create the environment (a .venv already exists, as on the runner)"; \
	uv venv --python 3.12 --allow-existing -q; \
	uv pip install -q -e ".[dev]"; \
	echo "-- lint"; uv run $(PY) -m pyflakes whatsrisky tests; \
	echo "-- unit tests"; uv run $(PY) -m pytest tests -q -m "not integration"; \
	rm -rf $$work; \
	echo "-- ok: the unit job would pass"

clean:  ## remove build and report artifacts
	rm -rf whatsrisky-reports .pytest_cache dist build *.egg-info
