.PHONY: all build test clean lint install docker-build completions test-rust test-go

TARGET_DIR := ./target
PREFIX ?= /usr/local/bin
SHARE_PREFIX ?= /usr/local/share

all: build test

build: build-rust build-go completions

build-rust:
	@echo "==> Building Bug Killer Rust Core..."
	cargo build --release
	@mkdir -p $(TARGET_DIR)
	@cp target/release/bug-killer $(TARGET_DIR)/bug-killer
	@ln -sf bug-killer $(TARGET_DIR)/bk
	@echo "==> Building Deep Binary Inspector..."
	cd services/inspector && cargo build --release
	@cp services/inspector/target/release/bug-killer-inspector $(TARGET_DIR)/bug-killer-inspector

completions:
	@echo "==> Generating Shell Completions..."
	@mkdir -p completions
	@$(TARGET_DIR)/bug-killer completion bash > completions/bug-killer.bash
	@$(TARGET_DIR)/bug-killer completion zsh > completions/_bug-killer
	@$(TARGET_DIR)/bug-killer completion fish > completions/bug-killer.fish

build-go:
	@echo "==> Building Go Orchestrator..."
	cd services/orchestrator && go build -o ../../target/bug-killer-orchestrator .
	@echo "==> Building Go Healer..."
	cd services/healer && go build -o ../../target/bug-killer-healer .

test: test-rust test-go test-python

test-rust:
	@echo "==> Running Rust Test Suites..."
	cargo test --workspace
	@echo "==> Running Inspector Test Suites..."
	cd services/inspector && cargo test

test-go:
	@echo "==> Running Go Test Suites..."
	cd services/orchestrator && go test -v ./...
	cd services/healer && go test -v ./...

test-python:
	@echo "==> Running Python CVE MCP Test Suites..."
	@if command -v pytest >/dev/null 2>&1; then cd services/cve-mcp-server && pytest -m "not online" -v; elif command -v uv >/dev/null 2>&1; then cd services/cve-mcp-server && uv run --extra test pytest -m "not online" -v; else echo "pytest not found; skipping python tests"; fi

lint:
	@echo "==> Running Linters..."
	cargo clippy --workspace --all-targets -- -D warnings
	cd services/inspector && cargo clippy --all-targets -- -D warnings
	cd services/orchestrator && go vet ./...
	cd services/healer && go vet ./...
	@if command -v ruff >/dev/null 2>&1; then cd services/cve-mcp-server && ruff check . && ruff format --check .; elif command -v uv >/dev/null 2>&1; then cd services/cve-mcp-server && uv run --with ruff ruff check . && uv run --with ruff ruff format --check .; fi
	@if command -v lat >/dev/null 2>&1; then echo "==> Running Lat.md Check..."; lat check; fi

install: build
	@echo "==> Installing bug-killer to $(PREFIX)..."
	install -m 755 $(TARGET_DIR)/bug-killer $(PREFIX)/bug-killer
	install -m 755 $(TARGET_DIR)/bug-killer-orchestrator $(PREFIX)/bug-killer-orchestrator
	install -m 755 $(TARGET_DIR)/bug-killer-inspector $(PREFIX)/bug-killer-inspector
	install -m 755 $(TARGET_DIR)/bug-killer-healer $(PREFIX)/bug-killer-healer
	install -m 755 scripts/bk-shell.sh $(PREFIX)/bk-shell
	install -m 755 scripts/bk-triage.sh $(PREFIX)/bk-triage
	install -m 755 scripts/bk-watch.sh $(PREFIX)/bk-watch
	ln -sf $(PREFIX)/bug-killer $(PREFIX)/bk
	@echo "==> Installing shell completions..."
	@mkdir -p $(DESTDIR)$(SHARE_PREFIX)/bash-completion/completions $(DESTDIR)$(SHARE_PREFIX)/zsh/site-functions $(DESTDIR)$(SHARE_PREFIX)/fish/vendor_completions.d 2>/dev/null || true
	-install -m 644 completions/bug-killer.bash $(DESTDIR)$(SHARE_PREFIX)/bash-completion/completions/bug-killer 2>/dev/null || true
	-install -m 644 completions/_bug-killer $(DESTDIR)$(SHARE_PREFIX)/zsh/site-functions/_bug-killer 2>/dev/null || true
	-install -m 644 completions/bug-killer.fish $(DESTDIR)$(SHARE_PREFIX)/fish/vendor_completions.d/bug-killer.fish 2>/dev/null || true
	@echo "==> Installation complete!"

clean:
	@echo "==> Cleaning build artifacts..."
	cargo clean
	cd services/inspector && cargo clean
	rm -rf $(TARGET_DIR) coverage-ledger.json findings.json test-ledger.json test-findings.json
