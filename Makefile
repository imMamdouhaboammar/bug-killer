.PHONY: all build test clean lint install docker-build completions test-rust test-go

TARGET_DIR := ./target
PREFIX ?= /usr/local/bin

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

test: test-rust test-go

test-rust:
	@echo "==> Running Rust Test Suites..."
	cargo test --workspace
	@echo "==> Running Inspector Test Suites..."
	cd services/inspector && cargo test

test-go:
	@echo "==> Running Go Test Suites..."
	cd services/orchestrator && go test -v ./...
	cd services/healer && go test -v ./...

lint:
	@echo "==> Running Linters..."
	cargo clippy --workspace --all-targets -- -D warnings
	cd services/inspector && cargo clippy --all-targets -- -D warnings
	cd services/orchestrator && go vet ./...
	cd services/healer && go vet ./...

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
	@echo "==> Installation complete!"

clean:
	@echo "==> Cleaning build artifacts..."
	cargo clean
	cd services/inspector && cargo clean
	rm -rf $(TARGET_DIR) coverage-ledger.json findings.json test-ledger.json test-findings.json
