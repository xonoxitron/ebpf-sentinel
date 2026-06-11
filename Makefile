.PHONY: all build ebpf userspace test clean run fmt clippy

all: build

build: userspace

ebpf userspace:
	cargo build --release -p sentinel --bin sentinel

test:
	cargo test --release -p sentinel --lib
	cargo test --release -p sentinel-common

integration:
	cargo test --release -p sentinel --test integration --no-run
	cargo test --release -p sentinel --test integration
	sudo sysctl -w kernel.perf_event_paranoid=1 2>/dev/null || true
	sudo $$(find target/release/deps -maxdepth 1 -type f -name 'integration-*' ! -name '*.d' -executable | head -1) \
		ebpf_probe_loader_attaches --ignored --exact --test-threads=1 --nocapture

clean:
	cargo clean

fmt:
	cargo fmt --all

clippy:
	cargo clippy --all-targets -- -D warnings

run:
	sudo -E ./target/release/sentinel --config config/sentinel.yaml

ingest:
	./target/release/grpc-ingest
