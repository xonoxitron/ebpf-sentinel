.PHONY: all build ebpf userspace test clean run fmt clippy

all: build

build: userspace

ebpf userspace:
	cargo build --release -p sentinel --bin sentinel

test:
	cargo test --release -p sentinel --lib
	cargo test --release -p sentinel-common

integration:
	cargo test --release -p sentinel --test integration
	sudo -E cargo test --release -p sentinel --test integration -- --ignored --test-threads=1

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
