.PHONY: build test release cross-linux-arm cross-linux-arm64 cross-windows cross-mips all

build:
	cargo build

test:
	cargo test

release:
	cargo build --release

# Cross-compilation targets (requires cross: cargo install cross)
cross-linux-arm:
	cross build --release --target armv7-unknown-linux-musleabihf

cross-linux-arm64:
	cross build --release --target aarch64-unknown-linux-musl

cross-windows:
	cross build --release --target x86_64-pc-windows-gnu

cross-mips:
	cross build --release --target mips-unknown-linux-musl

all: release cross-linux-arm cross-linux-arm64 cross-windows cross-mips
