# unpack Makefile: build, test and lint the library and CLI.
# Uses only constructs common to GNU make and BSD make.

CARGO = env -u MAKEFLAGS -u MAKELEVEL -u MFLAGS cargo

.PHONY: all build release test lint doc fix fmt clean help

all: build

help: ## Show this help
	@echo "Targets: build release test lint doc fix fmt clean"

build:
	$(CARGO) build

release:
	$(CARGO) build --release

test:
	$(CARGO) test

fmt:
	$(CARGO) fmt --all

# Auto-fix what clippy and rustfmt can fix on their own; mirrors `lint`.
fix:
	$(CARGO) clippy --fix --all-targets --all-features --allow-dirty --allow-staged
	$(CARGO) fmt --all

# The library and CLI with every feature, then the library alone as a
# dependent crate builds it.
lint: doc
	$(CARGO) fmt --all --check
	$(CARGO) clippy --all-targets --all-features -- -D warnings
	$(CARGO) clippy --lib --no-default-features -- -D warnings

doc:
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc --no-deps
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc --no-deps --document-private-items

clean:
	$(CARGO) clean
