.PHONY: upgrade unused_dependencies format clean test check

upgrade:
	rustup update
	cargo install -f cargo-upgrades
	cargo upgrades
	cargo update

unused_dependencies:
	cargo +nightly udeps

format:
	cargo fmt

clean:
	cargo clean
	rm -rf ./build/
	rm -rf ./target/

check:
	cargo hack check --all-features --all-targets

test:
	cargo test -- --nocapture
