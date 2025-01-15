.PHONY: upgrade unused_dependencies format clean test ios android

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

ios:
	# To test building for iOS
	cargo build --target=aarch64-apple-ios

android:
	# To test building for Android
	cross build --release --target x86_64-linux-android

test:
	cargo test
	cargo test --features packetcapture
	cargo test --features packetcapture,asyncpacketcapture
