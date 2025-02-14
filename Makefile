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
	# DLLs are required for tests to run on Windows
	if [ "$(shell uname | cut -c1-10)" = "MINGW64_NT" ]; then \
		mkdir -p ./target/release; \
		wget https://github.com/edamametechnologies/edamame_posture_cli/raw/refs/heads/main/windows/Packet.dll -O ./target/release/Packet.dll; \
		chmod +x ./target/release/Packet.dll; \
		wget https://github.com/edamametechnologies/edamame_posture_cli/raw/refs/heads/main/windows/wpcap.dll -O ./target/release/wpcap.dll; \
		chmod +x ./target/release/wpcap.dll; \
	fi
	cargo test --features packetcapture,asyncpacketcapture -- --nocapture
	cargo test --features packetcapture -- --nocapture
	cargo test -- --nocapture
