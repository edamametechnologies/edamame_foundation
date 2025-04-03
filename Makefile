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


windows_test:
	mkdir -p ./target/debug
	wget https://github.com/edamametechnologies/edamame_posture_cli/raw/refs/heads/main/windows/Packet.dll -O ./target/debug/Packet.dll
	chmod +x ./target/debug/Packet.dll
	wget https://github.com/edamametechnologies/edamame_posture_cli/raw/refs/heads/main/windows/wpcap.dll -O ./target/debug/wpcap.dll
	chmod +x ./target/debug/wpcap.dll
	# No capture tests on Windows for now
	cargo test -- --nocapture

unix_test:
	cargo test -- --nocapture
	# Use sudo for capture tests
	sudo -E cargo test --features packetcapture,asyncpacketcapture -- --nocapture
	sudo -E cargo test --features packetcapture -- --nocapture

linux_test: unix_test

macos_test: unix_test

mobile_test:
	cargo test -- --nocapture

ios_test: mobile_test

android_test: mobile_test


