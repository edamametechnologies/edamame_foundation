.PHONY: upgrade unused_dependencies format clean test ios android ebpf_setup

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
	cargo build --target=aarch64-apple-ios

android:
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
	# Use sudo for capture tests - on Linux need to pass cargo path
	$(shell which sudo) -E $(shell which cargo) test --features packetcapture,asyncpacketcapture -- --nocapture --test-threads=1
	$(shell which sudo) -E $(shell which cargo) test --features packetcapture -- --nocapture --test-threads=1

# Setup the environment for eBPF testing
ebpf_setup:
	@echo "Setting up eBPF environment..."
	-sudo mount -t debugfs none /sys/kernel/debug 2>/dev/null || true
	-sudo mount -t bpf none /sys/fs/bpf 2>/dev/null || true
	-sudo sysctl -w kernel.perf_event_paranoid=-1 || true
	-sudo sysctl -w kernel.unprivileged_bpf_disabled=0 || true
	-sudo sysctl -w net.core.bpf_jit_enable=1 || true

linux_test_ebpf: ebpf_setup
	@echo "Running eBPF tests with configured environment..."
	@echo "Current kernel: $$(uname -r)"
	@echo "Debug filesystem: $$(mount | grep debugfs || echo 'Not mounted')"
	@echo "BPF filesystem: $$(mount | grep bpf || echo 'Not mounted')"
	@echo "perf_event_paranoid = $$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo 'Not available')"
	@echo "unprivileged_bpf_disabled = $$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo 'Not available')"
	$(shell which sudo) -E $(shell which cargo) test --features packetcapture,asyncpacketcapture,ebpf -- --nocapture --test-threads=1

linux_test: unix_test ebpf_setup linux_test_ebpf

linux_test_no_ebpf: unix_test

macos_test: unix_test

ios_test: ios

android_test: android

# -----------------------------------------------------------------------------
# macOS → Linux test helper (runs full Linux test-suite inside Docker)
# -----------------------------------------------------------------------------

# Image name to use/build
LINUX_TEST_IMAGE ?= edamame_linux_test

.PHONY: docker_build_linux_test linux_test_macos

# Build the test image (only needs to run when the Dockerfile changes)
docker_build_linux_test:
	docker build -t $(LINUX_TEST_IMAGE) -f Dockerfile.linux-test .

# Run the full Linux test-suite inside the container, mounting the current
# workspace so that the code being edited on macOS is tested.
#   $ make linux_test_macos
linux_test_macos: docker_build_linux_test
	@echo "NOTE: Docker Desktop on macOS has limited eBPF support due to the LinuxKit kernel."
	@echo "      eBPF tests may be skipped due to perf_event_open failures."
	@echo "      For full eBPF testing, use a native Linux environment or VM."
	@echo ""
	docker run --rm -i \
		--privileged \
		--cap-add=SYS_ADMIN \
		--cap-add=SYS_PTRACE \
		--security-opt seccomp=unconfined \
		-v $(CURDIR):/workspace \
		-v /sys/kernel/debug:/sys/kernel/debug \
		-v /sys/fs/bpf:/sys/fs/bpf \
		-w /workspace \
		$(LINUX_TEST_IMAGE) make linux_test

