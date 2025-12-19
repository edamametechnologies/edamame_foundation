# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

EDAMAME Foundation provides core functionality for the EDAMAME security platform. It implements the helper protocol for privileged operations, the threat assessment engine, and platform-specific security metrics.

Part of the EDAMAME ecosystem - see `../edamame_core/CLAUDE.md` for full ecosystem documentation.

## Build Commands

```bash
# Standard build
cargo build

# With packet capture
cargo build --features packetcapture

# Format check
cargo fmt --all -- --check

# Cross-compilation (Android)
cargo install cross
cross build --target x86_64-linux-android
```

## Testing

```bash
# With packet capture feature
cargo test --features packetcapture -- --nocapture

# Requires environment variables for backend connectivity
# See Cross.toml for full list of EDAMAME_* variables
```

## Architecture

### Helper Protocol (IPC with privileged daemon)
- `helper_proto.rs` - Protocol Buffer definitions
- `helper_rx.rs` - Server-side (helper) implementation
- `helper_tx.rs` - Client-side interface
- `helper_rx_utility.rs` - Utility functions for helper
- `helper_state.rs` - Helper activation state

### Threat Assessment Engine
- `threat.rs` - Core threat model data structures
- `threat_factory.rs` - Threat model instantiation
- `threat_metrics_macos.rs` - macOS-specific checks
- `threat_metrics_windows.rs` - Windows-specific checks
- `threat_metrics_linux.rs` - Linux-specific checks
- `threat_metrics_ios.rs` - iOS-specific checks
- `threat_metrics_android.rs` - Android-specific checks

### Security & Scoring
- `score.rs` - Security score calculation
- `order.rs`, `order_type.rs` - Remediation order management
- `history.rs` - Order execution tracking
- `pwned.rs` - Password breach detection

### Network (Flodbadd Integration)
- `flodbadd_capture.rs` - Network traffic capture
- `flodbadd_packets.rs` - Packet parsing
- `flodbadd_dns.rs` - DNS analysis
- `flodbadd_l7.rs` - Layer 7 protocol analysis
- `flodbadd_mdns.rs` - Multicast DNS discovery
- `flodbadd_device_info.rs` - Device profiles

### Core Utilities
- `admin.rs` - Platform-specific admin privilege detection
- `version.rs` - Version management
- `runtime.rs` - Async runtime management
- `logger.rs` - Structured logging with memory buffering
- `rwlock.rs` - Read-write locks with deadlock detection
- `backend.rs` - Backend service interface

## Protocol Buffers

gRPC definitions in `proto/edamame.proto` for helper IPC.

## Dependencies

- `edamame_backend`, `edamame_models`, `flodbadd`, `undeadlock` (via Git)
- `tonic` + `prost` (gRPC)
- `tokio` (async runtime)
- `sentry` (error tracking)

## Local Development

Use `../edamame_app/flip.sh local` to switch to local path dependencies.
