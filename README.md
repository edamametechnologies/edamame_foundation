# EDAMAME Foundation Library

The `edamame_foundation` library provides the core functionality for the EDAMAME Security platform. It serves as the foundation for both the main application and its privileged helper component, enabling secure communication between them and implementing the security posture assessment engine.

The library integrates with official threat models from the [EDAMAME Threat Models Repository](https://github.com/edamametechnologies/threatmodels) to compute security scores and provide remediation recommendations.

## Architecture Overview

This library follows a modular design, organized into several functional categories:

### Core System Components

- **lib.rs** - Primary library entry point that exports all modules
- **admin.rs** - Platform-specific admin privilege detection
- **version.rs** - Version management and comparison utilities
- **runtime.rs** - Async runtime management and task handling
- **logger.rs** - Structured logging facilities with memory buffering
- **rwlock.rs** - Custom read-write locks with deadlock detection

### Helper Architecture (Privileged Operations)

- **helper_proto.rs** - Protocol Buffer definitions for IPC
- **helper_rx.rs** - Server-side helper implementation (receiving)
- **helper_tx.rs** - Client-side helper interface (transmitting)
- **helper_rx_utility.rs** - Helper utility functions (network interfaces, capture)
- **helper_state.rs** - Helper activation state management

### Network Analysis (LANScan)

#### Core Network Components
- **lanscan_interface.rs** - Network interface discovery and management
- **lanscan_ip.rs** - IP address utilities and LAN detection
- **lanscan_arp.rs** - Address Resolution Protocol operations
- **lanscan_broadcast.rs** - Network broadcast scanning
- **lanscan_neighbors.rs** - Neighbor discovery across platforms
- **lanscan_sessions.rs** - Network connection session tracking
- **lanscan_resolver.rs** - DNS resolution services

#### Packet Capture and Analysis
- **lanscan_capture.rs** - Network traffic capture engine
- **lanscan_packets.rs** - Packet parsing and classification
- **lanscan_dns.rs** - DNS packet analysis
- **lanscan_l7.rs** - Layer 7 (application) protocol analysis
- **lanscan_mdns.rs** - Multicast DNS service discovery

#### Device Intelligence
- **lanscan_device_info.rs** - Device profile data structure
- **lanscan_oui.rs** - MAC address vendor identification
- **lanscan_profiles.rs** - Device type identification engine
- **lanscan_profiles_db.rs** - Device profile database

#### Vulnerability Management
- **lanscan_port_info.rs** - Port information structures
- **lanscan_port_vulns.rs** - Port vulnerability assessment
- **lanscan_port_vulns_db.rs** - Port vulnerability database
- **lanscan_vendor_vulns.rs** - Vendor vulnerability tracking
- **lanscan_vulnerability_info.rs** - Vulnerability data structures
- **lanscan_asn.rs** - Autonomous System Number lookups
- **asn_db.rs** - ASN database operations

### Security Assessment Engine

#### Threat Management
- **threat.rs** - Core threat model data structures
- **threat_factory.rs** - Threat model instantiation
- **threat_metrics_macos.rs** - macOS-specific threat definitions
- **threat_metrics_windows.rs** - Windows-specific threat definitions
- **threat_metrics_linux.rs** - Linux-specific threat definitions
- **threat_metrics_ios.rs** - iOS-specific threat definitions
- **threat_metrics_android.rs** - Android-specific threat definitions

#### Scoring and Policy Enforcement
- **score.rs** - Security score calculation engine
- **order.rs** - Remediation order data structures
- **order_type.rs** - Order type definitions
- **history.rs** - Order execution history tracking
- **pwned_breach.rs** - Password breach detection

#### Network Policy
- **whitelists.rs** - Network connection whitelist implementation
- **whitelists_db.rs** - Whitelist database and inheritance

### Cloud Integration

- **cloud_model.rs** - Base trait for cloud-synchronized models
- **backend.rs** - Backend service interface
- **health.rs** - Health metrics tracking
- **runner_cli.rs** - CLI command execution engine

## Key Features

1. **Cross-Platform Support**: Works on macOS, Windows, Linux, iOS, and Android
2. **Privilege Separation**: Secure architecture with minimal privileged operations
3. **Network Visibility**: Advanced network monitoring with minimal performance impact
4. **Threat Detection**: Comprehensive security assessment based on industry standards
5. **Privacy Focus**: All analysis happens locally with privacy-preserving design
6. **Real-time Updates**: Cloud-synchronized threat models and vulnerability databases

## Usage

This library is primarily used by the EDAMAME Security application and is not intended for direct consumption. For end-user functionality, refer to the [EDAMAME Posture CLI](https://github.com/edamametechnologies/edamame_posture_cli) or the EDAMAME Security desktop application.

## EDAMAME Ecosystem

The `edamame_foundation` library serves as a critical component in the broader EDAMAME security ecosystem:

- **EDAMAME Core**: The core implementation used by all EDAMAME components (closed source)
- **EDAMAME Security**: Desktop security application with full UI and enhanced capabilities (closed source)
- **[EDAMAME Foundation](https://github.com/edamametechnologies/edamame_foundation)**: Foundation library providing security assessment functionality
- **[EDAMAME Posture](https://github.com/edamametechnologies/edamame_posture_cli)**: CLI tool for security posture assessment and remediation
- **[EDAMAME Helper](https://github.com/edamametechnologies/edamame_helper)**: Helper application for executing privileged security checks
- **[EDAMAME CLI](https://github.com/edamametechnologies/edamame_cli)**: Interface to EDAMAME core services
- **[GitHub Integration](https://github.com/edamametechnologies/edamame_posture_action)**: GitHub Action for integrating posture checks in CI/CD
- **[GitLab Integration](https://gitlab.com/edamametechnologies/edamame_posture_action)**: Similar integration for GitLab CI/CD workflows
- **[Threat Models](https://github.com/edamametechnologies/threatmodels)**: Threat model definitions used throughout the system
- **[EDAMAME Hub](https://hub.edamame.tech)**: Web portal for centralized management when using these components in team environments

## Author

EDAMAME Technologies