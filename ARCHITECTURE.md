# EDAMAME Foundation Architecture

Core library providing the helper protocol, threat assessment engine, and platform-specific security metrics.

## Overview

EDAMAME Foundation serves as the foundation for both the main application and its privileged helper component, enabling secure communication between them and implementing the security posture assessment engine.

## Module Structure

```
src/
├── lib.rs                    # Library entry point
│
│ # Core System
├── admin.rs                  # Platform-specific admin detection
├── version.rs                # Version management
├── runtime.rs                # Async runtime management
├── logger.rs                 # Structured logging with memory buffer
├── rwlock.rs                 # RwLock with deadlock detection
│
│ # Helper Protocol (gRPC IPC)
├── helper_proto.rs           # Protocol Buffer definitions
├── helper_rx.rs              # Server-side (helper) implementation
├── helper_tx.rs              # Client-side interface
├── helper_rx_utility.rs      # Helper utility functions
├── helper_state.rs           # Activation state management
│
│ # Threat Assessment
├── threat.rs                 # Core threat model structures
├── threat_factory.rs         # Threat model instantiation
├── threat_metrics_macos.rs   # macOS security checks
├── threat_metrics_windows.rs # Windows security checks
├── threat_metrics_linux.rs   # Linux security checks
├── threat_metrics_ios.rs     # iOS security checks
├── threat_metrics_android.rs # Android security checks
│
│ # Scoring & Policy
├── score.rs                  # Security score calculation
├── order.rs                  # Remediation order structures
├── order_type.rs             # Order type definitions
├── history.rs                # Order execution tracking
├── pwned.rs                  # Password breach detection
│
│ # Network (Flodbadd Integration)
├── flodbadd_*.rs             # Re-exports from flodbadd crate
│
│ # Cloud Integration
├── backend.rs                # Backend service interface
├── health.rs                 # Health metrics
└── runner_cli.rs             # CLI command execution
```

## Helper Protocol

gRPC-based IPC between main app and privileged helper daemon:

```protobuf
message HelperRequest {
  required string ordertype = 1;     // "metricorder" or "utilityorder"
  required string subordertype = 2;  // Command name
  required string arg1 = 3;
  required string arg2 = 4;
  required string signature = 5;     // Threat model signature
  required string version = 6;
}

service EDAMAMEHelper {
  rpc Execute(HelperRequest) returns (HelperResponse);
}
```

### Order Types

**Metric Orders** (security operations):
- `capture` - Detect current threat status
- `remediate` - Apply security fix
- `rollback` - Undo security fix

**Utility Orders** (system operations):
- `helper_check` - Verify helper running
- `start_capture` / `stop_capture` - Packet capture control
- `get_sessions` - Retrieve network sessions
- `set_whitelist` / `set_blacklist` - Network filtering
- `broadcast_ping` - Network discovery
- `arp_resolve` / `mdns_resolve` - Address resolution

## Threat Model System

Hierarchical JSON schema with platform-specific implementations:

```rust
ThreatMetricJSON {
    name: String,           // "response to ping enabled"
    metrictype: String,     // "bool", "count", "percentage"
    dimension: String,      // "network", "credentials", etc.
    severity: i32,          // 1-10 weight
    tags: Vec<String>,      // ["PCI-DSS", "HIPAA"]
    implementation: ThreatMetricImplementationJSON {
        system: String,     // "macOS", "Windows", "Linux"
        class: String,      // "cli", "internal", "installer"
        elevation: String,  // "user", "admin", "system"
        target: String,     // Command to execute
    },
    remediation: ThreatMetricImplementationJSON,
    rollback: ThreatMetricImplementationJSON,
}
```

## Scoring Algorithm

```
For each threat metric:
  dimension = metric.dimension  // e.g., "network"
  severity = metric.severity

  dim[dimension].max += severity
  if metric.status == Inactive:  // Threat mitigated
    dim[dimension].current += severity

Per-dimension score = (current / max) * 100
Overall = weighted average of all dimensions
Stars = overall * 5 / 100  // 0-5 scale
```

## Communication Flow

```
┌─────────────┐      gRPC/mTLS       ┌─────────────────┐
│  EDAMAME    │────────────────────► │  EDAMAME        │
│  App/Core   │                      │  Helper         │
│             │◄────────────────────│  (privileged)   │
└─────────────┘                      └─────────────────┘
      │                                      │
      │ ThreatMetricJSON                     │ Execute commands
      ▼                                      ▼
┌─────────────┐                      ┌─────────────────┐
│ Threat      │                      │ System          │
│ Models Repo │                      │ (root access)   │
└─────────────┘                      └─────────────────┘
```

## Dependencies

- `edamame_backend` - Backend data structures
- `edamame_models` - Threat model definitions
- `flodbadd` - Network capture (optional)
- `undeadlock` - Deadlock detection
- `tonic` + `prost` - gRPC
- `tokio` - Async runtime
- `sentry` - Error tracking

## Related Documentation

- [README.md](README.md) - Library overview and ecosystem
- [proto/edamame.proto](proto/edamame.proto) - gRPC protocol definitions
