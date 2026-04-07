// Built in default CVE detection params db
pub static CVE_DETECTION_PARAMS_DB: &str = r#"{
  "checks": {
    "credential_harvest": {
      "description": "Multi-category credential access: process has open handles to {count} credential categories ({labels})",
      "reference": "litellm 1.82.8 PyPI supply chain compromise (March 2026)",
      "severity": "CRITICAL"
    },
    "sandbox_exploitation": {
      "description": "Suspicious parent process path: {path}",
      "reference": "CVE-2026-24763",
      "severity": "HIGH"
    },
    "skill_supply_chain": {
      "description": "C2 traffic with credential file access detected",
      "reference": "VirusTotal Code Insight",
      "severity": "HIGH"
    },
    "file_system_tampering": {
      "description": "Sensitive file {event_type} detected: {path}",
      "reference": "CVE-2025-30066",
      "severity": "CRITICAL"
    },
    "token_exfiltration": {
      "description": "Anomalous session with credential file access detected",
      "reference": "CVE-2025-52882 / CVE-2026-25253",
      "severity": "HIGH"
    }
  },
  "credential_harvest_min_labels": 3,
  "date": "April 4th 2026",
  "fim_hash_size_threshold": 10485760,
  "fim_temp_executable_patterns": [
    "/tmp/",
    "/var/tmp/",
    "\\Temp\\",
    "\\AppData\\Local\\Temp\\"
  ],
  "generic_application_tokens": [
    "app",
    "apps",
    "bin",
    "browser",
    "cache",
    "caches",
    "contents",
    "framework",
    "helper",
    "library",
    "local",
    "macos",
    "preferences",
    "process",
    "program",
    "programfiles",
    "renderer",
    "resources",
    "service",
    "services",
    "share",
    "storage",
    "support",
    "temp",
    "tmp",
    "user",
    "users",
    "utility"
  ],
  "generic_reuse_tokens": [
    "app",
    "apps",
    "application",
    "applications",
    "bin",
    "cache",
    "contents",
    "current",
    "default",
    "frameworks",
    "helper",
    "home",
    "lib",
    "library",
    "local",
    "macos",
    "opt",
    "private",
    "profile",
    "profiles",
    "program",
    "programs",
    "python",
    "resources",
    "roaming",
    "runtime",
    "script",
    "scripts",
    "share",
    "support",
    "system",
    "tmp",
    "users",
    "usr",
    "var",
    "versions"
  ],
  "init_process_names": [
    "launchd",
    "systemd",
    "init",
    "svchost.exe"
  ],
  "signature": "f2f91e5a1258d21dd3371b87619709a9cc21bf80a824da77982c6eb776eb1403",
  "suspicious_parent_path_patterns": [
    "/tmp/",
    "/../",
    "/var/tmp/",
    "\\Temp\\",
    "\\..\\",
    "\\AppData\\Local\\Temp\\"
  ]
}"#;
