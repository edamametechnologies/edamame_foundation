// Built in default CVE detection params db
pub static CVE_DETECTION_PARAMS_DB: &str = r#"{
  "application_storage_patterns": [
    "/library/application support/",
    "/library/containers/",
    "/library/group containers/",
    "/library/keychains/",
    "/library/preferences/",
    "/library/caches/",
    "/library/webkit/",
    "/appdata/roaming/",
    "/appdata/local/",
    "/programdata/",
    "/.config/",
    "/.cache/",
    "/.local/share/",
    "/.local/state/"
  ],
  "benign_temp_artifact_suffixes": [
    ".tmp",
    ".temp",
    ".swp",
    ".swo",
    ".part",
    ".partial",
    ".download",
    ".crdownload",
    ".lock",
    ".log",
    ".txt",
    ".json",
    ".cache",
    ".sqlite",
    ".db",
    ".plist",
    ".yaml",
    ".yml",
    ".toml",
    ".ini"
  ],
  "checks": {
    "credential_harvest": {
      "description": "Multi-category credential access: process has open handles to {count} credential categories ({labels})",
      "reference": "litellm 1.82.8 PyPI supply chain compromise (March 2026)",
      "severity": "CRITICAL"
    },
    "file_system_tampering": {
      "description": "Sensitive file {event_type} detected: {path}",
      "reference": "CVE-2025-30066",
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
    "token_exfiltration": {
      "description": "Anomalous session with credential file access detected",
      "reference": "CVE-2025-52882 / CVE-2026-25253",
      "severity": "HIGH"
    }
  },
  "credential_harvest_min_labels": 3,
  "credential_store_patterns": {
    "linux": [
      "/.local/share/keyrings/",
      "/.gnome2/keyrings/",
      "/.local/share/kwalletd/",
      "/.kde/share/apps/kwallet/"
    ],
    "macos": [
      "/library/keychains/"
    ],
    "windows": [
      "/appdata/local/microsoft/credentials/",
      "/appdata/roaming/microsoft/credentials/",
      "/appdata/local/microsoft/vault/",
      "/appdata/roaming/microsoft/vault/",
      "/programdata/microsoft/vault/"
    ]
  },
  "date": "April 12th 2026",
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
  "packaged_application_contains_patterns": [
    ".app/",
    "/applications/",
    "/program files/",
    "/appdata/local/programs/"
  ],
  "packaged_application_ends_with_patterns": [
    ".app"
  ],
  "packaged_application_starts_with_patterns": [
    "/opt/",
    "/usr/lib/",
    "/snap/",
    "/usr/share/"
  ],
  "signature": "e27cb603271c47fff9dc62ead7e5892e66bbee04e05dbfa449281cb6d1200901",
  "suspicious_parent_path_patterns": [
    "/tmp/",
    "/var/tmp/",
    "\\Temp\\",
    "\\AppData\\Local\\Temp\\"
  ],
  "trusted_credential_helpers": {
    "generic_git": {
      "compact_leaf_names": [
        "gitcredentialmanager",
        "gitcredentialmanagercore",
        "gitcredentialmanagerexe",
        "gitcredentialmanagercoreexe"
      ],
      "compact_names": [
        "gitcredentialmanager",
        "gitcredentialmanagercore",
        "gitcredentialmanagerexe",
        "gitcredentialmanagercoreexe"
      ],
      "exact_paths": [],
      "leaf_trusted_dir_prefixes": [],
      "path_contains": [
        "/git-credential-manager",
        "/git-credential-manager-core"
      ],
      "path_ends_with": [],
      "path_starts_with": []
    },
    "linux": {
      "compact_leaf_names": [
        "kwalletd",
        "kwalletd5",
        "kwalletd6",
        "ksecretsservice",
        "kwalletmanager",
        "kwalletmanager5",
        "kwalletmanager6"
      ],
      "compact_names": [
        "gitcredentiallibsecret",
        "secrettool",
        "gnomekeyringdaemon",
        "kwalletd",
        "kwalletd5",
        "kwalletd6",
        "ksecretsservice",
        "kwalletmanager",
        "kwalletmanager5",
        "kwalletmanager6"
      ],
      "exact_paths": [],
      "leaf_trusted_dir_prefixes": [
        "/usr/bin/",
        "/usr/lib/",
        "/usr/libexec/"
      ],
      "path_contains": [
        "/git-core/git-credential-libsecret",
        "/gnome-keyring/gnome-keyring-daemon"
      ],
      "path_ends_with": [
        "/git-credential-libsecret",
        "/secret-tool",
        "/gnome-keyring-daemon"
      ],
      "path_starts_with": []
    },
    "macos": {
      "compact_leaf_names": [
        "secd",
        "securityd",
        "assistantd",
        "commcenter",
        "networkserviceproxy"
      ],
      "compact_names": [
        "security",
        "gitcredentialosxkeychain",
        "keychainaccess",
        "secd",
        "securityd"
      ],
      "exact_paths": [
        "/usr/bin/security"
      ],
      "leaf_trusted_dir_prefixes": [
        "/system/library/",
        "/usr/libexec/"
      ],
      "path_contains": [
        "/git-core/git-credential-osxkeychain",
        "/keychain access.app/"
      ],
      "path_ends_with": [
        "/git-credential-osxkeychain"
      ],
      "path_starts_with": []
    },
    "windows": {
      "compact_leaf_names": [
        "cmdkeyexe",
        "vaultcmdexe",
        "credentialuibrokerexe",
        "lsassexe"
      ],
      "compact_names": [
        "cmdkey",
        "cmdkeyexe",
        "vaultcmd",
        "vaultcmdexe",
        "credentialuibroker",
        "credentialuibrokerexe",
        "lsass",
        "lsassexe"
      ],
      "exact_paths": [],
      "leaf_trusted_dir_prefixes": [
        "/windows/system32/",
        "/windows/syswow64/"
      ],
      "path_contains": [],
      "path_ends_with": [],
      "path_starts_with": []
    }
  }
}"#;
