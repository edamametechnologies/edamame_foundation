//! P3 publisher attestation -- verified code-signing provenance for
//! process binaries.
//!
//! This module computes the structural fact that the detector's
//! name-based allowlists (`trusted_credential_helpers`,
//! `known_system_daemon_credential_maintenance_hints`,
//! `os_content_indexer_processes`, ...) have been proxying: *is this
//! binary signed by the platform publisher AND installed under a
//! canonical OS path?* An impostor can satisfy a name or path pattern;
//! it cannot satisfy a signature verification.
//!
//! Current scope: macOS implementation via `codesign` with an
//! `anchor apple` requirement (OS binaries pass; Developer ID /
//! ad-hoc / unsigned binaries fail). Windows (Authenticode) and Linux
//! (dpkg/rpm ownership) are not implemented yet; on those platforms the verdict is
//! `None` (unmeasured) -- callers MUST NOT treat `None` as either a
//! positive or a negative, per the no-permissive-`#[cfg]`-fallback
//! rule.
//!
//! Verification shells out to the platform tool, so results are cached
//! keyed by `(path, mtime, size)`; binaries change rarely and the
//! enrichment tick re-queries the same handful of paths every cycle.

use lazy_static::lazy_static;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::UNIX_EPOCH;

/// Signing/provenance verdict for one binary path.
#[derive(Debug, Clone, PartialEq)]
pub struct BinaryAttestation {
    /// Binary lives under a canonical OS install path (`/System/`,
    /// `/usr/` excluding `/usr/local/`, `/bin/`, `/sbin/`,
    /// `/Library/Apple/`, `C:\Windows\`). Computed on every platform.
    /// Deliberately tight: user-writable prefixes (`/usr/local/`,
    /// `/Applications/`, `/opt/`) are NOT canonical -- the benign
    /// credit must not be satisfiable by an impostor dropped into a
    /// writable prefix.
    pub canonical_path: bool,
    /// `Some(true)` = valid platform-publisher signature verified;
    /// `Some(false)` = verification ran and the binary is NOT
    /// platform-signed (a measured negative); `None` = the check is
    /// unimplemented on this platform or could not run (unmeasured).
    pub platform_signed: Option<bool>,
    /// First signing authority (macOS `Authority=` line), when
    /// available. Reserved for the destination<->publisher affinity
    /// relation.
    pub publisher: Option<String>,
}

const CACHE_MAX_ENTRIES: usize = 4096;

lazy_static! {
    /// path -> (mtime_secs, size, attestation).
    static ref ATTESTATION_CACHE: Mutex<HashMap<String, (u64, u64, BinaryAttestation)>> =
        Mutex::new(HashMap::new());
}

/// Canonical OS install-path predicate (the canonical-path half of the
/// P3 evidence pair). See `BinaryAttestation::canonical_path`.
pub fn is_canonical_os_path(path: &str) -> bool {
    let normalized = path.replace('\\', "/").to_ascii_lowercase();
    if normalized.starts_with("/usr/local/") {
        return false;
    }
    normalized.starts_with("/system/")
        || normalized.starts_with("/usr/")
        || normalized.starts_with("/bin/")
        || normalized.starts_with("/sbin/")
        || normalized.starts_with("/library/apple/")
        || normalized.starts_with("c:/windows/")
}

/// Verify the code-signing provenance of `path`, with caching.
///
/// Never panics; a missing/unreadable binary returns an unmeasured
/// (`platform_signed: None`) verdict.
pub fn attest_binary(path: &str) -> BinaryAttestation {
    let canonical_path = is_canonical_os_path(path);
    let metadata = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(_) => {
            // Binary not readable/present: signature state unmeasured.
            return BinaryAttestation {
                canonical_path,
                platform_signed: None,
                publisher: None,
            };
        }
    };
    let mtime_secs = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let size = metadata.len();

    if let Ok(cache) = ATTESTATION_CACHE.lock() {
        if let Some((cached_mtime, cached_size, attestation)) = cache.get(path) {
            if *cached_mtime == mtime_secs && *cached_size == size {
                return attestation.clone();
            }
        }
    }

    let (platform_signed, publisher) = verify_platform_signature(path);
    let attestation = BinaryAttestation {
        canonical_path,
        platform_signed,
        publisher,
    };
    if let Ok(mut cache) = ATTESTATION_CACHE.lock() {
        if cache.len() >= CACHE_MAX_ENTRIES {
            cache.clear();
        }
        cache.insert(path.to_string(), (mtime_secs, size, attestation.clone()));
    }
    attestation
}

#[cfg(target_os = "macos")]
fn verify_platform_signature(path: &str) -> (Option<bool>, Option<String>) {
    use std::process::Command;
    // `-R=anchor apple` restricts verification to Apple's own signing
    // chain: OS binaries pass, Developer ID / ad-hoc / unsigned
    // binaries fail. A verification failure is a MEASURED negative
    // (`Some(false)`); only a failure to run codesign itself is
    // unmeasured (`None`).
    // NOTE: codesign has no `--quiet`; `.output()` already swallows
    // stdout/stderr, the exit status is the verdict.
    let verify = Command::new("/usr/bin/codesign")
        .args(["--verify", "-R=anchor apple", path])
        .output();
    let signed = match verify {
        Ok(output) => Some(output.status.success()),
        Err(_) => return (None, None),
    };
    let publisher = Command::new("/usr/bin/codesign")
        .args(["--display", "--verbose=2", path])
        .output()
        .ok()
        .and_then(|output| {
            let text = String::from_utf8_lossy(&output.stderr).to_string();
            text.lines()
                .find_map(|line| line.strip_prefix("Authority=").map(str::to_string))
        });
    (signed, publisher)
}

#[cfg(target_os = "windows")]
fn verify_platform_signature(path: &str) -> (Option<bool>, Option<String>) {
    use std::process::Command;
    // Authenticode via PowerShell. `-LiteralPath` avoids wildcard
    // expansion; the single-quoted path escapes embedded quotes by
    // doubling (PowerShell rules). Output is `<Status>|<SignerSubject>`
    // on one line. A failed spawn (PowerShell unavailable/blocked) is
    // unmeasured (`None`); a signature whose Status is anything but
    // `Valid` is a MEASURED negative.
    let escaped = path.replace('\'', "''");
    let script = format!(
        "$s = Get-AuthenticodeSignature -LiteralPath '{escaped}'; \
         Write-Output (\"{{0}}|{{1}}\" -f $s.Status, $s.SignerCertificate.Subject)"
    );
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output();
    let output = match output {
        Ok(output) if output.status.success() => output,
        _ => return (None, None),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let line = text.trim();
    let (status, subject) = line.split_once('|').unwrap_or((line, ""));
    let signed = Some(status.trim().eq_ignore_ascii_case("Valid"));
    let publisher = subject
        .split(',')
        .find_map(|part| part.trim().strip_prefix("CN=").map(str::to_string))
        .filter(|cn| !cn.is_empty());
    (signed, publisher)
}

/// Paths to ask the package manager about, in query order.
///
/// usrmerge: on Debian 12 / Ubuntu 21.04+ (and Fedora long before that)
/// `/bin`, `/sbin` and `/lib` are symlinks into `/usr`, and the package
/// database records ONLY the `/usr` form. `dpkg -S /bin/ls` therefore answers
/// "not owned" for a coreutils binary, which graded every binary reached
/// through a merged prefix as the relocated-impostor class -- a measured
/// negative on exactly the paths most likely to be legitimate. Resolve the
/// link and query both forms.
#[cfg(target_os = "linux")]
fn package_query_paths(path: &str) -> Vec<String> {
    let mut paths = vec![path.to_string()];
    if let Ok(resolved) = std::fs::canonicalize(path) {
        let resolved = resolved.to_string_lossy().to_string();
        if resolved != path {
            paths.push(resolved);
        }
    }
    paths
}

#[cfg(target_os = "linux")]
fn verify_platform_signature(path: &str) -> (Option<bool>, Option<String>) {
    use std::process::Command;
    // Linux analogue of a platform signature: package-manager ownership
    // of the binary path. A canonical-path binary owned by NO package
    // is the relocated-impostor class (locally built tools install to
    // /usr/local, which is deliberately non-canonical, so `make
    // install` artifacts never reach this check). dpkg first, rpm as
    // the fallback; a host with neither manager is unmeasured (`None`).
    let candidates = package_query_paths(path);

    let mut dpkg_present = false;
    for candidate in &candidates {
        match Command::new("dpkg")
            .args(["-S", candidate.as_str()])
            .output()
        {
            Ok(output) => {
                dpkg_present = true;
                if output.status.success() {
                    let text = String::from_utf8_lossy(&output.stdout);
                    let package = text
                        .split(':')
                        .next()
                        .map(|name| name.trim().to_string())
                        .filter(|name| !name.is_empty());
                    return (Some(true), package);
                }
                // dpkg exists and says "not owned" for this spelling of the
                // path: try the next candidate, then rpm below.
            }
            // No dpkg on this host: the remaining candidates would fail the
            // same way, so stop asking it.
            Err(_) => break,
        }
    }

    let mut rpm_present = false;
    for candidate in &candidates {
        match Command::new("rpm")
            .args(["-qf", candidate.as_str()])
            .output()
        {
            Ok(output) => {
                rpm_present = true;
                if output.status.success() {
                    let package = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    return (Some(true), (!package.is_empty()).then_some(package));
                }
            }
            Err(_) => break,
        }
    }

    // A managed host that disclaims ownership is a measured negative; a host
    // with neither package manager asserts nothing.
    if dpkg_present || rpm_present {
        (Some(false), None)
    } else {
        (None, None)
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
fn verify_platform_signature(_path: &str) -> (Option<bool>, Option<String>) {
    // Mobile / other platforms: unmeasured, asserts nothing (the
    // detector does not run enrichment there anyway).
    (None, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_path_rejects_writable_prefixes() {
        assert!(is_canonical_os_path("/usr/bin/security"));
        assert!(is_canonical_os_path(
            "/System/Library/CoreServices/sharingd"
        ));
        assert!(is_canonical_os_path("C:\\Windows\\System32\\svchost.exe"));
        assert!(!is_canonical_os_path("/usr/local/bin/anything"));
        assert!(!is_canonical_os_path(
            "/Applications/Foo.app/Contents/MacOS/foo"
        ));
        assert!(!is_canonical_os_path("/opt/homebrew/bin/bash"));
        assert!(!is_canonical_os_path("/tmp/usr/bin/ls"));
    }

    #[test]
    fn missing_binary_is_unmeasured() {
        let attestation = attest_binary("/nonexistent/definitely/not/here");
        assert_eq!(attestation.platform_signed, None);
        assert!(!attestation.canonical_path);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_platform_binary_attests_signed_and_canonical() {
        let attestation = attest_binary("/bin/ls");
        assert!(attestation.canonical_path, "/bin/ls must be canonical");
        assert_eq!(
            attestation.platform_signed,
            Some(true),
            "/bin/ls must verify against anchor apple"
        );
        // Cache hit must return the same verdict.
        let cached = attest_binary("/bin/ls");
        assert_eq!(attestation, cached);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_copied_platform_binary_loses_canonical_path() {
        // A copied Apple binary keeps its embedded signature, which is
        // exactly why the evidence pair requires canonical_path AND
        // platform_signed: the copy in a writable prefix loses the
        // canonical half and earns no benign credit.
        let dir = std::env::temp_dir().join("edamame_pubattest_test");
        let _ = std::fs::create_dir_all(&dir);
        let copy = dir.join("ls_copy");
        std::fs::copy("/bin/ls", &copy).expect("copy /bin/ls");
        let attestation = attest_binary(copy.to_str().unwrap());
        assert!(!attestation.canonical_path);
        let _ = std::fs::remove_file(&copy);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn package_query_paths_include_the_usrmerge_resolution() {
        // `/bin/ls` is the canonical usrmerge case: the package database
        // records `/usr/bin/ls`, so querying only the literal path reports a
        // coreutils binary as unowned.
        let paths = package_query_paths("/bin/ls");
        assert_eq!(paths.first().map(String::as_str), Some("/bin/ls"));
        if std::path::Path::new("/bin").is_symlink() {
            assert!(
                paths.iter().any(|p| p == "/usr/bin/ls"),
                "usrmerge host must also be queried as /usr/bin/ls: {paths:?}"
            );
        }
        // A path that is already canonical yields exactly one candidate.
        let single = package_query_paths("/usr/bin/ls");
        assert_eq!(single.len(), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_package_owned_binary_attests_owned_and_canonical() {
        // CI ubuntu / dogfood mint are dpkg systems; /bin/ls is owned
        // by coreutils. On a host with neither dpkg nor rpm the verdict
        // is unmeasured and the assertion below still holds (skip).
        let attestation = attest_binary("/bin/ls");
        assert!(attestation.canonical_path, "/bin/ls must be canonical");
        if let Some(signed) = attestation.platform_signed {
            assert!(signed, "/bin/ls must be package-owned on dpkg/rpm systems");
            assert!(attestation.publisher.is_some(), "package name expected");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_unowned_file_is_measured_negative_on_managed_hosts() {
        let dir = std::env::temp_dir().join("edamame_pubattest_test");
        let _ = std::fs::create_dir_all(&dir);
        let junk = dir.join("junk_binary");
        std::fs::write(&junk, b"#!/bin/sh\necho hi\n").expect("write junk");
        let attestation = attest_binary(junk.to_str().unwrap());
        // On dpkg/rpm hosts this is Some(false); on unmanaged hosts None.
        assert_ne!(attestation.platform_signed, Some(true));
        assert!(!attestation.canonical_path);
        let _ = std::fs::remove_file(&junk);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_platform_binary_attests_signed_and_canonical() {
        let attestation = attest_binary("C:\\Windows\\System32\\notepad.exe");
        assert!(attestation.canonical_path, "notepad must be canonical");
        // Catalog-signed OS files can report NotSigned via Authenticode
        // alone on some builds; assert only that the check is MEASURED
        // and that an unsigned scratch file is a measured negative.
        assert!(attestation.platform_signed.is_some(), "must be measured");
        let dir = std::env::temp_dir().join("edamame_pubattest_test");
        let _ = std::fs::create_dir_all(&dir);
        let junk = dir.join("junk_binary.ps1");
        std::fs::write(&junk, b"Write-Output hi\n").expect("write junk");
        let junk_attestation = attest_binary(junk.to_str().unwrap());
        assert_eq!(junk_attestation.platform_signed, Some(false));
        assert!(!junk_attestation.canonical_path);
        let _ = std::fs::remove_file(&junk);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_unsigned_file_is_measured_negative() {
        let dir = std::env::temp_dir().join("edamame_pubattest_test");
        let _ = std::fs::create_dir_all(&dir);
        let junk = dir.join("junk_binary");
        std::fs::write(&junk, b"#!/bin/sh\necho hi\n").expect("write junk");
        let attestation = attest_binary(junk.to_str().unwrap());
        assert_eq!(
            attestation.platform_signed,
            Some(false),
            "an unsigned file must be a measured negative, not unmeasured"
        );
        let _ = std::fs::remove_file(&junk);
    }
}
