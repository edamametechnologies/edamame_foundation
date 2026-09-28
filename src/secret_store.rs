//! OS secret stores for credentials at rest (2.0.2).
//!
//! Before 2.0.2 the LLM credentials (EDAMAME Portal API key, OAuth tokens,
//! BYO provider keys, Slack / Telegram bot tokens, MCP PSK) sat in plain text
//! in the persisted agentic config. This module holds the per-platform
//! primitives that keep them out of it; `edamame_core::storage_secrets` picks
//! one per process and the agentic config load/save migrates through it.
//!
//! | Platform | Store | Why |
//! |---|---|---|
//! | macOS app | Data-protection Keychain ([`KeychainStore`]), item accessible after first unlock, this device only | The app is sandboxed; the data-protection keychain needs no ACL prompt and is scoped by the app's `application-identifier` / `keychain-access-groups` entitlement |
//! | macOS without the entitlement (posture as root, `edamame_cli`, unsigned dev builds) | [`OwnerOnlyFileStore`] | The data-protection keychain answers `errSecMissingEntitlement` deterministically for such a binary; the legacy file keychain would prompt or has no login keychain for root |
//! | iOS | Data-protection Keychain | Always entitled (default access group) |
//! | Windows (app as the user, posture as SYSTEM) | [`DpapiFileStore`]: `CryptProtectData`, user scope | The blob decrypts only for the account that wrote it (SYSTEM's own master key for posture). Machine scope would let any local account decrypt it |
//! | Linux (posture as root, app as the user) | [`OwnerOnlyFileStore`] `0600` in a `0700` dir | The Secret Service needs a D-Bus user session: absent for a root daemon, a headless host or a CI runner |
//! | Android | [`OwnerOnlyFileStore`] in the app's private files dir | Per-app UID sandbox; Keystore-backed encryption is not wired (no JNI path in the storage layer yet) |
//!
//! Names are storage keys (`[A-Za-z0-9._-]+`); values are UTF-8 strings (the
//! caller serializes). Every store treats "no such item" as `Ok(None)` and
//! reports every other failure as an error: a caller must be able to tell
//! "nothing stored" from "could not look", or a transient failure would read
//! as "signed out".

use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};

/// A place credentials can live outside the persisted config.
pub trait SecretStore: Send + Sync {
    /// Short backend name for logs and status (`keychain`, `dpapi`, `file`, ...).
    fn kind(&self) -> &'static str;
    /// The stored value, `Ok(None)` when there is none.
    fn read(&self, name: &str) -> Result<Option<String>>;
    /// Create or replace the value.
    fn write(&self, name: &str, value: &str) -> Result<()>;
    /// Remove the value; removing a missing one is not an error.
    fn delete(&self, name: &str) -> Result<()>;
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.starts_with('.')
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(anyhow!("invalid secret name {:?}", name));
    }
    Ok(())
}

/// Write `bytes` to `path` through a sibling temp file and a rename, so a
/// crash never leaves a truncated secret. On unix the file is created `0600`
/// (never wider, even for an instant) and the directory is kept `0700`.
fn write_file_atomically(dir: &Path, path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    ensure_private_dir(dir)?;
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&tmp)
        .with_context(|| format!("create {}", tmp.display()))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .with_context(|| format!("write {}", tmp.display()))?;
    drop(file);
    std::fs::rename(&tmp, path).with_context(|| format!("rename to {}", path.display()))?;
    Ok(())
}

fn ensure_private_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod 700 {}", dir.display()))?;
    }
    Ok(())
}

fn read_file_if_present(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow!("read {}: {}", path.display(), e)),
    }
}

fn remove_file_if_present(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow!("remove {}: {}", path.display(), e)),
    }
}

// ---------------------------------------------------------------------------
// Owner-only file (Linux, Android, macOS without the keychain entitlement)
// ---------------------------------------------------------------------------

/// One `<name>.secret` file per value, `0600`, in a `0700` directory owned by
/// the process user (root for posture). On a non-unix target the modes are
/// not applied: this store is only selected on unix targets.
pub struct OwnerOnlyFileStore {
    dir: PathBuf,
}

impl OwnerOnlyFileStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn path(&self, name: &str) -> Result<PathBuf> {
        validate_name(name)?;
        Ok(self.dir.join(format!("{name}.secret")))
    }
}

impl SecretStore for OwnerOnlyFileStore {
    fn kind(&self) -> &'static str {
        "file"
    }

    fn read(&self, name: &str) -> Result<Option<String>> {
        let path = self.path(name)?;
        match read_file_if_present(&path)? {
            Some(bytes) => Ok(Some(
                String::from_utf8(bytes).map_err(|_| anyhow!("{} is not UTF-8", path.display()))?,
            )),
            None => Ok(None),
        }
    }

    fn write(&self, name: &str, value: &str) -> Result<()> {
        let path = self.path(name)?;
        write_file_atomically(&self.dir, &path, value.as_bytes())
    }

    fn delete(&self, name: &str) -> Result<()> {
        remove_file_if_present(&self.path(name)?)
    }
}

// ---------------------------------------------------------------------------
// Windows DPAPI
// ---------------------------------------------------------------------------

/// Fixed, non-secret entropy that binds a blob to this use: a blob copied out
/// of another DPAPI consumer does not decrypt here and vice versa.
#[cfg(target_os = "windows")]
const DPAPI_ENTROPY: &[u8] = b"EDAMAME secret store v1";

/// One `<name>.dpapi` file per value holding the `CryptProtectData` blob,
/// user scope (`CRYPTPROTECT_LOCAL_MACHINE` is deliberately not set), no UI.
#[cfg(target_os = "windows")]
pub struct DpapiFileStore {
    dir: PathBuf,
}

#[cfg(target_os = "windows")]
impl DpapiFileStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn path(&self, name: &str) -> Result<PathBuf> {
        validate_name(name)?;
        Ok(self.dir.join(format!("{name}.dpapi")))
    }

    fn blob(bytes: &[u8]) -> windows::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB {
        windows::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB {
            cbData: bytes.len() as u32,
            pbData: bytes.as_ptr() as *mut u8,
        }
    }

    fn take_output(out: windows::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB) -> Vec<u8> {
        use windows::Win32::Foundation::{LocalFree, HLOCAL};
        if out.pbData.is_null() {
            return Vec::new();
        }
        // SAFETY: DPAPI returned `cbData` bytes at `pbData`, allocated with
        // LocalAlloc; copied out, then freed exactly once.
        let bytes = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) }.to_vec();
        unsafe {
            let _ = LocalFree(Some(HLOCAL(out.pbData as *mut core::ffi::c_void)));
        }
        bytes
    }

    fn protect(plain: &[u8]) -> Result<Vec<u8>> {
        use windows::Win32::Security::Cryptography::{
            CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
        };
        let input = Self::blob(plain);
        let entropy = Self::blob(DPAPI_ENTROPY);
        let mut out = CRYPT_INTEGER_BLOB::default();
        // SAFETY: input / entropy point at live slices for the call; `out` is
        // an out-parameter DPAPI fills and `take_output` frees.
        unsafe {
            CryptProtectData(
                &input,
                windows::core::PCWSTR::null(),
                Some(&entropy as *const CRYPT_INTEGER_BLOB),
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        }
        .map_err(|e| anyhow!("CryptProtectData: {}", e))?;
        Ok(Self::take_output(out))
    }

    fn unprotect(sealed: &[u8]) -> Result<Vec<u8>> {
        use windows::Win32::Security::Cryptography::{
            CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
        };
        let input = Self::blob(sealed);
        let entropy = Self::blob(DPAPI_ENTROPY);
        let mut out = CRYPT_INTEGER_BLOB::default();
        // SAFETY: as in `protect`.
        unsafe {
            CryptUnprotectData(
                &input,
                None,
                Some(&entropy as *const CRYPT_INTEGER_BLOB),
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        }
        .map_err(|e| anyhow!("CryptUnprotectData: {}", e))?;
        Ok(Self::take_output(out))
    }
}

#[cfg(target_os = "windows")]
impl SecretStore for DpapiFileStore {
    fn kind(&self) -> &'static str {
        "dpapi"
    }

    fn read(&self, name: &str) -> Result<Option<String>> {
        let path = self.path(name)?;
        match read_file_if_present(&path)? {
            Some(sealed) => {
                let plain = Self::unprotect(&sealed)?;
                Ok(Some(String::from_utf8(plain).map_err(|_| {
                    anyhow!("{} does not decrypt to UTF-8", path.display())
                })?))
            }
            None => Ok(None),
        }
    }

    fn write(&self, name: &str, value: &str) -> Result<()> {
        let path = self.path(name)?;
        let sealed = Self::protect(value.as_bytes())?;
        write_file_atomically(&self.dir, &path, &sealed)
    }

    fn delete(&self, name: &str) -> Result<()> {
        remove_file_if_present(&self.path(name)?)
    }
}

// ---------------------------------------------------------------------------
// Apple data-protection Keychain
// ---------------------------------------------------------------------------

/// `errSecItemNotFound`.
#[cfg(any(target_os = "macos", target_os = "ios"))]
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
/// `errSecMissingEntitlement`: the binary has no keychain access group, a
/// property of its signature, not of the moment.
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub const ERR_SEC_MISSING_ENTITLEMENT: i32 = -34018;

/// Generic-password items in the data-protection keychain, one per name
/// (`service` + account `name`), accessible after first unlock (background
/// ticks run with the screen locked), never synchronized, this device only.
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub struct KeychainStore {
    service: String,
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
impl KeychainStore {
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    fn options(&self, name: &str) -> security_framework::passwords::PasswordOptions {
        let mut options = security_framework::passwords::PasswordOptions::new_generic_password(
            &self.service,
            name,
        );
        options.use_protected_keychain();
        options
    }

    /// `Ok(true)` when this binary can use the data-protection keychain,
    /// `Ok(false)` when it lacks the entitlement (deterministic for the
    /// binary), `Err` for anything else (locked, interaction not allowed).
    ///
    /// Probes with a delete of an item that never exists: an unentitled
    /// binary's *read* answers `errSecItemNotFound` like an entitled one
    /// (measured on macOS 26), only a mutation reports the missing
    /// entitlement.
    pub fn probe(&self) -> Result<bool> {
        match security_framework::passwords::delete_generic_password_options(
            self.options("edamame-keychain-probe"),
        ) {
            Ok(()) => Ok(true),
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(true),
            Err(e) if e.code() == ERR_SEC_MISSING_ENTITLEMENT => Ok(false),
            Err(e) => Err(anyhow!("keychain probe: {} ({})", e, e.code())),
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
impl SecretStore for KeychainStore {
    fn kind(&self) -> &'static str {
        "keychain"
    }

    fn read(&self, name: &str) -> Result<Option<String>> {
        validate_name(name)?;
        match security_framework::passwords::generic_password(self.options(name)) {
            Ok(bytes) => {
                Ok(Some(String::from_utf8(bytes).map_err(|_| {
                    anyhow!("keychain item {name} is not UTF-8")
                })?))
            }
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(None),
            Err(e) => Err(anyhow!("keychain read {}: {} ({})", name, e, e.code())),
        }
    }

    fn write(&self, name: &str, value: &str) -> Result<()> {
        use security_framework::access_control::{ProtectionMode, SecAccessControl};
        validate_name(name)?;
        // Delete then add: an update keyed on a query that carries access
        // control is not portable across OS versions.
        self.delete(name)?;
        let mut options = self.options(name);
        let access = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleAfterFirstUnlockThisDeviceOnly),
            0,
        )
        .map_err(|e| anyhow!("keychain access control: {} ({})", e, e.code()))?;
        options.set_access_control(access);
        security_framework::passwords::set_generic_password_options(value.as_bytes(), options)
            .map_err(|e| anyhow!("keychain write {}: {} ({})", name, e, e.code()))
    }

    fn delete(&self, name: &str) -> Result<()> {
        validate_name(name)?;
        match security_framework::passwords::delete_generic_password_options(self.options(name)) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(()),
            Err(e) => Err(anyhow!("keychain delete {}: {} ({})", name, e, e.code())),
        }
    }
}

// ---------------------------------------------------------------------------
// Composition and test double
// ---------------------------------------------------------------------------

/// A primary store that adopts values left in a secondary one: a read that
/// misses the primary looks in `secondary`, moves a hit into the primary and
/// removes it from the secondary. Covers a binary that moves from the file
/// fallback to the keychain (it gained the entitlement) without losing what
/// the file held. Writes and deletes go to the primary (deletes to both).
pub struct AdoptingStore {
    primary: Box<dyn SecretStore>,
    secondary: Box<dyn SecretStore>,
}

impl AdoptingStore {
    pub fn new(primary: Box<dyn SecretStore>, secondary: Box<dyn SecretStore>) -> Self {
        Self { primary, secondary }
    }
}

impl SecretStore for AdoptingStore {
    fn kind(&self) -> &'static str {
        self.primary.kind()
    }

    fn read(&self, name: &str) -> Result<Option<String>> {
        if let Some(value) = self.primary.read(name)? {
            return Ok(Some(value));
        }
        match self.secondary.read(name) {
            Ok(Some(value)) => {
                self.primary.write(name, &value)?;
                if self.primary.read(name)?.as_deref() == Some(value.as_str()) {
                    let _ = self.secondary.delete(name);
                }
                Ok(Some(value))
            }
            // The secondary is a fallback: its failure never hides the
            // primary's answer.
            Ok(None) | Err(_) => Ok(None),
        }
    }

    fn write(&self, name: &str, value: &str) -> Result<()> {
        self.primary.write(name, value)
    }

    fn delete(&self, name: &str) -> Result<()> {
        self.primary.delete(name)?;
        let _ = self.secondary.delete(name);
        Ok(())
    }
}

/// In-memory store for tests (and a failure switch to exercise the
/// "could not look" paths).
pub struct MemorySecretStore {
    values: undeadlock::CustomDashMap<String, String>,
    failing: std::sync::atomic::AtomicBool,
}

impl Default for MemorySecretStore {
    fn default() -> Self {
        Self {
            values: undeadlock::CustomDashMap::new("memory_secret_store"),
            failing: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

impl MemorySecretStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Every operation fails while set.
    pub fn set_failing(&self, failing: bool) {
        self.failing
            .store(failing, std::sync::atomic::Ordering::SeqCst);
    }

    fn check(&self) -> Result<()> {
        if self.failing.load(std::sync::atomic::Ordering::SeqCst) {
            Err(anyhow!("secret store unavailable (test)"))
        } else {
            Ok(())
        }
    }
}

impl SecretStore for MemorySecretStore {
    fn kind(&self) -> &'static str {
        "memory"
    }

    fn read(&self, name: &str) -> Result<Option<String>> {
        self.check()?;
        validate_name(name)?;
        Ok(self.values.get(name).map(|value| value.value().clone()))
    }

    fn write(&self, name: &str, value: &str) -> Result<()> {
        self.check()?;
        validate_name(name)?;
        self.values.insert(name.to_string(), value.to_string());
        Ok(())
    }

    fn delete(&self, name: &str) -> Result<()> {
        self.check()?;
        validate_name(name)?;
        self.values.remove(name);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "edamame-secret-store-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn round_trip(store: &dyn SecretStore) {
        assert_eq!(store.read("agentic_llm_secrets").unwrap(), None);
        store
            .write("agentic_llm_secrets", "{\"k\":\"v1\"}")
            .unwrap();
        assert_eq!(
            store.read("agentic_llm_secrets").unwrap().as_deref(),
            Some("{\"k\":\"v1\"}")
        );
        store.write("agentic_llm_secrets", "v2").unwrap();
        assert_eq!(
            store.read("agentic_llm_secrets").unwrap().as_deref(),
            Some("v2")
        );
        store.delete("agentic_llm_secrets").unwrap();
        assert_eq!(store.read("agentic_llm_secrets").unwrap(), None);
        // Deleting what is not there is fine.
        store.delete("agentic_llm_secrets").unwrap();
    }

    #[test]
    fn file_store_round_trips() {
        let dir = temp_dir("file");
        round_trip(&OwnerOnlyFileStore::new(&dir));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn file_store_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("mode");
        let store = OwnerOnlyFileStore::new(&dir);
        store.write("name", "value").unwrap();
        let file_mode = std::fs::metadata(dir.join("name.secret"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600);
        assert_eq!(dir_mode, 0o700);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn names_cannot_escape_the_directory() {
        let store = OwnerOnlyFileStore::new(temp_dir("names"));
        for bad in ["", "../x", "a/b", ".hidden", "a\\b", "a b"] {
            assert!(store.write(bad, "v").is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn memory_store_round_trips_and_fails_on_demand() {
        let store = MemorySecretStore::new();
        round_trip(&store);
        store.set_failing(true);
        assert!(store.read("x").is_err());
        assert!(store.write("x", "v").is_err());
    }

    #[test]
    fn adopting_store_moves_a_secondary_value_into_the_primary() {
        let primary = std::sync::Arc::new(MemorySecretStore::new());
        let dir = temp_dir("adopt");
        let secondary = OwnerOnlyFileStore::new(&dir);
        secondary.write("n", "legacy").unwrap();

        struct Shared(std::sync::Arc<MemorySecretStore>);
        impl SecretStore for Shared {
            fn kind(&self) -> &'static str {
                self.0.kind()
            }
            fn read(&self, name: &str) -> Result<Option<String>> {
                self.0.read(name)
            }
            fn write(&self, name: &str, value: &str) -> Result<()> {
                self.0.write(name, value)
            }
            fn delete(&self, name: &str) -> Result<()> {
                self.0.delete(name)
            }
        }

        let store = AdoptingStore::new(
            Box::new(Shared(primary.clone())),
            Box::new(OwnerOnlyFileStore::new(&dir)),
        );
        assert_eq!(store.read("n").unwrap().as_deref(), Some("legacy"));
        assert_eq!(primary.read("n").unwrap().as_deref(), Some("legacy"));
        assert_eq!(
            secondary.read("n").unwrap(),
            None,
            "adopted value left behind"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An unsigned test binary has no keychain access group: the probe must
    /// say so (`Ok(false)`, the file fallback) rather than fail or prompt. An
    /// entitled runner gets the full round trip.
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    #[test]
    fn keychain_probe_is_deterministic_and_round_trips_when_entitled() {
        let store = KeychainStore::new("com.edamametech.edamame.secrets.test");
        match store.probe() {
            Ok(true) => round_trip(&store),
            Ok(false) => {
                let err = store
                    .write("agentic_llm_secrets", "v")
                    .unwrap_err()
                    .to_string();
                assert!(
                    err.contains(&ERR_SEC_MISSING_ENTITLEMENT.to_string()),
                    "{err}"
                );
            }
            Err(e) => panic!("keychain probe failed: {e}"),
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn dpapi_store_round_trips_and_is_not_plaintext() {
        let dir = temp_dir("dpapi");
        let store = DpapiFileStore::new(&dir);
        round_trip(&store);
        store.write("n", "plain-secret-value").unwrap();
        let raw = std::fs::read(dir.join("n.dpapi")).unwrap();
        assert!(!raw
            .windows(b"plain-secret-value".len())
            .any(|w| w == b"plain-secret-value"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
