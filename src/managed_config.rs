//! Managed (MDM) configuration of the EDAMAME Security app (2.0.2).
//!
//! An organization configures the app through two channels:
//!
//! | OS | Non-secret keys | Secrets (Hub PIN, LLM / Portal API key) |
//! |---|---|---|
//! | macOS | Forced managed preferences of [`MACOS_PREFERENCE_DOMAIN`] (configuration profile, device or user scope) | [`MACOS_SECRETS_PATH`], `root:wheel 0600`, read by the helper |
//! | Windows | `HKLM\`[`WINDOWS_POLICY_KEY`] (GPO / ADMX / Intune) | `%ProgramData%\EDAMAME\Managed\secrets.json`, SYSTEM + Administrators, read by the helper |
//! | Linux, iOS, Android | none (Linux: `/etc/edamame_posture.conf`) | none |
//!
//! Secrets never go into the profile or the policy key: managed preferences
//! and `HKLM\SOFTWARE\Policies` are readable by every local user. The helper
//! runs as root / SYSTEM and hands the file's content to the core over the
//! authenticated helper channel (`get_managed_secrets` utility order); a
//! standalone core (posture, run privileged) reads the file itself. Both paths
//! call [`read_managed_secrets`], the single source of truth.
//!
//! This module only reads and validates. What the values do (enrol with the
//! Hub, configure the model, turn protection on, locks) is
//! `edamame_core::core_manager_managed`.
//!
//! Only forced values count on macOS: a user can write any key into their own
//! preferences of the same domain with `defaults write`, and such a value is
//! not a policy. `CFPreferencesAppValueIsForced` tells the two apart.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Preference domain of the macOS app (its bundle identifier, see
/// `edamame_app/macos/Runner/Configs/AppInfo.xcconfig`).
pub const MACOS_PREFERENCE_DOMAIN: &str = "com.edamametechnologies.edamame";

/// Policy key under `HKEY_LOCAL_MACHINE` on Windows.
pub const WINDOWS_POLICY_KEY: &str = r"SOFTWARE\Policies\EDAMAME\EDAMAME Security";

/// Secrets file on macOS.
pub const MACOS_SECRETS_PATH: &str = "/Library/Application Support/EDAMAME/Managed/secrets.json";

/// Secrets file on Windows, relative to `%ProgramData%`.
pub const WINDOWS_SECRETS_RELATIVE_PATH: &str = r"EDAMAME\Managed\secrets.json";

/// Upper bound on the secrets file (it holds three short strings).
const MAX_SECRETS_FILE_BYTES: u64 = 64 * 1024;

/// Upper bound on one secret or policy string.
const MAX_VALUE_CHARS: usize = 4096;

// Policy key names (plist keys and registry value names).
pub const KEY_ORGANIZATION_NAME: &str = "OrganizationName";
pub const KEY_HUB_EMAIL: &str = "HubEmail";
pub const KEY_HUB_EMAIL_SOURCE: &str = "HubEmailSource";
pub const KEY_LOCK_HUB_ENROLLMENT: &str = "LockHubEnrollment";
pub const KEY_LLM_PROVIDER: &str = "LLMProvider";
pub const KEY_LLM_MODEL: &str = "LLMModel";
pub const KEY_LLM_BASE_URL: &str = "LLMBaseURL";
pub const KEY_LOCK_LLM: &str = "LockLLM";
pub const KEY_PROTECTION_ENABLED: &str = "ProtectionEnabled";
pub const KEY_ASSISTANT_LEVEL: &str = "AssistantLevel";
pub const KEY_LOCK_PROTECTION: &str = "LockProtection";
pub const KEY_NETWORK_MONITORING_CONSENT: &str = "NetworkMonitoringConsent";
pub const KEY_SHARE_AI_FAILURE_DETAILS: &str = "ShareAIFailureDetails";
pub const KEY_CAPTURE_ENABLED: &str = "CaptureEnabled";
pub const KEY_FILE_MONITOR_ENABLED: &str = "FileMonitorEnabled";
pub const KEY_LOCK_MONITORING: &str = "LockMonitoring";
pub const KEY_HIDE_AI_SETTINGS: &str = "HideAISettings";

/// Every key the app reads, in documentation order.
pub const MANAGED_POLICY_KEYS: &[&str] = &[
    KEY_ORGANIZATION_NAME,
    KEY_HUB_EMAIL,
    KEY_HUB_EMAIL_SOURCE,
    KEY_LOCK_HUB_ENROLLMENT,
    KEY_LLM_PROVIDER,
    KEY_LLM_MODEL,
    KEY_LLM_BASE_URL,
    KEY_LOCK_LLM,
    KEY_PROTECTION_ENABLED,
    KEY_ASSISTANT_LEVEL,
    KEY_LOCK_PROTECTION,
    KEY_NETWORK_MONITORING_CONSENT,
    KEY_SHARE_AI_FAILURE_DETAILS,
    KEY_CAPTURE_ENABLED,
    KEY_FILE_MONITOR_ENABLED,
    KEY_LOCK_MONITORING,
    KEY_HIDE_AI_SETTINGS,
];

/// A raw policy value as the OS store holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagedValue {
    Bool(bool),
    Int(i64),
    Str(String),
}

/// Where the Hub account e-mail comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HubEmailSource {
    /// `HubEmail` (an MDM variable the MDM already substituted).
    Policy,
    /// The signed-in Windows user's user principal name.
    Upn,
}

/// The model connection the organization chose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedLlmProvider {
    /// EDAMAME Portal (core provider id `internal`).
    Portal,
    Claude,
    OpenAI,
    Ollama,
    None,
}

impl ManagedLlmProvider {
    /// The provider id `LLMConfig::provider` uses.
    pub fn core_provider_id(self) -> &'static str {
        match self {
            Self::Portal => "internal",
            Self::Claude => "claude",
            Self::OpenAI => "openai",
            Self::Ollama => "ollama",
            Self::None => "none",
        }
    }

    /// The policy spelling.
    pub fn policy_name(self) -> &'static str {
        match self {
            Self::Portal => "portal",
            Self::Claude => "claude",
            Self::OpenAI => "openai",
            Self::Ollama => "ollama",
            Self::None => "none",
        }
    }
}

/// The Assistant's level (`ConfirmationLevel` in core).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedAssistantLevel {
    Review,
    Auto,
}

impl ManagedAssistantLevel {
    pub fn policy_name(self) -> &'static str {
        match self {
            Self::Review => "review",
            Self::Auto => "auto",
        }
    }
}

/// The validated policy. A key that is absent or invalid is `None` / `false`
/// and invalid ones are listed in `errors` (never with a secret: the policy
/// carries none). A lock only covers the values the policy sets: a lock with
/// nothing to lock is ignored and reported.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ManagedPolicy {
    pub organization_name: Option<String>,
    pub hub_email: Option<String>,
    pub hub_email_source: Option<HubEmailSource>,
    pub lock_hub_enrollment: bool,
    pub llm_provider: Option<ManagedLlmProvider>,
    pub llm_model: Option<String>,
    pub llm_base_url: Option<String>,
    pub lock_llm: bool,
    pub protection_enabled: Option<bool>,
    pub assistant_level: Option<ManagedAssistantLevel>,
    pub lock_protection: bool,
    pub network_monitoring_consent: Option<bool>,
    pub share_ai_failure_details: Option<bool>,
    pub capture_enabled: Option<bool>,
    pub file_monitor_enabled: Option<bool>,
    pub lock_monitoring: bool,
    pub hide_ai_settings: bool,
    /// Keys the store held (valid or not), in [`MANAGED_POLICY_KEYS`] order.
    pub present_keys: Vec<String>,
    /// One line per rejected value or ignored lock.
    pub errors: Vec<String>,
}

impl ManagedPolicy {
    /// Whether the organization set anything at all.
    pub fn is_managed(&self) -> bool {
        !self.present_keys.is_empty()
    }

    /// The Hub account is set by policy (an e-mail or the UPN source).
    pub fn manages_hub(&self) -> bool {
        self.hub_email.is_some() || self.hub_email_source == Some(HubEmailSource::Upn)
    }

    /// The protection switch or the Assistant level is set by policy.
    pub fn manages_protection(&self) -> bool {
        self.protection_enabled.is_some() || self.assistant_level.is_some()
    }

    /// Capture or the file monitor is set by policy.
    pub fn manages_monitoring(&self) -> bool {
        self.capture_enabled.is_some() || self.file_monitor_enabled.is_some()
    }

    /// Validate raw values into a policy. The single parser for every OS
    /// reader (and for tests): readers only turn the OS store into
    /// [`ManagedValue`]s.
    pub fn from_values(values: &BTreeMap<String, ManagedValue>) -> Self {
        let mut policy = ManagedPolicy::default();
        for key in MANAGED_POLICY_KEYS {
            if values.contains_key(*key) {
                policy.present_keys.push(key.to_string());
            }
        }
        let mut errors = Vec::new();

        policy.organization_name = string_value(values, KEY_ORGANIZATION_NAME, &mut errors);

        policy.hub_email_source = match string_value(values, KEY_HUB_EMAIL_SOURCE, &mut errors)
            .map(|s| s.to_ascii_lowercase())
            .as_deref()
        {
            None => None,
            Some("policy") => Some(HubEmailSource::Policy),
            Some("upn") => Some(HubEmailSource::Upn),
            Some(other) => {
                errors.push(format!(
                    "{}: '{}' is not one of policy, upn",
                    KEY_HUB_EMAIL_SOURCE, other
                ));
                None
            }
        };
        policy.hub_email = match string_value(values, KEY_HUB_EMAIL, &mut errors) {
            Some(email) => match validate_email(&email) {
                Ok(()) => Some(email),
                Err(reason) => {
                    errors.push(format!("{}: {}", KEY_HUB_EMAIL, reason));
                    None
                }
            },
            None => None,
        };
        if policy.hub_email_source == Some(HubEmailSource::Upn) && policy.hub_email.is_some() {
            errors.push(format!(
                "{}: ignored, {} is upn",
                KEY_HUB_EMAIL, KEY_HUB_EMAIL_SOURCE
            ));
            policy.hub_email = None;
        }
        policy.lock_hub_enrollment =
            bool_value(values, KEY_LOCK_HUB_ENROLLMENT, &mut errors).unwrap_or(false);
        if policy.lock_hub_enrollment && !policy.manages_hub() {
            errors.push(format!(
                "{}: ignored, the policy sets no Hub account ({} or {} = upn)",
                KEY_LOCK_HUB_ENROLLMENT, KEY_HUB_EMAIL, KEY_HUB_EMAIL_SOURCE
            ));
            policy.lock_hub_enrollment = false;
        }

        policy.llm_provider = match string_value(values, KEY_LLM_PROVIDER, &mut errors)
            .map(|s| s.to_ascii_lowercase())
            .as_deref()
        {
            None => None,
            Some("portal") | Some("internal") | Some("edamame") => Some(ManagedLlmProvider::Portal),
            Some("claude") | Some("anthropic") => Some(ManagedLlmProvider::Claude),
            Some("openai") => Some(ManagedLlmProvider::OpenAI),
            Some("ollama") => Some(ManagedLlmProvider::Ollama),
            Some("none") => Some(ManagedLlmProvider::None),
            Some(other) => {
                errors.push(format!(
                    "{}: '{}' is not one of portal, claude, openai, ollama, none",
                    KEY_LLM_PROVIDER, other
                ));
                None
            }
        };
        policy.llm_model = string_value(values, KEY_LLM_MODEL, &mut errors);
        policy.llm_base_url = match string_value(values, KEY_LLM_BASE_URL, &mut errors) {
            Some(url) if url.starts_with("https://") || url.starts_with("http://") => Some(url),
            Some(_) => {
                errors.push(format!(
                    "{}: must start with https:// or http://",
                    KEY_LLM_BASE_URL
                ));
                None
            }
            None => None,
        };
        if policy.llm_provider.is_none()
            && (policy.llm_model.is_some() || policy.llm_base_url.is_some())
        {
            errors.push(format!(
                "{} / {}: ignored without {}",
                KEY_LLM_MODEL, KEY_LLM_BASE_URL, KEY_LLM_PROVIDER
            ));
            policy.llm_model = None;
            policy.llm_base_url = None;
        }
        if policy.llm_provider == Some(ManagedLlmProvider::Portal) && policy.llm_model.is_some() {
            // The Portal chooses its model.
            errors.push(format!("{}: ignored for the EDAMAME Portal", KEY_LLM_MODEL));
            policy.llm_model = None;
        }
        policy.lock_llm = bool_value(values, KEY_LOCK_LLM, &mut errors).unwrap_or(false);
        if policy.lock_llm && policy.llm_provider.is_none() {
            errors.push(format!(
                "{}: ignored, the policy sets no {}",
                KEY_LOCK_LLM, KEY_LLM_PROVIDER
            ));
            policy.lock_llm = false;
        }

        policy.protection_enabled = bool_value(values, KEY_PROTECTION_ENABLED, &mut errors);
        policy.assistant_level = match string_value(values, KEY_ASSISTANT_LEVEL, &mut errors)
            .map(|s| s.to_ascii_lowercase())
            .as_deref()
        {
            None => None,
            Some("review") => Some(ManagedAssistantLevel::Review),
            Some("auto") => Some(ManagedAssistantLevel::Auto),
            Some(other) => {
                errors.push(format!(
                    "{}: '{}' is not one of review, auto",
                    KEY_ASSISTANT_LEVEL, other
                ));
                None
            }
        };
        policy.lock_protection =
            bool_value(values, KEY_LOCK_PROTECTION, &mut errors).unwrap_or(false);
        if policy.lock_protection && !policy.manages_protection() {
            errors.push(format!(
                "{}: ignored, the policy sets neither {} nor {}",
                KEY_LOCK_PROTECTION, KEY_PROTECTION_ENABLED, KEY_ASSISTANT_LEVEL
            ));
            policy.lock_protection = false;
        }

        policy.network_monitoring_consent =
            bool_value(values, KEY_NETWORK_MONITORING_CONSENT, &mut errors);
        policy.share_ai_failure_details =
            bool_value(values, KEY_SHARE_AI_FAILURE_DETAILS, &mut errors);

        policy.capture_enabled = bool_value(values, KEY_CAPTURE_ENABLED, &mut errors);
        policy.file_monitor_enabled = bool_value(values, KEY_FILE_MONITOR_ENABLED, &mut errors);
        policy.lock_monitoring =
            bool_value(values, KEY_LOCK_MONITORING, &mut errors).unwrap_or(false);
        if policy.lock_monitoring && !policy.manages_monitoring() {
            errors.push(format!(
                "{}: ignored, the policy sets neither {} nor {}",
                KEY_LOCK_MONITORING, KEY_CAPTURE_ENABLED, KEY_FILE_MONITOR_ENABLED
            ));
            policy.lock_monitoring = false;
        }

        policy.hide_ai_settings =
            bool_value(values, KEY_HIDE_AI_SETTINGS, &mut errors).unwrap_or(false);

        policy.errors = errors;
        policy
    }
}

/// A string value, trimmed; empty is "not set". A non-string is an error.
fn string_value(
    values: &BTreeMap<String, ManagedValue>,
    key: &str,
    errors: &mut Vec<String>,
) -> Option<String> {
    match values.get(key)? {
        ManagedValue::Str(s) => {
            let s = s.trim();
            if s.is_empty() {
                None
            } else if s.chars().count() > MAX_VALUE_CHARS || s.chars().any(char::is_control) {
                errors.push(format!("{}: value too long or not printable", key));
                None
            } else {
                Some(s.to_string())
            }
        }
        _ => {
            errors.push(format!("{}: expected a string", key));
            None
        }
    }
}

/// A boolean: a plist `<true/>` / `<false/>`, a registry `REG_DWORD` 0 / 1, or
/// the strings `true` / `false` / `1` / `0` (Intune custom OMA-URI and ADMX
/// ingestion deliver strings).
fn bool_value(
    values: &BTreeMap<String, ManagedValue>,
    key: &str,
    errors: &mut Vec<String>,
) -> Option<bool> {
    match values.get(key)? {
        ManagedValue::Bool(b) => Some(*b),
        ManagedValue::Int(0) => Some(false),
        ManagedValue::Int(1) => Some(true),
        ManagedValue::Str(s) => match s.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => Some(true),
            "false" | "0" | "no" => Some(false),
            _ => {
                errors.push(format!("{}: expected a boolean", key));
                None
            }
        },
        ManagedValue::Int(_) => {
            errors.push(format!("{}: expected a boolean (0 or 1)", key));
            None
        }
    }
}

/// `user@domain`, with the MDM variable already substituted.
pub fn validate_email(email: &str) -> std::result::Result<(), String> {
    if email.contains('$') || email.contains("{{") || email.contains('%') {
        return Err("contains an MDM variable the MDM did not substitute".to_string());
    }
    let mut parts = email.split('@');
    let (Some(user), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err("expected user@domain".to_string());
    };
    if user.is_empty()
        || domain.is_empty()
        || !domain.contains('.')
        || email.chars().any(char::is_whitespace)
    {
        return Err("expected user@domain".to_string());
    }
    Ok(())
}

/// Split a validated `user@domain` into the Hub's (user, domain) pair.
pub fn split_email(email: &str) -> Option<(String, String)> {
    validate_email(email).ok()?;
    let (user, domain) = email.split_once('@')?;
    Some((user.to_string(), domain.to_ascii_lowercase()))
}

/// Where the policy came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedPolicySource {
    /// macOS configuration profile (forced managed preferences).
    ConfigurationProfile,
    /// Windows `HKLM\SOFTWARE\Policies`.
    GroupPolicy,
    /// This OS has no managed-configuration channel for the app.
    Unsupported,
}

impl ManagedPolicySource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfigurationProfile => "configuration_profile",
            Self::GroupPolicy => "group_policy",
            Self::Unsupported => "unsupported",
        }
    }
}

/// The OS policy store of this platform, read now.
pub fn read_managed_policy() -> (ManagedPolicySource, ManagedPolicy) {
    #[cfg(target_os = "macos")]
    {
        (
            ManagedPolicySource::ConfigurationProfile,
            ManagedPolicy::from_values(&macos::read_forced_values(MACOS_PREFERENCE_DOMAIN)),
        )
    }
    #[cfg(target_os = "windows")]
    {
        (
            ManagedPolicySource::GroupPolicy,
            ManagedPolicy::from_values(&windows_policy::read_policy_values(WINDOWS_POLICY_KEY)),
        )
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        (ManagedPolicySource::Unsupported, ManagedPolicy::default())
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use core_foundation::base::TCFType;
    use core_foundation::boolean::CFBoolean;
    use core_foundation::number::CFNumber;
    use core_foundation::propertylist::CFPropertyList;
    use core_foundation::string::CFString;
    use core_foundation_sys::preferences::{
        CFPreferencesAppValueIsForced, CFPreferencesCopyAppValue,
    };

    /// The forced (profile-delivered) values of `domain`. A value the user
    /// wrote into their own preferences is not forced and is skipped.
    pub(super) fn read_forced_values(domain: &str) -> BTreeMap<String, ManagedValue> {
        let domain = CFString::new(domain);
        let mut values = BTreeMap::new();
        for key in MANAGED_POLICY_KEYS {
            let cf_key = CFString::new(key);
            // SAFETY: both arguments are valid CFStrings for the duration of
            // the calls; CopyAppValue returns a +1 reference (or NULL) that
            // `wrap_under_create_rule` takes ownership of.
            let value = unsafe {
                if CFPreferencesAppValueIsForced(
                    cf_key.as_concrete_TypeRef(),
                    domain.as_concrete_TypeRef(),
                ) == 0
                {
                    continue;
                }
                let raw = CFPreferencesCopyAppValue(
                    cf_key.as_concrete_TypeRef(),
                    domain.as_concrete_TypeRef(),
                );
                if raw.is_null() {
                    continue;
                }
                CFPropertyList::wrap_under_create_rule(raw)
            };
            let converted = if let Some(s) = value.downcast::<CFString>() {
                ManagedValue::Str(s.to_string())
            } else if let Some(b) = value.downcast::<CFBoolean>() {
                ManagedValue::Bool(b.into())
            } else if let Some(n) = value.downcast::<CFNumber>() {
                match n.to_i64() {
                    Some(i) => ManagedValue::Int(i),
                    None => ManagedValue::Str(String::new()),
                }
            } else {
                // Arrays, dictionaries, data, dates: no key takes one. An
                // empty string is "not set" for string keys and an error for
                // boolean ones, which is what the admin needs to see.
                ManagedValue::Int(i64::MIN)
            };
            values.insert(key.to_string(), converted);
        }
        values
    }
}

#[cfg(target_os = "windows")]
mod windows_policy {
    use super::*;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{
        RegGetValueW, HKEY_LOCAL_MACHINE, REG_DWORD, REG_EXPAND_SZ, REG_QWORD, REG_SZ,
        REG_VALUE_TYPE, RRF_NOEXPAND, RRF_RT_ANY, RRF_SUBKEY_WOW6464KEY,
    };

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// One value of `HKLM\<subkey>`, or `None` when the key or the value is
    /// absent.
    fn read_value(subkey: &[u16], name: &str) -> Option<ManagedValue> {
        let name = wide(name);
        let flags = RRF_RT_ANY | RRF_SUBKEY_WOW6464KEY | RRF_NOEXPAND;
        let mut kind = REG_VALUE_TYPE::default();
        let mut size: u32 = 0;
        // SAFETY: the strings are NUL-terminated and outlive the calls; the
        // first call only reports type and size, the second writes at most
        // `size` bytes into a buffer of that size.
        unsafe {
            let status = RegGetValueW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(subkey.as_ptr()),
                PCWSTR(name.as_ptr()),
                flags,
                Some(&mut kind),
                None,
                Some(&mut size),
            );
            if status != ERROR_SUCCESS || size == 0 {
                return None;
            }
            let mut buffer = vec![0u8; size as usize];
            let status = RegGetValueW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(subkey.as_ptr()),
                PCWSTR(name.as_ptr()),
                flags,
                Some(&mut kind),
                Some(buffer.as_mut_ptr() as *mut std::ffi::c_void),
                Some(&mut size),
            );
            if status != ERROR_SUCCESS {
                return None;
            }
            buffer.truncate(size as usize);
            if kind == REG_DWORD && buffer.len() >= 4 {
                let v = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
                Some(ManagedValue::Int(v as i64))
            } else if kind == REG_QWORD && buffer.len() >= 8 {
                let mut b = [0u8; 8];
                b.copy_from_slice(&buffer[..8]);
                Some(ManagedValue::Int(i64::from_le_bytes(b)))
            } else if kind == REG_SZ || kind == REG_EXPAND_SZ {
                let units: Vec<u16> = buffer
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .take_while(|u| *u != 0)
                    .collect();
                Some(ManagedValue::Str(String::from_utf16_lossy(&units)))
            } else {
                // REG_BINARY, REG_MULTI_SZ: no key takes one (see macOS).
                Some(ManagedValue::Int(i64::MIN))
            }
        }
    }

    pub(super) fn read_policy_values(subkey: &str) -> BTreeMap<String, ManagedValue> {
        let subkey = wide(subkey);
        let mut values = BTreeMap::new();
        for key in MANAGED_POLICY_KEYS {
            if let Some(value) = read_value(&subkey, key) {
                values.insert(key.to_string(), value);
            }
        }
        values
    }
}

/// The signed-in Windows user's user principal name (`HubEmailSource=upn`).
/// Runs as the user (the app's core); under SYSTEM (a service) there is no
/// UPN and this fails.
#[cfg(target_os = "windows")]
pub fn current_user_upn() -> Result<String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let output = std::process::Command::new("whoami")
        .arg("/upn")
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| anyhow!("whoami /upn: {}", e))?;
    if !output.status.success() {
        return Err(anyhow!(
            "whoami /upn failed (the account has no user principal name)"
        ));
    }
    let upn = String::from_utf8_lossy(&output.stdout).trim().to_string();
    validate_email(&upn).map_err(|reason| anyhow!("UPN '{}': {}", upn, reason))?;
    Ok(upn)
}

/// No UPN outside Windows.
#[cfg(not(target_os = "windows"))]
pub fn current_user_upn() -> Result<String> {
    Err(anyhow!("HubEmailSource=upn is only available on Windows"))
}

// ---------------------------------------------------------------------------
// Secrets file
// ---------------------------------------------------------------------------

/// The secrets file (`secrets.json`). Admin-authored input, not persisted app
/// state: every field is optional in the file (an `Option` is), and an
/// unknown field is an error so a typo does not silently drop a secret.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedSecrets {
    pub hub_pin: Option<String>,
    pub hub_enrollment_token: Option<String>,
    pub llm_api_key: Option<String>,
}

impl std::fmt::Debug for ManagedSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mask = |v: &Option<String>| if v.is_some() { "<set>" } else { "<unset>" };
        f.debug_struct("ManagedSecrets")
            .field("hub_pin", &mask(&self.hub_pin))
            .field("hub_enrollment_token", &mask(&self.hub_enrollment_token))
            .field("llm_api_key", &mask(&self.llm_api_key))
            .finish()
    }
}

impl ManagedSecrets {
    pub fn is_empty(&self) -> bool {
        self.hub_pin.is_none() && self.hub_enrollment_token.is_none() && self.llm_api_key.is_none()
    }
}

/// Parse and validate the secrets file content. Blank values are "not set".
pub fn parse_managed_secrets(content: &str) -> Result<ManagedSecrets> {
    let mut secrets: ManagedSecrets = serde_json::from_str(content).map_err(|e| {
        // serde's message names the field and position, never the value.
        anyhow!("not a valid secrets file: {}", e)
    })?;
    for (name, slot) in [
        ("hub_pin", &mut secrets.hub_pin),
        ("hub_enrollment_token", &mut secrets.hub_enrollment_token),
        ("llm_api_key", &mut secrets.llm_api_key),
    ] {
        if let Some(value) = slot.take() {
            let value = value.trim().to_string();
            if value.is_empty() {
                continue;
            }
            if value.chars().count() > MAX_VALUE_CHARS
                || value.chars().any(|c| c.is_control() || c.is_whitespace())
            {
                return Err(anyhow!("{}: too long or contains whitespace", name));
            }
            *slot = Some(value);
        }
    }
    Ok(secrets)
}

/// Outcome of reading the secrets file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedSecretsStatus {
    /// Read and valid.
    Loaded,
    /// No file: the organization delivers no secrets.
    Absent,
    /// Not valid JSON / unknown field / bad value.
    Invalid,
    /// Readable by others than root (macOS): refused, not read.
    InsecurePermissions,
    /// Exists but could not be read.
    Unreadable,
    /// This OS has no secrets file.
    Unsupported,
    /// The reader could not be reached (helper down, Store build without the
    /// helper). Never "no secrets".
    Unavailable,
}

impl ManagedSecretsStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Loaded => "loaded",
            Self::Absent => "absent",
            Self::Invalid => "invalid",
            Self::InsecurePermissions => "insecure_permissions",
            Self::Unreadable => "unreadable",
            Self::Unsupported => "unsupported",
            Self::Unavailable => "unavailable",
        }
    }
}

/// What [`read_managed_secrets`] returns, and what the helper sends back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedSecretsRead {
    pub status: ManagedSecretsStatus,
    /// Why, for the non-loaded statuses (never a secret).
    pub detail: String,
    pub secrets: Option<ManagedSecrets>,
}

impl ManagedSecretsRead {
    pub fn without_secrets(status: ManagedSecretsStatus, detail: impl Into<String>) -> Self {
        Self {
            status,
            detail: detail.into(),
            secrets: None,
        }
    }
}

/// The secrets file of this OS, or `None` where there is none.
pub fn managed_secrets_path() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        Some(PathBuf::from(MACOS_SECRETS_PATH))
    }
    #[cfg(target_os = "windows")]
    {
        let program_data =
            std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
        Some(PathBuf::from(program_data).join(WINDOWS_SECRETS_RELATIVE_PATH))
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        None
    }
}

/// Whether a file with this owner / mode may hold secrets: a regular file
/// owned by root, not readable or writable by group or others.
pub fn secrets_file_permissions_ok(owner_uid: u32, mode: u32, require_root_owner: bool) -> bool {
    (!require_root_owner || owner_uid == 0) && mode & 0o077 == 0
}

/// Read the secrets file of this OS. The single function both the helper
/// (`utility_get_managed_secrets`) and a standalone core call.
pub fn read_managed_secrets() -> ManagedSecretsRead {
    match managed_secrets_path() {
        Some(path) => read_managed_secrets_at(&path, true),
        None => ManagedSecretsRead::without_secrets(
            ManagedSecretsStatus::Unsupported,
            "no managed secrets file on this OS",
        ),
    }
}

/// [`read_managed_secrets`] for an explicit path. `require_root_owner` is
/// false only in tests (a test cannot create a root-owned file). On Windows
/// the file's ACL is the admin's responsibility (SYSTEM + Administrators, see
/// the deployment guide); it is not inspected here.
pub fn read_managed_secrets_at(path: &Path, require_root_owner: bool) -> ManagedSecretsRead {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return ManagedSecretsRead::without_secrets(ManagedSecretsStatus::Absent, "")
        }
        Err(e) => {
            return ManagedSecretsRead::without_secrets(
                ManagedSecretsStatus::Unreadable,
                format!("{}: {}", path.display(), e.kind()),
            )
        }
    };
    if !metadata.is_file() {
        return ManagedSecretsRead::without_secrets(
            ManagedSecretsStatus::InsecurePermissions,
            format!("{} is not a regular file", path.display()),
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if !secrets_file_permissions_ok(metadata.uid(), metadata.mode(), require_root_owner) {
            return ManagedSecretsRead::without_secrets(
                ManagedSecretsStatus::InsecurePermissions,
                format!(
                    "{} must be owned by root with mode 0600 (found uid {}, mode {:o})",
                    path.display(),
                    metadata.uid(),
                    metadata.mode() & 0o777
                ),
            );
        }
    }
    #[cfg(not(unix))]
    let _ = require_root_owner;
    if metadata.len() > MAX_SECRETS_FILE_BYTES {
        return ManagedSecretsRead::without_secrets(
            ManagedSecretsStatus::Invalid,
            format!(
                "{} is larger than {} bytes",
                path.display(),
                MAX_SECRETS_FILE_BYTES
            ),
        );
    }
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(e) => {
            return ManagedSecretsRead::without_secrets(
                ManagedSecretsStatus::Unreadable,
                format!("{}: {}", path.display(), e.kind()),
            )
        }
    };
    match parse_managed_secrets(&content) {
        Ok(secrets) => ManagedSecretsRead {
            status: ManagedSecretsStatus::Loaded,
            detail: String::new(),
            secrets: Some(secrets),
        },
        Err(e) => ManagedSecretsRead::without_secrets(ManagedSecretsStatus::Invalid, e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(pairs: &[(&str, ManagedValue)]) -> BTreeMap<String, ManagedValue> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    fn s(v: &str) -> ManagedValue {
        ManagedValue::Str(v.to_string())
    }

    #[test]
    fn empty_store_is_unmanaged() {
        let policy = ManagedPolicy::from_values(&BTreeMap::new());
        assert!(!policy.is_managed());
        assert_eq!(policy, ManagedPolicy::default());
    }

    #[test]
    fn full_macos_profile_parses() {
        let policy = ManagedPolicy::from_values(&values(&[
            (KEY_ORGANIZATION_NAME, s("Example Corp")),
            (KEY_HUB_EMAIL, s("Alice@Example.com")),
            (KEY_LOCK_HUB_ENROLLMENT, ManagedValue::Bool(true)),
            (KEY_LLM_PROVIDER, s("portal")),
            (KEY_LLM_MODEL, s("")),
            (KEY_LLM_BASE_URL, s("")),
            (KEY_LOCK_LLM, ManagedValue::Bool(true)),
            (KEY_PROTECTION_ENABLED, ManagedValue::Bool(true)),
            (KEY_ASSISTANT_LEVEL, s("Review")),
            (KEY_LOCK_PROTECTION, ManagedValue::Bool(true)),
            (KEY_NETWORK_MONITORING_CONSENT, ManagedValue::Bool(true)),
        ]));
        assert!(policy.errors.is_empty(), "{:?}", policy.errors);
        assert_eq!(policy.organization_name.as_deref(), Some("Example Corp"));
        assert_eq!(policy.hub_email.as_deref(), Some("Alice@Example.com"));
        assert!(policy.lock_hub_enrollment);
        assert_eq!(policy.llm_provider, Some(ManagedLlmProvider::Portal));
        assert_eq!(policy.llm_model, None, "blank strings are unset");
        assert!(policy.lock_llm);
        assert_eq!(policy.protection_enabled, Some(true));
        assert_eq!(policy.assistant_level, Some(ManagedAssistantLevel::Review));
        assert!(policy.lock_protection);
        assert_eq!(policy.network_monitoring_consent, Some(true));
        assert_eq!(policy.present_keys.len(), 11);
    }

    #[test]
    fn registry_dwords_and_intune_strings_are_booleans() {
        let policy = ManagedPolicy::from_values(&values(&[
            (KEY_PROTECTION_ENABLED, ManagedValue::Int(1)),
            (KEY_LOCK_PROTECTION, s("true")),
            (KEY_CAPTURE_ENABLED, ManagedValue::Int(0)),
            (KEY_SHARE_AI_FAILURE_DETAILS, s("0")),
        ]));
        assert!(policy.errors.is_empty(), "{:?}", policy.errors);
        assert_eq!(policy.protection_enabled, Some(true));
        assert!(policy.lock_protection);
        assert_eq!(policy.capture_enabled, Some(false));
        assert_eq!(policy.share_ai_failure_details, Some(false));
    }

    #[test]
    fn invalid_values_are_reported_and_dropped() {
        let policy = ManagedPolicy::from_values(&values(&[
            (KEY_PROTECTION_ENABLED, ManagedValue::Int(7)),
            (KEY_LLM_PROVIDER, s("gemini")),
            (KEY_ASSISTANT_LEVEL, s("yolo")),
            (KEY_ORGANIZATION_NAME, ManagedValue::Bool(true)),
            (KEY_LLM_BASE_URL, s("ftp://x")),
        ]));
        assert_eq!(policy.protection_enabled, None);
        assert_eq!(policy.llm_provider, None);
        assert_eq!(policy.assistant_level, None);
        assert_eq!(policy.organization_name, None);
        assert_eq!(policy.llm_base_url, None);
        assert_eq!(policy.errors.len(), 5, "{:?}", policy.errors);
        assert!(policy.is_managed(), "invalid keys are still present keys");
    }

    #[test]
    fn unsubstituted_mdm_variables_are_rejected() {
        for raw in ["$EMAIL", "{{mail}}", "%USERNAME%@corp.com", "alice", "a@b"] {
            let policy = ManagedPolicy::from_values(&values(&[(KEY_HUB_EMAIL, s(raw))]));
            assert_eq!(policy.hub_email, None, "{} accepted", raw);
            assert_eq!(policy.errors.len(), 1);
        }
        assert_eq!(
            split_email("Alice@Example.COM"),
            Some(("Alice".to_string(), "example.com".to_string()))
        );
    }

    #[test]
    fn locks_without_values_are_ignored() {
        let policy = ManagedPolicy::from_values(&values(&[
            (KEY_LOCK_HUB_ENROLLMENT, ManagedValue::Bool(true)),
            (KEY_LOCK_LLM, ManagedValue::Bool(true)),
            (KEY_LOCK_PROTECTION, ManagedValue::Bool(true)),
            (KEY_LOCK_MONITORING, ManagedValue::Bool(true)),
            (KEY_LLM_MODEL, s("gpt-5")),
        ]));
        assert!(!policy.lock_hub_enrollment);
        assert!(!policy.lock_llm);
        assert!(!policy.lock_protection);
        assert!(!policy.lock_monitoring);
        assert_eq!(
            policy.llm_model, None,
            "a model without a provider is ignored"
        );
        assert_eq!(policy.errors.len(), 5, "{:?}", policy.errors);
    }

    #[test]
    fn the_portal_chooses_its_model() {
        let policy = ManagedPolicy::from_values(&values(&[
            (KEY_LLM_PROVIDER, s("portal")),
            (KEY_LLM_MODEL, s("gpt-5")),
        ]));
        assert_eq!(policy.llm_model, None);
        assert_eq!(policy.errors.len(), 1);
    }

    #[test]
    fn upn_source_wins_over_a_fixed_email() {
        let policy = ManagedPolicy::from_values(&values(&[
            (KEY_HUB_EMAIL_SOURCE, s("UPN")),
            (KEY_HUB_EMAIL, s("alice@example.com")),
            (KEY_LOCK_HUB_ENROLLMENT, ManagedValue::Int(1)),
        ]));
        assert_eq!(policy.hub_email_source, Some(HubEmailSource::Upn));
        assert_eq!(policy.hub_email, None);
        assert!(policy.manages_hub());
        assert!(policy.lock_hub_enrollment);
        assert_eq!(policy.errors.len(), 1);
    }

    #[test]
    fn provider_ids_map_to_core() {
        assert_eq!(ManagedLlmProvider::Portal.core_provider_id(), "internal");
        assert_eq!(ManagedLlmProvider::Claude.core_provider_id(), "claude");
        assert_eq!(ManagedLlmProvider::None.core_provider_id(), "none");
    }

    #[test]
    fn secrets_parse_trim_and_reject_unknown_fields() {
        let secrets = parse_managed_secrets(
            r#"{"hub_pin": " 123456 ", "llm_api_key": "", "hub_enrollment_token": null}"#,
        )
        .unwrap();
        assert_eq!(secrets.hub_pin.as_deref(), Some("123456"));
        assert_eq!(secrets.llm_api_key, None);
        assert_eq!(secrets.hub_enrollment_token, None);
        assert!(parse_managed_secrets(r#"{"hub_pn": "1"}"#).is_err());
        assert!(parse_managed_secrets(r#"{"llm_api_key": "a b"}"#).is_err());
        assert!(parse_managed_secrets("not json").is_err());
        assert!(parse_managed_secrets("{}").unwrap().is_empty());
    }

    #[test]
    fn secrets_debug_never_prints_values() {
        let secrets =
            parse_managed_secrets(r#"{"hub_pin": "987654", "llm_api_key": "sk-live-x"}"#).unwrap();
        let read = ManagedSecretsRead {
            status: ManagedSecretsStatus::Loaded,
            detail: String::new(),
            secrets: Some(secrets),
        };
        let printed = format!("{:?}", read);
        assert!(!printed.contains("987654"), "{}", printed);
        assert!(!printed.contains("sk-live-x"), "{}", printed);
    }

    #[test]
    fn invalid_secrets_error_never_echoes_the_value() {
        let err = parse_managed_secrets(r#"{"llm_api_key": "sk live secret"}"#).unwrap_err();
        assert!(!err.to_string().contains("secret"), "{}", err);
    }

    #[test]
    fn permission_rule() {
        assert!(secrets_file_permissions_ok(0, 0o100600, true));
        assert!(secrets_file_permissions_ok(0, 0o100400, true));
        assert!(!secrets_file_permissions_ok(0, 0o100644, true));
        assert!(!secrets_file_permissions_ok(0, 0o100640, true));
        assert!(!secrets_file_permissions_ok(501, 0o100600, true));
        assert!(secrets_file_permissions_ok(501, 0o100600, false));
    }

    #[test]
    fn read_at_reports_absent_invalid_and_loaded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.json");
        assert_eq!(
            read_managed_secrets_at(&path, false).status,
            ManagedSecretsStatus::Absent
        );

        std::fs::write(&path, r#"{"hub_pin": "123456"}"#).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            let read = read_managed_secrets_at(&path, false);
            assert_eq!(read.status, ManagedSecretsStatus::InsecurePermissions);
            assert!(read.secrets.is_none());
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            // With root ownership required, a file owned by anyone else is
            // refused. CI containers run the tests as root, where the file IS
            // root-owned and loads.
            use std::os::unix::fs::MetadataExt;
            let expected_when_root_required = if std::fs::metadata(&path).unwrap().uid() == 0 {
                ManagedSecretsStatus::Loaded
            } else {
                ManagedSecretsStatus::InsecurePermissions
            };
            assert_eq!(
                read_managed_secrets_at(&path, true).status,
                expected_when_root_required
            );
        }
        let read = read_managed_secrets_at(&path, false);
        assert_eq!(read.status, ManagedSecretsStatus::Loaded);
        assert_eq!(read.secrets.unwrap().hub_pin.as_deref(), Some("123456"));

        std::fs::write(&path, r#"{"pin": "123456"}"#).unwrap();
        let read = read_managed_secrets_at(&path, false);
        assert_eq!(read.status, ManagedSecretsStatus::Invalid);
        assert!(!read.detail.contains("123456"), "{}", read.detail);
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real.json");
        std::fs::write(&target, "{}").unwrap();
        let link = dir.path().join("secrets.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(
            read_managed_secrets_at(&link, false).status,
            ManagedSecretsStatus::InsecurePermissions
        );
    }

    #[test]
    fn read_secrets_round_trips_through_json() {
        // The helper serializes this struct over the utility-order channel.
        let read = ManagedSecretsRead {
            status: ManagedSecretsStatus::Loaded,
            detail: String::new(),
            secrets: Some(ManagedSecrets {
                hub_pin: Some("1".into()),
                hub_enrollment_token: None,
                llm_api_key: Some("k".into()),
            }),
        };
        let json = serde_json::to_string(&read).unwrap();
        let back: ManagedSecretsRead = serde_json::from_str(&json).unwrap();
        assert_eq!(back, read);
        assert!(json.contains("\"loaded\""));
    }

    /// The live store of this host: no profile is installed on a dev or CI
    /// machine, so the policy is empty (and reading never panics).
    #[test]
    fn live_store_reads_without_panicking() {
        let (source, policy) = read_managed_policy();
        if cfg!(any(target_os = "macos", target_os = "windows")) {
            assert_ne!(source, ManagedPolicySource::Unsupported);
        } else {
            assert_eq!(source, ManagedPolicySource::Unsupported);
            assert!(!policy.is_managed());
        }
    }
}
