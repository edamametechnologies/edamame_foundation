//! Shared secret redaction: the one place that knows what a secret looks like.
//!
//! Every surface that can carry a credential into a log line, a Sentry event,
//! an RPC trace or an excerpt served to a client funnels through here:
//!
//! - [`redact_text`]: known secret *shapes* anywhere in free text (EDAMAME
//!   `edm_` / `edak_` keys, Anthropic `sk-ant-`, OpenAI `sk-`, GitHub `ghp_` /
//!   `gho_` / `ghu_` / `ghs_` / `ghr_` / `github_pat_`, AWS `AKIA` / `ASIA`,
//!   Slack `xox?-` / `xapp-`, Google `AIza`, `Bearer` values, JWTs, PEM private
//!   key blocks, `user:password@` URL userinfo) plus the values of
//!   secret-named fields (`pin`, `password`, `api_key`, `*_token`, `secret`,
//!   `authorization`, ... in JSON, `key=value`, `key: value` and
//!   `--flag value` shapes).
//! - [`redact_log_line`]: [`redact_text`] plus the privacy keys the log files
//!   have always masked (`id`, `uuid`, `device`, `device_id`, `code`, ...).
//!   Used by the file / stdout / memory log writers and the Sentry scrubber.
//! - [`redact_json_value`] / [`redact_json_str`]: secret-named fields of a JSON
//!   document replaced whole, JSON nested inside string values included.
//! - [`redact_cli_args`]: the value after a secret-named flag in an argv.
//! - [`redact_url_credentials`]: the password in a URL authority and the value
//!   of secret-bearing query parameters.
//! - [`redact_secret_like_text`]: the `redacted_excerpt` privacy-tier masker for
//!   transcript- and file-derived excerpts (line-level, high-entropy aware).
//! - [`mask_presence`]: the `Debug` convention for a credential field
//!   (`"empty"` or `"[REDACTED]"`, never the value).
//!
//! Before 2.0.2 each of these lived next to one caller (the logger, core's RPC
//! tracer, the raw-session debug dump, agent_visibility) with diverging lists;
//! a shape one of them knew the others missed. Add a new shape here, with a
//! positive and a negative test, and every surface picks it up.

use lazy_static::lazy_static;
use regex::{Captures, Regex};
use serde_json::Value;

/// Replacement for a secret whose length is not preserved.
pub const REDACTED: &str = "[REDACTED]";

/// `Debug` / display convention for a credential field: `"empty"` when unset,
/// [`REDACTED`] otherwise. The value itself is never returned.
pub fn mask_presence(value: &str) -> &'static str {
    if value.is_empty() {
        "empty"
    } else {
        REDACTED
    }
}

// ---------------------------------------------------------------------------
// Secret-named fields
// ---------------------------------------------------------------------------

/// Field names whose value is a secret when they are the whole name.
const SECRET_EXACT_FIELDS: &[&str] = &[
    "pin",
    "key",
    "psk",
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
    "credential",
    "credentials",
    "cookie",
];

/// Name endings that make a field a secret with any `_` / `-` separated
/// prefix: `api_key`, `edamame_api_key`, `mcp_psk`, `oauth_refresh_token`,
/// `slack_bot_token`, `client_secret`, `edamame_pin`, `x-api-key`, ... Whole
/// segments only, so `finding_key`, `session_id` and `input_tokens` stay
/// readable.
const SECRET_FIELD_SUFFIXES: &[&str] = &[
    "api_key",
    "apikey",
    "access_key",
    "secret_key",
    "private_key",
    "psk",
    "secret",
    "token",
    "password",
    "passwd",
    "pin",
    "credential",
    "credentials",
    "pem",
    "cookie",
];

/// Privacy keys the log writers mask on top of the secrets (whole words,
/// case-sensitive, as the logger always did).
const LOG_PRIVACY_FIELDS: &[&str] = &["id", "uuid", "device", "Device ID", "device_id", "code"];

/// True when a field (JSON key, header, flag, env var) of this name carries a
/// secret. Case-insensitive; `-` and `_` are equivalent; a leading `--` / `-`
/// (CLI flag) is ignored.
pub fn is_secret_field_name(name: &str) -> bool {
    let normalized = name
        .trim()
        .trim_start_matches('-')
        .to_ascii_lowercase()
        .replace('-', "_");
    if normalized.is_empty() {
        return false;
    }
    if SECRET_EXACT_FIELDS.contains(&normalized.as_str()) {
        return true;
    }
    SECRET_FIELD_SUFFIXES.iter().any(|suffix| {
        normalized == *suffix
            || normalized
                .strip_suffix(suffix)
                .map(|prefix| prefix.ends_with('_'))
                .unwrap_or(false)
    })
}

/// Regex over `<name><sep><value>` for the given name alternation. The value
/// is masked with one `*` per character, keeping its own quoting (plain,
/// JSON-escaped or none).
fn build_named_field_regex(names: &str) -> Regex {
    // Keys and values may be JSON-escaped (`\"pin\":\"123456\"`) when a
    // JSON string is logged through Debug. A quoted value steps over its
    // escape pairs, so a PEM body (`\n`) or a password holding `\\` or
    // `\"` is masked whole instead of up to its first backslash; the
    // JSON-escaped form sees those as `\\n`, `\\\\` and `\\\"`, and ends
    // at the first `\"` that does not close one of them. `"[^"]+"` stays
    // as the fallback for a quoted value ending in a lone backslash. A
    // bare value may hold a backslash but not start with one, so the
    // backslash of an escaped key is never masked in place of a value.
    // A separator (`:`, `=` or whitespace) is required between name and
    // value, so `--pin-file` or `pin_llm_adjudication` are not read as a
    // `pin` followed by a value.
    let quoted = r#"(?:[^"\\]|\\.)+"#;
    let escaped = r#"(?:[^"\\]|\\[^"\\]|\\\\(?:\\.|[^"\\]))+"#;
    let pattern = format!(
        r#"(?P<key>\\?"?\b(?:{names})\b\\?"?(?:\s*[:=]\s*|\s+))(?:\\"(?P<escaped>{escaped})\\"|"(?P<quoted>{quoted})"|"(?P<raw>[^"]+)"|(?P<bare>\b[^\s",}}\\][^\s",}}]*))"#
    );
    Regex::new(&pattern).expect("Failed to compile named-field redaction regex")
}

fn secret_names_alternation() -> String {
    let exact = SECRET_EXACT_FIELDS
        .iter()
        .map(|k| regex::escape(k))
        .collect::<Vec<_>>()
        .join("|");
    let suffixes = SECRET_FIELD_SUFFIXES
        .iter()
        .map(|s| s.replace('_', "[_-]?"))
        .collect::<Vec<_>>()
        .join("|");
    format!(r#"(?i:(?:[A-Za-z0-9]+[_-])*(?:{suffixes})|{exact})"#)
}

lazy_static! {
    static ref SECRET_FIELD_REGEX: Regex = build_named_field_regex(&secret_names_alternation());
    static ref LOG_FIELD_REGEX: Regex = {
        let privacy = LOG_PRIVACY_FIELDS
            .iter()
            .map(|k| regex::escape(k))
            .collect::<Vec<_>>()
            .join("|");
        build_named_field_regex(&format!("{}|{}", secret_names_alternation(), privacy))
    };

    /// Known secret shapes, one alternation so a log line is scanned once.
    /// Group names say what was found; the whole match is replaced.
    static ref SECRET_SHAPE_REGEX: Regex = Regex::new(concat!(
        // PEM private key blocks (literal or `\n`-escaped newlines).
        r"(?P<pem>-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----)",
        // `Bearer <token>` (Authorization header values, curl -H lines).
        r"|(?P<bearer>(?i:\bbearer)\s+[A-Za-z0-9._~+/\-]{6,}=*)",
        // Other Authorization schemes, only in a header context (`basic`
        // alone is an ordinary word).
        r"|(?P<authz>(?i:\b(?:proxy-)?authorization)[\x22']?\s*[:=]\s*[\x22']?(?i:basic|digest|negotiate|ntlm)\s+)[A-Za-z0-9._~+/=\-]+",
        // EDAMAME Portal API keys.
        r"|(?P<edamame>\b(?:edm|edak)_[A-Za-z0-9_\-]{8,})",
        // Anthropic, then OpenAI (project / service-account / admin / legacy).
        r"|(?P<anthropic>\bsk-ant-[A-Za-z0-9_\-]{10,})",
        r"|(?P<openai>\bsk-(?:proj-|svcacct-|admin-|None-)?[A-Za-z0-9_\-]{16,})",
        // GitHub tokens: classic / OAuth / user-to-server / server / refresh, and fine-grained PATs.
        r"|(?P<github>\bgh[pousr]_[A-Za-z0-9]{20,}|\bgithub_pat_[A-Za-z0-9_]{20,})",
        // AWS access key ids.
        r"|(?P<aws>\b(?:AKIA|ASIA)[0-9A-Z]{16}\b)",
        // Slack bot / user / app tokens.
        r"|(?P<slack>\bxox[abposre]-[A-Za-z0-9\-]{10,}|\bxapp-[A-Za-z0-9\-]{10,})",
        // Google API keys.
        r"|(?P<google>\bAIza[0-9A-Za-z_\-]{30,})",
        // JWTs (OAuth access / id tokens).
        r"|(?P<jwt>\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*)",
        // user:password@ in a URL authority: keep the user, drop the password.
        r"|(?P<userinfo>://[^\s/:@]+:)[^\s/@]+@",
    ))
    .expect("Failed to compile secret shape regex");
}

/// Mask the known secret shapes anywhere in `text` (see module docs). Field
/// names are not consulted; a key that fits none of the shapes survives here
/// and is caught by [`redact_text`]'s named-field pass.
pub fn redact_secret_tokens(text: &str) -> String {
    SECRET_SHAPE_REGEX
        .replace_all(text, |caps: &Captures| {
            if caps.name("bearer").is_some() {
                format!("Bearer {}", REDACTED)
            } else if let Some(prefix) = caps.name("authz") {
                format!("{}{}", prefix.as_str(), REDACTED)
            } else if let Some(prefix) = caps.name("userinfo") {
                format!("{}{}@", prefix.as_str(), REDACTED)
            } else {
                REDACTED.to_string()
            }
        })
        .into_owned()
}

/// Authorization scheme words: the shape pass has already masked the
/// credential that follows them, and keeping the scheme keeps the line
/// readable (`Authorization: Bearer [REDACTED]`).
fn is_auth_scheme(value: &str) -> bool {
    ["bearer", "basic", "digest", "negotiate", "ntlm"]
        .iter()
        .any(|scheme| value.eq_ignore_ascii_case(scheme))
}

fn mask_field_values(regex: &Regex, input: &str) -> String {
    regex
        .replace_all(input, |caps: &Captures| {
            let key = &caps["key"];
            if let Some(bare) = caps.name("bare") {
                if is_auth_scheme(bare.as_str()) {
                    return caps[0].to_string();
                }
            }
            // Keep the value's own quoting (JSON-escaped, plain or none).
            let (quote, value) = if let Some(m) = caps.name("escaped") {
                ("\\\"", m.as_str())
            } else if let Some(m) = caps.name("quoted").or_else(|| caps.name("raw")) {
                ("\"", m.as_str())
            } else {
                ("", caps.name("bare").map_or("", |m| m.as_str()))
            };
            format!(
                "{}{}{}{}",
                key,
                quote,
                "*".repeat(value.chars().count()),
                quote
            )
        })
        .into_owned()
}

/// Mask the values of secret-named fields (`pin: 123456`, `"api_key":"..."`,
/// `password=...`, `--pin 123456`, `Authorization: ...`), one `*` per
/// character. Shapes are not consulted.
pub fn redact_named_fields(text: &str) -> String {
    mask_field_values(&SECRET_FIELD_REGEX, text)
}

/// Secrets out of free text: known shapes first, then secret-named fields.
/// The general-purpose entry point for anything about to be logged, traced,
/// reported or shown.
pub fn redact_text(text: &str) -> String {
    redact_named_fields(&redact_secret_tokens(text))
}

/// [`redact_text`] plus the privacy keys the log writers have always masked
/// (`id`, `uuid`, `device`, `device_id`, `code`). For log lines and the Sentry
/// scrubber; not for text shown to the operator, where ids are useful.
pub fn redact_log_line(text: &str) -> String {
    mask_field_values(&LOG_FIELD_REGEX, &redact_secret_tokens(text))
}

// ---------------------------------------------------------------------------
// Structured payloads
// ---------------------------------------------------------------------------

/// Replace every secret-named field of a JSON document with [`REDACTED`]
/// (nulls stay null so "unset" remains visible). String values are scanned
/// for secret shapes, and a string that itself holds a JSON object or array
/// (RPC arguments travel that way) is redacted recursively.
pub fn redact_json_value(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (name, field) in map.iter_mut() {
                if is_secret_field_name(name) && !field.is_null() {
                    *field = Value::String(REDACTED.to_string());
                } else {
                    redact_json_value(field);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(redact_json_value),
        Value::String(text) => {
            if let Ok(mut inner) = serde_json::from_str::<Value>(text) {
                if inner.is_object() || inner.is_array() {
                    redact_json_value(&mut inner);
                    *text = inner.to_string();
                    return;
                }
            }
            let scrubbed = redact_secret_tokens(text);
            if scrubbed != *text {
                *text = scrubbed;
            }
        }
        _ => {}
    }
}

/// A JSON document made safe to log; text that is not JSON goes through
/// [`redact_text`].
pub fn redact_json_str(raw: &str) -> String {
    match serde_json::from_str::<Value>(raw) {
        Ok(mut value) => {
            redact_json_value(&mut value);
            value.to_string()
        }
        Err(_) => redact_text(raw),
    }
}

/// An argv made safe to print: the value after a secret-named flag
/// (`--pin 123456`, `--llm-api-key=...`) and any extra flags the caller names
/// (short forms such as `-p`, `-k`) is replaced with [`REDACTED`]; every other
/// argument goes through [`redact_secret_tokens`].
pub fn redact_cli_args<S: AsRef<str>>(args: &[S], extra_secret_flags: &[&str]) -> Vec<String> {
    let is_secret_flag = |flag: &str| {
        flag.starts_with('-') && (is_secret_field_name(flag) || extra_secret_flags.contains(&flag))
    };
    let mut out = Vec::with_capacity(args.len());
    let mut mask_next = false;
    for arg in args {
        let arg = arg.as_ref();
        if mask_next {
            out.push(REDACTED.to_string());
            mask_next = false;
            continue;
        }
        if let Some((flag, _)) = arg.split_once('=') {
            if is_secret_flag(flag) {
                out.push(format!("{}={}", flag, REDACTED));
                continue;
            }
        }
        if is_secret_flag(arg) {
            mask_next = true;
            out.push(arg.to_string());
            continue;
        }
        out.push(redact_secret_tokens(arg));
    }
    out
}

// ---------------------------------------------------------------------------
// URLs and excerpts (moved from agent_visibility in 2.0.2, behaviour unchanged
// apart from the `edm_` / `edak_` prefixes the excerpt masker now knows)
// ---------------------------------------------------------------------------

/// Query-parameter keys that conventionally carry a credential. Matched
/// case-insensitively. Only the *presence* of the key is ever used; the value
/// is never read or stored (invariant I5).
pub fn is_secret_query_key(key: &str) -> bool {
    matches!(
        key.trim().to_ascii_lowercase().as_str(),
        "secret"
            | "token"
            | "access_token"
            | "accesstoken"
            | "refresh_token"
            | "api_key"
            | "apikey"
            | "api-key"
            | "key"
            | "auth"
            | "authorization"
            | "password"
            | "passwd"
            | "pwd"
            | "sig"
            | "signature"
    )
}

/// Redact inline credentials from a URL for storage / display / hashing: drop
/// the password from a `user:pass@` authority and rewrite any secret-bearing
/// query-parameter value to `REDACTED`. The raw secret is never stored
/// (invariant I5); redacting before the id hash also keeps the endpoint id
/// stable across secret rotation.
pub fn redact_url_credentials(url: &str) -> String {
    let (base, rest) = match url.split_once('?') {
        Some((b, r)) => (b.to_string(), Some(r.to_string())),
        None => (url.to_string(), None),
    };
    let mut out = redact_userinfo(&base);
    if let Some(rest) = rest {
        let (query, frag) = match rest.split_once('#') {
            Some((q, f)) => (q.to_string(), Some(f.to_string())),
            None => (rest, None),
        };
        let redacted_query = query
            .split('&')
            .map(|pair| match pair.split_once('=') {
                Some((k, _)) if is_secret_query_key(k) => format!("{}=REDACTED", k),
                _ => pair.to_string(),
            })
            .collect::<Vec<_>>()
            .join("&");
        out.push('?');
        out.push_str(&redacted_query);
        if let Some(frag) = frag {
            out.push('#');
            out.push_str(&frag);
        }
    }
    out
}

/// Strip the password from a `scheme://user:pass@host/...` authority, keeping
/// only `scheme://user@host/...`. Authority-free inputs pass through unchanged.
fn redact_userinfo(base: &str) -> String {
    let (scheme, rest) = match base.split_once("://") {
        Some((s, r)) => (Some(s), r),
        None => (None, base),
    };
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a.to_string(), Some(p.to_string())),
        None => (rest.to_string(), None),
    };
    let authority = match authority.split_once('@') {
        Some((userinfo, host)) => {
            let user = userinfo.split(':').next().unwrap_or("");
            if user.is_empty() {
                host.to_string()
            } else {
                format!("{}@{}", user, host)
            }
        }
        None => authority,
    };
    let mut out = String::new();
    if let Some(s) = scheme {
        out.push_str(s);
        out.push_str("://");
    }
    out.push_str(&authority);
    if let Some(p) = path {
        out.push('/');
        out.push_str(&p);
    }
    out
}

/// Key-name hints that mark a `key = value` / `key: value` line as carrying a
/// secret value to mask at the `redacted_excerpt` tier.
const SECRET_KEY_HINTS: &[&str] = &[
    "secret",
    "token",
    "password",
    "passwd",
    "pwd",
    "api_key",
    "apikey",
    "api-key",
    "access_key",
    "private_key",
    "client_secret",
    "auth",
    "bearer",
    "credential",
    "session_key",
];

/// Standalone token prefixes that are masked wherever they appear, regardless
/// of the surrounding line shape.
const SECRET_TOKEN_PREFIXES: &[&str] = &[
    "sk-",
    "edm_",
    "edak_",
    "ghp_",
    "gho_",
    "ghs_",
    "github_pat_",
    "xox",
    "akia",
    "asia",
    "aiza",
    "ya29.",
    "eyj",
];

fn char_is_token(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '_' | '-' | '=' | '.')
}

/// True when `tok` looks like a high-entropy secret: a known secret prefix, or a
/// long mixed alphanumeric run (>= 28 chars with at least one digit and one
/// letter). Conservative on purpose -- this is defense in depth behind the tier
/// gate, not the primary control.
fn token_looks_secret(tok: &str) -> bool {
    let lower = tok.to_ascii_lowercase();
    if SECRET_TOKEN_PREFIXES
        .iter()
        .any(|p| lower.starts_with(p) && tok.len() >= p.len() + 6)
    {
        return true;
    }
    if tok.len() < 28 {
        return false;
    }
    let has_digit = tok.chars().any(|c| c.is_ascii_digit());
    let has_alpha = tok.chars().any(|c| c.is_ascii_alphabetic());
    let all_token = tok.chars().all(char_is_token);
    has_digit && has_alpha && all_token
}

/// A token that starts like a filesystem path (`/`, `~/`, `./`, `../`). Base64
/// secrets can contain `/` too, but they do not start with one of these.
fn token_looks_like_path(tok: &str) -> bool {
    tok.starts_with('/') || tok.starts_with("~/") || tok.starts_with("./") || tok.starts_with("../")
}

/// Mask secret-like spans in `line`. Returns the (possibly rewritten) line and
/// whether anything was masked.
fn redact_secret_line(line: &str) -> (String, bool) {
    let mut masked = false;

    // 1. `key <sep> value` where the key name hints at a secret.
    if let Some(sep_idx) = line.find([':', '=']) {
        let (key, rest) = line.split_at(sep_idx);
        let key_lower = key.to_ascii_lowercase();
        if SECRET_KEY_HINTS.iter().any(|h| key_lower.contains(h)) {
            let sep = &rest[..1];
            let value = &rest[1..];
            if !value.trim().is_empty() {
                let leading_ws: String = value.chars().take_while(|c| c.is_whitespace()).collect();
                return (format!("{key}{sep}{leading_ws}REDACTED"), true);
            }
        }
    }

    // 2. Standalone high-entropy tokens anywhere in the line.
    let mut out = String::with_capacity(line.len());
    let mut cur = String::new();
    let flush = |cur: &mut String, out: &mut String, masked: &mut bool| {
        if !cur.is_empty() {
            if token_looks_like_path(cur) {
                // A path is judged segment by segment: a long absolute path
                // with a digit anywhere is not a secret, a secret-looking
                // segment inside it still is.
                for (index, segment) in cur.split('/').enumerate() {
                    if index > 0 {
                        out.push('/');
                    }
                    if token_looks_secret(segment) {
                        out.push_str("REDACTED");
                        *masked = true;
                    } else {
                        out.push_str(segment);
                    }
                }
            } else if token_looks_secret(cur) {
                out.push_str("REDACTED");
                *masked = true;
            } else {
                out.push_str(cur);
            }
            cur.clear();
        }
    };
    for c in line.chars() {
        if char_is_token(c) {
            cur.push(c);
        } else {
            flush(&mut cur, &mut out, &mut masked);
            out.push(c);
        }
    }
    flush(&mut cur, &mut out, &mut masked);
    (out, masked)
}

/// Apply line-level secret redaction to `text`. Returns the redacted text and
/// the number of lines that had a value masked.
///
/// The `redacted_excerpt`-tier masker for every transcript- or file-derived
/// excerpt: instruction bodies here, and in core the recorder titles,
/// commands and tool-error text served over RPC and MCP.
pub fn redact_secret_like_text(text: &str) -> (String, usize) {
    let mut redacted_lines = 0usize;
    let mut out = String::with_capacity(text.len());
    for segment in text.split_inclusive('\n') {
        let (body, nl) = match segment.strip_suffix('\n') {
            Some(b) => (b, "\n"),
            None => (segment, ""),
        };
        let (line, masked) = redact_secret_line(body);
        if masked {
            redacted_lines += 1;
        }
        out.push_str(&line);
        out.push_str(nl);
    }
    (out, redacted_lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Built at runtime so the source never carries a token-shaped literal a
    // secret scanner would flag.
    fn fake(prefix: &str, body_len: usize) -> String {
        let alphabet = b"AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
        let body: String = (0..body_len)
            .map(|i| alphabet[i % alphabet.len()] as char)
            .collect();
        format!("{prefix}{body}")
    }

    #[test]
    fn every_known_secret_shape_is_masked() {
        let jwt = format!("{}.{}.{}", fake("eyJ", 20), fake("eyJ", 30), fake("", 20));
        let cases = [
            fake("edm_live_", 24),
            fake("edak_", 24),
            fake("sk-ant-api03-", 40),
            fake("sk-proj-", 40),
            fake("sk-", 32),
            fake("ghp_", 36),
            fake("gho_", 36),
            fake("ghs_", 36),
            fake("github_pat_", 60),
            "AKIAIOSFODNN7EXAMPLE".to_string(),
            "ASIAIOSFODNN7EXAMPL3".to_string(),
            fake("xoxb-", 40),
            fake("xoxp-", 40),
            fake("xapp-1-", 30),
            fake("AIza", 35),
            jwt,
        ];
        for secret in cases {
            let text = format!("request failed ({secret}) retrying");
            let out = redact_text(&text);
            assert!(!out.contains(&secret), "{secret} leaked: {out}");
            assert!(out.contains(REDACTED), "{out}");
            assert!(
                out.starts_with("request failed (") && out.ends_with(") retrying"),
                "{out}"
            );
        }
    }

    #[test]
    fn bearer_values_and_url_passwords_are_masked() {
        let out = redact_text(
            "curl -H 'Authorization: Bearer abcDEF123456789.xyz' https://api.example.com",
        );
        assert!(!out.contains("abcDEF123456789"), "{out}");
        assert!(out.contains("https://api.example.com"), "{out}");

        let out = redact_text("connecting to postgres://admin:s3cr3tpass@db.internal:5432/app");
        assert_eq!(
            out,
            "connecting to postgres://admin:[REDACTED]@db.internal:5432/app"
        );
    }

    #[test]
    fn pem_private_key_blocks_are_masked() {
        let pem =
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----";
        let out = redact_text(&format!("loaded {pem} ok"));
        assert_eq!(out, "loaded [REDACTED] ok");
        // A public key or certificate is not a secret.
        let cert = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----";
        assert_eq!(redact_text(cert), cert);
    }

    #[test]
    fn secret_named_fields_are_masked_in_every_shape() {
        for (input, leaked) in [
            (r#"{"pin":"123456"}"#, "123456"),
            (r#"{"edamame_pin": "123456"}"#, "123456"),
            (
                "Connected with user: bob, domain: x.com with pin: 123456",
                "123456",
            ),
            ("PIN 654321 accepted", "654321"),
            ("edamame_posture start --pin 123456 --user bob", "123456"),
            ("password=hunter2 user=bob", "hunter2"),
            ("x-api-key: plainvalue", "plainvalue"),
            ("EDAMAME_LLM_API_KEY=plainvalue", "plainvalue"),
            (
                r#"LLMConfig { api_key: "plainvalue", model: "m" }"#,
                "plainvalue",
            ),
            ("oauth_refresh_token=rt-plain", "rt-plain"),
            ("client_secret: s3", "s3"),
            ("Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
            (r#"{"authorization": "Basic dXNlcjpwYXNz"}"#, "dXNlcjpwYXNz"),
            ("Authorization: Bearer abcdefgh", "abcdefgh"),
        ] {
            let out = redact_text(input);
            assert!(
                !out.contains(leaked),
                "{leaked} leaked from {input:?}: {out}"
            );
        }
    }

    #[test]
    fn ordinary_text_is_left_alone() {
        for text in [
            r#"{"finding_key": "vuln:abc", "session_id": "s-1", "input_tokens": 1200}"#,
            "LLM decision: allow (tokens: 1200/80)",
            "skip-this task-force desk-top sk-short",
            "sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "AKIAshort and ghp_short and edm_short",
            "pin_llm_adjudication_when_auto ran; --pin-file /etc/edamame/pin",
            "shipping ping pinned spinner",
            "basic validation failed; the bearer of bad news",
            "http://localhost:11434/api/generate",
            "uuid 3f2504e0-4f89-11d3-9a0c-0305e82c3301",
        ] {
            assert_eq!(redact_text(text), text, "over-redacted");
        }
    }

    #[test]
    fn log_lines_also_mask_the_privacy_keys() {
        let out = redact_log_line(r#"{"id": "12345", "device_id": "abc", "user": "bob"}"#);
        assert_eq!(out, r#"{"id": "*****", "device_id": "***", "user": "bob"}"#);
        // Operator-facing text keeps ids.
        let text = r#"{"id": "12345"}"#;
        assert_eq!(redact_text(text), text);
    }

    #[test]
    fn secret_field_names() {
        for name in [
            "pin",
            "PIN",
            "edamame_pin",
            "--pin",
            "api_key",
            "apiKey",
            "x-api-key",
            "--llm-api-key",
            "edamame_api_key",
            "mcp_psk",
            "oauth_access_token",
            "slack_bot_token",
            "client_secret",
            "Authorization",
            "private_key",
            "aws_secret_access_key",
            "password",
            "credentials",
        ] {
            assert!(is_secret_field_name(name), "{name} should be secret");
        }
        for name in [
            "finding_key",
            "session_id",
            "input_tokens",
            "token_count",
            "pin_file",
            "--pin-file",
            "pinned",
            "model",
            "provider",
            "",
        ] {
            assert!(!is_secret_field_name(name), "{name} should not be secret");
        }
    }

    #[test]
    fn json_documents_are_redacted_recursively() {
        let edm = fake("edm_live_", 24);
        let doc = serde_json::json!({
            "provider": "claude",
            "api_key": "sk-plain",
            "pin": "1234",
            "finding_key": "fk",
            "input_tokens": 12,
            "oauth_id_token": null,
            "nested": { "llm_config": format!("{{\"edamame_api_key\":\"{edm}\",\"model\":\"m\"}}") },
            "free_text": format!("key is {edm}"),
        });
        let out = redact_json_str(&doc.to_string());
        assert!(!out.contains("sk-plain") && !out.contains("1234"), "{out}");
        assert!(!out.contains(&edm), "{out}");
        assert!(out.contains(r#""finding_key":"fk""#), "{out}");
        assert!(out.contains(r#""input_tokens":12"#), "{out}");
        assert!(
            out.contains(r#""oauth_id_token":null"#),
            "unset stays visible: {out}"
        );
        assert!(out.contains("model"), "{out}");
        // Not JSON: plain text redaction.
        assert_eq!(redact_json_str("psk=abc"), "psk=***");
    }

    #[test]
    fn cli_args_are_redacted() {
        let key = fake("edm_live_", 24);
        let args = [
            "edamame_posture",
            "start",
            "--user",
            "bob",
            "--pin",
            "123456",
            "-p",
            "654321",
            "--llm-api-key=secret-value",
            "--pin-file",
            "/etc/pin",
            &key,
        ];
        let out = redact_cli_args(&args, &["-p"]);
        assert_eq!(
            out,
            vec![
                "edamame_posture",
                "start",
                "--user",
                "bob",
                "--pin",
                REDACTED,
                "-p",
                REDACTED,
                "--llm-api-key=[REDACTED]",
                "--pin-file",
                "/etc/pin",
                REDACTED,
            ]
        );
    }

    #[test]
    fn mask_presence_never_returns_the_value() {
        assert_eq!(mask_presence(""), "empty");
        assert_eq!(mask_presence("hunter2"), REDACTED);
    }

    #[test]
    fn url_credentials_are_redacted_for_storage() {
        assert_eq!(
            redact_url_credentials("https://user:pass@host/p?token=abc&x=1#f"),
            "https://user@host/p?token=REDACTED&x=1#f"
        );
        assert!(is_secret_query_key("Access_Token"));
        assert!(!is_secret_query_key("page"));
    }

    #[test]
    fn excerpt_masker_knows_edamame_keys() {
        let key = fake("edm_live_", 24);
        let (out, n) = redact_secret_like_text(&format!("using {key} now"));
        assert!(!out.contains(&key), "{out}");
        assert_eq!(n, 1);
    }
}
