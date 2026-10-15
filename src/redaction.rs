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
//!   `authorization`, ... in JSON, `key=value`, `key: value`,
//!   `--flag value` and `name value` shapes).
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
    "pwd",
    "secret",
    "token",
    "authorization",
    "credential",
    "credentials",
    "cookie",
];

/// Name endings that make a field a secret with any `_` / `-` separated
/// prefix: `api_key`, `edamame_api_key`, `mcp_psk`, `oauth_refresh_token`,
/// `slack_bot_token`, `client_secret`, `edamame_pin`, `x-api-key`,
/// `mysql_pwd`, ... Whole segments only, so `finding_key`, `session_id` and
/// `input_tokens` stay readable.
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
    "pwd",
    "pin",
    "credential",
    "credentials",
    "pem",
    "cookie",
];

/// Privacy keys the log writers mask on top of the secrets (whole words,
/// case-sensitive, as the logger always did).
const LOG_PRIVACY_FIELDS: &[&str] = &["id", "uuid", "device", "Device ID", "device_id", "code"];

/// Name endings, compared without `_` and `-`, whose value is a secret
/// whatever it looks like: after one of them a plain word is a value too
/// (`password hunter`) and a small number is no exemption (`pin: 123`). The
/// other names (`key`, `credentials`, `cookie`, `authorization`, `pem` and
/// the privacy keys) are also ordinary words of log text.
const STRONG_SECRET_SUFFIXES: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "psk",
    "pin",
    "secret",
    "token",
    "apikey",
    "accesskey",
    "secretkey",
    "privatekey",
];

/// Words that are prose, not a value, after a strongly secret name and
/// spaces alone: function words, and the words EDAMAME's log lines,
/// notifications and threat names put after such a name (`token required`,
/// `secret store unavailable`, `password is too weak`, `no password
/// manager`, `PIN success flag`, `daily token budget`, `Token URL:`). Any
/// other plain word there is masked (`password hunter`). A password that is
/// exactly one of these words reads through: the price of those lines
/// staying readable.
const PROSE_AFTER_SECRET_NAME: &str = concat!(
    "a an the this that these those it its and or nor but not no never yet so if as at by ",
    "for from in into of on per than then to via with without is are was were be been ",
    "being has have had do does did will would can cannot could may might must should ",
    "still already also only now again here isn't aren't wasn't weren't hasn't haven't ",
    "doesn't don't didn't won't can't couldn't shouldn't wouldn't ",
    "accepted access auth authentication available budget called changed configured ",
    "content data disabled empty enabled endpoint exchange expired expires exposure ",
    "failed file flag found hint hints insufficient invalid length loaded manager ",
    "material missing permissions prompt refresh refreshed rejected removed required ",
    "reset rotated rotation saved scan set signal stats store stored strengths success ",
    "successfully type unavailable unset updated url usage valid validated validation ",
    "verified waste",
);

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

/// How a named field is written (see [`FIELD_SHAPES`]).
#[derive(Clone, Copy, PartialEq, Eq)]
enum ShapeKind {
    Flag,
    Pair,
    Spaced,
}

/// Capture groups of one way a named field is written (see
/// [`build_named_field_regex`]).
struct FieldShape {
    kind: ShapeKind,
    key: &'static str,
    name: &'static str,
    escaped: &'static str,
    quoted: &'static str,
    raw: &'static str,
    single: &'static str,
    bare: &'static str,
}

/// The ways a named field is written: a CLI flag (`--pin 123456`,
/// `--llm-api-key=...`), a pair (`pin: 123456`, `"api_key":"..."`,
/// `password=...`), and a name and value apart by spaces only
/// (`PIN 654321 accepted`).
const FIELD_SHAPES: [FieldShape; 3] = [
    FieldShape {
        kind: ShapeKind::Flag,
        key: "flag_key",
        name: "flag_name",
        escaped: "flag_escaped",
        quoted: "flag_quoted",
        raw: "flag_raw",
        single: "flag_single",
        bare: "flag_bare",
    },
    FieldShape {
        kind: ShapeKind::Pair,
        key: "pair_key",
        name: "pair_name",
        escaped: "pair_escaped",
        quoted: "pair_quoted",
        raw: "pair_raw",
        single: "pair_single",
        bare: "pair_bare",
    },
    FieldShape {
        kind: ShapeKind::Spaced,
        key: "spaced_key",
        name: "spaced_name",
        escaped: "spaced_escaped",
        quoted: "spaced_quoted",
        raw: "spaced_raw",
        single: "spaced_single",
        bare: "spaced_bare",
    },
];

/// Regex over `<name><sep><value>` for the given name alternation, in the
/// three [`FIELD_SHAPES`]. Which values are masked is decided in
/// [`NamedFields::mask`].
fn build_named_field_regex(names: &str) -> Regex {
    // Keys and values may be JSON-escaped (`\"pin\":\"123456\"`) when a
    // JSON string is logged through Debug. A quoted value steps over its
    // escape pairs, so a PEM body (`\n`) or a password holding `\\` or
    // `\"` is masked whole instead of up to its first backslash; the
    // JSON-escaped form sees those as `\\n`, `\\\\` and `\\\"`, and ends
    // at the first `\"` that does not close one of them. `"[^"]+"` stays
    // as the fallback for a quoted value ending in a lone backslash. A
    // single-quoted value runs to its closing quote on the same line
    // (`--password 'correct horse'`).
    let quoted = r#"(?:[^"\\]|\\.)+"#;
    let escaped = r#"(?:[^"\\]|\\[^"\\]|\\\\(?:\\.|[^"\\]))+"#;
    // A bare value runs to the next space, `"`, `,` or `}`. It may start
    // with a quote or a symbol (`'hunter2`, `$ecret99`, `!Passw0rd`, `-1`),
    // but not with a backslash (the backslash of an escaped key is never
    // masked in place of a value), a bracket (`[REDACTED]`, `(none)`, the
    // `{` of a nested struct), `:`, `=` or `&` (`token::refresh`, `pin ==
    // 0`, `pin: &str`), or a dash before anything but a digit (the next
    // flag in `--password --user bob`).
    let bare = r#"(?:[^\s",}\\()\[\]{<>:=&-]|-[0-9.])[^\s",}]*"#;
    let value = |shape: &FieldShape| {
        format!(
            r#"(?:\\"(?P<{}>{escaped})\\"|"(?P<{}>{quoted})"|"(?P<{}>[^"]+)"|'(?P<{}>[^'\n]+)'|(?P<{}>{bare}))"#,
            shape.escaped, shape.quoted, shape.raw, shape.single, shape.bare
        )
    };
    let [flag, pair, spaced] = &FIELD_SHAPES;
    // A separator is required between name and value, so `--pin-file` or
    // `pin_llm_adjudication` are not read as a `pin` followed by a value.
    // A flag's dashes start the text or follow a character that is no
    // letter, digit or `_` (` --pin`, `ARGS=--password`, `"--pin`), so
    // `well-known-token` is no flag. A flag or a pair steps over the `Some(`
    // of an `Option` around its value. A pair's name may be quoted either
    // way (`"pin":`, `'password':`, `\"pin\":`).
    let pattern = [
        format!(
            r#"(?P<{}>\B--?\b(?P<{}>{names})\b(?:\s*=\s*|\s+)(?:Some\()?){}"#,
            flag.key,
            flag.name,
            value(flag)
        ),
        format!(
            r#"(?P<{}>\\?["']?\b(?P<{}>{names})\b\\?["']?\s*[:=]\s*(?:Some\()?){}"#,
            pair.key,
            pair.name,
            value(pair)
        ),
        format!(
            r#"(?P<{}>\b(?P<{}>{names})\b\s+){}"#,
            spaced.key,
            spaced.name,
            value(spaced)
        ),
    ]
    .join("|");
    Regex::new(&pattern).expect("Failed to compile named-field redaction regex")
}

/// Whether a field of this name (as [`build_named_field_regex`] matched it)
/// holds a secret whatever its value looks like ([`STRONG_SECRET_SUFFIXES`]).
fn is_strong_secret_name(name: &str) -> bool {
    let compact: String = name
        .chars()
        .filter(|c| !matches!(c, '_' | '-'))
        .map(|c| c.to_ascii_lowercase())
        .collect();
    STRONG_SECRET_SUFFIXES
        .iter()
        .any(|suffix| compact.ends_with(suffix))
}

/// Punctuation that ends a word of prose (`token required.`, `password
/// hunter,`): it does not make the word a value.
const TRAILING_PUNCTUATION: [char; 8] = ['.', ',', ':', ';', '!', '?', ')', ']'];

/// Letters, `_`, `'` and `-` only: a word of prose or an identifier, with
/// no digit or symbol.
fn is_plain_word(word: &str) -> bool {
    word.chars()
        .all(|c| c.is_alphabetic() || matches!(c, '_' | '\'' | '-'))
}

fn is_prose_after_secret_name(word: &str) -> bool {
    PROSE_AFTER_SECRET_NAME
        .split_ascii_whitespace()
        .any(|prose| word.eq_ignore_ascii_case(prose))
}

/// After a name that is not strongly secret and spaces alone, a word is a
/// value when it starts with a letter, a digit or `_` and holds a digit or a
/// symbol (`device 4f3c2a1b...`, `code 1168`, `uuid 3f2504e0-...`), or is a
/// run of 16 letters or more (`key ABCDEFGHIJKLMNOP`). Any other word is
/// prose (`device type`, `credentials enabled`, `code is`, `key isn't`, `id
/// 'privacy'`).
fn word_is_value_after_weak_name(word: &str) -> bool {
    let body = word.trim_end_matches(TRAILING_PUNCTUATION);
    let letter_run = body.chars().count() >= 16 && body.chars().all(char::is_alphabetic);
    word.starts_with(|c: char| c.is_alphanumeric() || c == '_')
        && (!is_plain_word(body) || letter_run)
}

/// Bare values that hide nothing, so they stay readable: booleans and unset
/// markers (`false`, `None`, `null`) after any name; after a name that is
/// not strongly secret, a number of at most three integer digits and two
/// decimals (`48`, `3.65`, `-1`: sub-scores, counts, event ids; under ten
/// bits, nothing a key or an identifier is made of); and after `code`, a
/// status or error code ([`is_status_code`]). A quoted value is never
/// exempt, nor is anything else: an ambiguous field stays masked.
fn bare_value_hides_nothing(name: &str, value: &str) -> bool {
    let value = value.trim_end_matches([')', ']', ';', ',', '.', ':']);
    ["true", "false", "none", "null"]
        .iter()
        .any(|word| value.eq_ignore_ascii_case(word))
        || (!is_strong_secret_name(name) && is_small_number(value))
        || (name == "code" && is_status_code(value))
}

/// At most three integer digits and two decimals, an optional sign.
fn is_small_number(value: &str) -> bool {
    let unsigned = value.strip_prefix('-').unwrap_or(value);
    let (integer, fraction) = match unsigned.split_once('.') {
        Some((integer, fraction)) => (integer, Some(fraction)),
        None => (unsigned, None),
    };
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
    integer.len() <= 3
        && digits(integer)
        && fraction.is_none_or(|fraction| fraction.len() <= 2 && digits(fraction))
}

/// A status or error code: at most four decimal digits (`400`, `1168`), a
/// negative number (`-2147024891`, `-32601`: HRESULTs and JSON-RPC errors
/// written signed), a hex code (`0x80070005`) or a name made of letters and
/// `_` (`Unavailable`, `ConnectionRefused`, `ERROR_ACCESS_DENIED`). Five
/// digits or more are never a status code here, Windows socket errors
/// (`10061`) included: one-time codes and PINs are written that way
/// (`code: 482913`).
fn is_status_code(value: &str) -> bool {
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
    let decimal = value.len() <= 4 && digits(value);
    let negative = value.strip_prefix('-').is_some_and(digits);
    let hex = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .is_some_and(|hex| !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit()));
    let name = value.starts_with(|c: char| c.is_ascii_alphabetic())
        && value.bytes().all(|b| b.is_ascii_alphabetic() || b == b'_');
    decimal || negative || hex || name
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
    static ref SECRET_FIELDS: NamedFields = NamedFields::new(&secret_names_alternation());
    static ref LOG_FIELDS: NamedFields = {
        let privacy = LOG_PRIVACY_FIELDS
            .iter()
            .map(|k| regex::escape(k))
            .collect::<Vec<_>>()
            .join("|");
        NamedFields::new(&format!("{}|{}", secret_names_alternation(), privacy))
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

/// One named-field pass: the field regex, and the names alone (a word after
/// a name that is itself a name is not its value).
struct NamedFields {
    fields: Regex,
    name: Regex,
}

impl NamedFields {
    fn new(names: &str) -> Self {
        Self {
            fields: build_named_field_regex(names),
            name: Regex::new(&format!("^(?:{names})$"))
                .expect("Failed to compile field name regex"),
        }
    }

    /// Mask the field values in `input`, one `*` per character, keeping the
    /// value's own quoting (JSON-escaped, double, single or none). A match
    /// whose value hides nothing is left as it is and the search goes on
    /// from its value, so a word that is no value can still name the field
    /// that follows it (`Secret connection_pin: 123456`).
    fn mask(&self, input: &str) -> String {
        let mut out = String::with_capacity(input.len());
        let mut copied = 0;
        let mut at = 0;
        while let Some(caps) = self.fields.captures_at(input, at) {
            let (Some(whole), Some((shape, key))) = (
                caps.get(0),
                FIELD_SHAPES
                    .iter()
                    .find_map(|shape| caps.name(shape.key).map(|key| (shape, key))),
            ) else {
                break;
            };
            let name = caps.name(shape.name).map_or("", |m| m.as_str());
            let (quote, value) = if let Some(m) = caps.name(shape.escaped) {
                ("\\\"", m)
            } else if let Some(m) = caps.name(shape.quoted).or_else(|| caps.name(shape.raw)) {
                ("\"", m)
            } else if let Some(m) = caps.name(shape.single) {
                ("'", m)
            } else if let Some(m) = caps.name(shape.bare) {
                ("", m)
            } else {
                break;
            };
            let secret = match quote {
                "" => {
                    self.bare_value_is_secret(input, shape.kind, key.start(), name, value.as_str())
                }
                // After spaces alone and a weaker name, a quoted word is
                // prose unless a word in it is a value (`id 'privacy'`).
                "'" if shape.kind == ShapeKind::Spaced && !is_strong_secret_name(name) => value
                    .as_str()
                    .split_whitespace()
                    .any(word_is_value_after_weak_name),
                _ => true,
            };
            if secret {
                out.push_str(&input[copied..key.start()]);
                out.push_str(key.as_str());
                out.push_str(quote);
                out.push_str(&"*".repeat(value.as_str().chars().count()));
                out.push_str(quote);
                copied = whole.end();
                at = copied;
            } else {
                at = value.start();
            }
        }
        out.push_str(&input[copied..]);
        out
    }

    /// Whether a bare (unquoted) value is a secret to mask. In a URL query
    /// (`?code=`, `&device_id=`) every value is; after spaces alone the word
    /// has to read as a value ([`Self::spaced_word_is_value`]); then booleans,
    /// unset markers, small numbers, status codes and authorization schemes
    /// stay readable ([`bare_value_hides_nothing`]).
    fn bare_value_is_secret(
        &self,
        input: &str,
        kind: ShapeKind,
        key_start: usize,
        name: &str,
        value: &str,
    ) -> bool {
        if kind == ShapeKind::Pair && input[..key_start].ends_with(['?', '&', '#']) {
            return true;
        }
        if kind == ShapeKind::Spaced && !self.spaced_word_is_value(name, value) {
            return false;
        }
        !(is_auth_scheme(value) || bare_value_hides_nothing(name, value))
    }

    /// Whether a word after a name and spaces alone is the name's value
    /// rather than the prose that goes on. After a strongly secret name it
    /// is, unless it holds no letter or digit (`token | head`, an already
    /// masked `pin ****`), is a prose word ([`PROSE_AFTER_SECRET_NAME`]) or
    /// is a name of its own (`password pin 1234` masks the PIN): `password
    /// hunter`, `token abc-def_ghi`, `password $ecret99`. After another name
    /// it is only when it reads as one ([`word_is_value_after_weak_name`]).
    fn spaced_word_is_value(&self, name: &str, word: &str) -> bool {
        if !is_strong_secret_name(name) {
            return word_is_value_after_weak_name(word);
        }
        let body = word.trim_end_matches(TRAILING_PUNCTUATION);
        if !body.chars().any(char::is_alphanumeric) {
            return false;
        }
        if !is_plain_word(body) {
            return true;
        }
        let body = body.trim_matches('\'');
        !(is_prose_after_secret_name(body) || self.name.is_match(body))
    }
}

/// Mask the values of secret-named fields (`pin: 123456`, `"api_key":"..."`,
/// `password=...`, `--pin 123456`, `PIN 654321`, `Authorization: ...`), one
/// `*` per character. After spaces alone a word counts when it reads as a
/// value: any word after a strongly secret name but prose (`password
/// hunter`, not `token required`), a word with a digit or a symbol after the
/// others (`credentials enabled` is prose). Booleans and unset markers are
/// never masked (`is_success_pin: false`), nor are small numbers after a name
/// that is not strongly secret (`credentials: 48`). Shapes are not consulted.
pub fn redact_named_fields(text: &str) -> String {
    SECRET_FIELDS.mask(text)
}

/// Secrets out of free text: known shapes first, then secret-named fields.
/// The general-purpose entry point for anything about to be logged, traced,
/// reported or shown.
pub fn redact_text(text: &str) -> String {
    redact_named_fields(&redact_secret_tokens(text))
}

/// [`redact_text`] plus the privacy keys the log writers have always masked
/// (`id`, `uuid`, `device`, `device_id`, `code`). For log lines and the Sentry
/// scrubber; not for text shown to the operator, where ids are useful. A
/// status or error code after `code` (`code: Unavailable`, `code 1168`,
/// `code: -32601`) is not an identifier and stays readable; five digits or
/// more after `code`, and any value in a URL query, stay masked.
pub fn redact_log_line(text: &str) -> String {
    LOG_FIELDS.mask(&redact_secret_tokens(text))
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

/// Longest argument of a captured command line that leaves the host whole
/// (see [`redact_command_line`]); a longer one keeps its head and a count.
pub const COMMAND_LINE_ARG_MAX_CHARS: usize = 256;

/// A command line EDAMAME captured from another process, made safe to leave
/// the host (an LLM prompt, an MCP answer, an export): [`redact_cli_args`],
/// then every `NAME=value` assignment keeps its name and loses its value
/// (assignments are how a command line carries configuration and credentials,
/// and the name is the context), then [`redact_text`] per argument, and each
/// argument capped at [`COMMAND_LINE_ARG_MAX_CHARS`] characters so a long blob
/// (a certificate bundle, an encoded key) never travels whole.
pub fn redact_command_line<S: AsRef<str>>(args: &[S]) -> Vec<String> {
    redact_cli_args(args, &[])
        .into_iter()
        .map(|arg| {
            let arg = match arg.split_once('=') {
                Some((name, value)) if is_assignment_name(name) && !value.is_empty() => {
                    format!("{name}={REDACTED}")
                }
                _ => redact_text(&arg),
            };
            cap_argument(arg)
        })
        .collect()
}

/// A command, or a path taken from one (an interpreter's inline `-c` script),
/// made safe to leave the host: [`redact_text`] and the
/// [`COMMAND_LINE_ARG_MAX_CHARS`] cap.
pub fn redact_command_text(text: &str) -> String {
    cap_argument(redact_text(text))
}

/// `NAME` of a `NAME=value` assignment, as shells and `env` write them.
fn is_assignment_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// JSON keys whose value is a captured argv (flodbadd's session L7, the LLM
/// session summary).
const COMMAND_LINE_ARRAY_KEYS: &[&str] = &["cmd", "parent_cmd", "grandparent_cmd", "process_cmd"];

/// JSON keys whose string value is a command, or a path taken from one: an
/// interpreter's script argument can be a whole inline `-c` command.
const COMMAND_TEXT_KEYS: &[&str] = &[
    "command",
    "script_path",
    "parent_script_path",
    "grandparent_script_path",
];

/// Every captured command line in a JSON document EDAMAME is about to hand
/// off the host (an MCP answer, an export), redacted in place: arrays under a
/// `cmd`-named key through [`redact_command_line`], commands and script paths
/// through [`redact_text`] and the same length cap. A JSON document carried in
/// a string value (an export that nests one) is redacted the same way.
pub fn redact_command_lines_in_json(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, item) in map.iter_mut() {
                let key = key.as_str();
                match item {
                    Value::Array(args) if COMMAND_LINE_ARRAY_KEYS.contains(&key) => {
                        let text: Vec<String> = args
                            .iter()
                            .map(|a| a.as_str().map(str::to_string).unwrap_or_else(|| a.to_string()))
                            .collect();
                        *args = redact_command_line(&text).into_iter().map(Value::String).collect();
                    }
                    Value::String(text)
                        if COMMAND_LINE_ARRAY_KEYS.contains(&key) || COMMAND_TEXT_KEYS.contains(&key) =>
                    {
                        *text = redact_command_text(text);
                    }
                    _ => redact_command_lines_in_json(item),
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(redact_command_lines_in_json),
        Value::String(text) => {
            let trimmed = text.trim_start();
            if !(trimmed.starts_with('{') || trimmed.starts_with('[')) {
                return;
            }
            if let Ok(mut inner) = serde_json::from_str::<Value>(text) {
                let before = inner.clone();
                redact_command_lines_in_json(&mut inner);
                if inner != before {
                    if let Ok(redacted) = serde_json::to_string(&inner) {
                        *text = redacted;
                    }
                }
            }
        }
        _ => {}
    }
}

/// [`redact_command_lines_in_json`] on a serialized document; text that is not
/// JSON is returned unchanged, and a document with nothing to redact keeps its
/// formatting.
pub fn redact_command_lines_in_json_text(text: &str) -> String {
    let Ok(mut value) = serde_json::from_str::<Value>(text) else {
        return text.to_string();
    };
    let before = value.clone();
    redact_command_lines_in_json(&mut value);
    if value == before {
        return text.to_string();
    }
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| text.to_string())
}

fn cap_argument(arg: String) -> String {
    let total = arg.chars().count();
    if total <= COMMAND_LINE_ARG_MAX_CHARS {
        return arg;
    }
    let head: String = arg.chars().take(COMMAND_LINE_ARG_MAX_CHARS).collect();
    format!("{head}...[{} more chars]", total - COMMAND_LINE_ARG_MAX_CHARS)
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
            // A secret-like name with a label, a boolean, a small number,
            // nothing, or prose after it (logs of 2026-10-13).
            "Computed score: 3.65 (application: 51, network: 29, system services: 66, system integrity: 93, credentials: 100, ai: 48)",
            "ConnectionStatus { connected_user: \"bob\", is_success: true, is_success_pin: false, is_outdated: false }",
            "LLMConfig { api_key: None, oauth_refresh_token: null }",
            "Preserved status for threat: Cached logon credentials enabled = Inactive",
            "Preserved status for threat: password is too weak = Active",
            "Preserved status for threat: no password manager = Active",
            "Preserved status for threat: passwd permissions = Inactive",
            "   Authentication: Bearer token required (per-client credential or PSK)",
            "   Security: PSK authentication required, localhost only",
            "Starting MCP server on 127.0.0.1:3000 with PSK auth",
            "Secret store: file (/root/.edamame/secrets)",
            "  Token URL: https://portal.example/oauth2/token",
            "Setting credentials for user: bob, domain: example.com",
            "Credentials set to user: bob, domain: example.com",
            "ES credential-open client subscribed to NOTIFY_OPEN on 30 cold credential prefixes",
            "the key isn't loaded; secret's owner unknown",
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

    /// Log lines the privacy keys masked by mistake (dogfood hosts,
    /// 2026-10-13): prose after `device`, status and error codes after
    /// `code`, small numbers after `id`.
    #[test]
    fn log_lines_keep_status_codes_small_ids_and_prose() {
        for line in [
            "Error sending request to helper: Status { code: Unavailable, message: \"tcp connect error\", source: None }",
            "Os { code: 2, kind: NotFound, message: \"No such file or directory\" }",
            "Os { code: -2147024891, kind: PermissionDenied }; HRESULT code=0x80070005",
            "JSON-RPC error code: -32601, error code: 80",
            "GetIpNetTable2 failed with code 1168",
            "Call to backend failed with error code: InvalidSignature - report_score failed",
            "failed with code 400, response body: \"x\", error code is InputValidationFailed",
            "Conflicting device characteristics - aborting merge of DeviceInfo",
            "Unknown device type for ports [22], mdns []",
            "Loading device profiles from JSON",
            "Attempting to find device with interface: Wi-Fi",
            "Cleared 3 device todos and 2 session todos due to network change",
            "ETW audit-api-calls event id=5 version=0 opcode=0 level=4 keyword=0x0 pid=420",
            "especially if the device connects to untrusted networks",
            "Computed score: 3.65 (application: 51, network: 29, system services: 66, system integrity: 93, credentials: 100, ai: 48)",
            "ConnectionStatus { is_success: true, is_success_pin: false }",
            "Preserved status for threat: Cached logon credentials enabled = Inactive",
            "   Authentication: Bearer token required (per-client credential or PSK)",
            "Secret store: file (/var/root/.edamame/secrets), this binary has no keychain access group",
        ] {
            assert_eq!(redact_log_line(line), line, "over-redacted");
        }
    }

    /// What the names are there for stays masked in log lines: identifiers
    /// after `device`, a `code` that is no status code, PINs and passwords
    /// however written, the value inside an `Option`.
    #[test]
    fn log_lines_still_mask_identifiers_and_secrets() {
        for (line, hidden) in [
            (
                "Reporting score for device 4f3c2a1b9d8e7f6a5b4c3d2e1f0a9b8c (Linux Mint 22.1) with IPv4",
                "4f3c2a1b9d8e7f6a5b4c3d2e1f0a9b8c",
            ),
            (
                "Connecting device 3f2504e0-4f89-11d3-9a0c-0305e82c3301 (Windows 10) for user bob",
                "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
            ),
            (
                "Request to https://backend.example/api/plan?device_id=8a7b6c5d4e3f failed",
                "8a7b6c5d4e3f",
            ),
            ("GET /callback?code=4/0AfJohXnZ3pq&state=xyz", "4/0AfJohXnZ3pq"),
            ("authorization code: a1b2c3d4-e5f6", "a1b2c3d4-e5f6"),
            (
                "ConnectionStatus { pin: \"1234567890\", is_success_pin: false }",
                "1234567890",
            ),
            ("PIN 654321 accepted", "654321"),
            ("pin: 1234", "1234"),
            ("password hunter2 rejected", "hunter2"),
            ("secret p@ssw*rd! rejected", "p@ssw*rd!"),
            ("Secret connection_pin: 123456 written", "123456"),
            ("LLMConfig { api_key: Some(\"plainvalue\") }", "plainvalue"),
            ("edamame_posture start --password hunter --user bob", "hunter"),
            (r#"{"id": "12345"}"#, "12345"),
            ("uuid 3f2504e0-4f89-11d3-9a0c-0305e82c3301", "3f2504e0"),
        ] {
            let out = redact_log_line(line);
            assert!(!out.contains(hidden), "{hidden} leaked from {line:?}: {out}");
            assert!(out.contains('*'), "{line:?}: {out}");
        }
    }

    /// A secret-like label with a word after `:` reads as `name: value`: it
    /// stays masked, and the log format needs another label (core's
    /// `<call>_with_api_key:` prefixes and `Secret <slot>:` lines, core's
    /// community LAN line, flodbadd's capture device line).
    #[test]
    fn ambiguous_labels_stay_masked() {
        for (line, masked) in [
            (
                "get_agentic_subscription_status_with_api_key: Request failed for https://x",
                "get_agentic_subscription_status_with_api_key: ******* failed for https://x",
            ),
            (
                "Secret connection_pin: secret store write failed (create failed); the record keeps the credentials",
                "Secret connection_pin: ****** store write failed (create failed); the record keeps the credentials",
            ),
            (
                "Received 18 devices from the community, accepted 18, last seen device: 2026-10-13 20:05:44 UTC",
                "Received 18 devices from the community, accepted 18, last seen device: ********** 20:05:44 UTC",
            ),
            (
                "Attempting to find interface from device: eth0",
                "Attempting to find interface from device: ****",
            ),
        ] {
            assert_eq!(redact_log_line(line), masked);
        }
    }

    /// After `code`, a one-time code or a PIN is masked however it is
    /// written: five digits or more, and any value in a URL query (the Hub
    /// PIN travels as `code=`).
    #[test]
    fn log_lines_mask_codes_that_are_no_status_code() {
        for (line, hidden) in [
            ("code: 482913", "482913"),
            ("code=482913", "482913"),
            (r#"{"code":482913}"#, "482913"),
            ("Enter the mfa code 482913 to continue", "482913"),
            ("Os { code: 10061, kind: ConnectionRefused }", "10061"),
            ("GET /hub/enroll?code=482913 HTTP/1.1", "482913"),
            ("GET /hub/enroll?user=bob&code=482913", "482913"),
            ("GET /hub/enroll?code=4829&user=bob", "4829"),
            (
                "GET /oauth/callback?code=AbCdEfGhIjKl&state=x",
                "AbCdEfGhIjKl",
            ),
            ("GET /oauth/callback?id=42", "42"),
        ] {
            let out = redact_log_line(line);
            assert!(
                !out.contains(hidden),
                "{hidden} leaked from {line:?}: {out}"
            );
            assert!(out.contains('*'), "{line:?}: {out}");
        }
        assert_eq!(
            redact_log_line("Enter the mfa code 482913 to continue"),
            "Enter the mfa code ****** to continue"
        );
        assert_eq!(
            redact_log_line("GET /hub/enroll?user=bob&code=4829"),
            "GET /hub/enroll?user=bob&code=****"
        );
    }

    /// Values the named-field pass let through: a plain word after a
    /// strongly secret name, a flag after `=`, a small number after a
    /// strongly secret name or one with a long fraction, a value starting
    /// with a quote or a symbol, a single-quoted value, a quoted name.
    #[test]
    fn plain_quoted_and_symbol_values_are_masked() {
        for (line, hidden) in [
            ("password hunter", "hunter"),
            ("login with password hunter.", "hunter"),
            ("token abc-def_ghi", "abc-def_ghi"),
            ("key ABCDEFGHIJKLMNOP", "ABCDEFGHIJKLMNOP"),
            ("ARGS=--password hunter", "hunter"),
            ("password pin 1234", "1234"),
            ("pin: 123", "123"),
            ("psk=42", "42"),
            ("token: 7.25", "7.25"),
            ("secret 12", "12"),
            ("credentials: 3.14159", "3.14159"),
            ("password: 'hunter2'", "hunter2"),
            ("--password 'hunter2'", "hunter2"),
            ("--password 'correct horse battery'", "horse"),
            ("password 'correct horse battery'", "horse"),
            ("password: $ecret99", "ecret99"),
            ("password: !Passw0rd", "Passw0rd"),
            ("password $ecret99", "ecret99"),
            ("{'password': 'hunter2'}", "hunter2"),
            ("Server=db;Uid=sa;Pwd=hunter2;", "hunter2"),
            ("MYSQL_PWD=hunter2", "hunter2"),
        ] {
            for out in [redact_text(line), redact_log_line(line)] {
                assert!(
                    !out.contains(hidden),
                    "{hidden} leaked from {line:?}: {out}"
                );
                assert!(out.contains('*'), "{line:?}: {out}");
            }
        }
        for (line, masked) in [
            ("password hunter", "password ******"),
            ("ARGS=--password hunter", "ARGS=--password ******"),
            ("password: 'hunter2'", "password: '*******'"),
            ("{'password': 'hunter2'}", "{'password': '*******'}"),
            ("password pin 1234", "password pin ****"),
            ("pin: 123", "pin: ***"),
        ] {
            assert_eq!(redact_text(line), masked);
        }
    }

    /// Next to those, what stays readable: status and error codes after
    /// `code`, prose after a strongly secret name, prose and quoted words
    /// after the weaker names, and EDAMAME's own lines that put a word after
    /// a secret name.
    #[test]
    fn codes_and_prose_stay_readable_next_to_the_masked_values() {
        for line in [
            "Os { code: 2, kind: NotFound }",
            "Status { code: Unavailable, message: \"tcp connect error\" }",
            "error code: 80",
            "HRESULT code=0x80070005, JSON-RPC code: -32601",
            "GetIpNetTable2 failed with code 1168",
            "No refresh token available - skipping retry",
            "OAuth token refresh not needed on startup",
            "Access token refreshed successfully",
            "Token exchange failed: timed out",
            "PIN success flag switched to true",
            "Empty PIN and no Hub enrollment credential",
            "Ensure your firewall is configured and PSK is secure!",
            "Using GitHub token from secure file: /run/secrets/gh",
            "Secret store (connection_pin): adoption task failed",
            "Agent cursor exceeded its daily token budget: 120 tokens vs 100 cap",
            "Unknown consent document id 'privacy'",
            "the key isn't loaded",
            "cd $PWD && make",
            "--password --user bob",
            "api_key: [REDACTED]",
            "edamame_core::agentic::token::refresh: started",
            "fn set_pin(pin: &str, token: &'a str) { if pin == \"\" {} }",
        ] {
            assert_eq!(redact_log_line(line), line, "over-redacted");
        }
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
            "pwd",
            "MYSQL_PWD",
        ] {
            assert!(is_secret_field_name(name), "{name} should be secret");
        }
        for name in [
            "cwd",
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
    fn redact_command_line_masks_assignments_flags_shapes_and_caps_blobs() {
        let anthropic = format!("sk-ant-api03-{}", "A".repeat(40));
        let blob = "M".repeat(4000);
        let args = vec![
            "env".to_string(),
            "APPLE_DEVELOPER_ID_APPLICATION_KEY=MIIJQgIBADANBgkqhkiG9w0BAQEFAASCCSwwggkoAgEAAoICAQC".to_string(),
            "ANTHROPIC_API_KEY=x".to_string(),
            "CC=gcc".to_string(),
            "curl".to_string(),
            "-H".to_string(),
            format!("Authorization: Bearer {anthropic}"),
            "--password".to_string(),
            "hunter2".to_string(),
            "https://user:pa55word@example.com/path?token=abc123".to_string(),
            "/usr/bin/node".to_string(),
            "--port=8080".to_string(),
            "a=b=c".to_string(),
            "--title=Cursor Helper".to_string(),
            "--empty=".to_string(),
            blob.clone(),
        ];
        let out = redact_command_line(&args);
        assert_eq!(out[0], "env");
        assert_eq!(out[1], "APPLE_DEVELOPER_ID_APPLICATION_KEY=[REDACTED]");
        assert_eq!(out[2], "ANTHROPIC_API_KEY=[REDACTED]");
        assert_eq!(out[3], "CC=[REDACTED]");
        assert_eq!(out[4], "curl");
        assert!(!out[6].contains(&anthropic), "{}", out[6]);
        assert_eq!(out[7], "--password");
        assert_eq!(out[8], REDACTED);
        assert!(!out[9].contains("pa55word"), "{}", out[9]);
        assert_eq!(out[10], "/usr/bin/node");
        assert_eq!(out[11], "--port=8080");
        assert_eq!(out[12], "a=[REDACTED]");
        assert_eq!(out[13], "--title=Cursor Helper");
        assert_eq!(out[14], "--empty=");
        assert!(out[15].len() < 400, "a long blob is capped: {} chars", out[15].len());
        assert!(out[15].ends_with(&format!("...[{} more chars]", 4000 - COMMAND_LINE_ARG_MAX_CHARS)));
        assert!(out.iter().all(|a| !a.contains("MIIJQgIBADANBgkqhkiG9w0BAQEFAASCCSww")));
    }

    #[test]
    fn command_lines_in_json_are_redacted_wherever_they_sit() {
        let inner = serde_json::json!({"l7": {"parent_cmd": ["env", "API_TOKEN=nested-secret"]}});
        let mut doc = serde_json::json!({
            "sessions": [{
                "l7": {
                    "process_name": "node",
                    "cmd": ["node", "server.js", "--password", "hunter2"],
                    "parent_cmd": ["Cursor Helper (Plugin)", "ANTHROPIC_API_KEY=not-a-real-key"],
                    "grandparent_cmd": [],
                    "parent_script_path": "curl -H 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456' https://x",
                }
            }],
            "summary": {"command": "mysql --password=s3cret db"},
            "trace": inner.to_string(),
            "finding_key": "vuln:abc",
        });
        redact_command_lines_in_json(&mut doc);
        let text = doc.to_string();
        for leaked in ["hunter2", "not-a-real-key", "abcdefghijklmnopqrstuvwxyz123456", "s3cret", "nested-secret"] {
            assert!(!text.contains(leaked), "{leaked} survived: {text}");
        }
        assert_eq!(doc["sessions"][0]["l7"]["cmd"][1], "server.js");
        assert_eq!(doc["sessions"][0]["l7"]["process_name"], "node");
        assert_eq!(doc["finding_key"], "vuln:abc");
    }

    #[test]
    fn json_text_without_command_lines_keeps_its_formatting() {
        let text = "{\n  \"score\": 3.5,\n  \"name\": \"x\"\n}";
        assert_eq!(redact_command_lines_in_json_text(text), text);
        assert_eq!(redact_command_lines_in_json_text("not json"), "not json");
        let redacted = redact_command_lines_in_json_text(r#"{"cmd":["env","A_TOKEN=zzz"]}"#);
        assert!(redacted.contains("A_TOKEN=[REDACTED]"), "{redacted}");
    }

    #[test]
    fn redact_command_line_leaves_an_ordinary_command_readable() {
        let args = ["/opt/homebrew/bin/node", "/Users/u/app/server.js", "--inspect", "-p", "3000"];
        assert_eq!(redact_command_line(&args), args.to_vec());
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
