//! Shared secret redaction: the one place that knows what a secret looks like.
//!
//! Every surface that can carry a credential into a log line, a Sentry event,
//! an RPC trace or an excerpt served to a client funnels through here:
//!
//! - [`redact_text`]: known secret *shapes* anywhere in free text (EDAMAME
//!   `edm_` / `edak_` keys, Anthropic `sk-ant-`, OpenAI `sk-`, GitHub `ghp_` /
//!   `gho_` / `ghu_` / `ghs_` / `ghr_` / `github_pat_`, AWS `AKIA` / `ASIA`,
//!   Slack `xox?-` / `xapp-`, Google `AIza`, Telegram bot tokens (bare and as
//!   the `/bot<token>/` segment of a Bot API URL), `Bearer` values, JWTs, PEM
//!   private key blocks, `user:password@` URL userinfo) plus the values of
//!   secret-named fields (`pin`, `password`, `api_key`, `*_token`, `secret`,
//!   `authorization`, ... in JSON, `key=value`, `key: value`,
//!   `--flag value` and `name value` shapes).
//! - [`redact_log_line`]: [`redact_text`] plus the privacy keys the log files
//!   have always masked (`id`, `uuid`, `device`, `device_id`, `code`, ...) and
//!   e-mail addresses (the local part; see [`redact_email`]).
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
        // GitLab personal access tokens, npm tokens, Hugging Face tokens,
        // Stripe live secret and restricted keys.
        r"|(?P<gitlab>\bglpat-[A-Za-z0-9_\-]{20,})",
        r"|(?P<npm>\bnpm_[A-Za-z0-9]{30,})",
        r"|(?P<huggingface>\bhf_[A-Za-z0-9]{30,})",
        r"|(?P<stripe>\b(?:sk|rk)_live_[A-Za-z0-9]{16,})",
        // Telegram bot tokens (`<bot id>:<secret>`). In a Bot API URL the
        // token is a path segment (`/bot<token>/<method>`, `/file/bot<token>/`),
        // which an HTTP client's error message repeats: the `/bot` stays and
        // the whole token goes, whatever the secret part looks like. Bare, the
        // secret part starts with `AA` and runs 30 characters or more.
        r"|(?P<telegram_url>/bot)[0-9]{5,}:[A-Za-z0-9_\-]{30,}",
        r"|(?P<telegram>\b[0-9]{5,}:AA[A-Za-z0-9_\-]{30,})",
        // user:password@ in a URL authority: keep the user, drop the password.
        r"|(?P<userinfo>://[^\s/:@]+:)[^\s/@]+@",
        // A token in the user position of a web URL's authority
        // (`https://TOKEN@host`, `https://TOKEN:x-oauth-basic@host`), whatever
        // follows its colon: a user name is short, a token is not.
        r"|(?P<urltoken>https?://)[A-Za-z0-9_\-.~%]{20,}(?::[^\s/@]*)?@",
    ))
    .expect("Failed to compile secret shape regex");

    /// An e-mail address: a local part, `@`, a dotted domain. The local part
    /// is what names a person; the domain stays (an organization, a mail
    /// provider), as the host of a URL stays when its password is masked.
    static ref EMAIL_REGEX: Regex = Regex::new(
        r"(?i)(?:^|[^A-Za-z0-9._%+\-/:])(?P<local>[A-Za-z0-9._%+\-]+)@(?P<domain>[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?)+)\b"
    )
    .expect("Failed to compile e-mail regex");
}

/// One e-mail address made safe to log: `[REDACTED]@example.com`. A value
/// without an `@` is masked whole. For a log argument that IS an address
/// (the breach monitor's identities, the Hub account); addresses inside
/// free text are caught by [`redact_log_line`].
pub fn redact_email(email: &str) -> String {
    match email.trim().rsplit_once('@') {
        Some((_, domain)) if !domain.is_empty() => format!("{}@{}", REDACTED, domain),
        _ => REDACTED.to_string(),
    }
}

/// E-mail addresses anywhere in `text`, each reduced to its domain
/// ([`redact_email`]). Not an address: a `user@host` without a dotted
/// domain, the userinfo of a URL (`://user@host`, and `://user:pw@host`,
/// whose password its own shape masks while the user stays), a path or
/// scope before the `@` (`@scope/pkg@1.2.3`), and a version (`lodash@4.17.21`:
/// a domain's last label has a letter).
fn redact_email_addresses(text: &str) -> String {
    EMAIL_REGEX
        .replace_all(text, |caps: &Captures| {
            let whole = caps.get(0).map(|m| m.as_str()).unwrap_or("");
            let local = &caps["local"];
            let domain = &caps["domain"];
            let last_label = domain.rsplit('.').next().unwrap_or("");
            if !last_label.chars().any(|c| c.is_ascii_alphabetic()) {
                return whole.to_string();
            }
            let lead = &whole[..whole.len() - local.len() - 1 - domain.len()];
            format!("{lead}{REDACTED}@{domain}")
        })
        .into_owned()
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
            } else if let Some(prefix) = caps.name("urltoken") {
                format!("{}{}@", prefix.as_str(), REDACTED)
            } else if let Some(prefix) = caps.name("telegram_url") {
                format!("{}{}", prefix.as_str(), REDACTED)
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
/// (`id`, `uuid`, `device`, `device_id`, `code`) and e-mail addresses
/// ([`redact_email`]: the domain stays). For log lines and the Sentry
/// scrubber; not for text shown to the operator, where ids are useful. A
/// status or error code after `code` (`code: Unavailable`, `code 1168`,
/// `code: -32601`) is not an identifier and stays readable; five digits or
/// more after `code`, and any value in a URL query, stay masked.
pub fn redact_log_line(text: &str) -> String {
    LOG_FIELDS.mask(&redact_email_addresses(&redact_secret_tokens(text)))
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

/// Options of common command-line clients whose value is a credential
/// although the option's name does not say so. They are read only for the
/// words of a simple command whose program is the client (see
/// [`client_credential_replacements`]): `-p` is a password for one program and
/// a port for another, and a host, a path or another option's value that
/// happens to name a client selects nothing.
struct ClientCredentialOptions {
    /// Program names, lower case, without a path or `.exe`.
    programs: &'static [&'static str],
    /// Options whose value is a credential, attached (`-pVALUE`,
    /// `--pass=VALUE`) or in the next argument.
    value: &'static [&'static str],
    /// The value counts only when attached: the option alone asks for the
    /// credential on the terminal.
    attached_only: bool,
    /// Options whose value is `user:password`: the user stays, unless the
    /// password is empty (`-u KEY:`), where the user is the key.
    user_password: &'static [&'static str],
    /// Options that name the kind of credential given under
    /// `user_password` (HTTPie `-A`).
    auth_type: &'static [&'static str],
    /// Kinds under which the `user_password` value is a token, masked whole.
    token_auth_types: &'static [&'static str],
    /// When not empty, the options are read only in a command that names one
    /// of these subcommands (`docker login`): elsewhere the same letter is
    /// another option (`docker run -p 8080:80` publishes a port).
    subcommands: &'static [&'static str],
}

const CLIENT_CREDENTIAL_OPTIONS: &[ClientCredentialOptions] = &[
    ClientCredentialOptions {
        programs: &["curl"],
        value: &[],
        attached_only: false,
        user_password: &["-u", "--user", "-U", "--proxy-user"],
        auth_type: &[],
        token_auth_types: &[],
        subcommands: &[],
    },
    ClientCredentialOptions {
        programs: &["http", "https", "httpie"],
        value: &[],
        attached_only: false,
        user_password: &["-a", "--auth"],
        auth_type: &["-A", "--auth-type"],
        token_auth_types: &["bearer"],
        subcommands: &[],
    },
    // The MySQL and MariaDB clients and tools: `-p` alone prompts.
    ClientCredentialOptions {
        programs: &[
            "mysql",
            "mysqldump",
            "mysqladmin",
            "mysqlimport",
            "mysqlcheck",
            "mysqlshow",
            "mysqlslap",
            "mysqlpump",
            "mysqlbinlog",
            "mysqlsh",
            "mariadb",
            "mariadb-dump",
            "mariadb-admin",
            "mariadb-import",
            "mariadb-check",
            "mariadb-show",
            "mariadb-slap",
            "mariadb-binlog",
        ],
        value: &["-p"],
        attached_only: true,
        user_password: &[],
        auth_type: &[],
        token_auth_types: &[],
        subcommands: &[],
    },
    // mycli takes the password as the next argument too.
    ClientCredentialOptions {
        programs: &["mycli"],
        value: &["-p"],
        attached_only: false,
        user_password: &[],
        auth_type: &[],
        token_auth_types: &[],
        subcommands: &[],
    },
    ClientCredentialOptions {
        programs: &["redis-cli"],
        value: &["-a", "--pass"],
        attached_only: false,
        user_password: &[],
        auth_type: &[],
        token_auth_types: &[],
        subcommands: &[],
    },
    // The MongoDB shells and database tools.
    ClientCredentialOptions {
        programs: &[
            "mongosh",
            "mongo",
            "mongodump",
            "mongorestore",
            "mongoexport",
            "mongoimport",
            "mongostat",
            "mongotop",
            "mongofiles",
        ],
        value: &["-p"],
        attached_only: false,
        user_password: &[],
        auth_type: &[],
        token_auth_types: &[],
        subcommands: &[],
    },
    ClientCredentialOptions {
        programs: &["zip", "unzip"],
        value: &["-P"],
        attached_only: false,
        user_password: &[],
        auth_type: &[],
        token_auth_types: &[],
        subcommands: &[],
    },
    // Container registry logins: `docker login -u USER -p PASSWORD`,
    // `--password PASSWORD` (`--password-stdin` takes no value).
    ClientCredentialOptions {
        programs: &["docker", "podman", "nerdctl", "buildah", "skopeo"],
        value: &["-p", "--password"],
        attached_only: false,
        user_password: &[],
        auth_type: &[],
        token_auth_types: &[],
        subcommands: &["login"],
    },
];

/// Programs that run the command given after their own options, so that the
/// word after those options is in command position: `sudo`, `doas`, `env`,
/// `nohup`, `time`, `nice`, `ionice`, `timeout`, `xargs`, `exec`, `command`,
/// `stdbuf`, `setsid`, `caffeinate`, and `sshpass`, whose own `-p` is a
/// password. The list is short on purpose: a wrapper it does not name leaves
/// the command it runs unread for client options, never misread.
struct CommandWrapper {
    names: &'static [&'static str],
    /// Options that take the next word as their value.
    options_with_value: &'static [&'static str],
    /// Words after the options that belong to the wrapper (`timeout 10`).
    positionals: usize,
    /// `NAME=value` words belong to the wrapper (`env`).
    assignments: bool,
    /// Options whose value is a credential (`sshpass -p`).
    credential: &'static [&'static str],
}

const COMMAND_WRAPPERS: &[CommandWrapper] = &[
    CommandWrapper {
        names: &["sudo"],
        options_with_value: &[
            "-u",
            "-g",
            "-h",
            "-p",
            "-C",
            "-D",
            "-R",
            "-T",
            "-U",
            "-r",
            "-t",
            "--user",
            "--group",
            "--host",
            "--prompt",
            "--chdir",
            "--chroot",
            "--other-user",
            "--role",
            "--type",
            "--close-from",
            "--command-timeout",
        ],
        positionals: 0,
        assignments: false,
        credential: &[],
    },
    CommandWrapper {
        names: &["doas"],
        options_with_value: &["-u", "-C"],
        positionals: 0,
        assignments: false,
        credential: &[],
    },
    CommandWrapper {
        names: &["env"],
        options_with_value: &["-u", "-C", "-S", "--unset", "--chdir", "--split-string"],
        positionals: 0,
        assignments: true,
        credential: &[],
    },
    CommandWrapper {
        names: &["nohup", "setsid", "command"],
        options_with_value: &[],
        positionals: 0,
        assignments: false,
        credential: &[],
    },
    CommandWrapper {
        names: &["exec"],
        options_with_value: &["-a"],
        positionals: 0,
        assignments: false,
        credential: &[],
    },
    CommandWrapper {
        names: &["time"],
        options_with_value: &["-f", "-o", "--format", "--output"],
        positionals: 0,
        assignments: false,
        credential: &[],
    },
    CommandWrapper {
        names: &["nice"],
        options_with_value: &["-n", "--adjustment"],
        positionals: 0,
        assignments: false,
        credential: &[],
    },
    CommandWrapper {
        names: &["ionice"],
        options_with_value: &["-c", "-n", "--class", "--classdata"],
        positionals: 0,
        assignments: false,
        credential: &[],
    },
    CommandWrapper {
        names: &["timeout"],
        options_with_value: &["-s", "-k", "--signal", "--kill-after"],
        positionals: 1,
        assignments: false,
        credential: &[],
    },
    CommandWrapper {
        names: &["xargs"],
        options_with_value: &[
            "-I",
            "-L",
            "-n",
            "-P",
            "-s",
            "-d",
            "-E",
            "-a",
            "--max-args",
            "--max-procs",
            "--delimiter",
            "--arg-file",
            "--replace",
            "--max-lines",
            "--eof",
            "--max-chars",
        ],
        positionals: 0,
        assignments: false,
        credential: &[],
    },
    CommandWrapper {
        names: &["stdbuf"],
        options_with_value: &["-i", "-o", "-e", "--input", "--output", "--error"],
        positionals: 0,
        assignments: false,
        credential: &[],
    },
    CommandWrapper {
        names: &["caffeinate"],
        options_with_value: &["-t", "-w"],
        positionals: 0,
        assignments: false,
        credential: &[],
    },
    CommandWrapper {
        names: &["sshpass"],
        options_with_value: &["-f", "-d", "-P"],
        positionals: 0,
        assignments: false,
        credential: &["-p"],
    },
];

/// Shell words after which the next word is in command position.
const COMMAND_PREFIX_WORDS: &[&str] = &[
    "!", "{", "if", "then", "else", "elif", "do", "while", "until",
];

/// A command line's words that separate two simple commands, when they
/// stand as words of their own (an argv).
const COMMAND_SEPARATOR_WORDS: &[&str] = &[";", "&", "&&", "|", "||", "|&", "(", ")"];

/// How many levels of commands are read for a client's credential, the
/// command itself included: a command, and up to three levels of commands
/// nested in it, each inside the other (a quoted command such as a `-c`
/// string or the remote command of `ssh`, a command substitution `$(...)`,
/// `<(...)` or between backticks). A command nested deeper is not read for
/// client options; the other masks still apply to its text.
pub const MAX_COMMAND_NESTING: usize = 4;

/// A program's name as a command calls it: the file name of the word,
/// without quotes, a leading `\` (which skips an alias), a path or `.exe`,
/// lower case.
fn program_name(word: &str) -> String {
    let word = word.trim_matches(['"', '\'']).trim_start_matches('\\');
    let name = word.rsplit(['/', '\\']).next().unwrap_or(word);
    let name = name.to_ascii_lowercase();
    name.strip_suffix(".exe").unwrap_or(&name).to_string()
}

/// The client a program word names ([`CLIENT_CREDENTIAL_OPTIONS`]).
fn client_for_program(word: &str) -> Option<&'static ClientCredentialOptions> {
    let name = program_name(word);
    CLIENT_CREDENTIAL_OPTIONS
        .iter()
        .find(|client| client.programs.contains(&name.as_str()))
}

/// The wrapper a program word names ([`COMMAND_WRAPPERS`]).
fn wrapper_for_program(word: &str) -> Option<&'static CommandWrapper> {
    let name = program_name(word);
    COMMAND_WRAPPERS
        .iter()
        .find(|wrapper| wrapper.names.contains(&name.as_str()))
}

/// `NAME=value`, as a shell assignment before a command.
fn is_assignment_word(word: &str) -> bool {
    word.split_once('=')
        .is_some_and(|(name, _)| is_assignment_name(name))
}

/// `user:password` with the password masked. With an empty password the
/// user is the credential (`-u KEY:`, an API key given as the user) and is
/// masked. A value without `:` is a user alone and stays.
fn mask_password_of(value: &str) -> String {
    match value.split_once(':') {
        Some((user, password)) if !password.is_empty() => format!("{user}:{REDACTED}"),
        Some((user, _)) if !user.is_empty() => format!("{REDACTED}:"),
        _ => value.to_string(),
    }
}

/// What a client's option says about a word.
enum ClientOptionMatch {
    /// The credential is this word's tail, from this byte.
    Attached { at: usize, user_password: bool },
    /// The credential is the next word.
    Next { user_password: bool },
}

fn match_client_option(client: &ClientCredentialOptions, word: &str) -> Option<ClientOptionMatch> {
    let options = client
        .user_password
        .iter()
        .map(|option| (*option, true))
        .chain(client.value.iter().map(|option| (*option, false)));
    for (option, user_password) in options {
        if word == option {
            if !user_password && client.attached_only {
                return None;
            }
            return Some(ClientOptionMatch::Next { user_password });
        }
        // `--option=value`, or `-ovalue` for a one-letter option.
        if let Some(value) = word.strip_prefix(option) {
            let long = option.starts_with("--");
            let attached = if long {
                value.strip_prefix('=')
            } else {
                Some(value)
            };
            if let Some(value) = attached.filter(|value| !value.is_empty()) {
                return Some(ClientOptionMatch::Attached {
                    at: word.len() - value.len(),
                    user_password,
                });
            }
        }
    }
    // Short options written together (`-sSu user:password`,
    // `-sSuuser:password`): letters that take no value, then a `user:password`
    // option. Only for those: a value-taking letter before a password option
    // would hide where the value starts.
    let cluster = word
        .strip_prefix('-')
        .filter(|rest| !rest.starts_with('-'))?;
    for (at, letter) in cluster.char_indices() {
        if !letter.is_ascii_alphabetic() {
            return None;
        }
        let option = format!("-{letter}");
        if client.user_password.contains(&option.as_str()) {
            let start = 1 + at + letter.len_utf8();
            return Some(if start < word.len() {
                ClientOptionMatch::Attached {
                    at: start,
                    user_password: true,
                }
            } else {
                ClientOptionMatch::Next {
                    user_password: true,
                }
            });
        }
    }
    None
}

/// One word of a command line, or a mark between two simple commands.
#[derive(Clone, Copy)]
enum CommandPiece<'a> {
    Word(&'a str),
    Separator,
}

/// The replacement of each piece whose value is a client's credential;
/// `None` for one that stays. Each simple command (the pieces between two
/// separators) is read on its own: its program is its first word after
/// leading `NAME=value` assignments, shell keywords and the wrappers of
/// [`COMMAND_WRAPPERS`] with their own options, and a client's options are
/// read only in a simple command whose program is that client.
fn client_credential_replacements(pieces: &[CommandPiece]) -> Vec<Option<String>> {
    let mut out: Vec<Option<String>> = vec![None; pieces.len()];
    let mut start = 0usize;
    while start < pieces.len() {
        let end = pieces[start..]
            .iter()
            .position(|piece| matches!(piece, CommandPiece::Separator))
            .map_or(pieces.len(), |at| start + at);
        let words: Vec<&str> = pieces[start..end]
            .iter()
            .map(|piece| match piece {
                CommandPiece::Word(word) => *word,
                CommandPiece::Separator => "",
            })
            .collect();
        for (offset, replacement) in simple_command_replacements(&words) {
            out[start + offset] = Some(replacement);
        }
        start = end + 1;
    }
    out
}

/// The masked form of a credential option's value; `None` when it stays.
fn masked_value(value: &str, user_password: bool, token: bool) -> Option<String> {
    let masked = if user_password && !token {
        mask_password_of(value)
    } else {
        REDACTED.to_string()
    };
    (masked != value).then_some(masked)
}

/// [`client_credential_replacements`] for one simple command: the index of
/// each word to replace and its replacement.
fn simple_command_replacements(words: &[&str]) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    // The program: past assignments, keywords and wrappers.
    let mut at = 0usize;
    let program = loop {
        let Some(word) = words.get(at) else {
            return out;
        };
        if is_assignment_word(word) || COMMAND_PREFIX_WORDS.contains(word) {
            at += 1;
            continue;
        }
        let Some(wrapper) = wrapper_for_program(word) else {
            break at;
        };
        at = skip_wrapper(wrapper, words, at + 1, &mut out);
    };
    let Some(client) = client_for_program(words[program]) else {
        return out;
    };
    if !client.subcommands.is_empty()
        && !words[program + 1..]
            .iter()
            .any(|word| client.subcommands.contains(word))
    {
        return out;
    }
    // The kind of credential, wherever it is given.
    let token = !client.token_auth_types.is_empty()
        && words[program + 1..]
            .iter()
            .enumerate()
            .any(|(offset, word)| {
                let kind = client.auth_type.iter().find_map(|option| {
                    let option: &str = option;
                    if *word == option {
                        words.get(program + 2 + offset).copied()
                    } else if option.starts_with("--") {
                        word.strip_prefix(option)
                            .and_then(|rest| rest.strip_prefix('='))
                    } else {
                        word.strip_prefix(option).filter(|rest| !rest.is_empty())
                    }
                });
                kind.is_some_and(|kind| {
                    client
                        .token_auth_types
                        .iter()
                        .any(|token| kind.eq_ignore_ascii_case(token))
                })
            });
    let mut index = program + 1;
    while index < words.len() {
        let word = words[index];
        if word == "--" {
            break;
        }
        match match_client_option(client, word) {
            Some(ClientOptionMatch::Next { user_password }) => {
                // A value never starts with `-`: that is the next option, and
                // this one asks on the terminal.
                if let Some(value) = words.get(index + 1).filter(|value| !value.starts_with('-')) {
                    if let Some(masked) = masked_value(value, user_password, token) {
                        out.push((index + 1, masked));
                    }
                    index += 2;
                    continue;
                }
            }
            Some(ClientOptionMatch::Attached { at, user_password }) => {
                let (head, value) = word.split_at(at);
                if let Some(masked) = masked_value(value, user_password, token) {
                    out.push((index, format!("{head}{masked}")));
                }
            }
            None => {}
        }
        index += 1;
    }
    out
}

/// Skip a wrapper's own words from `from` (its options, their values, its
/// assignments and positional words), masking a credential option's value
/// (`sshpass -p`); the index of the word after them.
fn skip_wrapper(
    wrapper: &CommandWrapper,
    words: &[&str],
    from: usize,
    out: &mut Vec<(usize, String)>,
) -> usize {
    let mut index = from;
    let mut positionals = wrapper.positionals;
    while let Some(word) = words.get(index) {
        if *word == "--" {
            return index + 1;
        }
        if word.starts_with('-') && word.len() > 1 {
            if let Some(option) = wrapper
                .credential
                .iter()
                .find(|option| word.starts_with(**option))
            {
                let attached = &word[option.len()..];
                if attached.is_empty() {
                    if index + 1 < words.len() {
                        out.push((index + 1, REDACTED.to_string()));
                    }
                    index += 2;
                } else {
                    out.push((index, format!("{option}{REDACTED}")));
                    index += 1;
                }
                continue;
            }
            index += if wrapper.options_with_value.contains(word) {
                2
            } else {
                1
            };
            continue;
        }
        if wrapper.assignments && is_assignment_word(word) {
            index += 1;
            continue;
        }
        if positionals > 0 {
            positionals -= 1;
            index += 1;
            continue;
        }
        break;
    }
    index
}

/// One word of a command written as one string: where it is, where it is
/// without the quotes around it, and, when the whole word is one quoted
/// string, where that string's content is.
struct TextWord {
    core: (usize, usize),
    quoted: Option<(usize, usize)>,
}

enum TextPiece {
    Word(TextWord),
    Separator,
}

/// The index after the `)` that closes the `(` before `from` (`$(`, `<(`),
/// or the end of the text: quotes and escapes are skipped, parentheses
/// nest.
fn closing_paren(bytes: &[u8], from: usize) -> usize {
    let mut depth = 1usize;
    let mut index = from;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 1,
            b'\'' => {
                index = bytes[index + 1..]
                    .iter()
                    .position(|byte| *byte == b'\'')
                    .map_or(bytes.len(), |at| index + 1 + at);
            }
            b'"' => {
                let mut inner = index + 1;
                while inner < bytes.len() && bytes[inner] != b'"' {
                    inner += if bytes[inner] == b'\\' { 2 } else { 1 };
                }
                index = inner.min(bytes.len());
            }
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return index;
                }
            }
            _ => {}
        }
        index += 1;
    }
    bytes.len()
}

/// The index of the backtick that closes the one before `from`, or the end
/// of the text.
fn closing_backtick(bytes: &[u8], from: usize) -> usize {
    let mut index = from;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            b'`' => return index,
            _ => index += 1,
        }
    }
    bytes.len()
}

/// A command written as one string, as a shell splits it: words (quotes,
/// escapes, command substitutions inside them), the separators between
/// simple commands (`;`, `&`, `&&`, `|`, `||`, `(`, `)`, a new line, with or
/// without spaces around them; `>&` and `&>` are redirections, not
/// separators), and the spans of the commands nested in it (`$(...)`, `<(...)`,
/// `>(...)`, backticks; inside double quotes too).
fn split_command_text(text: &str) -> (Vec<TextPiece>, Vec<(usize, usize)>) {
    let bytes = text.as_bytes();
    let mut pieces = Vec::new();
    let mut nested = Vec::new();
    let mut word_start: Option<usize> = None;
    let close_word = |pieces: &mut Vec<TextPiece>, start: &mut Option<usize>, end: usize| {
        if let Some(from) = start.take() {
            pieces.push(TextPiece::Word(text_word(text, from, end.min(bytes.len()))));
        }
    };
    let mut index = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        let next = bytes.get(index + 1).copied();
        match byte {
            b' ' | b'\t' | b'\r' | b'\n' => {
                close_word(&mut pieces, &mut word_start, index);
                if byte == b'\n' {
                    pieces.push(TextPiece::Separator);
                }
                index += 1;
            }
            b'&' if (index > 0 && matches!(bytes[index - 1], b'>' | b'<'))
                || next == Some(b'>') =>
            {
                word_start.get_or_insert(index);
                index += 1;
            }
            b';' | b'|' | b'&' | b'(' | b')' => {
                close_word(&mut pieces, &mut word_start, index);
                pieces.push(TextPiece::Separator);
                index += 1;
            }
            b'$' | b'<' | b'>' if next == Some(b'(') => {
                word_start.get_or_insert(index);
                let end = closing_paren(bytes, index + 2);
                nested.push((index + 2, end));
                index = end + 1;
            }
            b'`' => {
                word_start.get_or_insert(index);
                let end = closing_backtick(bytes, index + 1);
                nested.push((index + 1, end));
                index = end + 1;
            }
            b'\\' => {
                word_start.get_or_insert(index);
                index += 2;
            }
            b'\'' => {
                word_start.get_or_insert(index);
                index = bytes[index + 1..]
                    .iter()
                    .position(|byte| *byte == b'\'')
                    .map_or(bytes.len(), |at| index + 2 + at);
            }
            b'"' => {
                word_start.get_or_insert(index);
                let mut inner = index + 1;
                loop {
                    match bytes.get(inner) {
                        None => break,
                        Some(b'"') => {
                            inner += 1;
                            break;
                        }
                        Some(b'\\') => inner += 2,
                        Some(b'`') => {
                            let end = closing_backtick(bytes, inner + 1);
                            nested.push((inner + 1, end));
                            inner = end + 1;
                        }
                        Some(b'$') if bytes.get(inner + 1) == Some(&b'(') => {
                            let end = closing_paren(bytes, inner + 2);
                            nested.push((inner + 2, end));
                            inner = end + 1;
                        }
                        Some(_) => inner += 1,
                    }
                }
                index = inner;
            }
            _ => {
                word_start.get_or_insert(index);
                index += 1;
            }
        }
    }
    close_word(&mut pieces, &mut word_start, bytes.len());
    let nested = nested
        .into_iter()
        .map(|(from, to)| (from.min(bytes.len()), to.min(bytes.len())))
        .filter(|(from, to)| from < to)
        .collect();
    (pieces, nested)
}

/// The word of `text` from `from` to `to`, with its core (the quotes around
/// it left out) and the content of a word that is one quoted string.
fn text_word(text: &str, from: usize, to: usize) -> TextWord {
    let raw = &text[from..to];
    let quotes: &[char] = &['"', '\''];
    let lead = raw.len() - raw.trim_start_matches(quotes).len();
    let trail = raw.len() - raw.trim_end_matches(quotes).len();
    let core = if lead + trail >= raw.len() {
        (from, to)
    } else {
        (from + lead, to - trail)
    };
    let quoted = raw
        .chars()
        .next()
        .filter(|first| quotes.contains(first))
        .filter(|first| raw.len() >= 2 && raw.ends_with(*first) && raw.matches(*first).count() == 2)
        .map(|_| (from + 1, to - 1));
    TextWord { core, quoted }
}

/// [`client_credential_replacements`] over a command written as one string,
/// and over the commands nested in it, `depth` levels down already: the
/// text with each credential replaced and everything else as it was.
fn redact_client_credentials_in_text(text: &str, depth: usize) -> String {
    let (pieces, nested) = split_command_text(text);
    let words: Vec<CommandPiece> = pieces
        .iter()
        .map(|piece| match piece {
            TextPiece::Word(word) => CommandPiece::Word(&text[word.core.0..word.core.1]),
            TextPiece::Separator => CommandPiece::Separator,
        })
        .collect();
    let replacements = client_credential_replacements(&words);
    let mut edits: Vec<(usize, usize, String)> = Vec::new();
    let nest = depth + 1 < MAX_COMMAND_NESTING;
    for (piece, replacement) in pieces.iter().zip(replacements) {
        let TextPiece::Word(word) = piece else {
            continue;
        };
        if let Some(replacement) = replacement {
            edits.push((word.core.0, word.core.1, replacement));
            continue;
        }
        // A quoted command (a `-c` string, a remote command).
        if let Some((from, to)) = word.quoted.filter(|_| nest) {
            let inner = &text[from..to];
            if inner.contains(char::is_whitespace) {
                let redacted = redact_client_credentials_in_text(inner, depth + 1);
                if redacted != inner {
                    edits.push((from, to, redacted));
                }
            }
        }
    }
    if nest {
        for (from, to) in nested {
            let inner = &text[from..to];
            let redacted = redact_client_credentials_in_text(inner, depth + 1);
            if redacted != inner {
                edits.push((from, to, redacted));
            }
        }
    }
    if edits.is_empty() {
        return text.to_string();
    }
    // A replaced word holds a nested command it replaced too: the first edit
    // of a span wins, and an edit inside one already made is left out.
    edits.sort_by_key(|(from, to, _)| (*from, std::cmp::Reverse(*to)));
    let mut out = String::with_capacity(text.len());
    let mut copied = 0usize;
    for (from, to, replacement) in edits {
        if from < copied {
            continue;
        }
        out.push_str(&text[copied..from]);
        out.push_str(&replacement);
        copied = to;
    }
    out.push_str(&text[copied..]);
    out
}

/// A header name that says it carries a credential: one of its `-` or `_`
/// separated parts is a credential word (`Authorization`, `X-Api-Key`,
/// `X-Auth-Token`, `Cookie`), compared whole and without case. A word inside
/// a part does not count: `X-Author` is not a credential header.
const CREDENTIAL_HEADER_NAME: &str = r"(?i:(?:[A-Za-z0-9]+[-_])*(?:authorization|auth|token|key|apikey|secret|cookie|password|passwd|credentials?)(?:[-_][A-Za-z0-9]+)*)";

lazy_static! {
    /// A quoted header given with `-H` / `--header` (`-H "Name: value"`)
    /// whose name is a [`CREDENTIAL_HEADER_NAME`]: the value runs to the
    /// closing quote.
    static ref CREDENTIAL_HEADER_OPTION_QUOTED: Regex = Regex::new(&format!(
        r#"(?P<lead>(?:^|\s)(?:-H|--header)(?:=|\s*)["']{CREDENTIAL_HEADER_NAME}\s*:\s*)(?P<value>[^"'\r\n]+)"#
    ))
    .expect("Failed to compile credential header regex");
    /// The same without quotes (`-H Name:value`): the value is one word.
    static ref CREDENTIAL_HEADER_OPTION_BARE: Regex = Regex::new(&format!(
        r"(?P<lead>(?:^|\s)(?:-H|--header)(?:=|\s*){CREDENTIAL_HEADER_NAME}:)(?P<value>\S+)"
    ))
    .expect("Failed to compile credential header regex");
    /// The same header as an argument of its own (`Name: value`).
    static ref CREDENTIAL_HEADER: Regex = Regex::new(&format!(
        r"^(?P<lead>{CREDENTIAL_HEADER_NAME}\s*:\s*)(?P<value>.+)$"
    ))
    .expect("Failed to compile credential header regex");
}

/// A header value the passes before this one already masked: it holds the
/// marker, or stars alone.
fn header_value_is_masked(value: &str) -> bool {
    value.contains(REDACTED) || value.trim().chars().all(|c| c == '*')
}

/// The value of a credential-named header option masked, in a command
/// written as one string or in one argument that holds the option and its
/// value.
fn redact_credential_header_options(text: &str) -> String {
    let mask = |caps: &Captures| {
        if header_value_is_masked(&caps["value"]) {
            caps[0].to_string()
        } else {
            format!("{}{}", &caps["lead"], REDACTED)
        }
    };
    let quoted = CREDENTIAL_HEADER_OPTION_QUOTED.replace_all(text, mask);
    CREDENTIAL_HEADER_OPTION_BARE
        .replace_all(&quoted, mask)
        .into_owned()
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
/// (a certificate bundle, an encoded key) never travels whole. Before that,
/// the credential a common client takes under an option whose name does not
/// say so is masked (`curl -u user:password`, `mysql -pPASSWORD`, `sshpass -p`,
/// `redis-cli -a`: [`CLIENT_CREDENTIAL_OPTIONS`]), read only in a simple
/// command whose program is that client (its first word after assignments
/// and the wrappers of [`COMMAND_WRAPPERS`]); an argument that holds a
/// command of its own (a `-c` string) is read the same way, nested up to
/// [`MAX_COMMAND_NESTING`] levels. After that, the value of a `-H` /
/// `--header` option whose header name has a credential word as one of its
/// parts ([`CREDENTIAL_HEADER_NAME`]).
///
/// What this cannot know stays: a password given as a plain argument, a
/// secret inside an inline script that is not a `name=value` assignment, a
/// token of a shape or under an option not listed here, a client run by a
/// wrapper not listed here.
pub fn redact_command_line<S: AsRef<str>>(args: &[S]) -> Vec<String> {
    let words: Vec<&str> = args.iter().map(|arg| arg.as_ref()).collect();
    let pieces: Vec<CommandPiece> = words
        .iter()
        .map(|word| {
            if COMMAND_SEPARATOR_WORDS.contains(word) {
                CommandPiece::Separator
            } else {
                CommandPiece::Word(*word)
            }
        })
        .collect();
    let args: Vec<String> = words
        .iter()
        .zip(client_credential_replacements(&pieces))
        .map(|(word, replacement)| match replacement {
            Some(replacement) => replacement,
            // An argument that is itself a command (`sh -c "..."`).
            None if word.contains(char::is_whitespace) => {
                redact_client_credentials_in_text(word, 1)
            }
            None => word.to_string(),
        })
        .collect();
    let mut out: Vec<String> = redact_cli_args(&args, &[])
        .into_iter()
        .map(|arg| match arg.split_once('=') {
            Some((name, value)) if is_assignment_name(name) && !value.is_empty() => {
                format!("{name}={REDACTED}")
            }
            _ => redact_java_properties(&redact_credential_header_options(&redact_text(&arg))),
        })
        .collect();
    // A secret-named word and its value as two arguments (`aws configure set
    // aws_secret_access_key VALUE`): read as the text form reads the pair.
    for index in 1..out.len() {
        let (name, value) = (&out[index - 1], &out[index]);
        if name.starts_with('-')
            || name.contains(char::is_whitespace)
            || value.starts_with('-')
            || value.contains(char::is_whitespace)
            || !is_secret_field_name(name)
        {
            continue;
        }
        let pair = format!("{name} {value}");
        let masked = redact_named_fields(&pair);
        if let Some(rest) = masked.strip_prefix(&format!("{name} ")) {
            if rest != value {
                out[index] = rest.to_string();
            }
        }
    }
    // A header that is the argument after `-H` / `--header`.
    for index in 1..out.len() {
        if !matches!(out[index - 1].as_str(), "-H" | "--header") {
            continue;
        }
        let masked = CREDENTIAL_HEADER
            .captures(&out[index])
            .filter(|caps| !header_value_is_masked(&caps["value"]))
            .map(|caps| format!("{}{}", &caps["lead"], REDACTED));
        if let Some(masked) = masked {
            out[index] = masked;
        }
    }
    out.into_iter().map(cap_argument).collect()
}

/// A command, or a path taken from one (an interpreter's inline `-c` script),
/// made safe to leave the host: the client credentials and header options of
/// [`redact_command_line`], [`redact_text`], and the
/// [`COMMAND_LINE_ARG_MAX_CHARS`] cap. The same limit holds: what is not a
/// known shape, a named field or a listed client's option stays.
pub fn redact_command_text(text: &str) -> String {
    cap_argument(redact_java_properties(&redact_credential_header_options(
        &redact_text(&redact_client_credentials_in_text(text, 0)),
    )))
}

lazy_static! {
    /// A JVM system property on a command line (`-Dname=value`, also behind
    /// `-J`): the value runs to the next space or quote.
    static ref JAVA_PROPERTY: Regex =
        Regex::new(r#"(?P<lead>(?:^|\s|["'])(?:-J)?-D(?P<name>[A-Za-z0-9_.\-]+)=)(?P<value>[^\s"']+)"#)
            .expect("Failed to compile JVM property regex");
}

/// The value of a JVM system property whose name says it is a credential
/// (`-Djavax.net.ssl.keyStorePassword=...`, `-Ddb.password=...`): the last
/// dotted segment of the name, its camel case read as words, is a
/// [`is_secret_field_name`] name.
fn redact_java_properties(text: &str) -> String {
    if !text.contains("-D") {
        return text.to_string();
    }
    JAVA_PROPERTY
        .replace_all(text, |caps: &regex::Captures| {
            let name = &caps["name"];
            let last = name.rsplit('.').next().unwrap_or(name);
            let mut snake = String::with_capacity(last.len() + 4);
            for (i, c) in last.chars().enumerate() {
                if c.is_ascii_uppercase() && i > 0 {
                    snake.push('_');
                }
                snake.push(c.to_ascii_lowercase());
            }
            if caps["value"] != *REDACTED && is_secret_field_name(&snake) {
                format!("{}{}", &caps["lead"], REDACTED)
            } else {
                caps[0].to_string()
            }
        })
        .into_owned()
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
/// interpreter's script argument can be a whole inline `-c` command. The last
/// two are the commands of a denied-command event, as an agent's transcript
/// holds them.
const COMMAND_TEXT_KEYS: &[&str] = &[
    "command",
    "script_path",
    "parent_script_path",
    "grandparent_script_path",
    "denied_command",
    "bypass_command",
];

/// JSON keys whose string value is made of a command's words and is only ever
/// compared for equality (the key two spellings of one command share). The
/// value is replaced by a digest of itself: equal values stay equal, and the
/// words do not travel.
const COMMAND_DIGEST_KEYS: &[&str] = &["semantic_key"];

/// What a digested value starts with ([`digest_command_key`]).
pub const COMMAND_DIGEST_PREFIX: &str = "sha256:";

/// Hex characters of a digested value after its prefix (128 bits).
const COMMAND_DIGEST_HEX_CHARS: usize = 32;

fn is_command_digest(text: &str) -> bool {
    text.strip_prefix(COMMAND_DIGEST_PREFIX).is_some_and(|hex| {
        hex.len() == COMMAND_DIGEST_HEX_CHARS
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// A value that is only compared for equality, replaced by a digest of
/// itself: [`COMMAND_DIGEST_PREFIX`] and the first 128 bits of its SHA-256.
/// Two equal values give the same digest. An empty value stays empty and a
/// value that is already a digest stays as it is, so applying this twice
/// changes nothing.
pub fn digest_command_key(text: &str) -> String {
    use sha2::{Digest, Sha256};
    if text.is_empty() || is_command_digest(text) {
        return text.to_string();
    }
    let digest = Sha256::digest(text.as_bytes());
    format!(
        "{COMMAND_DIGEST_PREFIX}{}",
        hex::encode(&digest[..COMMAND_DIGEST_HEX_CHARS / 2])
    )
}

/// The JSON keys [`redact_command_lines_in_json`] acts on, for a caller that
/// accounts for what the redaction changed.
pub fn redacted_command_keys() -> Vec<&'static str> {
    COMMAND_LINE_ARRAY_KEYS
        .iter()
        .chain(COMMAND_TEXT_KEYS)
        .chain(COMMAND_DIGEST_KEYS)
        .copied()
        .collect()
}

/// Every captured command line in a JSON document EDAMAME is about to hand
/// off the host (an MCP answer, an export), redacted in place: arrays under a
/// `cmd`-named key through [`redact_command_line`], commands and script paths
/// through [`redact_command_text`], a command given as an array of strings
/// under one of those keys as an argv (any other array there is walked as a
/// document), and a value under a [`COMMAND_DIGEST_KEYS`] key through
/// [`digest_command_key`]. A JSON document carried in a string value (an
/// export that nests one) is redacted the same way.
///
/// This is a redaction of known shapes, not a guarantee that no secret
/// travels: see [`redact_command_line`] for what stays.
pub fn redact_command_lines_in_json(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, item) in map.iter_mut() {
                let key = key.as_str();
                match item {
                    // An argv: the array under a `cmd`-named key, or an array
                    // of strings under a command or script key. Any other
                    // array under one of those is a document and is walked.
                    Value::Array(args)
                        if COMMAND_LINE_ARRAY_KEYS.contains(&key)
                            || (COMMAND_TEXT_KEYS.contains(&key)
                                && !args.is_empty()
                                && args.iter().all(Value::is_string)) =>
                    {
                        let text: Vec<String> = args
                            .iter()
                            .map(|a| {
                                a.as_str()
                                    .map(str::to_string)
                                    .unwrap_or_else(|| a.to_string())
                            })
                            .collect();
                        *args = redact_command_line(&text)
                            .into_iter()
                            .map(Value::String)
                            .collect();
                    }
                    Value::String(text)
                        if COMMAND_LINE_ARRAY_KEYS.contains(&key)
                            || COMMAND_TEXT_KEYS.contains(&key) =>
                    {
                        *text = redact_command_text(text);
                    }
                    Value::String(text) if COMMAND_DIGEST_KEYS.contains(&key) => {
                        *text = digest_command_key(text);
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
    if total <= COMMAND_LINE_ARG_MAX_CHARS || is_capped_argument(&arg) {
        return arg;
    }
    let head: String = arg.chars().take(COMMAND_LINE_ARG_MAX_CHARS).collect();
    format!(
        "{head}...[{} more chars]",
        total - COMMAND_LINE_ARG_MAX_CHARS
    )
}

/// An argument [`cap_argument`] already capped: its head and the
/// `...[N more chars]` count. Capping it again would replace the count of the
/// original's characters with the count of the marker's, so a stored value
/// redacted a second time (a record read back, a document served twice)
/// keeps the first count.
fn is_capped_argument(arg: &str) -> bool {
    let Some((head_end, _)) = arg.char_indices().nth(COMMAND_LINE_ARG_MAX_CHARS) else {
        return false;
    };
    arg[head_end..]
        .strip_prefix("...[")
        .and_then(|rest| rest.strip_suffix(" more chars]"))
        .is_some_and(|count| !count.is_empty() && count.bytes().all(|b| b.is_ascii_digit()))
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

    /// A Telegram bot token as the Bot API issues them: a numeric bot id, a
    /// colon, a 35-character secret starting with `AA`.
    fn fake_telegram_token() -> String {
        let bot_id: String = (1u8..=10).map(|i| char::from(b'0' + i % 10)).collect();
        format!("{bot_id}:{}", fake("AA", 33))
    }

    #[test]
    fn every_known_secret_shape_is_masked() {
        let jwt = format!("{}.{}.{}", fake("eyJ", 20), fake("eyJ", 30), fake("", 20));
        let cases = [
            fake_telegram_token(),
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
    fn telegram_bot_tokens_are_masked_in_bot_api_urls_and_bare() {
        let token = fake_telegram_token();
        let secret = token.split_once(':').map(|(_, s)| s.to_string()).unwrap();
        // What reqwest's Display appends to a failed request.
        let line = format!(
            "WARN core: Telegram polling failed: Telegram getUpdates request failed: \
             error sending request for url (https://api.telegram.org/bot{token}/getUpdates)"
        );
        let out = redact_log_line(&line);
        assert!(!out.contains(&secret), "{out}");
        assert!(
            out.ends_with("for url (https://api.telegram.org/bot[REDACTED]/getUpdates)"),
            "{out}"
        );
        // The file download path carries it too.
        let out = redact_text(&format!(
            "GET https://api.telegram.org/file/bot{token}/photos/file_7.jpg failed"
        ));
        assert_eq!(
            out,
            "GET https://api.telegram.org/file/bot[REDACTED]/photos/file_7.jpg failed"
        );
        // Bare, in free text or a structured field.
        for text in [
            format!("token {token} accepted"),
            format!("bot_config={{\"value\": \"{token}\"}}"),
        ] {
            let out = redact_log_line(&text);
            assert!(!out.contains(&secret), "{out}");
        }
    }

    #[test]
    fn telegram_shapes_leave_lookalikes_alone() {
        for text in [
            "2026-11-12T10:30:45.123456Z  INFO edamame_core: tick at 10:30:45",
            "GET /bot/status 200",
            "routed through /bottleneck/12345:short",
            "port 443:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA open",
            "peer 2001:0db8:85a3:0000:0000:8a2e:0370:7334 joined",
            "chat 123456789: AA batteries low",
        ] {
            assert_eq!(redact_text(text), text);
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

    /// E-mail addresses in log lines keep their domain and lose the local
    /// part, however they are written; operator-facing text keeps them.
    #[test]
    fn log_lines_mask_the_local_part_of_email_addresses() {
        for (line, masked) in [
            (
                "Initializing breach cache with email: jane.doe+work@example.com",
                "Initializing breach cache with email: [REDACTED]@example.com",
            ),
            (
                "Failed to check email John_Doe99@Mail.Example.co.uk: timeout",
                "Failed to check email [REDACTED]@Mail.Example.co.uk: timeout",
            ),
            (
                "accounts [\"a@x.org\", \"b@y.net\"] monitored",
                "accounts [\"[REDACTED]@x.org\", \"[REDACTED]@y.net\"] monitored",
            ),
            (
                "Removing trust domain email from registry: frank@edamame.tech",
                "Removing trust domain email from registry: [REDACTED]@edamame.tech",
            ),
            ("<ops@example.com>", "<[REDACTED]@example.com>"),
        ] {
            assert_eq!(redact_log_line(line), masked);
        }
        assert_eq!(redact_email("jane@example.com"), "[REDACTED]@example.com");
        assert_eq!(redact_email(" jane@example.com "), "[REDACTED]@example.com");
        assert_eq!(redact_email("not-an-address"), REDACTED);
        assert_eq!(redact_email(""), REDACTED);
        let text = "breach for jane@example.com";
        assert_eq!(
            redact_text(text),
            text,
            "operator-facing text keeps addresses"
        );
    }

    /// Not an address: a user without a dotted domain, a URL's userinfo
    /// (its own shape keeps the user), a scoped package or version, an
    /// npm-style `@scope/name`, decorators and handles.
    #[test]
    fn log_lines_keep_what_only_looks_like_an_email() {
        for line in [
            "ssh user@host failed",
            "listening on root@localhost",
            "fetched https://user@registry.example.com/pkg",
            "installed @scope/package@1.2.3 and lodash@4.17.21",
            "image nginx@sha256:abcdef",
            "decorator @Override applied",
            "mention @frank in the thread",
            "process at 0x7f@1",
        ] {
            assert_eq!(redact_log_line(line), line, "over-redacted");
        }
        // A URL password is masked by its own shape; the user stays.
        assert_eq!(
            redact_log_line("https://bob:hunter2@git.example.com/repo"),
            "https://bob:[REDACTED]@git.example.com/repo"
        );
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
        assert!(
            out[15].len() < 400,
            "a long blob is capped: {} chars",
            out[15].len()
        );
        assert!(out[15].ends_with(&format!(
            "...[{} more chars]",
            4000 - COMMAND_LINE_ARG_MAX_CHARS
        )));
        assert!(out
            .iter()
            .all(|a| !a.contains("MIIJQgIBADANBgkqhkiG9w0BAQEFAASCCSww")));
        // A redacted command line redacted again is unchanged: the capped
        // blob keeps the count of the original's characters.
        assert_eq!(redact_command_line(&out), out);
        assert_eq!(redact_command_text(&out[15]), out[15]);
    }

    #[test]
    fn registry_logins_secret_pairs_and_jvm_properties_are_masked() {
        let password = fake("Pq", 14);
        let secret = fake("", 40);
        let argv = |words: &[&str]| words.iter().map(|w| w.to_string()).collect::<Vec<_>>();
        let cases: Vec<(Vec<String>, &String)> = vec![
            (
                argv(&["docker", "login", "-u", "me", "-p", &password]),
                &password,
            ),
            (
                argv(&[
                    "docker",
                    "login",
                    "--password",
                    &password,
                    "registry.example.com",
                ]),
                &password,
            ),
            (
                argv(&[
                    "podman",
                    "login",
                    &format!("--password={password}"),
                    "quay.io",
                ]),
                &password,
            ),
            (
                argv(&["aws", "configure", "set", "aws_secret_access_key", &secret]),
                &secret,
            ),
            (
                argv(&[
                    "java",
                    &format!("-Djavax.net.ssl.keyStorePassword={password}"),
                    "-jar",
                    "app.jar",
                ]),
                &password,
            ),
            (
                argv(&[
                    "java",
                    &format!("-Djavax.net.ssl.trustStorePassword={password}"),
                    &format!("-Ddb.password={password}"),
                    "-jar",
                    "app.jar",
                ]),
                &password,
            ),
        ];
        for (words, value) in &cases {
            let out = redact_command_line(words);
            assert!(!out.join(" ").contains(value.as_str()), "{:?}", out);
            assert_eq!(redact_command_line(&out), out, "idempotent");
            let text = redact_command_text(&words.join(" "));
            assert!(!text.contains(value.as_str()), "{text}");
            assert_eq!(redact_command_text(&text), text, "idempotent");
        }
        // The same letters elsewhere keep their meaning.
        let run = argv(&["docker", "run", "-p", "8080:80", "nginx"]);
        assert_eq!(redact_command_line(&run), run);
        let stdin = argv(&["docker", "login", "--password-stdin", "-u", "me"]);
        assert_eq!(redact_command_line(&stdin), stdin);
        let props = argv(&[
            "java",
            "-Dfile.encoding=UTF-8",
            "-Dserver.port=8080",
            "-jar",
            "x",
        ]);
        assert_eq!(redact_command_line(&props), props);
        // The JVM rule holds in free text too (a log line).
        let line = format!("started java -Dmail.smtp.password={password} -jar mail.jar");
        assert!(!redact_command_text(&line).contains(&password));
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
        for leaked in [
            "hunter2",
            "not-a-real-key",
            "abcdefghijklmnopqrstuvwxyz123456",
            "s3cret",
            "nested-secret",
        ] {
            assert!(!text.contains(leaked), "{leaked} survived: {text}");
        }
        assert_eq!(doc["sessions"][0]["l7"]["cmd"][1], "server.js");
        assert_eq!(doc["sessions"][0]["l7"]["process_name"], "node");
        assert_eq!(doc["finding_key"], "vuln:abc");
    }

    /// The two commands of a denied-command event are redacted like any
    /// other command, as a string or as an argv, and the key the two
    /// spellings share is replaced by a digest: equal keys stay equal, and
    /// the words they were made of are gone.
    #[test]
    fn the_commands_of_a_denied_command_event_are_redacted_and_its_key_digested() {
        let key = "curl\u{1}-H\u{1}Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456";
        let event = |key: &str| {
            serde_json::json!({
                "agent_type": "claude_code",
                "tool": "Bash",
                "denied_command": "curl -H 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456' https://x",
                "bypass_command": ["/bin/sh", "-c", "API_TOKEN=nested-secret curl https://x"],
                "semantic_key": key,
            })
        };
        let mut doc =
            serde_json::json!({"events": [event(key), event(key), event("git\u{1}push")]});
        redact_command_lines_in_json(&mut doc);
        let text = doc.to_string();
        for leaked in ["abcdefghijklmnopqrstuvwxyz123456", "nested-secret"] {
            assert!(!text.contains(leaked), "{leaked} survived: {text}");
        }
        let events = doc["events"].as_array().unwrap();
        assert_eq!(events[0]["tool"], "Bash");
        assert_eq!(events[0]["agent_type"], "claude_code");
        assert!(events[0]["denied_command"]
            .as_str()
            .unwrap()
            .starts_with("curl -H"));
        assert_eq!(events[0]["bypass_command"][0], "/bin/sh");
        let digest = events[0]["semantic_key"].as_str().unwrap().to_string();
        assert!(digest.starts_with(COMMAND_DIGEST_PREFIX));
        assert_eq!(digest.len(), COMMAND_DIGEST_PREFIX.len() + 32);
        assert!(!digest.contains("curl") && !digest.contains("Bearer"));
        assert_eq!(events[1]["semantic_key"], events[0]["semantic_key"]);
        assert_ne!(events[2]["semantic_key"], events[0]["semantic_key"]);
        // A second pass changes nothing: a digest is not digested again.
        let once = doc.clone();
        redact_command_lines_in_json(&mut doc);
        assert_eq!(
            doc["events"][0]["semantic_key"],
            once["events"][0]["semantic_key"]
        );
        assert_eq!(digest_command_key(""), "");
        assert_eq!(digest_command_key(&digest), digest);
        // A value that only looks like a digest is digested.
        assert_ne!(digest_command_key("sha256:XYZ"), "sha256:XYZ");
        for key in [
            "denied_command",
            "bypass_command",
            "semantic_key",
            "cmd",
            "parent_script_path",
        ] {
            assert!(redacted_command_keys().contains(&key), "{key}");
        }
    }

    /// `argv` through [`redact_command_line`], joined with spaces, and the
    /// same words written as one string through [`redact_command_text`]:
    /// both give `expected`. For words without white space in them, where
    /// the two forms are the same command.
    fn same_in_both_forms(argv: &[&str], expected: &str) {
        assert_eq!(
            redact_command_line(argv).join(" "),
            expected,
            "as an argv: {argv:?}"
        );
        assert_eq!(
            redact_command_text(&argv.join(" ")),
            expected,
            "as one string: {argv:?}"
        );
    }

    /// The credential a common client takes under an option whose name does
    /// not say so, as an argv and as one string.
    #[test]
    fn a_clients_credential_option_is_masked() {
        // A user and a password: the user stays.
        same_in_both_forms(
            &["curl", "-u", "alice:hunter2pass", "https://example.test"],
            "curl -u alice:[REDACTED] https://example.test",
        );
        same_in_both_forms(
            &[
                "/usr/bin/curl",
                "--user=alice:hunter2pass",
                "-s",
                "https://example.test",
            ],
            "/usr/bin/curl --user=alice:[REDACTED] -s https://example.test",
        );
        same_in_both_forms(
            &[
                "curl.exe",
                "--proxy-user",
                "bob:hunter2pass",
                "https://example.test",
            ],
            "curl.exe --proxy-user bob:[REDACTED] https://example.test",
        );
        same_in_both_forms(
            &["http", "-a", "alice:hunter2pass", "GET", "example.test"],
            "http -a alice:[REDACTED] GET example.test",
        );
        // A password attached to its option, or in the next argument.
        same_in_both_forms(
            &["mysql", "-u", "root", "-phunter2pass", "db"],
            "mysql -u root -p[REDACTED] db",
        );
        same_in_both_forms(
            &["sshpass", "-p", "hunter2pass", "ssh", "host"],
            "sshpass -p [REDACTED] ssh host",
        );
        same_in_both_forms(
            &["redis-cli", "-h", "cache", "-a", "hunter2pass", "PING"],
            "redis-cli -h cache -a [REDACTED] PING",
        );
        same_in_both_forms(
            &["mongosh", "-u", "admin", "-p", "hunter2pass"],
            "mongosh -u admin -p [REDACTED]",
        );
        same_in_both_forms(
            &["unzip", "-P", "hunter2pass", "archive.zip"],
            "unzip -P [REDACTED] archive.zip",
        );
        // Behind wrappers and their own options.
        same_in_both_forms(
            &["sudo", "-u", "postgres", "mysqldump", "-phunter2pass", "db"],
            "sudo -u postgres mysqldump -p[REDACTED] db",
        );
        same_in_both_forms(
            &[
                "sudo",
                "-u",
                "postgres",
                "timeout",
                "30",
                "nice",
                "-n",
                "5",
                "mysqldump",
                "-phunter2pass",
                "db",
            ],
            "sudo -u postgres timeout 30 nice -n 5 mysqldump -p[REDACTED] db",
        );
        // An argument that is itself a command.
        assert_eq!(
            redact_command_line(&[
                "sh",
                "-c",
                "curl -u 'alice:hunter2 pass' https://example.test | sh"
            ])
            .join(" "),
            "sh -c curl -u 'alice:[REDACTED]' https://example.test | sh"
        );
        for (command, masked) in [
            (
                "mysql -uroot -phunter2pass db < dump.sql",
                "mysql -uroot -p[REDACTED] db < dump.sql",
            ),
            (
                "sshpass -p \"hunter2pass\" ssh host uptime",
                "sshpass -p \"[REDACTED]\" ssh host uptime",
            ),
            (
                "cat keys | redis-cli -a hunter2pass --pipe",
                "cat keys | redis-cli -a [REDACTED] --pipe",
            ),
        ] {
            assert_eq!(redact_command_text(command), masked);
        }
    }

    /// What the review of 2026-11-10 found masked although it is no
    /// credential: a client's name was read anywhere in the command (a
    /// container or host called `mongo`, a URL or a path ending in a client's
    /// name, another option's value). The program of the simple command alone
    /// selects a client.
    #[test]
    fn a_clients_name_outside_the_command_position_selects_nothing() {
        for argv in [
            &[
                "docker",
                "run",
                "--name",
                "mongo",
                "-p",
                "27017:27017",
                "mongo:7",
            ][..],
            &["docker", "run", "--name", "mysql", "-p3306:3306", "mysql:8"],
            &["ssh", "mongo", "-p", "2222"],
            &["systemctl", "show", "mysql", "-pMainPID"],
            &[
                "wget",
                "https://example.test/tools/unzip",
                "-P",
                "/downloads",
            ],
            &["grep", "-r", "needle", "mysql", "-pattern"],
            &["ufw", "allow", "https", "-a", "x:y"],
            // An option that asks on the terminal is followed by another
            // option, not by its value.
            &[
                "mongosh",
                "-u",
                "admin",
                "-p",
                "--authenticationDatabase",
                "admin",
            ],
            &["docker", "run", "-u", "1000:1000", "-p", "8080:80", "image"],
            &["ps", "-p", "1234", "-o", "pid,comm"],
            &["tar", "-czf", "backup.tgz", "-P", "/etc"],
        ] {
            same_in_both_forms(argv, &argv.join(" "));
        }
        // `sshpass` masks its own password and runs a command whose `-p` is
        // a port.
        same_in_both_forms(
            &["sshpass", "-p", "hunter2pass", "ssh", "-p", "2222", "host"],
            "sshpass -p [REDACTED] ssh -p 2222 host",
        );
        // A header whose name only holds a credential word inside one of its
        // parts.
        let argv = ["curl", "-H", "X-Author: Bob Smith", "https://example.test"];
        assert_eq!(redact_command_line(&argv), argv);
        let text = "curl -H 'X-Author: Bob Smith' https://example.test";
        assert_eq!(redact_command_text(text), text);
        let text = "curl -H X-Authored-By:BobSmith https://example.test";
        assert_eq!(redact_command_text(text), text);
    }

    /// What the review of 2026-11-10 found left as it was although it is the
    /// listed shape, each as an argv and as one string.
    #[test]
    fn a_clients_credential_is_masked_wherever_the_command_puts_it() {
        // A URL or a path whose last part names another client.
        same_in_both_forms(
            &[
                "curl",
                "https://example.test/api/http",
                "-u",
                "alice:hunter2pass",
            ],
            "curl https://example.test/api/http -u alice:[REDACTED]",
        );
        same_in_both_forms(
            &[
                "curl",
                "https://example.test/db/mysql",
                "-u",
                "alice:hunter2pass",
            ],
            "curl https://example.test/db/mysql -u alice:[REDACTED]",
        );
        // Short options written together, the value next or attached.
        same_in_both_forms(
            &["curl", "-sSu", "alice:hunter2pass", "https://example.test"],
            "curl -sSu alice:[REDACTED] https://example.test",
        );
        same_in_both_forms(
            &["curl", "-sSualice:hunter2pass", "https://example.test"],
            "curl -sSualice:[REDACTED] https://example.test",
        );
        // A key given as the user with an empty password.
        same_in_both_forms(
            &["curl", "-u", "AbCdEf0123:", "https://example.test"],
            "curl -u [REDACTED]: https://example.test",
        );
        // A user alone asks for the password, and stays.
        same_in_both_forms(
            &["curl", "-u", "alice", "https://example.test"],
            "curl -u alice https://example.test",
        );
        // HTTPie with a bearer token, the kind given before or after.
        same_in_both_forms(
            &[
                "http",
                "-A",
                "bearer",
                "-a",
                "TokenValue0123",
                "https://example.test",
            ],
            "http -A bearer -a [REDACTED] https://example.test",
        );
        same_in_both_forms(
            &[
                "http",
                "--auth=TokenValue0123",
                "--auth-type=bearer",
                "https://example.test",
            ],
            "http --auth=[REDACTED] --auth-type=bearer https://example.test",
        );
        same_in_both_forms(
            &["http", "-a", "alice", "https://example.test"],
            "http -a alice https://example.test",
        );
        // More clients of the MySQL and MariaDB families.
        same_in_both_forms(
            &["mysqlsh", "-uroot", "-phunter2pass", "--sql"],
            "mysqlsh -uroot -p[REDACTED] --sql",
        );
        same_in_both_forms(
            &["mycli", "-u", "root", "-p", "hunter2pass", "db"],
            "mycli -u root -p [REDACTED] db",
        );
        same_in_both_forms(
            &["mariadb-import", "-phunter2pass", "db", "rows.csv"],
            "mariadb-import -p[REDACTED] db rows.csv",
        );
        same_in_both_forms(
            &[
                "mongoexport",
                "-u",
                "admin",
                "-p",
                "hunter2pass",
                "--db",
                "app",
            ],
            "mongoexport -u admin -p [REDACTED] --db app",
        );
        // A password with a space in it: escaped in one string, one argument
        // in an argv.
        assert_eq!(
            redact_command_text("curl -u alice:hunter2\\ pass https://example.test"),
            "curl -u alice:[REDACTED] https://example.test"
        );
        assert_eq!(
            redact_command_line(&["curl", "-u", "alice:hunter2 pass", "https://example.test"])
                .join(" "),
            "curl -u alice:[REDACTED] https://example.test"
        );
        // After a separator, with or without spaces around it, and behind
        // leading assignments and wrappers.
        for separator in [";", " ; ", "&&", " && ", "||", "|", " | ", "&", "\n"] {
            let text = format!("true{separator}curl -u alice:hunter2pass https://example.test");
            let masked = redact_command_text(&text);
            assert_eq!(
                masked,
                format!("true{separator}curl -u alice:[REDACTED] https://example.test"),
                "{separator:?}"
            );
        }
        assert_eq!(
            redact_command_text("HOME=/tmp nohup curl -u alice:hunter2pass https://example.test"),
            "HOME=/tmp nohup curl -u alice:[REDACTED] https://example.test"
        );
        assert_eq!(
            redact_command_text("curl -s https://example.test 2>&1 | mysql -phunter2pass db"),
            "curl -s https://example.test 2>&1 | mysql -p[REDACTED] db"
        );
    }

    /// A command nested in another is read like the outer one: a `-c`
    /// string, a quoted remote command, a subshell, a command substitution,
    /// backticks. Each as one string, and as the argv of a shell given it.
    #[test]
    fn a_nested_command_is_read_for_client_options() {
        let inner = "curl -u alice:hunter2pass https://example.test";
        let masked = "curl -u alice:[REDACTED] https://example.test";
        for (command, expected) in [
            (
                format!("bash -c \"{inner}\""),
                format!("bash -c \"{masked}\""),
            ),
            (
                format!("bash -lc '{inner}'"),
                format!("bash -lc '{masked}'"),
            ),
            (format!("({inner})"), format!("({masked})")),
            (format!("echo $({inner})"), format!("echo $({masked})")),
            (
                format!("echo \"$({inner})\""),
                format!("echo \"$({masked})\""),
            ),
            (format!("echo `{inner}`"), format!("echo `{masked}`")),
            (
                format!("diff <({inner}) local.json"),
                format!("diff <({masked}) local.json"),
            ),
            (
                "ssh host \"mysql -uroot -phunter2pass db\"".to_string(),
                "ssh host \"mysql -uroot -p[REDACTED] db\"".to_string(),
            ),
        ] {
            assert_eq!(redact_command_text(&command), expected, "{command}");
            // The shell's argv: the command as one argument.
            assert_eq!(
                redact_command_line(&["bash", "-c", &command]).join(" "),
                format!("bash -c {expected}"),
                "{command}"
            );
        }
        // Up to MAX_COMMAND_NESTING levels, the outer command included.
        let mut command = inner.to_string();
        let mut expected = masked.to_string();
        for _ in 1..MAX_COMMAND_NESTING {
            command = format!("echo $({command})");
            expected = format!("echo $({expected})");
        }
        assert_eq!(redact_command_text(&command), expected, "{command}");
        // One level more is not read for client options (a bound, pinned).
        let deeper = format!("echo $({command})");
        assert_eq!(redact_command_text(&deeper), deeper);
    }

    /// Token shapes with a prefix of their own, a token in the user position
    /// of a URL, and a header option whose name says it carries one. The
    /// token-shaped values are built at run time: no literal of a provider's
    /// token shape is in the source.
    #[test]
    fn tokens_by_prefix_in_a_url_and_in_a_header_option_are_masked() {
        let secrets = [
            fake("glpat-", 20),
            fake("npm_", 36),
            fake("hf_", 34),
            fake("sk_live_", 24),
            fake("rk_live_", 24),
        ];
        for secret in &secrets {
            let text = redact_text(&format!("deploy with {secret} now"));
            assert_eq!(text, "deploy with [REDACTED] now", "{}", &secret[..4]);
        }
        // Names that only start like a token prefix stay.
        for plain in [
            "npm_config_registry",
            "hf_hub_download",
            "sk_live_",
            "glpat-",
        ] {
            assert_eq!(redact_secret_tokens(plain), plain);
        }
        let url_token = fake("", 24);
        assert_eq!(
            redact_text(&format!(
                "git clone https://{url_token}@gitlab.example.test/o/r.git"
            )),
            "git clone https://[REDACTED]@gitlab.example.test/o/r.git"
        );
        // A token as the user, whatever follows its colon.
        assert_eq!(
            redact_text(&format!(
                "git clone https://{url_token}:x-oauth-basic@github.example.test/o/r.git"
            )),
            "git clone https://[REDACTED]@github.example.test/o/r.git"
        );
        assert_eq!(
            redact_text("https://deploy:AbCdEfGhIjKl@host/o/r.git"),
            "https://deploy:[REDACTED]@host/o/r.git"
        );
        // A header option, quoted, bare, attached, and as the next argument.
        assert_eq!(
            redact_command_text("curl -H 'X-Auth-Value: abc def' https://example.test"),
            "curl -H 'X-Auth-Value: [REDACTED]' https://example.test"
        );
        assert_eq!(
            redact_command_text("curl -H X-Custom-Auth:abcdef https://example.test"),
            "curl -H X-Custom-Auth:[REDACTED] https://example.test"
        );
        // (A name the named-field rule knows may already be masked by it.)
        let api_key = redact_command_text("curl -H 'X-Api-Key: abcdef123' https://example.test");
        assert!(!api_key.contains("abcdef123"), "{api_key}");
        assert!(api_key.starts_with("curl -H 'X-Api-Key: "), "{api_key}");
        let args = redact_command_line(&[
            "curl",
            "-H",
            "X-Custom-Auth: abc def",
            "--header=X-Signing-Secret:abcdef",
            "-H",
            "X_Session_Token: abcdef",
            "https://example.test",
        ]);
        assert_eq!(args[2], "X-Custom-Auth: [REDACTED]");
        assert!(!args[3].contains("abcdef"), "{}", args[3]);
        assert!(!args[5].contains("abcdef"), "{}", args[5]);
        // An Authorization header keeps its scheme, as before.
        let bearer = redact_command_text(
            "curl -H 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456' https://example.test",
        );
        assert_eq!(
            bearer,
            "curl -H 'Authorization: Bearer [REDACTED]' https://example.test"
        );
    }

    /// An option that is a credential for one program is something else for
    /// another, and an ordinary argument is left alone.
    #[test]
    fn an_ordinary_argument_is_left_alone() {
        for args in [
            vec!["docker", "run", "-u", "1000:1000", "-p", "8080:80", "image"],
            vec!["ssh", "-p", "2222", "host"],
            vec!["ps", "-p", "1234", "-o", "pid,comm"],
            vec!["grep", "-a", "pattern", "file"],
            vec!["mysql", "-u", "root", "-p"],
            vec!["mysql", "-P", "3306", "-h", "db"],
            vec!["curl", "-u", "alice", "https://example.test"],
            vec![
                "curl",
                "-H",
                "Accept: application/json",
                "https://example.test",
            ],
            vec![
                "curl",
                "-H",
                "Content-Type: text/plain",
                "-d",
                "@body.txt",
                "https://example.test",
            ],
            vec!["git", "clone", "https://git@github.com/owner/repo.git"],
            vec!["tar", "-czf", "backup.tgz", "-P", "/etc"],
            vec!["npm", "run", "build", "--", "--mode", "production"],
            vec![
                "/opt/homebrew/bin/node",
                "/Users/u/app/server.js",
                "--inspect",
            ],
        ] {
            assert_eq!(redact_command_line(&args), args, "{args:?}");
        }
        for command in [
            "docker run -u 1000:1000 image",
            "ssh -p 2222 host uptime",
            "curl -s https://example.test/v1/items?page=2",
            "git clone https://git@github.com/owner/repo.git",
            "curl -H 'Accept: application/json' https://example.test",
            "python3 manage.py migrate --noinput",
        ] {
            assert_eq!(redact_command_text(command), command);
        }
    }

    /// What the redaction does not know stays: it masks known shapes, named
    /// fields and listed clients' options, and cannot tell a password given
    /// as a plain argument, or a literal inside an inline script, from any
    /// other word. This pins the limit; it is not a wish.
    #[test]
    fn a_secret_of_no_known_shape_stays() {
        let args = redact_command_line(&[
            "/usr/local/bin/backup-tool",
            "positional-Passw0rd-of-no-shape",
            "prod",
        ]);
        assert_eq!(args[1], "positional-Passw0rd-of-no-shape");
        let script = "python3 -c \"import db; db.connect('literal-Passw0rd-in-a-script')\"";
        assert!(redact_command_text(script).contains("literal-Passw0rd-in-a-script"));
    }

    /// An array of strings under a command or script key is an argv; any
    /// other array there is a document and is walked, not rewritten.
    #[test]
    fn only_an_array_of_strings_under_a_command_key_is_an_argv() {
        let mut doc = serde_json::json!({
            "command": ["mysql", "-phunter2pass", "db"],
            "bypass_command": [{"cmd": ["env", "API_TOKEN=nested-secret"], "n": 1}, 2],
            "script_path": [],
        });
        redact_command_lines_in_json(&mut doc);
        assert_eq!(
            doc["command"],
            serde_json::json!(["mysql", "-p[REDACTED]", "db"])
        );
        assert_eq!(
            doc["bypass_command"],
            serde_json::json!([{"cmd": ["env", "API_TOKEN=[REDACTED]"], "n": 1}, 2]),
            "objects and numbers stay what they are"
        );
        assert_eq!(doc["script_path"], serde_json::json!([]));
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
        let args = [
            "/opt/homebrew/bin/node",
            "/Users/u/app/server.js",
            "--inspect",
            "-p",
            "3000",
        ];
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
