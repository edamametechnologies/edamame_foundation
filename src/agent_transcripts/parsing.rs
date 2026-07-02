//! Shared transcript parsing helpers.
//!
//! Mirrors the field-extraction logic in the Node-side
//! `adapters/session_prediction_adapter.mjs` files (see e.g.
//! `edamame_cursor/adapters/session_prediction_adapter.mjs`). The goal is
//! "produce a payload that EDAMAME's `validate_and_normalize` accepts and
//! the LLM can model"; we do not aim for byte-for-byte parity with the
//! Node output.

use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::BTreeSet;

/// Matches text that looks like a filesystem path token. Mirrors
/// `PATH_LIKE_REGEX` in the JS adapter.
static PATH_LIKE_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?:file:///[^\s"'`)>]+|~/[^\s"'`)>]+|/[^\s"'`)>]+|[A-Za-z0-9_.\-]+(?:/[A-Za-z0-9_.@\-]+)+(?:\.[A-Za-z0-9_\-]+)?)"#,
    )
    .expect("path regex")
});

/// Windows drive-letter paths (`C:\Users\...` / `D:/repo/...`).
static WINDOWS_DRIVE_PATH_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"[A-Za-z]:[\\/][^\s"'`)\]>]+"#).expect("win drive path regex"));

static URL_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"https?://[^\s"'`)>]+"#).expect("url regex"));

static GIT_REMOTE_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"git@([A-Za-z0-9.\-]+):([^\s"'`)>]+)"#).expect("git remote regex"));

/// Common port-mention patterns (`localhost:NNN`, `port NNN`, `--port NNN`,
/// `NNN/tcp`).
static PORT_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)\b(?:localhost|127\.0\.0\.1|0\.0\.0\.0):(\d{2,5})\b|\bport\s+(\d{2,5})\b|\b--port(?:=|\s+)(\d{2,5})\b|\b(\d{1,5})/(?:tcp|udp)\b"#,
    )
    .expect("port regex")
});

static TOOL_CALL_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?m)^\[Tool call\]\s*(.+)$"#).expect("tool call regex"));
static TOOL_NAME_ARG_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?m)^\s*toolName:\s*([A-Za-z0-9_.\-]+)\s*$"#).expect("tool name regex")
});
static RECIPIENT_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?m)^\s*recipient_name:\s*([A-Za-z0-9_.\-]+)\s*$"#).expect("recipient regex")
});
static COMMAND_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?m)^\s*command:\s*(.+)$"#).expect("command regex"));

static DOMAIN_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)\b((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|org|net|io|dev|tech|cloud|co|info|biz|us|uk|eu|fr|de|app|xyz|me|ai|security|local))\b"#,
    )
    .expect("domain regex")
});

const SOURCE_FILE_SUFFIXES: &[&str] = &[
    ".rs", ".py", ".js", ".ts", ".tsx", ".jsx", ".dart", ".md", ".toml", ".yaml", ".yml", ".json",
    ".html", ".css", ".scss", ".sh",
];

// Generic credential-store path stems. Used by the agent-transcript
// scanner to detect prompts/tool-calls that mention sensitive locations.
//
// We DELIBERATELY keep this list small and generic. The full
// credential-stealer reconnaissance corpus (DPAPI master keys, Windows
// Credential Manager paths, Active Directory database paths, browser
// `User Data` directories, password manager extension IDs, crypto-wallet
// locations) lives in the obfuscated `sensitive-paths-db.json`
// CloudModel fallback shipped via flodbadd::sensitive_paths_db. That
// fallback is gzip+XOR'd in the binary so the strings do not surface in
// `strings(1)`. Embedding the same corpus here as a plain `&str` list
// would re-introduce the exact Stealc/Stealga ML fingerprint
// (`Trojan:Win32/Stealga.HAK!MTB`) we just spent significant effort
// removing from the rodata section.
//
// The patterns below stay because:
//   1. They are GENERIC stems that match many legitimate use cases
//      (developer dotfiles, cloud CLIs, package manager configs) rather
//      than the high-signal credential-vault paths.
//   2. They are short and unlikely to dominate ML feature weights.
//   3. Removing them would weaken transcript-side prompt-injection
//      detection without a corresponding runtime alternative in this
//      crate (foundation does not depend on flodbadd's CloudModel).
//
// If transcript scanning needs to cover the credential-vault paths,
// consume `sensitive_paths_db` at runtime through a foundation-owned
// accessor rather than re-embedding strings here.
const SENSITIVE_PATH_PATTERNS: &[&str] = &[
    "~/.ssh/",
    "~/.aws/",
    "~/.config/gcloud/",
    "~/.kube/",
    "~/.gnupg/",
    "~/.docker/",
    "~/.npmrc",
    "~/.netrc",
    "~/.env",
    "~/.pgpass",
    "~/.pypirc",
    "~/.git-credentials",
    "~/.vault-token",
    "~/.azure/",
    "~/.my.cnf",
    "~/Library/Keychains/",
];

/// Two roles parsed from a transcript file.
#[derive(Debug, Clone, Default)]
pub struct ParsedTranscript {
    pub user_text: String,
    pub assistant_text: String,
    pub raw_text: String,
}

/// Parse a `.txt` Cursor-style transcript with `user:` / `assistant:` markers.
pub fn parse_txt_transcript(raw_text: &str) -> ParsedTranscript {
    let mut user_sections: Vec<String> = Vec::new();
    let mut assistant_sections: Vec<String> = Vec::new();
    let mut current_role: Option<&'static str> = None;
    let mut buffer: Vec<&str> = Vec::new();

    let flush = |role: Option<&'static str>,
                 buffer: &mut Vec<&str>,
                 user: &mut Vec<String>,
                 assistant: &mut Vec<String>| {
        let joined = buffer.join("\n").trim().to_string();
        buffer.clear();
        if joined.is_empty() {
            return;
        }
        match role {
            Some("user") => user.push(joined),
            Some("assistant") => assistant.push(joined),
            _ => {}
        }
    };

    for line in raw_text.split('\n') {
        let trimmed = line.trim_end_matches('\r');
        match trimmed.trim() {
            "user:" => {
                flush(
                    current_role,
                    &mut buffer,
                    &mut user_sections,
                    &mut assistant_sections,
                );
                current_role = Some("user");
            }
            "assistant:" => {
                flush(
                    current_role,
                    &mut buffer,
                    &mut user_sections,
                    &mut assistant_sections,
                );
                current_role = Some("assistant");
            }
            _ => buffer.push(trimmed),
        }
    }
    flush(
        current_role,
        &mut buffer,
        &mut user_sections,
        &mut assistant_sections,
    );

    ParsedTranscript {
        user_text: user_sections.join("\n\n").trim().to_string(),
        assistant_text: assistant_sections.join("\n\n").trim().to_string(),
        raw_text: raw_text.to_string(),
    }
}

/// Parse a `.jsonl` transcript (Claude Code / Cursor JSONL format).
/// Each line is a JSON object with `role` ("user" | "assistant") and
/// `message.content` array containing `{ type: "text", text: ... }`.
pub fn parse_jsonl_transcript(raw_text: &str) -> ParsedTranscript {
    let mut user_sections = Vec::new();
    let mut assistant_sections = Vec::new();

    for line in raw_text.split('\n') {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let role = value.get("role").and_then(|v| v.as_str()).unwrap_or("");
        let content = value
            .get("message")
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_array());
        let text = content
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| {
                        let kind = item.get("type").and_then(|v| v.as_str()).unwrap_or("");
                        if kind == "text" {
                            item.get("text").and_then(|v| v.as_str()).map(str::to_owned)
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default();
        let trimmed = text.trim();
        if trimmed.is_empty() {
            continue;
        }
        match role {
            "user" => user_sections.push(trimmed.to_string()),
            "assistant" => assistant_sections.push(trimmed.to_string()),
            _ => {}
        }
    }

    ParsedTranscript {
        user_text: user_sections.join("\n\n").trim().to_string(),
        assistant_text: assistant_sections.join("\n\n").trim().to_string(),
        raw_text: raw_text.to_string(),
    }
}

/// Extract paths mentioned in `text`, normalizing forward slashes and
/// resolving relative paths against `workspace_root`.
pub fn extract_paths(text: &str, workspace_root: &str) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();

    let mut add = |raw: &str| {
        let cleaned = clean_trailing_path_junk(raw);
        if let Some(normalized) = decode_file_path_token(&cleaned, workspace_root) {
            let normalized = normalized.replace('\\', "/");
            if seen.insert(normalized.clone()) {
                out.push(normalized);
            }
        }
    };

    for m in PATH_LIKE_REGEX.find_iter(text) {
        add(m.as_str());
    }
    for m in WINDOWS_DRIVE_PATH_REGEX.find_iter(text) {
        add(m.as_str());
    }
    out
}

fn clean_trailing_path_junk(s: &str) -> String {
    let mut t =
        s.trim_end_matches(|c: char| matches!(c, ' ' | ',' | '.' | ':' | ';' | '!' | '?' | '\\'));
    while t.ends_with(')') {
        let opens = t.chars().filter(|c| *c == '(').count();
        let closes = t.chars().filter(|c| *c == ')').count();
        if closes > opens {
            t = &t[..t.len() - 1];
        } else {
            break;
        }
    }
    t.to_string()
}

fn decode_file_path_token(token: &str, workspace_root: &str) -> Option<String> {
    let mut candidate = token.trim().to_string();
    if candidate.is_empty() || candidate.starts_with("http://") || candidate.starts_with("https://")
    {
        return None;
    }
    if let Some(rest) = candidate.strip_prefix("file:///") {
        candidate = format!("/{rest}");
    } else if let Some(rest) = candidate.strip_prefix("file://") {
        candidate = rest.to_string();
    }
    if candidate.starts_with("~/") {
        return Some(candidate);
    }
    if candidate.starts_with('/')
        || (candidate.len() >= 3
            && candidate.chars().nth(1) == Some(':')
            && (candidate.chars().nth(2) == Some('/') || candidate.chars().nth(2) == Some('\\')))
    {
        return Some(candidate);
    }
    if candidate.contains('/') {
        if !workspace_root.is_empty() {
            let mut joined = workspace_root.trim_end_matches('/').to_string();
            joined.push('/');
            joined.push_str(&candidate);
            return Some(joined);
        }
        return Some(candidate);
    }
    None
}

/// Best-effort `host:port` extraction from an absolute http(s) URL. Avoids
/// pulling in the `url` crate for this single use case.
fn parse_host_port(url: &str) -> Option<(String, String)> {
    let (scheme, rest) = if let Some(rest) = url.strip_prefix("https://") {
        ("https", rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        ("http", rest)
    } else {
        return None;
    };
    let authority_end = rest
        .find(|c: char| matches!(c, '/' | '?' | '#'))
        .unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() {
        return None;
    }
    // Strip userinfo if present.
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, hp)| hp);
    if let Some((host, port)) = host_port.rsplit_once(':') {
        if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
            return Some((host.to_string(), port.to_string()));
        }
    }
    let default_port = if scheme == "http" { "80" } else { "443" };
    Some((host_port.to_string(), default_port.to_string()))
}

pub fn extract_urls(text: &str) -> Vec<String> {
    URL_REGEX
        .find_iter(text)
        .map(|m| {
            m.as_str()
                .trim_end_matches(|c: char| matches!(c, '.' | ',' | ';' | ':' | '!' | '?' | ')'))
                .to_string()
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub fn extract_hostnames(text: &str) -> Vec<String> {
    let mut out = BTreeSet::new();
    for m in DOMAIN_REGEX.captures_iter(text) {
        if let Some(domain) = m.get(1).map(|d| d.as_str().to_lowercase()) {
            // Skip values that look like source file references (e.g. `foo.rs`).
            let is_source_suffix = SOURCE_FILE_SUFFIXES
                .iter()
                .any(|suffix| domain.ends_with(suffix));
            if is_source_suffix {
                continue;
            }
            if !domain.contains('.') {
                continue;
            }
            out.insert(domain);
        }
    }
    out.into_iter().collect()
}

/// Compute `derived_expected_traffic` from a transcript's text and the
/// agent's known LLM hosts. Returns deduplicated `host:port` strings.
pub fn extract_traffic(text: &str, commands: &[String], llm_hosts: &[&str]) -> Vec<String> {
    let mut hosts: Vec<String> = Vec::new();

    for url in extract_urls(text) {
        if let Some((host, port)) = parse_host_port(&url) {
            hosts.push(format!("{host}:{port}"));
        }
    }

    for caps in GIT_REMOTE_REGEX.captures_iter(text) {
        if let Some(host) = caps.get(1) {
            hosts.push(format!("{}:22", host.as_str()));
        }
    }

    for host in llm_hosts {
        if host.contains(':') {
            hosts.push((*host).to_string());
        } else {
            hosts.push(format!("{host}:443"));
        }
    }

    for domain in extract_hostnames(text) {
        hosts.push(format!("{domain}:443"));
    }

    for command in commands {
        let lower = command.to_lowercase();
        if lower.starts_with("cargo ") || lower == "cargo" || lower.starts_with("cargo\t") {
            hosts.push("crates.io:443".into());
            hosts.push("static.crates.io:443".into());
            hosts.push("github.com:443".into());
        }
        if lower.contains("npm ") || lower.contains("pnpm ") || lower.contains("yarn ") {
            hosts.push("registry.npmjs.org:443".into());
            hosts.push("github.com:443".into());
        }
        if lower.contains("pip ") || lower.contains("uv pip") || lower.contains("python -m pip") {
            hosts.push("pypi.org:443".into());
            hosts.push("files.pythonhosted.org:443".into());
        }
        if lower.contains("git clone") || lower.contains("git fetch") || lower.contains("git pull")
        {
            hosts.push("github.com:443".into());
        }
        if lower.contains("docker pull") || lower.contains("docker build") {
            hosts.push("registry-1.docker.io:443".into());
        }
    }

    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for host in hosts {
        if seen.insert(host.clone()) {
            out.push(host);
        }
    }
    out
}

/// Extract listening / outbound TCP/UDP ports referenced in the transcript.
pub fn extract_ports(text: &str, commands: &[String]) -> Vec<u16> {
    let mut seen = BTreeSet::new();
    let mut out: Vec<u16> = Vec::new();
    let push = |port: u16, seen: &mut BTreeSet<u16>, out: &mut Vec<u16>| {
        if port > 0 && port < 65535 && seen.insert(port) {
            out.push(port);
        }
    };

    for caps in PORT_REGEX.captures_iter(text) {
        for slot in 1..=4 {
            if let Some(token) = caps.get(slot) {
                if let Ok(value) = token.as_str().parse::<u16>() {
                    push(value, &mut seen, &mut out);
                    break;
                }
            }
        }
    }

    let port_flag = Regex::new(r#"(?i)(?:--port(?:=|\s+)|-p\s+)(\d{2,5})"#).unwrap();
    for command in commands {
        if let Some(caps) = port_flag.captures(command) {
            if let Some(token) = caps.get(1) {
                if let Ok(value) = token.as_str().parse::<u16>() {
                    push(value, &mut seen, &mut out);
                }
            }
        }
    }

    out.sort_unstable();
    out
}

const CURSOR_TOOL_NAMES: &[&str] = &[
    "Read",
    "ReadFile",
    "Write",
    "Shell",
    "Grep",
    "StrReplace",
    "Glob",
    "Delete",
    "SemanticSearch",
    "EditNotebook",
    "Task",
    "Subagent",
    "WebSearch",
    "WebFetch",
    "GenerateImage",
    "ReadLints",
    "SwitchMode",
    "AskQuestion",
    "ApplyPatch",
    "CallMcpTool",
    "FetchMcpResource",
    "TodoWrite",
];

pub fn extract_tool_names(raw_text: &str, assistant_text: &str) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();

    let mut add = |name: &str| {
        let trimmed = name.trim().trim_start_matches("functions.").to_string();
        if !trimmed.is_empty() && seen.insert(trimmed.clone()) {
            out.push(trimmed);
        }
    };

    for caps in TOOL_CALL_REGEX.captures_iter(raw_text) {
        if let Some(name) = caps.get(1) {
            add(name.as_str());
        }
    }
    for caps in TOOL_NAME_ARG_REGEX.captures_iter(raw_text) {
        if let Some(name) = caps.get(1) {
            add(name.as_str());
        }
    }
    for caps in RECIPIENT_REGEX.captures_iter(raw_text) {
        if let Some(name) = caps.get(1) {
            add(name.as_str());
        }
    }

    if !assistant_text.is_empty() {
        let cleaned = assistant_text.replace('`', "");
        for tool in CURSOR_TOOL_NAMES {
            let pattern = format!(r#"\b{}\b(?:\s+tool)?"#, regex::escape(tool));
            if let Ok(regex) = Regex::new(&pattern) {
                if regex.is_match(&cleaned) {
                    add(tool);
                }
            }
        }
    }

    out
}

pub fn extract_commands(raw_text: &str, assistant_text: &str) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();

    let mut add = |command: &str| {
        let trimmed = command
            .trim()
            .replace('"', "")
            .replace('\'', "")
            .trim()
            .to_string();
        if !trimmed.is_empty() && seen.insert(trimmed.clone()) {
            out.push(trimmed);
        }
    };

    for caps in COMMAND_REGEX.captures_iter(raw_text) {
        if let Some(value) = caps.get(1) {
            add(value.as_str());
        }
    }

    if !assistant_text.is_empty() {
        let cleaned = assistant_text.replace('`', "");
        // Word-boundary prose patterns mirror PROSE_COMMAND_PATTERNS in
        // edamame_cursor/adapters/session_prediction_adapter.mjs: they catch
        // command mentions anywhere in the assistant text, not only at line
        // start. Bounded suffix length limits accidental over-capture.
        let prose_patterns: &[&str] = &[
            r#"\b(cargo\s+(?:build|test|run|check|clippy|fmt|bench|doc|publish|install|clean)(?:\s+[^\n]{0,120})?)"#,
            r#"\b(flutter\s+(?:build|run|test|analyze|gen-l10n|pub\s+\w+)(?:\s+[^\n]{0,80})?)"#,
            r#"\b(git\s+(?:clone|pull|push|fetch|commit|checkout|merge|rebase|diff|status|log|stash|add|reset|branch)(?:\s+[^\n]{0,80})?)"#,
            r#"\b(npm\s+(?:install|run|test|build|publish|ci|start)(?:\s+[^\n]{0,80})?)"#,
            r#"\b(yarn\s+(?:install|add|test|build|start)(?:\s+[^\n]{0,80})?)"#,
            r#"\b(make\s+\w+(?:\s+[^\n]{0,80})?)"#,
            r#"\b(docker\s+(?:build|run|pull|push|compose|exec)(?:\s+[^\n]{0,80})?)"#,
            r#"\b(curl\s+[^\n]{0,120})"#,
            r#"\b(wget\s+[^\n]{0,120})"#,
            r#"\b(ssh\s+[^\n]{0,80})"#,
            r#"\b(scp\s+[^\n]{0,80})"#,
            r#"\b(rsync\s+[^\n]{0,80})"#,
            r#"\b(kubectl\s+(?:get|apply|delete|describe|logs|exec|port-forward)(?:\s+[^\n]{0,80})?)"#,
            r#"\b(terraform\s+(?:init|plan|apply|destroy|validate)(?:\s+[^\n]{0,80})?)"#,
            r#"\b(aws\s+\w+(?:\s+[^\n]{0,80})?)"#,
            r#"\b(gcloud\s+\w+(?:\s+[^\n]{0,80})?)"#,
            r#"\b(az\s+\w+(?:\s+[^\n]{0,80})?)"#,
        ];
        for pattern in prose_patterns {
            if let Ok(regex) = Regex::new(pattern) {
                for caps in regex.captures_iter(&cleaned) {
                    if let Some(value) = caps.get(1) {
                        add(value.as_str());
                    }
                }
            }
        }
    }

    out
}

#[derive(Debug, Clone, Default)]
pub struct InferredProcessPaths {
    pub process_paths: Vec<String>,
    pub parent_paths: Vec<String>,
}

/// From a list of shell-like commands, infer plausible process path patterns
/// and parent paths the divergence engine can use as expected scope/intent.
pub fn infer_process_paths(commands: &[String], workspace_root: &str) -> InferredProcessPaths {
    let mut process_seen = BTreeSet::new();
    let mut parent_seen = BTreeSet::new();
    let mut process_paths = Vec::new();
    let mut parent_paths = Vec::new();

    for command in commands {
        let mut parts = command.split_whitespace();
        let head = match parts.next() {
            Some(h) => h,
            None => continue,
        };
        let pattern = command_process_pattern(head);
        if process_seen.insert(pattern.clone()) {
            process_paths.push(pattern);
        }

        for token in parts {
            if token.starts_with('-') {
                continue;
            }
            if let Some(normalized) = decode_file_path_token(token, workspace_root) {
                if parent_seen.insert(normalized.clone()) {
                    parent_paths.push(normalized);
                }
                break;
            }
        }
    }

    InferredProcessPaths {
        process_paths,
        parent_paths,
    }
}

fn command_process_pattern(head: &str) -> String {
    let normalized = head.to_lowercase();
    match normalized.as_str() {
        "cargo" => "*/cargo".to_string(),
        "git" => "*/git".to_string(),
        "node" | "npm" | "pnpm" | "yarn" | "npx" => "*/node".to_string(),
        "python" | "python3" | "uv" => "*/python*".to_string(),
        "bash" | "zsh" | "sh" => "*/sh".to_string(),
        "dart" => "*/dart".to_string(),
        "flutter" => "*/flutter".to_string(),
        "make" => "*/make".to_string(),
        "curl" => "*/curl".to_string(),
        "wget" => "*/wget".to_string(),
        "ssh" => "*/ssh".to_string(),
        "scp" => "*/scp".to_string(),
        "rsync" => "*/rsync".to_string(),
        "kubectl" => "*/kubectl".to_string(),
        "terraform" => "*/terraform".to_string(),
        "aws" => "*/aws".to_string(),
        "gcloud" => "*/gcloud".to_string(),
        "az" => "*/az".to_string(),
        "go" => "*/go".to_string(),
        "rustup" => "*/rustup".to_string(),
        "brew" => "*/brew".to_string(),
        "apt" | "apt-get" => "*/apt".to_string(),
        _ => {
            if head.starts_with('/') {
                head.to_string()
            } else {
                format!("*/{normalized}")
            }
        }
    }
}

/// Returns a sensitive-path-only filtered subset of `paths`.
pub fn classify_sensitive_paths(paths: &[String], home: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for path in paths {
        let normalized = normalize_sensitive_path(path, home);
        let lower = normalized.to_lowercase();
        let matches_pattern = SENSITIVE_PATH_PATTERNS.iter().any(|pattern| {
            let p = pattern.to_lowercase();
            if p.ends_with('/') {
                lower.starts_with(&p)
            } else {
                lower == p
            }
        });
        let suffix_sensitive = lower.ends_with(".env")
            || lower.ends_with(".pem")
            || lower.ends_with(".key")
            || lower.ends_with(".p12")
            || lower.ends_with("credentials.json")
            || lower.contains("mcp_psk")
            || lower.contains(".edamame_psk");
        if (matches_pattern || suffix_sensitive) && seen.insert(normalized.clone()) {
            out.push(normalized);
        }
    }
    out
}

fn normalize_sensitive_path(path: &str, home: &str) -> String {
    let normalized = path.replace('\\', "/");
    let home_norm = home.replace('\\', "/");
    if !home_norm.is_empty() && normalized.starts_with(&format!("{home_norm}/")) {
        format!("~/{}", &normalized[home_norm.len() + 1..])
    } else {
        normalized
    }
}

/// `derived_expected_open_files` is "all observed paths minus the sensitive
/// subset" -- the sensitive subset is reported via `derived_expected_open_files`
/// in the `expected_sensitive_files` slot of the generated window.
pub fn classify_open_files_excluding_sensitive(paths: &[String], home: &str) -> Vec<String> {
    let sensitive = classify_sensitive_paths(paths, home)
        .into_iter()
        .collect::<BTreeSet<_>>();
    paths
        .iter()
        .filter(|p| !sensitive.contains(*p))
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------
// Run economics: deterministic token / cost / latency / tool-call extraction.
//
// Parses the per-session "what did this run cost" figures from the transcript
// the session was loaded from. Pure function -- no filesystem or network
// access; it consumes the `raw_text` the adapter already read. The output
// rides a dedicated economics RPC, NOT the LLM behavioral-model path, so it
// adds zero tokens to the divergence prompt.
//
// Handles two on-disk shapes:
//   * Anthropic / Claude Code `.jsonl` -- per-turn `message.usage`
//     {input_tokens, output_tokens, cache_creation_input_tokens,
//      cache_read_input_tokens}; summed across assistant turns.
//   * OpenAI / Codex `.jsonl` -- cumulative `total_token_usage`
//     (under `payload.info` / `info`); the largest snapshot is the session
//     total. Key spellings (prompt_tokens / completion_tokens /
//     cached_input_tokens) are aliased.
//
// Plain `.txt` transcripts carry no usage -> `has_token_data == false`.
// ---------------------------------------------------------------------------

// Per-model pricing (USD per 1M tokens) lives in the CloudModel-refreshable
// `model_pricing` table in `cve-detection-params-db.json`, resolved via
// `crate::vuln_detector_params::resolve_model_price` with longest /
// most-specific `match_substring` matching. Cost remains an ESTIMATE: token
// counts are exact, but the dollar conversion is approximate (drifts with
// provider pricing) and falls back to a Sonnet-class rate for unrecognized
// model ids (`ResolvedModelPrice::is_fallback`).

fn as_u64_any(v: &serde_json::Value) -> u64 {
    match v {
        serde_json::Value::Number(n) => n
            .as_u64()
            .or_else(|| n.as_f64().map(|f| f.max(0.0) as u64))
            .unwrap_or(0),
        serde_json::Value::String(s) => s.trim().parse::<u64>().unwrap_or(0),
        _ => 0,
    }
}

/// First non-zero value among the given key aliases of a usage object.
fn usage_field(usage: &serde_json::Value, keys: &[&str]) -> u64 {
    for key in keys {
        if let Some(v) = usage.get(key) {
            let n = as_u64_any(v);
            if n > 0 {
                return n;
            }
        }
    }
    0
}

/// Reads the input-token count and whether its source key implies OpenAI-style
/// cache-INCLUSIVE accounting. Anthropic's `input_tokens` EXCLUDES cache (the
/// four buckets are disjoint) -> `false`. OpenAI Chat's `prompt_tokens`
/// INCLUDES the cached subset -> `true`. Codex's `total_token_usage` also uses
/// the `input_tokens` spelling but with cache-inclusive semantics; that case
/// is caught by the cache-read key spelling (see [`read_cache_read_with_shape`]).
fn read_input_with_shape(usage: &serde_json::Value) -> (u64, bool) {
    if let Some(v) = usage.get("input_tokens") {
        let n = as_u64_any(v);
        if n > 0 {
            return (n, false);
        }
    }
    if let Some(v) = usage.get("prompt_tokens") {
        let n = as_u64_any(v);
        if n > 0 {
            return (n, true);
        }
    }
    (0, false)
}

/// Reads the cache-read count and whether its source key is an OpenAI/Codex
/// family key (`cached_input_tokens` / `cached_tokens`), which means the cached
/// tokens are a SUBSET already counted in `input`. Anthropic's
/// `cache_read_input_tokens` is DISJOINT from `input`. The ambiguous generic
/// `cache_read_tokens` spelling defaults to disjoint (Anthropic-style) so we
/// never wrongly subtract it from `input`.
fn read_cache_read_with_shape(usage: &serde_json::Value) -> (u64, bool) {
    if let Some(v) = usage.get("cache_read_input_tokens") {
        let n = as_u64_any(v);
        if n > 0 {
            return (n, false);
        }
    }
    for key in ["cached_input_tokens", "cached_tokens"] {
        if let Some(v) = usage.get(key) {
            let n = as_u64_any(v);
            if n > 0 {
                return (n, true);
            }
        }
    }
    if let Some(v) = usage.get("cache_read_tokens") {
        let n = as_u64_any(v);
        if n > 0 {
            return (n, false);
        }
    }
    (0, false)
}

/// Token usage parsed from one usage object, with the per-provider cache shape.
#[derive(Debug, Clone, Copy, Default)]
struct UsageRead {
    input: u64,
    output: u64,
    cache_creation: u64,
    cache_read: u64,
    total: u64,
    /// True when `input` already INCLUDES `cache_read` (OpenAI / Codex), so the
    /// cached subset must be subtracted from `input` before billing it at the
    /// (cheaper) cache-read rate. False for Anthropic, where the four buckets
    /// are disjoint and the straight four-bucket sum is correct.
    cache_inclusive: bool,
}

/// Parse a usage object, tolerating Anthropic, OpenAI Chat, and Codex key
/// spellings, and recording the per-provider cache-accounting shape.
fn read_usage(usage: &serde_json::Value) -> UsageRead {
    let (input, input_inclusive) = read_input_with_shape(usage);
    let output = usage_field(usage, &["output_tokens", "completion_tokens"]);
    let cache_creation = usage_field(
        usage,
        &[
            "cache_creation_input_tokens",
            "cache_creation_tokens",
            "cache_write_tokens",
        ],
    );
    let (cache_read, cache_read_openai) = read_cache_read_with_shape(usage);
    let total = usage_field(usage, &["total_tokens"]);
    UsageRead {
        input,
        output,
        cache_creation,
        cache_read,
        total,
        cache_inclusive: input_inclusive || cache_read_openai,
    }
}

fn epoch_to_dt(n: i64) -> Option<chrono::DateTime<chrono::Utc>> {
    use chrono::TimeZone;
    // Values above ~1e12 are milliseconds since epoch; below are seconds.
    let (secs, nsecs) = if n > 1_000_000_000_000 {
        (n / 1000, ((n % 1000) * 1_000_000) as u32)
    } else {
        (n, 0)
    };
    chrono::Utc.timestamp_opt(secs, nsecs).single()
}

fn parse_ts(v: &serde_json::Value) -> Option<chrono::DateTime<chrono::Utc>> {
    match v {
        serde_json::Value::String(s) => {
            let s = s.trim();
            if s.is_empty() {
                return None;
            }
            if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
                return Some(dt.with_timezone(&chrono::Utc));
            }
            s.parse::<i64>().ok().and_then(epoch_to_dt)
        }
        serde_json::Value::Number(n) => n.as_i64().and_then(epoch_to_dt),
        _ => None,
    }
}

/// True when a raw transcript line carries a canonical provider error marker
/// (the `type`/`code` tokens Anthropic and OpenAI emit on throttle/outage).
///
/// Deliberately conservative: the markers are provider-canonical lowercase
/// tokens (`rate_limit_error`, `overloaded_error`, `server_error`,
/// `service_unavailable`, `insufficient_quota`, `too_many_requests`) that are
/// vanishingly unlikely to appear as benign assistant prose, so a plain
/// case-sensitive substring test avoids both per-line allocation and the false
/// positives a bare numeric `429`/`503` match would cause. This is an inferred
/// signal for an EXTERNAL agent's provider health -- not a measured SLA.
fn line_has_provider_error_marker(line: &str) -> bool {
    const PROVIDER_ERROR_MARKERS: [&str; 6] = [
        "rate_limit",
        "overloaded_error",
        "server_error",
        "service_unavailable",
        "insufficient_quota",
        "too_many_requests",
    ];
    PROVIDER_ERROR_MARKERS
        .iter()
        .any(|marker| line.contains(marker))
}

/// Priority-ordered argument keys that identify a tool call's *target* -- the
/// file, command, pattern, query, or URL the call operates on. First match
/// wins, so `Read(/etc/passwd)` and `Read(/tmp/x)` are distinct signatures but
/// two `Read`s of the same file collapse into a repeat. Mirrors the arg names
/// the major agents emit (Anthropic tools, Codex `shell`, Cursor tools).
const TOOL_TARGET_KEYS: &[&str] = &[
    "file_path",
    "filePath",
    "path",
    "target_file",
    "notebook_path",
    "absolute_path",
    "abspath",
    "command",
    "cmd",
    "pattern",
    "query",
    "url",
    "glob_pattern",
    "glob",
    "search",
];

/// The raw args object for a tool-call block. Anthropic / Claude Code carry a
/// structured `input` object; Codex `function_call` carries `arguments` as a
/// JSON *string* (parsed here). Returns `None` when neither is present or
/// parseable.
fn tool_call_input(item: &serde_json::Value) -> Option<serde_json::Value> {
    if let Some(input) = item.get("input") {
        if input.is_object() {
            return Some(input.clone());
        }
    }
    if let Some(args) = item.get("arguments") {
        if let Some(s) = args.as_str() {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(s) {
                if v.is_object() {
                    return Some(v);
                }
            }
        } else if args.is_object() {
            return Some(args.clone());
        }
    }
    None
}

/// Build a stable `(tool, target)` signature used for redundant-call and
/// retry-after-error detection. The target is the first recognized
/// target-key string in the args, else the whole args object serialized
/// (deterministic key order under serde_json's default map), else empty.
/// Path-like targets are slash-normalized and every target is length-capped so
/// one giant inline argument cannot dominate. Pure (allocating only).
fn tool_target_signature(name: &str, input: Option<&serde_json::Value>) -> String {
    const MAX_TARGET_LEN: usize = 160;
    let name = name.trim();
    let target = match input {
        Some(obj) => {
            let mut found: Option<String> = None;
            for key in TOOL_TARGET_KEYS {
                if let Some(v) = obj.get(*key) {
                    let s = match v {
                        serde_json::Value::String(s) => s.trim().to_string(),
                        other => other.to_string(),
                    };
                    if !s.is_empty() {
                        found = Some(s);
                        break;
                    }
                }
            }
            found.unwrap_or_else(|| {
                // No recognized target key: serialize the whole args object so
                // distinct argument sets still separate. An empty object yields
                // an empty target (a bare-name signature).
                if obj.as_object().map(|m| m.is_empty()).unwrap_or(true) {
                    String::new()
                } else {
                    obj.to_string()
                }
            })
        }
        None => String::new(),
    };
    let target = target.replace('\\', "/");
    let target: String = target.chars().take(MAX_TARGET_LEN).collect();
    format!("{name}\u{1}{target}")
}

/// Parse deterministic run economics from a single session's transcript text.
/// See module-level economics comment for the supported on-disk shapes.
pub fn parse_session_economics(
    session_key: &str,
    source_path: &str,
    raw_text: &str,
) -> super::SessionEconomics {
    use chrono::{DateTime, Utc};

    // Per-turn accumulators (Anthropic / Claude Code).
    let mut summed_input = 0u64;
    let mut summed_output = 0u64;
    let mut summed_cache_creation = 0u64;
    let mut summed_cache_read = 0u64;
    let mut summed_cache_inclusive = false;

    // Cumulative snapshot (Codex `total_token_usage`): keep the object with the
    // largest total seen -- that is the session-final cumulative count.
    let mut cum_seen = false;
    let mut cum_total = 0u64;
    let mut cum_input = 0u64;
    let mut cum_output = 0u64;
    let mut cum_cache_creation = 0u64;
    let mut cum_cache_read = 0u64;
    let mut cum_cache_inclusive = false;
    // Provider-authoritative cumulative total (`total_tokens`), if reported.
    let mut cum_authoritative_total = 0u64;

    let mut assistant_turns = 0u64;
    let mut tool_calls = 0u64;
    let mut tool_errors = 0u64;
    let mut model = String::new();
    let mut first_ts: Option<DateTime<Utc>> = None;
    let mut last_ts: Option<DateTime<Utc>> = None;
    let mut had_usage = false;

    // Derived, APPROXIMATE per-turn responsiveness (Workstream C). `pending_trigger_ts`
    // is the timestamp of the most recent non-assistant line (the user message or
    // tool-result that prompted the next generation); when an assistant line that
    // carries output-token usage appears after it, the gap is one turn's latency.
    // Consumed (cleared) on use so back-to-back assistant lines never fabricate a
    // bogus latency from a stale trigger.
    let mut pending_trigger_ts: Option<DateTime<Utc>> = None;
    let mut turn_latency_ms_total = 0u64;
    let mut turn_latency_samples = 0u64;
    let mut turn_latency_ms_max = 0u64;
    let mut turn_output_tokens_total = 0u64;
    let mut turn_throughput_ms_total = 0u64;
    let mut inferred_provider_errors = 0u64;
    let mut mcp_calls_by_server: std::collections::BTreeMap<String, u64> =
        std::collections::BTreeMap::new();

    // Deterministic path-directness / friction accumulators. Signatures are
    // `(tool, target)`; a signature seen twice is rework, a signature that
    // previously errored and reappears is a retry-after-error. `sig_by_call_id`
    // correlates a tool_use/function_call to the erroring result that
    // references it (Anthropic `tool_use_id`, Codex `call_id`).
    let mut repeated_tool_calls = 0u64;
    let mut retried_after_error_calls = 0u64;
    let mut seen_tool_sigs: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut errored_tool_sigs: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut sig_by_call_id: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    let mut last_tool_result_error: Option<bool> = None;
    // Self-Augmentation: per-skill and per-tool-name usage attribution.
    let mut skill_invocations_by_name: std::collections::BTreeMap<String, u64> =
        std::collections::BTreeMap::new();
    let mut tool_calls_by_name: std::collections::BTreeMap<String, u64> =
        std::collections::BTreeMap::new();

    for line in raw_text.split('\n') {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Model (most recent non-empty wins).
        for candidate in [
            value
                .get("message")
                .and_then(|m| m.get("model"))
                .and_then(|v| v.as_str()),
            value.get("model").and_then(|v| v.as_str()),
            value
                .get("payload")
                .and_then(|p| p.get("model"))
                .and_then(|v| v.as_str()),
            value
                .get("response")
                .and_then(|r| r.get("model"))
                .and_then(|v| v.as_str()),
        ] {
            if let Some(s) = candidate {
                if !s.trim().is_empty() {
                    model = s.trim().to_string();
                }
            }
        }

        // Timestamps (min/max for wall-clock duration). `line_ts` keeps this
        // line's own timestamp (first parseable candidate) for per-turn latency.
        let mut line_ts: Option<DateTime<Utc>> = None;
        for candidate in [
            value.get("timestamp"),
            value.get("payload").and_then(|p| p.get("timestamp")),
            value.get("ts"),
        ] {
            if let Some(v) = candidate {
                if let Some(dt) = parse_ts(v) {
                    if line_ts.is_none() {
                        line_ts = Some(dt);
                    }
                    if first_ts.map(|f| dt < f).unwrap_or(true) {
                        first_ts = Some(dt);
                    }
                    if last_ts.map(|l| dt > l).unwrap_or(true) {
                        last_ts = Some(dt);
                    }
                }
            }
        }

        // Per-turn usage (Anthropic message.usage / OpenAI usage). `this_line_output`
        // is the output tokens generated by THIS line's turn (the tokens/sec
        // numerator); it stays 0 for Codex, whose usage is cumulative and handled
        // below, so Codex turns never contribute a throughput sample.
        let mut this_line_output = 0u64;
        let per_turn_usage = value
            .get("message")
            .and_then(|m| m.get("usage"))
            .or_else(|| value.get("usage"))
            .or_else(|| value.get("response").and_then(|r| r.get("usage")))
            .or_else(|| value.get("payload").and_then(|p| p.get("usage")));
        if let Some(usage) = per_turn_usage {
            if usage.is_object() {
                let u = read_usage(usage);
                if u.input > 0 || u.output > 0 || u.cache_creation > 0 || u.cache_read > 0 {
                    summed_input += u.input;
                    summed_output += u.output;
                    summed_cache_creation += u.cache_creation;
                    summed_cache_read += u.cache_read;
                    // All turns of one session share a provider; latch the shape.
                    summed_cache_inclusive |= u.cache_inclusive;
                    had_usage = true;
                    this_line_output = u.output;
                }
            }
        }

        // Cumulative usage (Codex token_count event `total_token_usage`).
        let cumulative_usage = value
            .get("payload")
            .and_then(|p| p.get("info"))
            .and_then(|i| i.get("total_token_usage"))
            .or_else(|| value.get("info").and_then(|i| i.get("total_token_usage")))
            .or_else(|| value.get("total_token_usage"));
        if let Some(usage) = cumulative_usage {
            if usage.is_object() {
                let u = read_usage(usage);
                let total = if u.total > 0 {
                    u.total
                } else {
                    u.input + u.output + u.cache_creation + u.cache_read
                };
                if total >= cum_total {
                    cum_seen = true;
                    cum_total = total;
                    cum_input = u.input;
                    cum_output = u.output;
                    cum_cache_creation = u.cache_creation;
                    cum_cache_read = u.cache_read;
                    cum_cache_inclusive = u.cache_inclusive;
                    cum_authoritative_total = u.total;
                }
                if total > 0 {
                    had_usage = true;
                }
            }
        }

        // Assistant turns + tool-call / tool-error counts from the content array.
        let role = value
            .get("message")
            .and_then(|m| m.get("role"))
            .and_then(|v| v.as_str())
            .or_else(|| value.get("role").and_then(|v| v.as_str()))
            .unwrap_or("");
        if role == "assistant" {
            assistant_turns += 1;
        } else if role == "user" {
            // Leading `/command` (or Claude Code's `<command-name>` marker) in a
            // user turn -> command invocation. A universal signal that works
            // even when the agent exposes no structured SlashCommand tool.
            if let Some(cmd) = user_turn_slash_command(&value) {
                *skill_invocations_by_name
                    .entry(format!("command:{cmd}"))
                    .or_insert(0) += 1;
            }
        }
        // Candidate blocks for this line. Anthropic / Claude Code carry a
        // `content` array of typed blocks; Codex rollouts carry one
        // `response_item` per line whose `payload` IS the block; a few shapes
        // put the block at top level. Mirror `parse_tool_error_details` so tool
        // counting + friction signatures work regardless of transcript shape.
        let content = value
            .get("message")
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_array())
            .or_else(|| value.get("content").and_then(|c| c.as_array()));
        let mut candidates: Vec<&serde_json::Value> = Vec::new();
        if let Some(items) = content {
            candidates.extend(items.iter());
        } else if let Some(payload) = value.get("payload") {
            candidates.push(payload);
        } else {
            candidates.push(&value);
        }
        for item in candidates {
            let kind = item.get("type").and_then(|v| v.as_str()).unwrap_or("");
            match kind {
                "tool_use" | "function_call" => {
                    tool_calls += 1;
                    // Attribute MCP-namespaced tool calls to their server
                    // (the `mcp__<server>__<tool>` convention). Native tools
                    // carry no `mcp__` prefix and are not bucketed here.
                    let tool_name = item
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .trim();
                    if let Some(server) = mcp_server_from_tool_name(tool_name) {
                        *mcp_calls_by_server.entry(server.to_string()).or_insert(0) += 1;
                    }
                    // Per-tool-name breakdown (native + MCP) for the most/least
                    // used tools histogram. Length-capped so a malformed name
                    // cannot bloat the map key.
                    if !tool_name.is_empty() {
                        let key: String = tool_name.chars().take(120).collect();
                        *tool_calls_by_name.entry(key).or_insert(0) += 1;
                    }
                    // Path-directness: repeated `(tool, target)` = rework; a
                    // signature that previously errored = retry-after-error.
                    // Correlate this call's id -> signature so the erroring
                    // result can mark the signature as failed.
                    let input = tool_call_input(item);
                    // Skill / command / rule / subagent attribution from the
                    // structured call (explicit dispatch tool or a file-read of a
                    // skill/command/rule artifact).
                    if let Some(skill_id) = skill_from_tool_call(tool_name, input.as_ref()) {
                        *skill_invocations_by_name.entry(skill_id).or_insert(0) += 1;
                    }
                    let sig = tool_target_signature(tool_name, input.as_ref());
                    if !seen_tool_sigs.insert(sig.clone()) {
                        repeated_tool_calls += 1;
                    }
                    if errored_tool_sigs.contains(&sig) {
                        retried_after_error_calls += 1;
                    }
                    if let Some(id) = item
                        .get("id")
                        .and_then(|v| v.as_str())
                        .or_else(|| item.get("call_id").and_then(|v| v.as_str()))
                    {
                        if !id.is_empty() {
                            sig_by_call_id.insert(id.to_string(), sig);
                        }
                    }
                }
                "tool_result" | "function_call_output" => {
                    let is_err = item
                        .get("is_error")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                        || item.get("error").map(|e| !e.is_null()).unwrap_or(false);
                    // Track the LAST result's error state for the clean-finish
                    // proxy (updated on every result; final value wins).
                    last_tool_result_error = Some(is_err);
                    if is_err {
                        tool_errors += 1;
                        // Mark this call's signature as errored so a later
                        // reissue of the same `(tool, target)` counts as a retry.
                        let ref_id = item
                            .get("tool_use_id")
                            .and_then(|v| v.as_str())
                            .or_else(|| item.get("call_id").and_then(|v| v.as_str()))
                            .unwrap_or("");
                        if let Some(sig) = sig_by_call_id.get(ref_id) {
                            errored_tool_sigs.insert(sig.clone());
                        }
                    }
                }
                _ => {}
            }
        }

        // Per-turn latency (APPROXIMATE, Workstream C). A non-assistant line
        // (user message or tool-result) arms the trigger timestamp; the next
        // assistant line that carries output-token usage closes the turn and the
        // gap is its latency. The trigger is consumed so consecutive assistant
        // lines without an intervening trigger never reuse a stale timestamp.
        if role == "assistant" {
            if let (Some(assistant_ts), Some(trigger_ts)) = (line_ts, pending_trigger_ts) {
                if this_line_output > 0 && assistant_ts > trigger_ts {
                    let latency_ms = (assistant_ts - trigger_ts).num_milliseconds().max(0) as u64;
                    turn_latency_ms_total = turn_latency_ms_total.saturating_add(latency_ms);
                    turn_latency_samples += 1;
                    turn_latency_ms_max = turn_latency_ms_max.max(latency_ms);
                    if latency_ms > 0 {
                        turn_output_tokens_total =
                            turn_output_tokens_total.saturating_add(this_line_output);
                        turn_throughput_ms_total =
                            turn_throughput_ms_total.saturating_add(latency_ms);
                    }
                    pending_trigger_ts = None;
                }
            }
        } else if let Some(ts) = line_ts {
            // Any non-assistant line with a timestamp arms the next turn's trigger.
            pending_trigger_ts = Some(ts);
        }

        // Inferred provider-error signal: a canonical provider error `type`/`code`
        // token on this line (rate limit / overloaded / 5xx-class). Counted at
        // most once per line; distinct from local `tool_errors`.
        if line_has_provider_error_marker(line) {
            inferred_provider_errors += 1;
        }
    }

    // Prefer the cumulative snapshot when present (Codex), else the per-turn
    // sum (Claude).
    let (
        input_tokens,
        output_tokens,
        cache_creation_input_tokens,
        cache_read_input_tokens,
        cache_inclusive,
        authoritative_total,
    ) = if cum_seen && cum_total > 0 {
        (
            cum_input,
            cum_output,
            cum_cache_creation,
            cum_cache_read,
            cum_cache_inclusive,
            cum_authoritative_total,
        )
    } else {
        (
            summed_input,
            summed_output,
            summed_cache_creation,
            summed_cache_read,
            summed_cache_inclusive,
            0,
        )
    };

    // Total tokens, counting each token once. Prefer the provider's
    // authoritative `total_tokens` when reported (Codex). Otherwise, for
    // cache-inclusive providers (OpenAI / Codex) the cached subset is already
    // inside `input`, so it is NOT re-added; for Anthropic the four buckets are
    // disjoint and all are summed.
    let total_tokens = if authoritative_total > 0 {
        authoritative_total
    } else if cache_inclusive {
        input_tokens + output_tokens + cache_creation_input_tokens
    } else {
        input_tokens + output_tokens + cache_creation_input_tokens + cache_read_input_tokens
    };

    // Per-provider cache cost semantics (G10/G11): Anthropic's `input_tokens`
    // excludes cache, so all four buckets bill independently. OpenAI / Codex
    // report a cache-INCLUSIVE input, so the cached subset is removed from the
    // full-rate input bill and charged once at the cache-read rate.
    let price = crate::vuln_detector_params::resolve_model_price(&model);
    let billable_input = if cache_inclusive {
        input_tokens.saturating_sub(cache_read_input_tokens)
    } else {
        input_tokens
    };
    let est_cost_usd = (billable_input as f64) / 1_000_000.0 * price.input
        + (output_tokens as f64) / 1_000_000.0 * price.output
        + (cache_creation_input_tokens as f64) / 1_000_000.0 * price.cache_write
        + (cache_read_input_tokens as f64) / 1_000_000.0 * price.cache_read;

    let duration_secs = match (first_ts, last_ts) {
        (Some(f), Some(l)) if l > f => (l - f).num_seconds().max(0) as u64,
        _ => 0,
    };

    super::SessionEconomics {
        session_key: session_key.to_string(),
        source_path: source_path.to_string(),
        model,
        assistant_turns,
        input_tokens,
        output_tokens,
        cache_creation_input_tokens,
        cache_read_input_tokens,
        total_tokens,
        tool_calls,
        tool_errors,
        est_cost_usd,
        first_event_at: first_ts,
        last_event_at: last_ts,
        duration_secs,
        has_token_data: had_usage,
        price_is_fallback: price.is_fallback,
        turn_latency_ms_total,
        turn_latency_samples,
        turn_latency_ms_max,
        turn_output_tokens_total,
        turn_throughput_ms_total,
        inferred_provider_errors,
        mcp_calls_by_server,
        skill_invocations_by_name,
        tool_calls_by_name,
        repeated_tool_calls,
        retried_after_error_calls,
        ended_with_tool_error: last_tool_result_error.unwrap_or(false),
    }
}

/// Extract the MCP server name from a tool invocation name, using the standard
/// `mcp__<server>__<tool>` namespacing that Claude Code / Cursor / Codex apply
/// when surfacing an MCP server's tools to the model. Returns `None` for native
/// agent tools (`Read`, `Edit`, `Bash`, `Grep`, ...) which carry no `mcp__`
/// prefix, and for a malformed name with an empty server segment.
fn mcp_server_from_tool_name(name: &str) -> Option<&str> {
    let rest = name.strip_prefix("mcp__")?;
    let server = rest.split("__").next().unwrap_or("");
    if server.is_empty() {
        None
    } else {
        Some(server)
    }
}

/// Native/agent file-read tool names whose target may be a skill/command/rule
/// artifact (a progressive-disclosure load). Lowercased comparison. Covers the
/// major agents: Claude Code `Read`, Cursor `read_file`, and common shell/open
/// spellings.
fn is_instruction_read_tool(lower_name: &str) -> bool {
    matches!(
        lower_name,
        "read" | "read_file" | "readfile" | "cat" | "open" | "open_file" | "view" | "view_file"
    )
}

/// Normalize a skill / command / rule name (or a path fragment) to a stable
/// slug: take the last path segment, strip a `.md` / `.mdc` extension,
/// lowercase, keep `[a-z0-9._-]`, collapse any other run to a single `-`, and
/// length-cap. Pure (allocating only).
fn normalize_skill_slug(s: &str) -> String {
    const MAX: usize = 80;
    let s = s.trim().trim_matches('/');
    let seg = s.rsplit('/').next().unwrap_or(s);
    let seg = seg
        .strip_suffix(".mdc")
        .or_else(|| seg.strip_suffix(".md"))
        .unwrap_or(seg);
    let mut out = String::new();
    for ch in seg.chars() {
        let c = ch.to_ascii_lowercase();
        if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
            out.push(c);
        } else if !out.ends_with('-') {
            out.push('-');
        }
        if out.len() >= MAX {
            break;
        }
    }
    out.trim_matches('-').to_string()
}

/// Extract a leading slash-command name from a user message string, e.g.
/// `"/healthcheck run now"` -> `Some("healthcheck")`. Returns `None` when the
/// text does not start with a slash-command word. Rejects file paths such as
/// `"/Users/foo"` by requiring the first token to be followed by whitespace or
/// end-of-string (not another path segment).
fn slash_command_name(text: &str) -> Option<String> {
    let rest = text.trim_start().strip_prefix('/')?;
    let token: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect();
    if token.is_empty() {
        return None;
    }
    let after = &rest[token.len()..];
    if after.is_empty() || after.starts_with(char::is_whitespace) {
        let slug = normalize_skill_slug(&token);
        if slug.is_empty() {
            None
        } else {
            Some(slug)
        }
    } else {
        None
    }
}

/// Classify a file path as a skill / command / rule artifact and return the
/// normalized skill id (`skill:<name>`, `command:<name>`, `rule:<name>`), else
/// `None`. Slash-normalized so Windows-style paths also match. A read of such a
/// file is treated as a progressive-disclosure load of that instruction.
fn skill_from_path(path: &str) -> Option<String> {
    let p = path.trim().replace('\\', "/");
    if p.is_empty() {
        return None;
    }
    let segs: Vec<&str> = p.split('/').filter(|s| !s.is_empty()).collect();
    for (dir, prefix) in [
        ("skills", "skill"),
        ("commands", "command"),
        ("rules", "rule"),
    ] {
        if let Some(idx) = segs.iter().position(|s| s.eq_ignore_ascii_case(dir)) {
            if let Some(next) = segs.get(idx + 1) {
                let name = normalize_skill_slug(next);
                if !name.is_empty() {
                    return Some(format!("{prefix}:{name}"));
                }
            }
        }
    }
    None
}

/// Canonical join id (`<kind>:<slug>`) for an on-disk instruction artifact,
/// matching the ids emitted into `skill_invocations_by_name`. `kind` is the
/// SBOM `edamame:kind` (`skill` | `command` | `rule` | `subagent`); `relpath`
/// is the artifact path relative to its config dir.
///
/// The slug rules mirror how usage ids are minted from transcripts:
/// - `skill`: the slug is the *containing directory* (`skills/<slug>/SKILL.md`
///   -> `skill:<slug>`), matching a file-read of `**/skills/<slug>/SKILL.md`
///   and an explicit `Skill{name}` dispatch.
/// - `command` / `rule` / `subagent`: the slug is the file stem
///   (`commands/<slug>.md` -> `command:<slug>`).
///
/// Returns `None` for kinds that are not usage-trackable (`memory`, `prompt`,
/// `instruction`, `hook`) so the self-augmentation join only spans artifacts a
/// transcript can actually attribute a use to.
pub fn instruction_join_id(kind: &str, relpath: &str) -> Option<String> {
    let p = relpath.trim().replace('\\', "/");
    let segs: Vec<&str> = p.split('/').filter(|s| !s.is_empty()).collect();
    if segs.is_empty() {
        return None;
    }
    match kind {
        "skill" => {
            // Prefer the segment right after a `skills` dir (the skill folder).
            if let Some(idx) = segs.iter().position(|s| s.eq_ignore_ascii_case("skills")) {
                if let Some(next) = segs.get(idx + 1) {
                    let slug = normalize_skill_slug(next);
                    if !slug.is_empty() {
                        return Some(format!("skill:{slug}"));
                    }
                }
            }
            // Fallback: a bare `<slug>/SKILL.md` uses the parent dir; otherwise
            // the file stem.
            let last = *segs.last().unwrap();
            let slug = if last.eq_ignore_ascii_case("SKILL.md") && segs.len() >= 2 {
                normalize_skill_slug(segs[segs.len() - 2])
            } else {
                normalize_skill_slug(last)
            };
            (!slug.is_empty()).then(|| format!("skill:{slug}"))
        }
        "command" => {
            let slug = normalize_skill_slug(segs.last().unwrap());
            (!slug.is_empty()).then(|| format!("command:{slug}"))
        }
        "rule" => {
            let slug = normalize_skill_slug(segs.last().unwrap());
            (!slug.is_empty()).then(|| format!("rule:{slug}"))
        }
        "subagent" => {
            let slug = normalize_skill_slug(segs.last().unwrap());
            (!slug.is_empty()).then(|| format!("subagent:{slug}"))
        }
        _ => None,
    }
}

/// Recognize a skill / command / rule / subagent invocation from a structured
/// tool call and return a normalized skill id, else `None`. Covers explicit
/// dispatch tools (`Skill`, `SlashCommand`, `Task`) and file-reads of
/// skill/command/rule artifacts. Deterministic.
fn skill_from_tool_call(tool_name: &str, input: Option<&serde_json::Value>) -> Option<String> {
    let lower = tool_name.trim().to_ascii_lowercase();
    match lower.as_str() {
        "skill" => {
            let obj = input?;
            for key in ["command", "name", "skill", "skill_name"] {
                if let Some(s) = obj.get(key).and_then(|v| v.as_str()) {
                    let slug = normalize_skill_slug(s);
                    if !slug.is_empty() {
                        return Some(format!("skill:{slug}"));
                    }
                }
            }
            None
        }
        "slashcommand" => {
            let obj = input?;
            let s = obj.get("command").and_then(|v| v.as_str())?;
            let cmd = slash_command_name(s).or_else(|| {
                let slug = normalize_skill_slug(s);
                if slug.is_empty() {
                    None
                } else {
                    Some(slug)
                }
            })?;
            Some(format!("command:{cmd}"))
        }
        "task" => {
            let obj = input?;
            let s = obj.get("subagent_type").and_then(|v| v.as_str())?;
            let slug = normalize_skill_slug(s);
            if slug.is_empty() {
                None
            } else {
                Some(format!("subagent:{slug}"))
            }
        }
        other if is_instruction_read_tool(other) => {
            let obj = input?;
            for key in TOOL_TARGET_KEYS {
                if let Some(p) = obj.get(*key).and_then(|v| v.as_str()) {
                    if let Some(id) = skill_from_path(p) {
                        return Some(id);
                    }
                }
            }
            None
        }
        _ => None,
    }
}

/// Extract a leading slash-command from a user-role transcript line, if any.
/// Prefers Claude Code's explicit `<command-name>...</command-name>` marker,
/// then falls back to a literal leading `/command` in the concatenated user
/// text. Returns the normalized command slug (without the `command:` prefix).
fn user_turn_slash_command(value: &serde_json::Value) -> Option<String> {
    let content = value
        .get("message")
        .and_then(|m| m.get("content"))
        .or_else(|| value.get("content"));
    let text = match content {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Array(items)) => {
            let mut buf = String::new();
            for it in items {
                if let Some(t) = it.get("text").and_then(|v| v.as_str()) {
                    buf.push_str(t);
                    buf.push('\n');
                    if buf.len() > 512 {
                        break;
                    }
                }
            }
            buf
        }
        _ => return None,
    };
    if let Some(start) = text.find("<command-name>") {
        let after = &text[start + "<command-name>".len()..];
        if let Some(end) = after.find("</command-name>") {
            let raw = after[..end].trim().trim_start_matches('/');
            let slug = normalize_skill_slug(raw);
            if !slug.is_empty() {
                return Some(slug);
            }
        }
    }
    slash_command_name(&text)
}

/// Deterministically extract per-tool error details from a transcript's raw
/// JSONL text. Companion to [`parse_session_economics`] (which only *counts*
/// `tool_errors`): this names the failing tool and a truncated error snippet so
/// the LLM-free flight recorder can offer a drill-down ("Read failed:
/// permission denied" instead of just "1 tool error"). Returns at most
/// `MAX_TOOL_ERROR_DETAILS` entries, in transcript order.
///
/// Correlation: `tool_use` blocks carry `id` + `name` (Anthropic / Claude
/// Code) and `function_call` blocks carry `call_id` + `name` (Codex). An
/// erroring `tool_result` references its invocation via `tool_use_id`, and a
/// `function_call_output` via `call_id`; the tool name is resolved through that
/// id when present, else left empty. Metadata only -- the message is truncated
/// to a single line and carries no file/transcript body.
pub fn parse_tool_error_details(raw_text: &str) -> Vec<super::ToolErrorDetail> {
    const MAX_TOOL_ERROR_DETAILS: usize = 50;
    const MAX_MESSAGE_LEN: usize = 200;

    let mut id_to_name: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    let mut details: Vec<super::ToolErrorDetail> = Vec::new();

    for line in raw_text.split('\n') {
        if details.len() >= MAX_TOOL_ERROR_DETAILS {
            break;
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let ts = [
            value.get("timestamp"),
            value.get("payload").and_then(|p| p.get("timestamp")),
            value.get("ts"),
        ]
        .into_iter()
        .flatten()
        .find_map(parse_ts);

        // Candidate items for this line. Anthropic / Claude Code carry a
        // `content` array of typed blocks; Codex rollouts carry one
        // `response_item` per line whose `payload` IS the block (or a bare
        // top-level block). Cover all three so correlation works regardless of
        // the agent's transcript shape.
        let content = value
            .get("message")
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_array())
            .or_else(|| value.get("content").and_then(|c| c.as_array()));
        let mut candidates: Vec<&serde_json::Value> = Vec::new();
        if let Some(items) = content {
            candidates.extend(items.iter());
        } else if let Some(payload) = value.get("payload") {
            candidates.push(payload);
        } else {
            candidates.push(&value);
        }

        for item in candidates {
            let kind = item.get("type").and_then(|v| v.as_str()).unwrap_or("");
            match kind {
                // Record id -> tool name for later result correlation.
                "tool_use" | "function_call" => {
                    let id = item
                        .get("id")
                        .and_then(|v| v.as_str())
                        .or_else(|| item.get("call_id").and_then(|v| v.as_str()));
                    let name = item
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .trim();
                    if let Some(id) = id {
                        if !id.is_empty() && !name.is_empty() {
                            id_to_name.insert(id.to_string(), name.to_string());
                        }
                    }
                }
                "tool_result" | "function_call_output" => {
                    let is_err = item
                        .get("is_error")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                        || item.get("error").map(|e| !e.is_null()).unwrap_or(false);
                    if !is_err {
                        continue;
                    }
                    let ref_id = item
                        .get("tool_use_id")
                        .and_then(|v| v.as_str())
                        .or_else(|| item.get("call_id").and_then(|v| v.as_str()))
                        .unwrap_or("");
                    let tool_name = id_to_name.get(ref_id).cloned().unwrap_or_default();
                    let message = truncate_one_line(&extract_error_message(item), MAX_MESSAGE_LEN);
                    details.push(super::ToolErrorDetail {
                        tool_name,
                        message,
                        at: ts,
                    });
                    if details.len() >= MAX_TOOL_ERROR_DETAILS {
                        break;
                    }
                }
                _ => {}
            }
        }
    }

    details
}

/// Pull a human-readable error snippet from a `tool_result` /
/// `function_call_output` item: prefer an explicit `error` field, else fall
/// back to the result `content` (string, or concatenated `text` blocks).
fn extract_error_message(item: &serde_json::Value) -> String {
    if let Some(err) = item.get("error") {
        if let Some(s) = err.as_str() {
            return s.to_string();
        }
        if let Some(obj) = err.as_object() {
            for key in ["message", "error", "detail", "description"] {
                if let Some(s) = obj.get(key).and_then(|v| v.as_str()) {
                    return s.to_string();
                }
            }
        }
        if !err.is_null() {
            return err.to_string();
        }
    }
    match item.get("content") {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Array(arr)) => {
            let mut parts = Vec::new();
            for c in arr {
                if let Some(s) = c.get("text").and_then(|v| v.as_str()) {
                    parts.push(s.to_string());
                } else if let Some(s) = c.as_str() {
                    parts.push(s.to_string());
                }
            }
            parts.join(" ")
        }
        Some(other) => other.to_string(),
        None => String::new(),
    }
}

/// Collapse whitespace to a single line and cap at `max` chars (char-safe,
/// appends an ASCII ellipsis on truncation).
fn truncate_one_line(s: &str, max: usize) -> String {
    let one_line = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if one_line.chars().count() > max {
        let truncated: String = one_line.chars().take(max).collect();
        format!("{}...", truncated)
    } else {
        one_line
    }
}

#[cfg(test)]
mod economics_tests {
    use super::*;

    #[test]
    fn parses_claude_per_turn_usage_and_tools() {
        let jsonl = concat!(
            r#"{"type":"user","timestamp":"2026-05-06T18:15:00.000Z","message":{"role":"user","content":[{"type":"text","text":"hi"}]}}"#,
            "\n",
            r#"{"type":"assistant","timestamp":"2026-05-06T18:15:10.000Z","message":{"role":"assistant","model":"claude-sonnet-4-6","content":[{"type":"text","text":"ok"},{"type":"tool_use","name":"Read"}],"usage":{"input_tokens":100,"output_tokens":50,"cache_creation_input_tokens":10,"cache_read_input_tokens":200}}}"#,
            "\n",
            r#"{"type":"user","timestamp":"2026-05-06T18:15:20.000Z","message":{"role":"user","content":[{"type":"tool_result","is_error":true,"content":"boom"}]}}"#,
            "\n",
            r#"{"type":"assistant","timestamp":"2026-05-06T18:16:00.000Z","message":{"role":"assistant","model":"claude-sonnet-4-6","content":[{"type":"text","text":"done"}],"usage":{"input_tokens":300,"output_tokens":80,"cache_creation_input_tokens":0,"cache_read_input_tokens":210}}}"#,
            "\n",
        );
        let econ = parse_session_economics("sess-1", "/tmp/sess-1.jsonl", jsonl);
        assert!(econ.has_token_data);
        assert_eq!(econ.model, "claude-sonnet-4-6");
        assert_eq!(econ.input_tokens, 400);
        assert_eq!(econ.output_tokens, 130);
        assert_eq!(econ.cache_creation_input_tokens, 10);
        assert_eq!(econ.cache_read_input_tokens, 410);
        assert_eq!(econ.total_tokens, 950);
        assert_eq!(econ.assistant_turns, 2);
        assert_eq!(econ.tool_calls, 1);
        assert_eq!(econ.tool_errors, 1);
        assert_eq!(econ.duration_secs, 60);
        assert!(econ.est_cost_usd > 0.0);
    }

    #[test]
    fn cumulative_codex_total_token_usage_wins() {
        let jsonl = concat!(
            r#"{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":100,"output_tokens":20,"total_tokens":120}}}}"#,
            "\n",
            r#"{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":500,"output_tokens":90,"total_tokens":590}}}}"#,
            "\n",
        );
        let econ = parse_session_economics("c1", "/tmp/c1.jsonl", jsonl);
        assert!(econ.has_token_data);
        // Cumulative -> the larger snapshot wins (not summed to 710).
        assert_eq!(econ.input_tokens, 500);
        assert_eq!(econ.output_tokens, 90);
        assert_eq!(econ.total_tokens, 590);
    }

    /// G11: Anthropic's four token buckets are DISJOINT -- `input_tokens`
    /// excludes cache -- so the cost is the straight four-bucket sum with the
    /// full input billed at the input rate.
    #[test]
    fn anthropic_disjoint_cache_billed_in_full() {
        let jsonl = concat!(
            r#"{"type":"assistant","timestamp":"2026-05-06T18:15:10.000Z","message":{"role":"assistant","model":"claude-3-5-sonnet","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":100,"output_tokens":50,"cache_creation_input_tokens":10,"cache_read_input_tokens":200}}}"#,
            "\n",
        );
        let econ = parse_session_economics("an", "/tmp/an.jsonl", jsonl);
        // Disjoint: all four buckets summed.
        assert_eq!(econ.total_tokens, 360);
        let price = crate::vuln_detector_params::resolve_model_price(&econ.model);
        let expected = (100.0 / 1_000_000.0) * price.input
            + (50.0 / 1_000_000.0) * price.output
            + (10.0 / 1_000_000.0) * price.cache_write
            + (200.0 / 1_000_000.0) * price.cache_read;
        assert!((econ.est_cost_usd - expected).abs() < 1e-9);
    }

    /// G10: OpenAI / Codex report a cache-INCLUSIVE input (`cached_input_tokens`
    /// is a subset already counted in `input_tokens`). The cached subset must
    /// NOT be re-added to the token total and must be removed from the
    /// full-rate input bill before being charged once at the cache-read rate.
    #[test]
    fn codex_cache_inclusive_input_not_double_counted() {
        let jsonl = concat!(
            r#"{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":500,"cached_input_tokens":200,"output_tokens":90}}}}"#,
            "\n",
        );
        let econ = parse_session_economics("cx", "/tmp/cx.jsonl", jsonl);
        assert!(econ.has_token_data);
        assert_eq!(econ.input_tokens, 500);
        assert_eq!(econ.output_tokens, 90);
        assert_eq!(econ.cache_read_input_tokens, 200);
        // Cache-inclusive: the cached subset is already inside input, so it is
        // NOT re-added (590, not 790).
        assert_eq!(econ.total_tokens, 590);
        // Cost subtracts the cached subset from the full-rate input bill.
        let price = crate::vuln_detector_params::resolve_model_price(&econ.model);
        let expected = (300.0 / 1_000_000.0) * price.input
            + (90.0 / 1_000_000.0) * price.output
            + (200.0 / 1_000_000.0) * price.cache_read;
        assert!((econ.est_cost_usd - expected).abs() < 1e-9);
    }

    /// G12: when the provider reports an authoritative `total_tokens`, it is
    /// used verbatim regardless of the per-bucket cache shape.
    #[test]
    fn codex_authoritative_total_tokens_preferred() {
        let jsonl = concat!(
            r#"{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":500,"cached_input_tokens":200,"output_tokens":90,"total_tokens":600}}}}"#,
            "\n",
        );
        let econ = parse_session_economics("cx2", "/tmp/cx2.jsonl", jsonl);
        assert_eq!(econ.total_tokens, 600);
    }

    /// G3: a recognized model prices with a table entry (`price_is_fallback`
    /// false); an unknown model falls back to the default rate and is flagged so
    /// consumers can present its cost as a lower-confidence estimate.
    #[test]
    fn price_is_fallback_flags_unknown_models() {
        let known = concat!(
            r#"{"type":"assistant","timestamp":"2026-05-06T18:15:10.000Z","message":{"role":"assistant","model":"claude-sonnet-4-6","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":100,"output_tokens":50}}}"#,
            "\n",
        );
        let econ_known = parse_session_economics("k", "/tmp/k.jsonl", known);
        assert!(
            !econ_known.price_is_fallback,
            "a recognized model must not be priced from the fallback rate"
        );

        let unknown = concat!(
            r#"{"type":"assistant","timestamp":"2026-05-06T18:15:10.000Z","message":{"role":"assistant","model":"zzz-nonexistent-model-9000","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":100,"output_tokens":50}}}"#,
            "\n",
        );
        let econ_unknown = parse_session_economics("u", "/tmp/u.jsonl", unknown);
        assert!(
            econ_unknown.price_is_fallback,
            "an unknown model must be flagged as fallback-priced"
        );
    }

    #[test]
    fn txt_transcript_has_no_token_data() {
        let txt = "user:\nhello\n\nassistant:\nhi there\n";
        let econ = parse_session_economics("t1", "/tmp/t1.txt", txt);
        assert!(!econ.has_token_data);
        assert_eq!(econ.total_tokens, 0);
        assert_eq!(econ.est_cost_usd, 0.0);
        assert_eq!(econ.duration_secs, 0);
    }

    #[test]
    fn tool_error_details_correlate_anthropic_tool_use_id() {
        let jsonl = concat!(
            r#"{"type":"assistant","timestamp":"2026-05-06T18:15:10.000Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"tu_1","name":"Read"}]}}"#,
            "\n",
            r#"{"type":"user","timestamp":"2026-05-06T18:15:20.000Z","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"tu_1","is_error":true,"content":"permission denied: /etc/shadow"}]}}"#,
            "\n",
        );
        let details = parse_tool_error_details(jsonl);
        assert_eq!(details.len(), 1);
        assert_eq!(details[0].tool_name, "Read");
        assert_eq!(details[0].message, "permission denied: /etc/shadow");
        assert!(details[0].at.is_some());
    }

    #[test]
    fn tool_error_details_correlate_codex_call_id_and_error_object() {
        let jsonl = concat!(
            r#"{"type":"response_item","payload":{"type":"function_call","call_id":"call_9","name":"shell"}}"#,
            "\n",
            r#"{"type":"response_item","payload":{"type":"function_call_output","call_id":"call_9","error":{"message":"exit code 1: command not found"}}}"#,
            "\n",
        );
        let details = parse_tool_error_details(jsonl);
        assert_eq!(details.len(), 1);
        assert_eq!(details[0].tool_name, "shell");
        assert_eq!(details[0].message, "exit code 1: command not found");
    }

    #[test]
    fn tool_error_details_ignore_successful_results() {
        let jsonl = concat!(
            r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","id":"tu_ok","name":"Write"}]}}"#,
            "\n",
            r#"{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"tu_ok","content":"ok"}]}}"#,
            "\n",
        );
        assert!(parse_tool_error_details(jsonl).is_empty());
    }

    #[test]
    fn mcp_server_name_extracted_from_namespaced_tool() {
        assert_eq!(
            mcp_server_from_tool_name("mcp__edamame__get_score"),
            Some("edamame")
        );
        assert_eq!(
            mcp_server_from_tool_name("mcp__github__create_issue"),
            Some("github")
        );
        // Native tools carry no `mcp__` prefix.
        assert_eq!(mcp_server_from_tool_name("Read"), None);
        assert_eq!(mcp_server_from_tool_name("Bash"), None);
        // Malformed (empty server segment) yields None.
        assert_eq!(mcp_server_from_tool_name("mcp____tool"), None);
        assert_eq!(mcp_server_from_tool_name("mcp__"), None);
    }

    #[test]
    fn parse_session_economics_attributes_mcp_calls_by_server() {
        let jsonl = concat!(
            r#"{"type":"assistant","timestamp":"2026-05-06T18:15:10.000Z","message":{"role":"assistant","model":"claude-sonnet-4-6","content":[{"type":"tool_use","name":"mcp__edamame__get_score"},{"type":"tool_use","name":"Read"}]}}"#,
            "\n",
            r#"{"type":"assistant","timestamp":"2026-05-06T18:15:20.000Z","message":{"role":"assistant","model":"claude-sonnet-4-6","content":[{"type":"tool_use","name":"mcp__edamame__get_sessions"},{"type":"tool_use","name":"mcp__github__create_issue"}]}}"#,
            "\n",
        );
        let econ = parse_session_economics("m1", "/tmp/m1.jsonl", jsonl);
        // 4 tool calls total (2 edamame MCP, 1 github MCP, 1 native Read).
        assert_eq!(econ.tool_calls, 4);
        // Only MCP-namespaced calls are bucketed per server.
        assert_eq!(econ.mcp_calls_by_server.get("edamame").copied(), Some(2));
        assert_eq!(econ.mcp_calls_by_server.get("github").copied(), Some(1));
        // Native tools are not attributed to any server.
        assert_eq!(econ.mcp_calls_by_server.len(), 2);
    }

    #[test]
    fn parse_session_economics_no_mcp_calls_yields_empty_map() {
        let jsonl = concat!(
            r#"{"type":"assistant","timestamp":"2026-05-06T18:15:10.000Z","message":{"role":"assistant","model":"claude-sonnet-4-6","content":[{"type":"tool_use","name":"Read"},{"type":"tool_use","name":"Edit"}]}}"#,
            "\n",
        );
        let econ = parse_session_economics("m2", "/tmp/m2.jsonl", jsonl);
        assert_eq!(econ.tool_calls, 2);
        assert!(econ.mcp_calls_by_server.is_empty());
    }

    #[test]
    fn skill_slug_and_path_helpers() {
        assert_eq!(normalize_skill_slug("Security-Posture"), "security-posture");
        assert_eq!(normalize_skill_slug("a/b/SKILL.md"), "skill");
        assert_eq!(
            normalize_skill_slug(".cursor/rules/invariants.mdc"),
            "invariants"
        );
        assert_eq!(normalize_skill_slug("  Fancy Name!  "), "fancy-name");

        assert_eq!(
            skill_from_path("/home/u/.cursor/skills/dogfood-status/SKILL.md"),
            Some("skill:dogfood-status".to_string())
        );
        assert_eq!(
            skill_from_path("C:\\Users\\u\\.claude\\commands\\healthcheck.md"),
            Some("command:healthcheck".to_string())
        );
        assert_eq!(
            skill_from_path("/repo/.cursor/rules/invariants.mdc"),
            Some("rule:invariants".to_string())
        );
        assert_eq!(skill_from_path("/repo/src/lib.rs"), None);

        // Slash-command extraction rejects file paths, accepts command words.
        assert_eq!(
            slash_command_name("/healthcheck now"),
            Some("healthcheck".to_string())
        );
        assert_eq!(
            slash_command_name("/fp-version-release"),
            Some("fp-version-release".to_string())
        );
        assert_eq!(slash_command_name("/Users/foo/bar"), None);
        assert_eq!(slash_command_name("no command here"), None);
    }

    #[test]
    fn parse_session_economics_attributes_skills_and_tool_names() {
        let jsonl = concat!(
            // Explicit Skill tool + a native Read of a SKILL.md (progressive load).
            r#"{"type":"assistant","message":{"role":"assistant","model":"claude-sonnet-4-6","content":[{"type":"tool_use","name":"Skill","input":{"command":"security-posture"}},{"type":"tool_use","name":"Read","input":{"file_path":"/repo/.cursor/skills/dogfood-status/SKILL.md"}}]}}"#,
            "\n",
            // Task subagent + a rule read + an ordinary Edit.
            r#"{"type":"assistant","message":{"role":"assistant","model":"claude-sonnet-4-6","content":[{"type":"tool_use","name":"Task","input":{"subagent_type":"explore"}},{"type":"tool_use","name":"Read","input":{"file_path":"/repo/.cursor/rules/invariants.mdc"}},{"type":"tool_use","name":"Edit","input":{"file_path":"/repo/src/a.rs"}}]}}"#,
            "\n",
            // User turn invoking a slash command.
            r#"{"type":"user","message":{"role":"user","content":"/fp-version-release please"}}"#,
            "\n",
        );
        let econ = parse_session_economics("s1", "/tmp/s1.jsonl", jsonl);

        // Skills: explicit Skill, SKILL.md read, subagent, rule read, slash cmd.
        assert_eq!(
            econ.skill_invocations_by_name
                .get("skill:security-posture")
                .copied(),
            Some(1)
        );
        assert_eq!(
            econ.skill_invocations_by_name
                .get("skill:dogfood-status")
                .copied(),
            Some(1)
        );
        assert_eq!(
            econ.skill_invocations_by_name
                .get("subagent:explore")
                .copied(),
            Some(1)
        );
        assert_eq!(
            econ.skill_invocations_by_name
                .get("rule:invariants")
                .copied(),
            Some(1)
        );
        assert_eq!(
            econ.skill_invocations_by_name
                .get("command:fp-version-release")
                .copied(),
            Some(1)
        );

        // Per-tool-name breakdown counts every tool_use (native + dispatch).
        assert_eq!(econ.tool_calls_by_name.get("Read").copied(), Some(2));
        assert_eq!(econ.tool_calls_by_name.get("Skill").copied(), Some(1));
        assert_eq!(econ.tool_calls_by_name.get("Task").copied(), Some(1));
        assert_eq!(econ.tool_calls_by_name.get("Edit").copied(), Some(1));
        // 5 structured tool calls total across the two assistant turns
        // (turn 1: Skill+Read; turn 2: Task+Read+Edit).
        assert_eq!(econ.tool_calls, 5);
    }

    #[test]
    fn instruction_join_id_matches_transcript_usage_ids() {
        // Skill: slug is the containing folder, not the SKILL.md filename.
        assert_eq!(
            instruction_join_id("skill", "skills/dogfood-status/SKILL.md").as_deref(),
            Some("skill:dogfood-status")
        );
        // A bare `<slug>/SKILL.md` (no `skills` dir) falls back to the parent.
        assert_eq!(
            instruction_join_id("skill", "dogfood-status/SKILL.md").as_deref(),
            Some("skill:dogfood-status")
        );
        // Command / rule / subagent slugs are the file stem (ext stripped).
        assert_eq!(
            instruction_join_id("command", "commands/fp-version-release.md").as_deref(),
            Some("command:fp-version-release")
        );
        assert_eq!(
            instruction_join_id("rule", "rules/invariants.mdc").as_deref(),
            Some("rule:invariants")
        );
        assert_eq!(
            instruction_join_id("subagent", "agents/explore.md").as_deref(),
            Some("subagent:explore")
        );
        // Non-usage-trackable kinds and empty paths yield no join id.
        assert_eq!(instruction_join_id("instruction", "AGENTS.md"), None);
        assert_eq!(instruction_join_id("memory", "memories/x.md"), None);
        assert_eq!(instruction_join_id("skill", ""), None);
    }

    #[test]
    fn parse_session_economics_no_skill_activity_yields_empty_maps() {
        let jsonl = concat!(
            r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"Read","input":{"file_path":"/repo/src/lib.rs"}}]}}"#,
            "\n",
            r#"{"type":"user","message":{"role":"user","content":"just a normal message"}}"#,
            "\n",
        );
        let econ = parse_session_economics("s2", "/tmp/s2.jsonl", jsonl);
        assert!(econ.skill_invocations_by_name.is_empty());
        assert_eq!(econ.tool_calls_by_name.get("Read").copied(), Some(1));
    }

    #[test]
    fn friction_repeated_tool_calls_counts_same_target_only() {
        let jsonl = concat!(
            r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","id":"a","name":"Read","input":{"file_path":"/repo/src/lib.rs"}}]}}"#,
            "\n",
            r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","id":"b","name":"Read","input":{"file_path":"/repo/src/lib.rs"}}]}}"#,
            "\n",
            r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","id":"c","name":"Read","input":{"file_path":"/repo/src/other.rs"}}]}}"#,
            "\n",
        );
        let econ = parse_session_economics("f1", "/tmp/f1.jsonl", jsonl);
        assert_eq!(econ.tool_calls, 3);
        // The 2nd Read of lib.rs is a repeat; other.rs is a distinct target.
        assert_eq!(econ.repeated_tool_calls, 1);
        assert_eq!(econ.retried_after_error_calls, 0);
        assert!(!econ.ended_with_tool_error);
    }

    #[test]
    fn friction_retry_after_error_and_unclean_finish() {
        let jsonl = concat!(
            r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"Shell","input":{"command":"cargo build"}}]}}"#,
            "\n",
            r#"{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","is_error":true,"content":"error[E0432]"}]}}"#,
            "\n",
            r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","id":"t2","name":"Shell","input":{"command":"cargo build"}}]}}"#,
            "\n",
            r#"{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"t2","is_error":true,"content":"error[E0432]"}]}}"#,
            "\n",
        );
        let econ = parse_session_economics("f2", "/tmp/f2.jsonl", jsonl);
        assert_eq!(econ.tool_calls, 2);
        assert_eq!(econ.tool_errors, 2);
        // Same command reissued after it errored -> repeat AND retry-after-error.
        assert_eq!(econ.repeated_tool_calls, 1);
        assert_eq!(econ.retried_after_error_calls, 1);
        // The final tool result was an error -> unclean finish.
        assert!(econ.ended_with_tool_error);
    }

    #[test]
    fn friction_codex_payload_function_calls_counted_and_clean_finish() {
        let jsonl = concat!(
            r#"{"type":"response_item","payload":{"type":"function_call","call_id":"c1","name":"shell","arguments":"{\"command\":\"ls\"}"}}"#,
            "\n",
            r#"{"type":"response_item","payload":{"type":"function_call_output","call_id":"c1","content":"ok"}}"#,
            "\n",
        );
        let econ = parse_session_economics("f3", "/tmp/f3.jsonl", jsonl);
        // Codex payload-wrapped function_call is now counted (candidate resolution
        // falls back to `payload` when there is no `content` array).
        assert_eq!(econ.tool_calls, 1);
        assert_eq!(econ.tool_errors, 0);
        assert_eq!(econ.repeated_tool_calls, 0);
        assert_eq!(econ.retried_after_error_calls, 0);
        // Final result succeeded -> clean finish.
        assert!(!econ.ended_with_tool_error);
    }
}
