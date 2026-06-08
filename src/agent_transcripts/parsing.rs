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

/// Per-model price in USD per 1,000,000 tokens. Cost is an ESTIMATE: token
/// counts are exact, the dollar conversion is approximate and drifts as
/// providers change pricing. A future increment can move this to a
/// CloudModel-refreshable table; an embedded table is sufficient for an
/// at-a-glance "what did this run cost" figure.
#[derive(Debug, Clone, Copy)]
struct ModelPrice {
    input: f64,
    output: f64,
    cache_write: f64,
    cache_read: f64,
}

/// Resolve approximate pricing for a model identifier by lowercased substring.
/// Falls back to a Sonnet-class rate for unknown models so the estimate is
/// never wildly off for a mainstream coding model.
fn model_price(model: &str) -> ModelPrice {
    let m = model.to_ascii_lowercase();
    // Anthropic.
    if m.contains("opus") {
        return ModelPrice {
            input: 15.0,
            output: 75.0,
            cache_write: 18.75,
            cache_read: 1.5,
        };
    }
    if m.contains("haiku") {
        return ModelPrice {
            input: 0.80,
            output: 4.0,
            cache_write: 1.0,
            cache_read: 0.08,
        };
    }
    if m.contains("sonnet") {
        return ModelPrice {
            input: 3.0,
            output: 15.0,
            cache_write: 3.75,
            cache_read: 0.30,
        };
    }
    // OpenAI / Codex.
    if m.contains("gpt-5") || m.contains("gpt5") || m.contains("codex") {
        return ModelPrice {
            input: 1.25,
            output: 10.0,
            cache_write: 0.0,
            cache_read: 0.125,
        };
    }
    if m.contains("gpt-4o") || m.contains("gpt4o") {
        return ModelPrice {
            input: 2.5,
            output: 10.0,
            cache_write: 0.0,
            cache_read: 1.25,
        };
    }
    if m.contains("gpt-4.1") || m.contains("gpt-4-1") {
        return ModelPrice {
            input: 2.0,
            output: 8.0,
            cache_write: 0.0,
            cache_read: 0.5,
        };
    }
    if m.contains("o3") || m.contains("o4-mini") || m.contains("o4 ") {
        return ModelPrice {
            input: 2.0,
            output: 8.0,
            cache_write: 0.0,
            cache_read: 0.5,
        };
    }
    // Google Gemini.
    if m.contains("gemini") {
        return ModelPrice {
            input: 1.25,
            output: 5.0,
            cache_write: 0.0,
            cache_read: 0.31,
        };
    }
    // Fallback: Sonnet-class.
    ModelPrice {
        input: 3.0,
        output: 15.0,
        cache_write: 3.75,
        cache_read: 0.30,
    }
}

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

/// (input, output, cache_creation, cache_read, total) from a usage object,
/// tolerating Anthropic and OpenAI key spellings.
fn read_usage(usage: &serde_json::Value) -> (u64, u64, u64, u64, u64) {
    let input = usage_field(usage, &["input_tokens", "prompt_tokens"]);
    let output = usage_field(usage, &["output_tokens", "completion_tokens"]);
    let cache_creation = usage_field(
        usage,
        &[
            "cache_creation_input_tokens",
            "cache_creation_tokens",
            "cache_write_tokens",
        ],
    );
    let cache_read = usage_field(
        usage,
        &[
            "cache_read_input_tokens",
            "cached_input_tokens",
            "cache_read_tokens",
        ],
    );
    let total = usage_field(usage, &["total_tokens"]);
    (input, output, cache_creation, cache_read, total)
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

    // Cumulative snapshot (Codex `total_token_usage`): keep the object with the
    // largest total seen -- that is the session-final cumulative count.
    let mut cum_seen = false;
    let mut cum_total = 0u64;
    let mut cum_input = 0u64;
    let mut cum_output = 0u64;
    let mut cum_cache_creation = 0u64;
    let mut cum_cache_read = 0u64;

    let mut assistant_turns = 0u64;
    let mut tool_calls = 0u64;
    let mut tool_errors = 0u64;
    let mut model = String::new();
    let mut first_ts: Option<DateTime<Utc>> = None;
    let mut last_ts: Option<DateTime<Utc>> = None;
    let mut had_usage = false;

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

        // Timestamps (min/max for wall-clock duration).
        for candidate in [
            value.get("timestamp"),
            value.get("payload").and_then(|p| p.get("timestamp")),
            value.get("ts"),
        ] {
            if let Some(v) = candidate {
                if let Some(dt) = parse_ts(v) {
                    if first_ts.map(|f| dt < f).unwrap_or(true) {
                        first_ts = Some(dt);
                    }
                    if last_ts.map(|l| dt > l).unwrap_or(true) {
                        last_ts = Some(dt);
                    }
                }
            }
        }

        // Per-turn usage (Anthropic message.usage / OpenAI usage).
        let per_turn_usage = value
            .get("message")
            .and_then(|m| m.get("usage"))
            .or_else(|| value.get("usage"))
            .or_else(|| value.get("response").and_then(|r| r.get("usage")))
            .or_else(|| value.get("payload").and_then(|p| p.get("usage")));
        if let Some(usage) = per_turn_usage {
            if usage.is_object() {
                let (i, o, cc, cr, _t) = read_usage(usage);
                if i > 0 || o > 0 || cc > 0 || cr > 0 {
                    summed_input += i;
                    summed_output += o;
                    summed_cache_creation += cc;
                    summed_cache_read += cr;
                    had_usage = true;
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
                let (i, o, cc, cr, t) = read_usage(usage);
                let total = if t > 0 { t } else { i + o + cc + cr };
                if total >= cum_total {
                    cum_seen = true;
                    cum_total = total;
                    cum_input = i;
                    cum_output = o;
                    cum_cache_creation = cc;
                    cum_cache_read = cr;
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
        }
        let content = value
            .get("message")
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_array())
            .or_else(|| value.get("content").and_then(|c| c.as_array()));
        if let Some(items) = content {
            for item in items {
                let kind = item.get("type").and_then(|v| v.as_str()).unwrap_or("");
                match kind {
                    "tool_use" | "function_call" => tool_calls += 1,
                    "tool_result" | "function_call_output" => {
                        let is_err = item
                            .get("is_error")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false)
                            || item.get("error").map(|e| !e.is_null()).unwrap_or(false);
                        if is_err {
                            tool_errors += 1;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // Prefer the cumulative snapshot when present (Codex), else the per-turn
    // sum (Claude).
    let (input_tokens, output_tokens, cache_creation_input_tokens, cache_read_input_tokens) =
        if cum_seen && cum_total > 0 {
            (cum_input, cum_output, cum_cache_creation, cum_cache_read)
        } else {
            (
                summed_input,
                summed_output,
                summed_cache_creation,
                summed_cache_read,
            )
        };

    let total_tokens =
        input_tokens + output_tokens + cache_creation_input_tokens + cache_read_input_tokens;

    let price = model_price(&model);
    let est_cost_usd = (input_tokens as f64) / 1_000_000.0 * price.input
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

    #[test]
    fn txt_transcript_has_no_token_data() {
        let txt = "user:\nhello\n\nassistant:\nhi there\n";
        let econ = parse_session_economics("t1", "/tmp/t1.txt", txt);
        assert!(!econ.has_token_data);
        assert_eq!(econ.total_tokens, 0);
        assert_eq!(econ.est_cost_usd, 0.0);
        assert_eq!(econ.duration_secs, 0);
    }
}
