//! Deterministic "craft" heuristics: prompt / workflow quality signals
//! measuring the HUMAN side of the augmentation equation -- how well the
//! user drives the agent. Inspired by AgentsView's Coach layer (prompt
//! maturity, stuck re-asks, frustration markers, runaway tool loops,
//! intent classification), ported to our parsed transcript shapes.
//!
//! Everything here is pure (allocating only), LLM-free, and operates on
//! already-extracted prompt text and tool-call sequences -- never on raw
//! transcript files. Labels and scores only; prompt content never leaves
//! the parser.

use once_cell::sync::Lazy;
use regex::Regex;

/// One tool call in session order, with its failure state resolved (the
/// erroring result correlated back by call id). `signature` is the exact
/// `(tool, target)` signature from `tool_target_signature`; `class` is the
/// coarse bucket used for dominant-class window detection (`exec:<argv0>`
/// for exec tools, `tool:<name>` otherwise).
#[derive(Debug, Clone, Default)]
pub struct CraftToolCall {
    pub signature: String,
    pub class: String,
    pub failed: bool,
}

/// Craft signal bundle for one session. All maturity dimensions are 0-100.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CraftSignals {
    pub prompt_maturity_constraints: u64,
    pub prompt_maturity_success_criteria: u64,
    pub prompt_maturity_verification: u64,
    pub prompt_maturity_context: u64,
    pub prompt_maturity_specificity: u64,
    /// Mean of the five dimensions (0 when no substantive prompts).
    pub prompt_maturity_score: u64,
    /// Number of substantive (non-control) user prompts that fed the
    /// maturity analysis. 0 means "not scored" (control-only or empty).
    pub substantive_user_prompts: u64,
    pub duplicate_prompt_count: u64,
    /// True when duplicate prompts co-occur with tool errors/retries in the
    /// same session -- the user re-asking the same thing while it fails.
    pub stuck_reask: bool,
    pub frustration_marker_count: u64,
    pub runaway_tool_loop: bool,
    /// `planning` / `implementation` / `debugging` / `review` /
    /// `exploration`, or empty when no substantive prompt exists.
    pub intent_class: String,
    pub spec_driven_start: bool,
}

static CODE_FENCE_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?s)```.*?```").expect("code fence regex"));
static FILE_REF_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:^|[\s"'`])(?:\.{0,2}/)?[a-z0-9_.\-]+(?:/[a-z0-9_. \-]+)+|[a-z0-9_.\-]+\.(?:go|ts|tsx|js|jsx|py|rs|dart|java|kt|rb|php|cs|cpp|c|h|hpp|sql|svelte|vue|css|scss|html|json|ya?ml|toml|md|sh|zsh|bash)\b"#,
    )
    .expect("file ref regex")
});
static BULLET_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)^\s*(?:[-*+]|\d+\.)\s+\S+").expect("bullet regex"));
static FRUSTRATION_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(!{3,}|\?{3,}|\b(?:wtf|come on|why won't|this is broken|doesn't work|does not work|still broken|same error|you broke|fucking|fuck)\b)",
    )
    .expect("frustration regex")
});

const CONTROL_PROMPTS: &[&str] = &[
    "yes",
    "y",
    "no",
    "n",
    "ok",
    "okay",
    "continue",
    "go ahead",
    "proceed",
    "do it",
    "done",
    "thanks",
    "thank you",
    "please continue",
    "keep going",
];

const CONSTRAINT_TOKENS: &[&str] = &[
    "must",
    "never",
    "only",
    "preserve",
    "keep",
    "avoid",
    "require",
    "requires",
    "constraint",
    "constraints",
    "acceptance",
    "criteria",
    "expected",
    "format",
];

const SUCCESS_PHRASES: &[&str] = &[
    "success",
    "acceptance",
    "expected",
    "done when",
    "should result",
    "criteria",
];

const VERIFICATION_TOKENS: &[&str] = &[
    "test",
    "tests",
    "verify",
    "verification",
    "validate",
    "validation",
    "check",
    "reproduce",
    "proof",
];

const SPEC_PHRASES: &[&str] = &[
    "acceptance criteria",
    "success criteria",
    "requirements",
    "steps",
    "plan",
    "scope",
    "non-scope",
];

const DEBUG_TOKENS: &[&str] = &[
    "fix",
    "debug",
    "bug",
    "error",
    "broken",
    "failing",
    "fails",
    "crash",
    "crashes",
    "traceback",
    "regression",
    "panic",
];

const REVIEW_TOKENS: &[&str] = &["review", "audit", "critique", "assess"];

const PLAN_TOKENS: &[&str] = &[
    "plan",
    "design",
    "architecture",
    "spec",
    "proposal",
    "roadmap",
    "strategy",
];

const IMPL_TOKENS: &[&str] = &[
    "implement",
    "add",
    "create",
    "write",
    "build",
    "refactor",
    "update",
    "change",
    "remove",
    "wire",
    "migrate",
    "rename",
];

/// Shell argv0 values that indicate context-gathering activity (the user or
/// agent grounding itself in the codebase) when run through an exec tool.
const CONTEXT_COMMANDS: &[&str] = &[
    "rg", "grep", "git", "ls", "find", "cat", "sed", "awk", "go", "npm", "pnpm", "yarn", "pytest",
    "cargo", "make", "head", "tail",
];

/// Strip fenced code, lowercase, trim, and collapse whitespace runs. Pasted
/// logs / code must not distort tone or duplicate detection.
pub fn normalize_prompt(content: &str) -> String {
    let without_code = if content.contains("```") {
        CODE_FENCE_REGEX.replace_all(content, " ").into_owned()
    } else {
        content.to_string()
    };
    let lower = without_code.trim().to_lowercase();
    let mut out = String::with_capacity(lower.len());
    let mut in_space = false;
    let mut wrote = false;
    for ch in lower.chars() {
        if ch.is_whitespace() {
            if wrote {
                in_space = true;
            }
            continue;
        }
        if in_space {
            out.push(' ');
            in_space = false;
        }
        out.push(ch);
        wrote = true;
    }
    out
}

/// Tokens of >= 3 chars from a normalized prompt (letters/digits/`_`/`-`).
fn prompt_tokens(normalized: &str) -> Vec<String> {
    normalized
        .split(|c: char| !c.is_alphanumeric() && c != '_' && c != '-')
        .filter(|t| t.len() >= 3)
        .map(str::to_string)
        .collect()
}

fn is_control_prompt(normalized: &str) -> bool {
    CONTROL_PROMPTS.contains(&normalized)
}

fn contains_any_token(tokens: &[String], words: &[&str]) -> bool {
    tokens.iter().any(|t| words.contains(&t.as_str()))
}

fn contains_any_phrase(normalized: &str, phrases: &[&str]) -> bool {
    phrases.iter().any(|p| normalized.contains(p))
}

/// Structured-spec shape: markdown headings, bullet/numbered lists, or
/// canonical spec phrases.
fn has_spec_structure(content: &str, normalized: &str) -> bool {
    if content.contains("\n#") || BULLET_REGEX.is_match(content) {
        return true;
    }
    contains_any_phrase(normalized, SPEC_PHRASES)
}

fn has_file_ref(content: &str) -> bool {
    FILE_REF_REGEX.is_match(content)
}

/// Ratio of ALL-CAPS words (>= 2 letters) outside code fences.
fn caps_word_ratio(content: &str, min_words: usize) -> f64 {
    let without_code = CODE_FENCE_REGEX.replace_all(content, " ");
    let mut total = 0usize;
    let mut caps = 0usize;
    for word in without_code.split(|c: char| !c.is_alphabetic()) {
        if word.chars().count() < 2 {
            continue;
        }
        total += 1;
        let has_lower = word.chars().any(|c| c.is_lowercase());
        let has_upper = word.chars().any(|c| c.is_uppercase());
        if has_upper && !has_lower {
            caps += 1;
        }
    }
    if total < min_words {
        return 0.0;
    }
    caps as f64 / total as f64
}

/// True when a user prompt reads as frustration: repeated punctuation,
/// hostile phrases, or a high ALL-CAPS word ratio. Code fences stripped
/// first so pasted logs never become tone signals.
pub fn is_frustration_marker(content: &str) -> bool {
    let normalized = normalize_prompt(content);
    if normalized.chars().count() < 10 {
        return false;
    }
    if FRUSTRATION_REGEX.is_match(&normalized) {
        return true;
    }
    caps_word_ratio(content, 3) >= 0.4
}

/// Jaccard similarity of two token sets.
fn jaccard(a: &[String], b: &[String]) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let set_a: std::collections::HashSet<&str> = a.iter().map(String::as_str).collect();
    let mut intersections = 0usize;
    let mut union = set_a.len();
    let mut seen_b: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for token in b {
        if !seen_b.insert(token.as_str()) {
            continue;
        }
        if set_a.contains(token.as_str()) {
            intersections += 1;
        } else {
            union += 1;
        }
    }
    if union == 0 {
        return 0.0;
    }
    intersections as f64 / union as f64
}

struct PromptInfo {
    content: String,
    normalized: String,
    tokens: Vec<String>,
}

/// True when `lower_name` is a context-gathering tool (read / grep / glob /
/// search-class), or an exec call whose command's argv0 is a recognized
/// context command. Used for the maturity `context` dimension: tool-side
/// grounding partially substitutes for prompt-side file references.
pub fn is_context_tool_call(lower_name: &str, input: Option<&serde_json::Value>) -> bool {
    const READ_CLASS: &[&str] = &[
        "read", "grep", "glob", "search", "codebase", "list_dir", "ls",
    ];
    if READ_CLASS.iter().any(|t| lower_name.contains(t)) {
        return true;
    }
    let is_exec = ["bash", "shell", "terminal", "exec", "cmd"]
        .iter()
        .any(|t| lower_name.contains(t));
    if !is_exec {
        return false;
    }
    let command = input
        .and_then(|obj| {
            obj.get("command")
                .or_else(|| obj.get("cmd"))
                .and_then(|v| v.as_str())
        })
        .unwrap_or("");
    let argv0 = command.split_whitespace().next().unwrap_or("");
    CONTEXT_COMMANDS.contains(&argv0) || command.contains(" test") || command.contains(" lint")
}

/// Coarse command-class bucket for the runaway-loop window detector.
/// Exec tools bucket by argv0 (`exec:cargo`), everything else by tool name
/// (`tool:read`).
pub fn tool_command_class(lower_name: &str, input: Option<&serde_json::Value>) -> String {
    let is_exec = ["bash", "shell", "terminal", "exec", "cmd"]
        .iter()
        .any(|t| lower_name.contains(t));
    if is_exec {
        let command = input
            .and_then(|obj| {
                obj.get("command")
                    .or_else(|| obj.get("cmd"))
                    .and_then(|v| v.as_str())
            })
            .unwrap_or("");
        let argv0 = command.split_whitespace().next().unwrap_or("");
        if !argv0.is_empty() {
            let argv0: String = argv0.to_ascii_lowercase().chars().take(60).collect();
            return format!("exec:{argv0}");
        }
    }
    format!("tool:{lower_name}")
}

/// Runaway tool loop: >= 5 identical consecutive signatures with >= 3
/// failures among them, OR any 12-call window with >= 6 failures, OR a
/// 12-call window with >= 3 failures where one command class saturates
/// (>= 10 of 12 calls).
fn has_runaway_tool_loop(calls: &[CraftToolCall]) -> bool {
    if has_repeated_failing_exact_run(calls, 5, 3) {
        return true;
    }
    const WINDOW: usize = 12;
    if calls.len() < WINDOW {
        return false;
    }
    for window in calls.windows(WINDOW) {
        let failures = window.iter().filter(|c| c.failed).count();
        if failures >= 6 {
            return true;
        }
        if failures >= 3 {
            let mut counts: std::collections::HashMap<&str, usize> =
                std::collections::HashMap::new();
            for c in window {
                *counts.entry(c.class.as_str()).or_insert(0) += 1;
            }
            if counts.values().copied().max().unwrap_or(0) >= 10 {
                return true;
            }
        }
    }
    false
}

fn has_repeated_failing_exact_run(
    calls: &[CraftToolCall],
    threshold: usize,
    failure_threshold: usize,
) -> bool {
    let mut run = 1usize;
    let mut failures = usize::from(calls.first().map(|c| c.failed).unwrap_or(false));
    for i in 1..calls.len() {
        if calls[i].signature == calls[i - 1].signature {
            run += 1;
            if calls[i].failed {
                failures += 1;
            }
            if run >= threshold && failures >= failure_threshold {
                return true;
            }
        } else {
            run = 1;
            failures = usize::from(calls[i].failed);
        }
    }
    false
}

/// Duplicate-prompt count: substantive prompts (>= 20 chars, >= 4 tokens)
/// that exactly match, or Jaccard >= 0.85 against, an earlier prompt.
fn count_duplicate_prompts(prompts: &[PromptInfo]) -> u64 {
    let mut seen: Vec<&PromptInfo> = Vec::new();
    let mut repeats = 0u64;
    for p in prompts {
        if is_control_prompt(&p.normalized) || p.normalized.len() < 20 || p.tokens.len() < 4 {
            continue;
        }
        let duplicate = seen.iter().any(|prev| {
            p.normalized == prev.normalized || jaccard(&p.tokens, &prev.tokens) >= 0.85
        });
        if duplicate {
            repeats += 1;
        } else {
            seen.push(p);
        }
    }
    repeats
}

/// Specificity of the first substantive prompt: normalized length (10-70)
/// plus a structure bonus (+30 for headings/bullets/spec phrases), capped
/// at 100. A bare "fix it" scores ~10; a structured multi-line spec scores
/// 100.
fn specificity_score(first: &PromptInfo) -> u64 {
    let len = first.normalized.chars().count();
    let length_score = if len < 30 {
        10.0
    } else {
        10.0 + 60.0 * (((len - 30) as f64) / 170.0).min(1.0)
    };
    let structure_bonus = if has_spec_structure(&first.content, &first.normalized) {
        30.0
    } else {
        0.0
    };
    (length_score + structure_bonus).min(100.0) as u64
}

/// Grade a presence-style dimension: 100 when the FIRST substantive prompt
/// carries the language (front-loaded intent), 50 when only a later prompt
/// does (added under duress), 0 when absent everywhere.
fn presence_dimension(prompts: &[PromptInfo], check: impl Fn(&PromptInfo) -> bool) -> u64 {
    match prompts.iter().position(check) {
        Some(0) => 100,
        Some(_) => 50,
        None => 0,
    }
}

/// Intent classification from the first substantive prompt's tokens plus the
/// session's edit activity. Priority: debugging > review > planning >
/// implementation > exploration.
fn classify_intent(first: &PromptInfo, edited_file_count: u64) -> &'static str {
    if contains_any_token(&first.tokens, DEBUG_TOKENS) {
        return "debugging";
    }
    if contains_any_token(&first.tokens, REVIEW_TOKENS) {
        return "review";
    }
    if contains_any_token(&first.tokens, PLAN_TOKENS) && edited_file_count == 0 {
        return "planning";
    }
    if contains_any_token(&first.tokens, IMPL_TOKENS) || edited_file_count > 0 {
        return "implementation";
    }
    "exploration"
}

/// Analyze craft signals for one session.
///
/// `user_prompts` is the ordered list of user prose turns (code fences may be
/// present; they are stripped internally). `tool_calls` is the ordered tool
/// sequence with per-call failure resolved. `context_tool_activity` reports
/// whether any context-gathering tool ran (read/grep/glob or a context exec
/// command). `had_errors` gates the stuck-re-ask flag.
pub fn analyze_craft(
    user_prompts: &[String],
    tool_calls: &[CraftToolCall],
    context_tool_activity: bool,
    edited_file_count: u64,
    had_errors: bool,
) -> CraftSignals {
    let prompts: Vec<PromptInfo> = user_prompts
        .iter()
        .filter_map(|content| {
            let normalized = normalize_prompt(content);
            if normalized.is_empty() {
                return None;
            }
            let tokens = prompt_tokens(&normalized);
            Some(PromptInfo {
                content: content.clone(),
                normalized,
                tokens,
            })
        })
        .collect();

    let substantive: Vec<PromptInfo> = prompts
        .iter()
        .filter(|p| !is_control_prompt(&p.normalized))
        .map(|p| PromptInfo {
            content: p.content.clone(),
            normalized: p.normalized.clone(),
            tokens: p.tokens.clone(),
        })
        .collect();

    let duplicate_prompt_count = count_duplicate_prompts(&prompts);
    let frustration_marker_count = prompts
        .iter()
        .filter(|p| is_frustration_marker(&p.content))
        .count() as u64;
    let runaway_tool_loop = has_runaway_tool_loop(tool_calls);

    let mut signals = CraftSignals {
        duplicate_prompt_count,
        stuck_reask: duplicate_prompt_count > 0 && had_errors,
        frustration_marker_count,
        runaway_tool_loop,
        substantive_user_prompts: substantive.len() as u64,
        ..Default::default()
    };

    let Some(first) = substantive.first() else {
        return signals;
    };

    signals.prompt_maturity_constraints = presence_dimension(&substantive, |p| {
        contains_any_token(&p.tokens, CONSTRAINT_TOKENS)
            || has_spec_structure(&p.content, &p.normalized)
    });
    signals.prompt_maturity_success_criteria = presence_dimension(&substantive, |p| {
        contains_any_phrase(&p.normalized, SUCCESS_PHRASES)
    });
    signals.prompt_maturity_verification = presence_dimension(&substantive, |p| {
        contains_any_token(&p.tokens, VERIFICATION_TOKENS)
    });
    signals.prompt_maturity_context = {
        let prompt_side = presence_dimension(&substantive, |p| {
            has_file_ref(&p.content) || p.content.contains("```")
        });
        if prompt_side > 0 {
            prompt_side
        } else if context_tool_activity {
            // Tool-side grounding (agent read/grepped the codebase) partially
            // substitutes for prompt-side references.
            60
        } else {
            0
        }
    };
    signals.prompt_maturity_specificity = specificity_score(first);
    signals.prompt_maturity_score = (signals.prompt_maturity_constraints
        + signals.prompt_maturity_success_criteria
        + signals.prompt_maturity_verification
        + signals.prompt_maturity_context
        + signals.prompt_maturity_specificity)
        / 5;
    signals.intent_class = classify_intent(first, edited_file_count).to_string();
    signals.spec_driven_start = has_spec_structure(&first.content, &first.normalized);

    signals
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(sig: &str, class: &str, failed: bool) -> CraftToolCall {
        CraftToolCall {
            signature: sig.to_string(),
            class: class.to_string(),
            failed,
        }
    }

    #[test]
    fn empty_session_yields_default_signals() {
        let s = analyze_craft(&[], &[], false, 0, false);
        assert_eq!(s, CraftSignals::default());
    }

    #[test]
    fn control_only_prompts_are_not_substantive() {
        let prompts = vec!["ok".to_string(), "continue".to_string()];
        let s = analyze_craft(&prompts, &[], false, 0, false);
        assert_eq!(s.substantive_user_prompts, 0);
        assert_eq!(s.prompt_maturity_score, 0);
        assert!(s.intent_class.is_empty());
    }

    #[test]
    fn structured_spec_prompt_scores_high_maturity() {
        let prompts = vec![
            "Refactor the session parser in src/parser.rs.\n\n# Requirements\n- must preserve the existing public API\n- acceptance criteria: all tests pass\n- verify with cargo test after each change"
                .to_string(),
        ];
        let s = analyze_craft(&prompts, &[], false, 0, false);
        assert_eq!(s.substantive_user_prompts, 1);
        assert_eq!(s.prompt_maturity_constraints, 100);
        assert_eq!(s.prompt_maturity_success_criteria, 100);
        assert_eq!(s.prompt_maturity_verification, 100);
        assert_eq!(s.prompt_maturity_context, 100);
        assert!(s.prompt_maturity_specificity >= 90);
        assert!(s.prompt_maturity_score >= 90);
        assert!(s.spec_driven_start);
        assert_eq!(s.intent_class, "implementation");
    }

    #[test]
    fn bare_short_prompt_scores_low_maturity() {
        let prompts = vec!["make it work".to_string()];
        let s = analyze_craft(&prompts, &[], false, 0, false);
        assert_eq!(s.prompt_maturity_constraints, 0);
        assert_eq!(s.prompt_maturity_success_criteria, 0);
        assert_eq!(s.prompt_maturity_verification, 0);
        assert_eq!(s.prompt_maturity_context, 0);
        assert_eq!(s.prompt_maturity_specificity, 10);
        assert!(!s.spec_driven_start);
    }

    #[test]
    fn late_constraints_score_half() {
        let prompts = vec![
            "please update the login page styling somehow".to_string(),
            "wait, you must keep the existing color palette".to_string(),
        ];
        let s = analyze_craft(&prompts, &[], false, 0, false);
        assert_eq!(s.prompt_maturity_constraints, 50);
    }

    #[test]
    fn context_tool_activity_substitutes_for_prompt_context() {
        let prompts = vec!["please improve the error handling somehow".to_string()];
        let s = analyze_craft(&prompts, &[], true, 0, false);
        assert_eq!(s.prompt_maturity_context, 60);
    }

    #[test]
    fn duplicate_prompts_detected_exact_and_jaccard() {
        let prompts = vec![
            "please fix the database connection pool timeout issue".to_string(),
            "please fix the database connection pool timeout issue".to_string(),
            "fix the database connection pool timeout issue please now".to_string(),
        ];
        let s = analyze_craft(&prompts, &[], false, 0, true);
        assert!(s.duplicate_prompt_count >= 2);
        assert!(s.stuck_reask);
    }

    #[test]
    fn duplicates_without_errors_are_not_stuck_reask() {
        let prompts = vec![
            "please fix the database connection pool timeout issue".to_string(),
            "please fix the database connection pool timeout issue".to_string(),
        ];
        let s = analyze_craft(&prompts, &[], false, 0, false);
        assert!(s.duplicate_prompt_count >= 1);
        assert!(!s.stuck_reask);
    }

    #[test]
    fn frustration_markers_counted_and_code_fences_ignored() {
        let prompts = vec![
            "this is broken!!! why won't it compile".to_string(),
            "```\nERROR ERROR ERROR THIS IS BROKEN!!!\n```\nplease look at the log above and diagnose".to_string(),
        ];
        let s = analyze_craft(&prompts, &[], false, 0, false);
        assert_eq!(s.frustration_marker_count, 1);
    }

    #[test]
    fn runaway_loop_from_consecutive_failing_run() {
        let calls: Vec<CraftToolCall> = (0..5)
            .map(|i| call("bash\u{1}cargo build", "exec:cargo", i % 2 == 0))
            .collect();
        assert!(has_runaway_tool_loop(&calls));
    }

    #[test]
    fn runaway_loop_from_failure_saturated_window() {
        let mut calls = Vec::new();
        for i in 0..12 {
            calls.push(call(&format!("bash\u{1}cmd{i}"), "exec:misc", i % 2 == 0));
        }
        // 6 failures in the 12-call window.
        assert!(has_runaway_tool_loop(&calls));
    }

    #[test]
    fn no_runaway_loop_for_healthy_session() {
        let calls = vec![
            call("read\u{1}a.rs", "tool:read", false),
            call("edit\u{1}a.rs", "tool:edit", false),
            call("bash\u{1}cargo test", "exec:cargo", false),
        ];
        assert!(!has_runaway_tool_loop(&calls));
    }

    #[test]
    fn intent_classification_priorities() {
        let dbg = analyze_craft(
            &["fix the flaky test crash".to_string()],
            &[],
            false,
            0,
            false,
        );
        assert_eq!(dbg.intent_class, "debugging");
        let review = analyze_craft(
            &["review the auth module for style issues".to_string()],
            &[],
            false,
            0,
            false,
        );
        assert_eq!(review.intent_class, "review");
        let plan = analyze_craft(
            &["draft an architecture proposal for the ingest layer".to_string()],
            &[],
            false,
            0,
            false,
        );
        assert_eq!(plan.intent_class, "planning");
        let implem = analyze_craft(
            &["add a dark mode toggle to settings".to_string()],
            &[],
            false,
            2,
            false,
        );
        assert_eq!(implem.intent_class, "implementation");
        let explore = analyze_craft(
            &["how does the capture pipeline hand sessions to the analyzer".to_string()],
            &[],
            false,
            0,
            false,
        );
        assert_eq!(explore.intent_class, "exploration");
    }

    #[test]
    fn context_tool_call_detection() {
        assert!(is_context_tool_call("read", None));
        assert!(is_context_tool_call("grep", None));
        let bash_ctx = serde_json::json!({"command": "rg pattern src/"});
        assert!(is_context_tool_call("bash", Some(&bash_ctx)));
        let bash_other = serde_json::json!({"command": "curl https://example.com"});
        assert!(!is_context_tool_call("bash", Some(&bash_other)));
        assert!(!is_context_tool_call("edit", None));
    }

    #[test]
    fn command_class_buckets() {
        let bash = serde_json::json!({"command": "cargo build --release"});
        assert_eq!(tool_command_class("bash", Some(&bash)), "exec:cargo");
        assert_eq!(tool_command_class("read", None), "tool:read");
    }
}
