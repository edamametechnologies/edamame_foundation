//! Grading of passwordless sudo rules for the host blast-radius assessment
//! (`agent_visibility::assess_host_privilege`, INC-7).
//!
//! A passwordless (`NOPASSWD`) rule is graded by what it allows:
//! - **root-equivalent** (the `passwordless_root` amplifier): `ALL`, a binary
//!   that escalates when sudo runs it (a shell, an interpreter, an editor or
//!   pager with a shell escape, a tool that runs a command or writes any
//!   file), a command path the user can write, and everything the parser
//!   cannot pin down to one command: a directory or wildcard command, an
//!   undefined command alias, a relative command, a rule that lets the caller
//!   set the environment (`SETENV`, `Defaults setenv`, an `env_keep` of a
//!   loader variable) or pick a chroot;
//! - **limited**: any other specific command. That is the lower
//!   "passwordless sudo for N commands" signal, not an amplifier.
//!
//! Arguments never relax the grade: sudoers wildcards match spaces, and many
//! escalatable binaries escape to a shell interactively whatever their
//! arguments. Negated commands (`!cmd`) never lower a grade either.
//!
//! Pure: the caller reads the policy files and supplies the writability
//! predicate (it stats the command path on the privileged side). The sudoers
//! grammar (tags, aliases, `Defaults`, escapes, host groups) is code; the
//! binaries, families and environment variables it matches are data
//! (`agent_visibility_params::host_privilege()`). The run-as target and the
//! host list are not graded: a rule counts on this host, as root.

use crate::agent_visibility_params::HostPrivilegeJSON;
use std::collections::BTreeMap;

/// Longest command text kept in an evidence line (resource bound).
const MAX_EVIDENCE_COMMAND_CHARS: usize = 120;
/// Commands named per evidence line before "+N more" (resource bound).
const MAX_EVIDENCE_COMMANDS: usize = 3;
/// Alias nesting followed before an alias counts as unresolved.
const MAX_ALIAS_DEPTH: usize = 8;

/// sudoers tags (`TAG:`), grammar.
const TAGS: &[&str] = &[
    "EXEC",
    "NOEXEC",
    "FOLLOW",
    "NOFOLLOW",
    "LOG_INPUT",
    "NOLOG_INPUT",
    "LOG_OUTPUT",
    "NOLOG_OUTPUT",
    "MAIL",
    "NOMAIL",
    "INTERCEPT",
    "NOINTERCEPT",
    "PASSWD",
    "NOPASSWD",
    "SETENV",
    "NOSETENV",
];

/// sudoers option specs (`NAME=value` before the command), grammar.
const OPTION_NAMES: &[&str] = &[
    "CWD",
    "CHROOT",
    "TIMEOUT",
    "NOTBEFORE",
    "NOTAFTER",
    "ROLE",
    "TYPE",
    "APPARMOR_PROFILE",
    "PRIVS",
    "LIMITPRIVS",
];

/// sudoers digest algorithms (`sha256:<digest> /path`), grammar.
const DIGEST_ALGORITHMS: &[&str] = &["sha224", "sha256", "sha384", "sha512"];

/// One sudoers policy file: its display name (the file name) and body.
#[derive(Debug, Clone)]
pub struct SudoersSource {
    pub name: String,
    pub text: String,
}

/// The account the rules are evaluated for.
#[derive(Debug, Clone, Copy)]
pub struct SudoPrincipal<'a> {
    pub user: &'a str,
    pub uid: Option<u32>,
    /// Group names the user belongs to (without `%`).
    pub groups: &'a [String],
    pub gids: &'a [u32],
}

/// Why a passwordless command reaches root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RootReason {
    AllCommands,
    EscalatableBinary,
    UserWritablePath,
    CommandDirectory,
    WildcardCommand,
    CallerSetsEnvironment,
    KeptLoaderVariable,
    Chroot,
    UnresolvedAlias,
    Unparsed,
}

impl RootReason {
    pub fn label(self) -> &'static str {
        match self {
            RootReason::AllCommands => "all commands",
            RootReason::EscalatableBinary => "escalatable binary",
            RootReason::UserWritablePath => "path the user can write",
            RootReason::CommandDirectory => "every command in a directory",
            RootReason::WildcardCommand => "wildcard command path",
            RootReason::CallerSetsEnvironment => "caller sets the environment",
            RootReason::KeptLoaderVariable => "env_keep keeps a loader variable",
            RootReason::Chroot => "caller-chosen chroot",
            RootReason::UnresolvedAlias => "undefined command alias",
            RootReason::Unparsed => "command not understood",
        }
    }
}

/// What one passwordless command allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SudoReach {
    Root(RootReason),
    Limited,
}

/// One passwordless command, as written (whitespace collapsed), and its grade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GradedSudoCommand {
    pub command: String,
    pub reach: SudoReach,
}

/// The passwordless commands one principal item of one policy file grants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SudoFileGrant {
    pub file: String,
    /// The user-list item that matched (`alice`, `%admin`, `ALL`, an alias).
    pub principal: String,
    pub commands: Vec<GradedSudoCommand>,
}

impl SudoFileGrant {
    pub fn reaches_root(&self) -> bool {
        self.commands
            .iter()
            .any(|c| matches!(c.reach, SudoReach::Root(_)))
    }

    pub fn limited_commands(&self) -> impl Iterator<Item = &str> {
        self.commands
            .iter()
            .filter(|c| c.reach == SudoReach::Limited)
            .map(|c| c.command.as_str())
    }

    /// One evidence line naming the file, the principal and the commands:
    /// `NOPASSWD for 'alice' in 90-tools (3 commands): root via /usr/bin/vim
    /// (escalatable binary); limited to /usr/bin/uptime, /usr/sbin/reboot`.
    pub fn evidence_line(&self) -> String {
        let root: Vec<String> = self
            .commands
            .iter()
            .filter_map(|c| match c.reach {
                SudoReach::Root(reason) => Some(format!("{} ({})", c.command, reason.label())),
                SudoReach::Limited => None,
            })
            .collect();
        let limited: Vec<String> = self.limited_commands().map(str::to_string).collect();
        let head = if self.commands.len() > 1 {
            format!(
                "NOPASSWD for '{}' in {} ({} commands)",
                self.principal,
                self.file,
                self.commands.len()
            )
        } else {
            format!("NOPASSWD for '{}' in {}", self.principal, self.file)
        };
        let mut parts: Vec<String> = Vec::new();
        if !root.is_empty() {
            parts.push(format!("root via {}", list_with_more(&root)));
        }
        if !limited.is_empty() {
            parts.push(format!("limited to {}", list_with_more(&limited)));
        }
        format!("{}: {}", head, parts.join("; "))
    }
}

fn list_with_more(items: &[String]) -> String {
    let shown: Vec<&str> = items
        .iter()
        .take(MAX_EVIDENCE_COMMANDS)
        .map(String::as_str)
        .collect();
    let mut out = shown.join(", ");
    if items.len() > MAX_EVIDENCE_COMMANDS {
        out.push_str(&format!(" +{} more", items.len() - MAX_EVIDENCE_COMMANDS));
    }
    out
}

/// Metadata of one path node, as `lstat` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeMeta {
    pub uid: u32,
    pub mode: u32,
    pub is_dir: bool,
    pub is_symlink: bool,
}

/// Whether the account `uid` can replace the file at `path`, so a rule
/// running it as root runs the account's own code.
///
/// It can when it owns the file or a directory above it, when the file is
/// writable by its group or others, or when a directory above it is (then
/// the entry below can be replaced), except that a sticky directory lets
/// only the entry's owner replace an existing entry. Group membership is not
/// resolved: a group-writable node counts, the conservative side. A missing
/// node counts through its nearest existing directory (the account could
/// create it there). Symlinks are passed over (their own mode means
/// nothing): the caller checks the resolved path as well. A relative path or
/// one with `..` cannot be pinned down and counts as replaceable.
pub fn path_replaceable_by(
    path: &str,
    uid: u32,
    lookup: &dyn Fn(&str) -> Option<NodeMeta>,
) -> bool {
    if !path.starts_with('/') {
        return true;
    }
    let components: Vec<&str> = path
        .split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .collect();
    if components.contains(&"..") {
        return true;
    }
    // The node below the one being looked at: `None` while at the leaf,
    // `Some(None)` when it does not exist, `Some(Some(owner))` otherwise.
    let mut below: Option<Option<u32>> = None;
    for depth in (0..=components.len()).rev() {
        let node = if depth == 0 {
            "/".to_string()
        } else {
            format!("/{}", components[..depth].join("/"))
        };
        let is_leaf = depth == components.len();
        let Some(meta) = lookup(&node) else {
            below = Some(None);
            continue;
        };
        if meta.is_symlink {
            below = Some(Some(meta.uid));
            continue;
        }
        if meta.uid == uid {
            return true;
        }
        let writable_by_others = meta.mode & 0o022 != 0;
        if writable_by_others {
            if is_leaf {
                if !meta.is_dir {
                    return true;
                }
            } else {
                let sticky = meta.mode & 0o1000 != 0;
                match below {
                    Some(None) => return true,
                    Some(Some(owner)) if !sticky || owner == uid => return true,
                    _ => {}
                }
            }
        }
        below = Some(Some(meta.uid));
    }
    false
}

/// Everything the policy defines outside user specs: aliases and the
/// environment `Defaults` that make every command reach root.
#[derive(Debug, Default)]
struct PolicyContext {
    user_aliases: BTreeMap<String, Vec<String>>,
    cmnd_aliases: BTreeMap<String, Vec<String>>,
    /// `Defaults setenv` anywhere (scope not graded).
    global_setenv: bool,
    /// An `env_keep` that keeps an escalatable environment variable.
    kept_loader_variable: Option<String>,
}

/// Grade every passwordless command the policy grants `principal`, grouped
/// per (file, matched principal item) in policy order. `writable` answers
/// whether the account can replace a command path (see
/// [`path_replaceable_by`]).
pub fn grade_passwordless_sudo(
    sources: &[SudoersSource],
    principal: &SudoPrincipal<'_>,
    params: &HostPrivilegeJSON,
    writable: &dyn Fn(&str) -> bool,
) -> Vec<SudoFileGrant> {
    let parsed: Vec<(&SudoersSource, Vec<String>)> = sources
        .iter()
        .map(|source| (source, logical_lines(&source.text)))
        .collect();

    // Aliases and Defaults apply across files (sudo reads one policy).
    let mut ctx = PolicyContext::default();
    for (_, lines) in &parsed {
        for line in lines {
            match classify_line(line) {
                LineKind::Defaults(rest) => apply_defaults(rest, params, &mut ctx),
                LineKind::Alias(kind, rest) => {
                    for (name, items) in parse_alias_definitions(rest) {
                        match kind {
                            AliasKind::User => {
                                ctx.user_aliases.insert(name, items);
                            }
                            AliasKind::Cmnd => {
                                ctx.cmnd_aliases.insert(name, items);
                            }
                            AliasKind::Other => {}
                        }
                    }
                }
                LineKind::Include | LineKind::UserSpec(_) => {}
            }
        }
    }

    let mut grants: Vec<SudoFileGrant> = Vec::new();
    for (source, lines) in &parsed {
        for line in lines {
            let LineKind::UserSpec(spec) = classify_line(line) else {
                continue;
            };
            let Some((users, groups)) = parse_user_spec(spec) else {
                continue;
            };
            let Some(matched) = user_list_matches(&users, principal, &ctx.user_aliases, 0) else {
                continue;
            };
            let mut commands: Vec<GradedSudoCommand> = Vec::new();
            for group in &groups {
                match group {
                    HostGroup::Commands(list) => {
                        grade_spec_list(list, params, &ctx, writable, &mut commands)
                    }
                    HostGroup::Malformed(text) => {
                        // A host group the parser cannot split: count it if
                        // it could be passwordless at all.
                        if text.contains("NOPASSWD") {
                            commands.push(GradedSudoCommand {
                                command: evidence_command(text),
                                reach: SudoReach::Root(RootReason::Unparsed),
                            });
                        }
                    }
                }
            }
            if commands.is_empty() {
                continue;
            }
            match grants
                .iter_mut()
                .find(|g| g.file == source.name && g.principal == matched)
            {
                Some(existing) => existing.commands.extend(commands),
                None => grants.push(SudoFileGrant {
                    file: source.name.clone(),
                    principal: matched,
                    commands,
                }),
            }
        }
    }
    grants
}

// ---------------------------------------------------------------------------
// Lines
// ---------------------------------------------------------------------------

/// Logical lines: comments removed (`#` starting a word, not a `#uid`),
/// backslash continuations joined, blank lines dropped.
fn logical_lines(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut current = String::new();
    for raw in text.lines() {
        let line = strip_comment(raw.trim_end_matches('\r'));
        let trailing_backslashes = line.chars().rev().take_while(|c| *c == '\\').count();
        if trailing_backslashes % 2 == 1 {
            current.push_str(&line[..line.len() - 1]);
            current.push(' ');
            continue;
        }
        current.push_str(&line);
        let logical = current.trim();
        if !logical.is_empty() {
            out.push(logical.to_string());
        }
        current.clear();
    }
    let rest = current.trim();
    if !rest.is_empty() {
        out.push(rest.to_string());
    }
    out
}

fn strip_comment(line: &str) -> String {
    let trimmed = line.trim_start();
    if trimmed.starts_with("#include") {
        // `#include` / `#includedir`: a directive, classified later.
        return trimmed.to_string();
    }
    let bytes = line.as_bytes();
    let mut escaped = false;
    let mut in_quotes = false;
    for (i, &b) in bytes.iter().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        match b {
            b'\\' => escaped = true,
            b'"' => in_quotes = !in_quotes,
            b'#' if !in_quotes => {
                let word_start = i == 0
                    || matches!(
                        bytes[i - 1],
                        b' ' | b'\t' | b',' | b'(' | b'=' | b':' | b'!' | b'%'
                    );
                let uid_like = bytes.get(i + 1).is_some_and(|c| c.is_ascii_digit());
                if word_start && !uid_like {
                    return line[..i].to_string();
                }
            }
            _ => {}
        }
    }
    line.to_string()
}

enum AliasKind {
    User,
    Cmnd,
    Other,
}

enum LineKind<'a> {
    Include,
    Defaults(&'a str),
    Alias(AliasKind, &'a str),
    UserSpec(&'a str),
}

fn classify_line(line: &str) -> LineKind<'_> {
    if line.starts_with("#include") || line.starts_with("@include") {
        return LineKind::Include;
    }
    if let Some(rest) = line.strip_prefix("Defaults") {
        if rest.is_empty()
            || rest.starts_with(|c: char| c.is_whitespace() || matches!(c, ':' | '@' | '>' | '!'))
        {
            return LineKind::Defaults(rest);
        }
    }
    for (keyword, kind) in [
        ("User_Alias", AliasKind::User),
        ("Cmnd_Alias", AliasKind::Cmnd),
        ("Cmd_Alias", AliasKind::Cmnd),
        ("Runas_Alias", AliasKind::Other),
        ("Host_Alias", AliasKind::Other),
    ] {
        if let Some(rest) = line.strip_prefix(keyword) {
            if rest.starts_with(char::is_whitespace) {
                return LineKind::Alias(kind, rest);
            }
        }
    }
    LineKind::UserSpec(line)
}

// ---------------------------------------------------------------------------
// Lexical helpers
// ---------------------------------------------------------------------------

/// Byte offsets of `sep` outside parentheses and double quotes, not escaped.
fn top_level_positions(s: &str, sep: u8) -> Vec<usize> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut in_quotes = false;
    let mut escaped = false;
    for (i, &b) in s.as_bytes().iter().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        match b {
            b'\\' => escaped = true,
            b'"' => in_quotes = !in_quotes,
            b'(' if !in_quotes => depth += 1,
            b')' if !in_quotes => depth = depth.saturating_sub(1),
            _ if b == sep && depth == 0 && !in_quotes => out.push(i),
            _ => {}
        }
    }
    out
}

fn split_at(s: &str, positions: &[usize]) -> Vec<String> {
    let mut out = Vec::with_capacity(positions.len() + 1);
    let mut start = 0usize;
    for &pos in positions {
        out.push(s[start..pos].to_string());
        start = pos + 1;
    }
    out.push(s[start..].to_string());
    out
}

fn split_top_level(s: &str, sep: u8) -> Vec<String> {
    split_at(s, &top_level_positions(s, sep))
}

/// A top-level `:` that separates definitions or host groups, as opposed to
/// the colon of a tag (`NOPASSWD:`), a digest (`sha256:`) or a non-Unix
/// group (`%:group`).
fn separator_colons(s: &str) -> Vec<usize> {
    top_level_positions(s, b':')
        .into_iter()
        .filter(|&pos| {
            if pos > 0 && s.as_bytes()[pos - 1] == b'%' {
                return false;
            }
            // The word the colon ends, also when tags are written without a
            // space between them (`NOPASSWD:SETENV:`, as sudoers files
            // usually spell them; `sudo -l` re-spaces them).
            let before = s[..pos].trim_end();
            let word = before
                .rsplit(|c: char| c.is_whitespace() || c == ',' || c == ')' || c == ':')
                .next()
                .unwrap_or("");
            !(TAGS.contains(&word) || DIGEST_ALGORITHMS.contains(&word))
        })
        .collect()
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut escaped = false;
    for c in s.chars() {
        if escaped {
            out.push(c);
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else {
            out.push(c);
        }
    }
    out
}

fn is_alias_name(s: &str) -> bool {
    let mut chars = s.chars();
    chars.next().is_some_and(|c| c.is_ascii_uppercase())
        && chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// Strip leading `!` (with optional blanks); odd count = negated.
fn strip_negation(item: &str) -> (bool, &str) {
    let mut negated = false;
    let mut rest = item.trim_start();
    while let Some(after) = rest.strip_prefix('!') {
        negated = !negated;
        rest = after.trim_start();
    }
    (negated, rest.trim_end())
}

fn evidence_command(text: &str) -> String {
    let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() > MAX_EVIDENCE_COMMAND_CHARS {
        let cut: String = collapsed.chars().take(MAX_EVIDENCE_COMMAND_CHARS).collect();
        format!("{cut}...")
    } else {
        collapsed
    }
}

// ---------------------------------------------------------------------------
// Aliases and Defaults
// ---------------------------------------------------------------------------

/// `NAME = item, item : NAME2 = item` -> [(NAME, items), ...].
fn parse_alias_definitions(rest: &str) -> Vec<(String, Vec<String>)> {
    let rest = rest.trim();
    split_at(rest, &separator_colons(rest))
        .into_iter()
        .filter_map(|definition| {
            let eq = *top_level_positions(&definition, b'=').first()?;
            let name = definition[..eq].trim().to_string();
            if !is_alias_name(&name) {
                return None;
            }
            let items = split_top_level(&definition[eq + 1..], b',')
                .into_iter()
                .map(|item| item.trim().to_string())
                .filter(|item| !item.is_empty())
                .collect();
            Some((name, items))
        })
        .collect()
}

/// `Defaults[scope] param, param`: records `setenv` and an `env_keep` of an
/// escalatable variable. The scope is not graded (conservative: a scoped
/// setting counts for every rule).
fn apply_defaults(rest: &str, params: &HostPrivilegeJSON, ctx: &mut PolicyContext) {
    let rest = if rest.starts_with([':', '@', '>', '!']) {
        match rest.find(char::is_whitespace) {
            Some(i) => &rest[i..],
            None => return,
        }
    } else {
        rest
    };
    for param in split_top_level(rest.trim(), b',') {
        let param = param.trim();
        if param == "setenv" {
            ctx.global_setenv = true;
            continue;
        }
        let Some(after) = param.strip_prefix("env_keep") else {
            continue;
        };
        let after = after.trim_start();
        let value = if let Some(v) = after.strip_prefix("+=") {
            v
        } else if let Some(v) = after.strip_prefix('=') {
            v
        } else {
            // `-=` removes, a bare `env_keep` is not a list.
            continue;
        };
        let value = value.trim().trim_matches('"');
        for kept in value.split_whitespace() {
            let kept = kept.to_ascii_uppercase();
            let hit = params.escalatable_environment_variables.iter().find(|var| {
                match kept.strip_suffix('*') {
                    Some(prefix) => var.starts_with(prefix),
                    None => **var == kept,
                }
            });
            if let Some(var) = hit {
                ctx.kept_loader_variable.get_or_insert_with(|| var.clone());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// User specs
// ---------------------------------------------------------------------------

enum HostGroup {
    Commands(String),
    Malformed(String),
}

/// `User_List Host_List = Cmnd_Spec_List [: Host_List = Cmnd_Spec_List]`
/// -> (user list items, host groups).
fn parse_user_spec(spec: &str) -> Option<(Vec<String>, Vec<HostGroup>)> {
    let eq = *top_level_positions(spec, b'=').first()?;
    let left = normalize_list_spacing(&spec[..eq]);
    let user_list = left.split_whitespace().next()?;
    let users: Vec<String> = split_top_level(user_list, b',')
        .into_iter()
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty())
        .collect();
    if users.is_empty() {
        return None;
    }
    let rhs = &spec[eq + 1..];
    let mut groups: Vec<HostGroup> = Vec::new();
    for (index, segment) in split_at(rhs, &separator_colons(rhs))
        .into_iter()
        .enumerate()
    {
        if index == 0 {
            groups.push(HostGroup::Commands(segment));
            continue;
        }
        match top_level_positions(&segment, b'=').first() {
            Some(&pos) => groups.push(HostGroup::Commands(segment[pos + 1..].to_string())),
            None => groups.push(HostGroup::Malformed(segment)),
        }
    }
    Some((users, groups))
}

/// `a , b` -> `a,b` so a list is one whitespace-separated token.
fn normalize_list_spacing(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut pending_space = false;
    for c in s.trim().chars() {
        if c.is_whitespace() {
            pending_space = true;
            continue;
        }
        if c == ',' {
            pending_space = false;
            out.push(',');
            continue;
        }
        if pending_space && !out.ends_with(',') {
            out.push(' ');
        }
        pending_space = false;
        out.push(c);
    }
    out
}

/// The last matching item decides (`!` negates), sudo's list semantics.
/// Returns the matching item as written.
fn user_list_matches(
    items: &[String],
    principal: &SudoPrincipal<'_>,
    aliases: &BTreeMap<String, Vec<String>>,
    depth: usize,
) -> Option<String> {
    let mut matched: Option<String> = None;
    for item in items {
        let (negated, body) = strip_negation(item);
        if user_item_matches(body, principal, aliases, depth) {
            matched = if negated {
                None
            } else {
                Some(body.to_string())
            };
        }
    }
    matched
}

fn user_item_matches(
    body: &str,
    principal: &SudoPrincipal<'_>,
    aliases: &BTreeMap<String, Vec<String>>,
    depth: usize,
) -> bool {
    if body == "ALL" {
        return true;
    }
    if body.starts_with("%:") || body.starts_with('+') {
        // Non-Unix groups and netgroups are not resolved here.
        return false;
    }
    if let Some(gid) = body.strip_prefix("%#") {
        return gid
            .parse::<u32>()
            .is_ok_and(|gid| principal.gids.contains(&gid));
    }
    if let Some(group) = body.strip_prefix('%') {
        let group = unescape(group);
        return principal.groups.iter().any(|g| *g == group);
    }
    if let Some(uid) = body.strip_prefix('#') {
        return uid
            .parse::<u32>()
            .is_ok_and(|uid| principal.uid == Some(uid));
    }
    if let Some(items) = aliases.get(body) {
        return depth < MAX_ALIAS_DEPTH
            && user_list_matches(items, principal, aliases, depth + 1).is_some();
    }
    unescape(body) == principal.user
}

// ---------------------------------------------------------------------------
// Command specs
// ---------------------------------------------------------------------------

/// Tag and option state, inherited left to right along a Cmnd_Spec_List.
#[derive(Debug, Clone, Copy, Default)]
struct SpecState {
    nopasswd: bool,
    setenv: bool,
    chroot: bool,
}

fn grade_spec_list(
    list: &str,
    params: &HostPrivilegeJSON,
    ctx: &PolicyContext,
    writable: &dyn Fn(&str) -> bool,
    out: &mut Vec<GradedSudoCommand>,
) {
    let mut state = SpecState::default();
    for spec in split_top_level(list, b',') {
        let command = consume_spec_prefix(spec.trim(), &mut state);
        if !state.nopasswd || command.is_empty() {
            continue;
        }
        grade_command(command, state, params, ctx, writable, 0, out);
    }
}

/// Consume `(runas)`, option specs, tags and digests; returns the command.
fn consume_spec_prefix<'a>(spec: &'a str, state: &mut SpecState) -> &'a str {
    let mut rest = spec.trim_start();
    if rest.starts_with('(') {
        let mut depth = 0usize;
        let mut end = rest.len();
        for (i, c) in rest.char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        end = i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        rest = rest[end..].trim_start();
    }
    loop {
        if let Some((name, after)) = consume_option(rest) {
            if name == "CHROOT" {
                state.chroot = true;
            }
            rest = after.trim_start();
            continue;
        }
        if let Some((tag, after)) = consume_tag(rest) {
            match tag {
                "NOPASSWD" => state.nopasswd = true,
                "PASSWD" => state.nopasswd = false,
                "SETENV" => state.setenv = true,
                "NOSETENV" => state.setenv = false,
                _ => {}
            }
            rest = after.trim_start();
            continue;
        }
        break;
    }
    while let Some(after) = consume_digest(rest) {
        rest = after.trim_start();
    }
    rest.trim()
}

fn leading_word(s: &str) -> &str {
    let end = s
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(s.len());
    &s[..end]
}

fn consume_tag(s: &str) -> Option<(&'static str, &str)> {
    let word = leading_word(s);
    let tag = TAGS.iter().copied().find(|t| *t == word)?;
    let after = s[word.len()..].trim_start().strip_prefix(':')?;
    Some((tag, after))
}

fn consume_option(s: &str) -> Option<(&'static str, &str)> {
    let word = leading_word(s);
    let name = OPTION_NAMES.iter().copied().find(|n| *n == word)?;
    let after = s[word.len()..].trim_start().strip_prefix('=')?.trim_start();
    let rest = if let Some(quoted) = after.strip_prefix('"') {
        match quoted.find('"') {
            Some(end) => &quoted[end + 1..],
            None => "",
        }
    } else {
        match after.find(char::is_whitespace) {
            Some(end) => &after[end..],
            None => "",
        }
    };
    Some((name, rest))
}

fn consume_digest(s: &str) -> Option<&str> {
    let word = leading_word(s);
    if !DIGEST_ALGORITHMS.contains(&word) {
        return None;
    }
    let after = s[word.len()..].trim_start().strip_prefix(':')?.trim_start();
    let end = after.find(char::is_whitespace).unwrap_or(after.len());
    Some(&after[end..])
}

fn grade_command(
    command: &str,
    state: SpecState,
    params: &HostPrivilegeJSON,
    ctx: &PolicyContext,
    writable: &dyn Fn(&str) -> bool,
    depth: usize,
    out: &mut Vec<GradedSudoCommand>,
) {
    let (negated, body) = strip_negation(command);
    if negated || body.is_empty() {
        // A negation never lowers what the positive entries grant.
        return;
    }
    let text = evidence_command(body);
    let root = |reason| GradedSudoCommand {
        command: text.clone(),
        reach: SudoReach::Root(reason),
    };
    if body == "ALL" {
        out.push(root(RootReason::AllCommands));
        return;
    }
    let word = body.split_whitespace().next().unwrap_or(body);
    if is_alias_name(word) && body == word {
        match ctx.cmnd_aliases.get(word) {
            Some(items) if depth < MAX_ALIAS_DEPTH => {
                for item in items {
                    grade_command(item, state, params, ctx, writable, depth + 1, out);
                }
            }
            _ => out.push(root(RootReason::UnresolvedAlias)),
        }
        return;
    }
    let reach = grade_command_path(&unescape(word), state, params, ctx, writable);
    out.push(GradedSudoCommand {
        command: text,
        reach,
    });
}

fn grade_command_path(
    path: &str,
    state: SpecState,
    params: &HostPrivilegeJSON,
    ctx: &PolicyContext,
    writable: &dyn Fn(&str) -> bool,
) -> SudoReach {
    let builtin = !path.contains('/');
    if builtin {
        // `sudoedit` and `list` are the only commands sudoers takes without
        // a path; anything else (a regex `^...$`, a bare name) is not
        // understood.
        return match path {
            "sudoedit" if is_escalatable_name("sudoedit", params) => {
                SudoReach::Root(RootReason::EscalatableBinary)
            }
            "sudoedit" | "list" => environment_reach(state, ctx),
            _ => SudoReach::Root(RootReason::Unparsed),
        };
    }
    if !path.starts_with('/') {
        return SudoReach::Root(RootReason::Unparsed);
    }
    if path.ends_with('/') {
        return SudoReach::Root(RootReason::CommandDirectory);
    }
    if path.contains(['*', '?', '[']) {
        return SudoReach::Root(RootReason::WildcardCommand);
    }
    let basename = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    if is_escalatable_name(&basename, params) {
        return SudoReach::Root(RootReason::EscalatableBinary);
    }
    if writable(path) {
        return SudoReach::Root(RootReason::UserWritablePath);
    }
    environment_reach(state, ctx)
}

fn environment_reach(state: SpecState, ctx: &PolicyContext) -> SudoReach {
    if state.setenv || ctx.global_setenv {
        return SudoReach::Root(RootReason::CallerSetsEnvironment);
    }
    if ctx.kept_loader_variable.is_some() {
        return SudoReach::Root(RootReason::KeptLoaderVariable);
    }
    if state.chroot {
        return SudoReach::Root(RootReason::Chroot);
    }
    SudoReach::Limited
}

/// `name` is an escalatable binary: listed, or a listed family under a
/// version suffix (`python3.12`, `gcc-13`).
fn is_escalatable_name(name: &str, params: &HostPrivilegeJSON) -> bool {
    params.escalatable_binaries.iter().any(|b| b == name)
        || params
            .escalatable_binary_families
            .iter()
            .any(|family| family_matches(name, family))
}

fn family_matches(name: &str, family: &str) -> bool {
    let Some(rest) = name.strip_prefix(family) else {
        return false;
    };
    if rest.is_empty() {
        return true;
    }
    let version = rest.strip_prefix('-').unwrap_or(rest);
    version.starts_with(|c: char| c.is_ascii_digit())
        && version.chars().all(|c| c.is_ascii_digit() || c == '.')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> HostPrivilegeJSON {
        crate::agent_visibility_params::host_privilege()
    }

    fn alice() -> SudoPrincipal<'static> {
        static GROUPS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
        let groups = GROUPS.get_or_init(|| vec!["admin".to_string(), "staff".to_string()]);
        SudoPrincipal {
            user: "alice",
            uid: Some(501),
            groups,
            gids: &[20, 80],
        }
    }

    fn never_writable(_: &str) -> bool {
        false
    }

    fn grade(text: &str) -> Vec<SudoFileGrant> {
        grade_with(text, &never_writable)
    }

    fn grade_with(text: &str, writable: &dyn Fn(&str) -> bool) -> Vec<SudoFileGrant> {
        let sources = vec![SudoersSource {
            name: "90-test".to_string(),
            text: text.to_string(),
        }];
        grade_passwordless_sudo(&sources, &alice(), &params(), writable)
    }

    fn reaches(grants: &[SudoFileGrant]) -> Vec<SudoReach> {
        grants
            .iter()
            .flat_map(|g| g.commands.iter().map(|c| c.reach))
            .collect()
    }

    #[test]
    fn all_is_root() {
        let grants = grade("alice ALL=(ALL) NOPASSWD: ALL");
        assert_eq!(
            reaches(&grants),
            vec![SudoReach::Root(RootReason::AllCommands)]
        );
        assert!(grants[0].reaches_root());
        assert_eq!(grants[0].principal, "alice");
    }

    #[test]
    fn escalatable_binaries_are_root_whatever_their_arguments() {
        for rule in [
            "alice ALL=(ALL) NOPASSWD: /usr/sbin/tcpdump",
            "alice ALL=(root) NOPASSWD: /usr/sbin/tcpdump -i en0",
            "alice ALL = NOPASSWD: /usr/bin/find /var/log -name *.log",
            "alice ALL=(ALL) NOPASSWD: /usr/bin/vim /etc/hosts",
            "alice ALL=(ALL) NOPASSWD: /usr/bin/less /var/log/syslog",
            "alice ALL=(ALL) NOPASSWD: /usr/bin/python3.12 /opt/tool.py",
            "alice ALL=(ALL) NOPASSWD: /usr/bin/env *",
            "alice ALL=(ALL) NOPASSWD: /usr/bin/bash *",
            "alice ALL=(ALL) NOPASSWD: /bin/systemctl restart nginx",
            "alice ALL=(ALL) NOPASSWD: /usr/bin/docker ps",
            "alice ALL=(ALL) NOPASSWD: /usr/bin/gcc-13",
            "alice ALL=(ALL) NOPASSWD: /usr/bin/PERL5.36",
        ] {
            assert_eq!(
                reaches(&grade(rule)),
                vec![SudoReach::Root(RootReason::EscalatableBinary)],
                "{rule}"
            );
        }
    }

    #[test]
    fn a_specific_harmless_command_is_limited() {
        let grants =
            grade("alice ALL=(root) NOPASSWD: /usr/bin/uptime, /usr/local/sbin/backup-now");
        assert_eq!(
            reaches(&grants),
            vec![SudoReach::Limited, SudoReach::Limited]
        );
        assert!(!grants[0].reaches_root());
        let limited: Vec<&str> = grants[0].limited_commands().collect();
        assert_eq!(
            limited,
            vec!["/usr/bin/uptime", "/usr/local/sbin/backup-now"]
        );
        assert_eq!(
            grants[0].evidence_line(),
            "NOPASSWD for 'alice' in 90-test (2 commands): limited to /usr/bin/uptime, /usr/local/sbin/backup-now"
        );
    }

    #[test]
    fn a_path_the_user_can_write_is_root() {
        let writable = |path: &str| path.starts_with("/Users/alice/");
        let grants = grade_with(
            "alice ALL=(root) NOPASSWD: /Users/alice/bin/tool, /usr/bin/uptime",
            &writable,
        );
        assert_eq!(
            reaches(&grants),
            vec![
                SudoReach::Root(RootReason::UserWritablePath),
                SudoReach::Limited
            ]
        );
        assert_eq!(
            grants[0].evidence_line(),
            "NOPASSWD for 'alice' in 90-test (2 commands): root via /Users/alice/bin/tool (path the user can write); limited to /usr/bin/uptime"
        );
    }

    #[test]
    fn password_rules_and_tag_inheritance() {
        // PASSWD after NOPASSWD turns it off for the rest of the list.
        let grants = grade("alice ALL = NOPASSWD: /usr/bin/uptime, PASSWD: /usr/bin/vim, /bin/sh");
        assert_eq!(reaches(&grants), vec![SudoReach::Limited]);
        // No NOPASSWD tag at all: nothing is passwordless.
        assert!(grade("alice ALL=(ALL) ALL").is_empty());
        // NOPASSWD inherited by the following commands.
        let grants = grade("alice ALL = (root) NOPASSWD: /usr/bin/uptime, /usr/bin/vim");
        assert_eq!(
            reaches(&grants),
            vec![
                SudoReach::Limited,
                SudoReach::Root(RootReason::EscalatableBinary)
            ]
        );
    }

    #[test]
    fn negations_never_lower_the_grade() {
        let grants = grade("alice ALL=(ALL) NOPASSWD: ALL, !/usr/bin/passwd, !/bin/su");
        assert_eq!(
            reaches(&grants),
            vec![SudoReach::Root(RootReason::AllCommands)]
        );
        let grants = grade("alice ALL=(ALL) NOPASSWD: /usr/bin/uptime, !/usr/bin/uptime -x");
        assert_eq!(reaches(&grants), vec![SudoReach::Limited]);
    }

    #[test]
    fn command_aliases_expand_and_undefined_ones_are_root() {
        let text = "\
Cmnd_Alias STATUS = /usr/bin/uptime, /usr/bin/who
Cmnd_Alias SHELLS = /bin/sh, /bin/bash : EDIT = /usr/bin/vi
alice ALL = NOPASSWD: STATUS
alice ALL = NOPASSWD: EDIT
alice ALL = NOPASSWD: MISSING
";
        let grants = grade(text);
        assert_eq!(
            reaches(&grants),
            vec![
                SudoReach::Limited,
                SudoReach::Limited,
                SudoReach::Root(RootReason::EscalatableBinary),
                SudoReach::Root(RootReason::UnresolvedAlias),
            ]
        );
        // One grant per (file, principal): the three lines fold together.
        assert_eq!(grants.len(), 1);
    }

    #[test]
    fn directories_wildcards_relative_and_regex_commands_are_root() {
        assert_eq!(
            reaches(&grade("alice ALL = NOPASSWD: /usr/local/bin/")),
            vec![SudoReach::Root(RootReason::CommandDirectory)]
        );
        assert_eq!(
            reaches(&grade("alice ALL = NOPASSWD: /opt/tools/*")),
            vec![SudoReach::Root(RootReason::WildcardCommand)]
        );
        assert_eq!(
            reaches(&grade("alice ALL = NOPASSWD: uptime")),
            vec![SudoReach::Root(RootReason::Unparsed)]
        );
        assert_eq!(
            reaches(&grade("alice ALL = NOPASSWD: ^/usr/bin/up.*$")),
            vec![SudoReach::Root(RootReason::Unparsed)]
        );
    }

    #[test]
    fn setenv_chroot_and_kept_loader_variables_are_root() {
        assert_eq!(
            reaches(&grade(
                "alice ALL = (root) SETENV: NOPASSWD: /usr/bin/uptime"
            )),
            vec![SudoReach::Root(RootReason::CallerSetsEnvironment)]
        );
        assert_eq!(
            reaches(&grade(
                "alice ALL = CHROOT=/home/alice/jail NOPASSWD: /usr/bin/uptime"
            )),
            vec![SudoReach::Root(RootReason::Chroot)]
        );
        let text =
            "Defaults env_keep += \"LANG LD_PRELOAD\"\nalice ALL = NOPASSWD: /usr/bin/uptime";
        assert_eq!(
            reaches(&grade(text)),
            vec![SudoReach::Root(RootReason::KeptLoaderVariable)]
        );
        let text = "Defaults:alice setenv\nalice ALL = NOPASSWD: /usr/bin/uptime";
        assert_eq!(
            reaches(&grade(text)),
            vec![SudoReach::Root(RootReason::CallerSetsEnvironment)]
        );
        // The macOS default env_keep list keeps nothing escalatable.
        let text = "\
Defaults	env_keep += \"BLOCKSIZE\"
Defaults	env_keep += \"EDITOR VISUAL\"
Defaults	env_keep += \"HOME MAIL\"
alice ALL = NOPASSWD: /usr/bin/uptime";
        assert_eq!(reaches(&grade(text)), vec![SudoReach::Limited]);
        // A removal does not keep anything.
        let text = "Defaults env_keep -= \"LD_PRELOAD\"\nalice ALL = NOPASSWD: /usr/bin/uptime";
        assert_eq!(reaches(&grade(text)), vec![SudoReach::Limited]);
    }

    #[test]
    fn principals_groups_aliases_ids_and_negation() {
        let alice = alice();
        let principals = [
            ("alice ALL=(ALL) NOPASSWD: /usr/bin/uptime", Some("alice")),
            ("%admin ALL=(ALL) NOPASSWD: /usr/bin/uptime", Some("%admin")),
            ("ALL ALL=(ALL) NOPASSWD: /usr/bin/uptime", Some("ALL")),
            ("#501 ALL=(ALL) NOPASSWD: /usr/bin/uptime", Some("#501")),
            ("%#80 ALL=(ALL) NOPASSWD: /usr/bin/uptime", Some("%#80")),
            (
                "bob, alice ALL=(ALL) NOPASSWD: /usr/bin/uptime",
                Some("alice"),
            ),
            ("bob ALL=(ALL) NOPASSWD: ALL", None),
            ("%wheel ALL=(ALL) NOPASSWD: ALL", None),
            ("ALL, !alice ALL=(ALL) NOPASSWD: ALL", None),
            ("+admins ALL=(ALL) NOPASSWD: ALL", None),
            ("%:domain_admins ALL=(ALL) NOPASSWD: ALL", None),
        ];
        for (rule, expected) in principals {
            let sources = vec![SudoersSource {
                name: "f".to_string(),
                text: rule.to_string(),
            }];
            let grants = grade_passwordless_sudo(&sources, &alice, &params(), &never_writable);
            assert_eq!(
                grants.first().map(|g| g.principal.as_str()),
                expected,
                "{rule}"
            );
        }
        let text = "User_Alias OPS = bob, %admin\nOPS ALL = NOPASSWD: ALL";
        let grants = grade(text);
        assert_eq!(grants[0].principal, "OPS");
        assert!(grants[0].reaches_root());
    }

    #[test]
    fn comments_continuations_includes_and_defaults_lines() {
        let text = "\
# alice ALL=(ALL) NOPASSWD: ALL
#includedir /private/etc/sudoers.d
@include /etc/sudoers.local
Defaults!/usr/bin/foo !authenticate
Defaults env_reset
alice ALL = (root) NOPASSWD: /usr/bin/uptime, \\
    /usr/bin/who   # the continuation keeps the list
bob ALL=(ALL) NOPASSWD: ALL
";
        let grants = grade(text);
        assert_eq!(
            reaches(&grants),
            vec![SudoReach::Limited, SudoReach::Limited]
        );
        let limited: Vec<&str> = grants[0].limited_commands().collect();
        assert_eq!(limited, vec!["/usr/bin/uptime", "/usr/bin/who"]);
    }

    #[test]
    fn linux_mint_and_cloud_init_drop_ins() {
        // test-mint's drop-ins (2026-09-30): cloud-init's rule for the image
        // user, and Mint's tools granted to every user, tags glued to the
        // command.
        let sources = vec![
            SudoersSource {
                name: "90-cloud-init-users".to_string(),
                text: "packer ALL=(ALL) NOPASSWD:ALL\nalice ALL=(ALL) NOPASSWD:ALL\n".to_string(),
            },
            SudoersSource {
                name: "mintdrivers".to_string(),
                text: "ALL ALL = NOPASSWD:/usr/bin/mintdrivers-remove-live-media\nALL ALL = NOPASSWD:/usr/bin/mintdrivers-load-broadcom-modules\n".to_string(),
            },
            SudoersSource {
                name: "mintupdate".to_string(),
                text: "ALL ALL = NOPASSWD:/usr/bin/mint-refresh-cache\nALL ALL = NOPASSWD:/usr/lib/linuxmint/mintUpdate/dpkg_lock_check.sh\n".to_string(),
            },
        ];
        let grants = grade_passwordless_sudo(&sources, &alice(), &params(), &never_writable);
        assert_eq!(grants.len(), 3);
        assert_eq!(
            grants[0].evidence_line(),
            "NOPASSWD for 'alice' in 90-cloud-init-users: root via ALL (all commands)"
        );
        let limited: Vec<&str> = grants[1..]
            .iter()
            .flat_map(|g| g.limited_commands())
            .collect();
        assert_eq!(
            limited,
            vec![
                "/usr/bin/mintdrivers-remove-live-media",
                "/usr/bin/mintdrivers-load-broadcom-modules",
                "/usr/bin/mint-refresh-cache",
                "/usr/lib/linuxmint/mintUpdate/dpkg_lock_check.sh",
            ]
        );
        // Without the cloud-init rule, the host is limited, not root.
        let grants = grade_passwordless_sudo(&sources[1..], &alice(), &params(), &never_writable);
        assert!(!grants.iter().any(SudoFileGrant::reaches_root));
    }

    #[test]
    fn tags_written_without_spaces_are_tags() {
        // Sudoers files usually chain tags with no space (`sudo -l` re-spaces
        // them): each tag applies, and no colon is taken for a host-group
        // separator (which dropped the rule, or read `SETENV` as a command).
        for rule in [
            "alice ALL=(root) NOPASSWD:SETENV: /usr/bin/uptime",
            "alice ALL=(root) SETENV:NOPASSWD: /usr/bin/uptime",
            "alice ALL=(root) NOEXEC:SETENV:NOPASSWD: /usr/bin/uptime",
            "alice ALL = SETENV:NOPASSWD:/usr/bin/uptime",
        ] {
            let grants = grade(rule);
            assert_eq!(
                reaches(&grants),
                vec![SudoReach::Root(RootReason::CallerSetsEnvironment)],
                "{rule}"
            );
            assert_eq!(grants[0].commands[0].command, "/usr/bin/uptime", "{rule}");
        }
        // Without SETENV the same command stays limited.
        let grants = grade("alice ALL=(root) NOEXEC:NOPASSWD: /usr/bin/uptime");
        assert_eq!(reaches(&grants), vec![SudoReach::Limited]);
        // PASSWD chained after NOPASSWD turns it off.
        assert!(grade("alice ALL=(root) NOPASSWD:PASSWD: /usr/bin/uptime").is_empty());
        // A real host-group separator still splits, after chained tags.
        let text = "alice ALL = NOPASSWD:SETENV: /usr/bin/uptime : buildhost = NOPASSWD:NOEXEC: /usr/bin/who";
        assert_eq!(
            reaches(&grade(text)),
            vec![
                SudoReach::Root(RootReason::CallerSetsEnvironment),
                SudoReach::Limited
            ]
        );
    }

    #[test]
    fn host_groups_and_digests() {
        // A second host group granting ALL counts (the host is not graded).
        let text = "alice ALL = NOPASSWD: /usr/bin/uptime : buildhost = NOPASSWD: ALL";
        assert_eq!(
            reaches(&grade(text)),
            vec![SudoReach::Limited, SudoReach::Root(RootReason::AllCommands)]
        );
        // A digest before the command is skipped; Runas lists with colons too.
        let text = "alice ALL = (root : wheel) NOPASSWD: sha256:2t7aRm7qvKXMnDkNLu3GqEo4hOL8VB3bJ5xT0DGz2Ho= /usr/bin/uptime";
        let grants = grade(text);
        assert_eq!(reaches(&grants), vec![SudoReach::Limited]);
        assert_eq!(
            grants[0].commands[0].command.split_whitespace().last(),
            Some("/usr/bin/uptime")
        );
    }

    #[test]
    fn this_macs_hand_made_rules_all_reach_root() {
        // The three drop-ins on the dev Mac (2026-09-30), as written on disk
        // (`NOPASSWD:SETENV:` without a space; `sudo -l` shows them re-spaced,
        // which hid the chained-tag bug); the user's own trees and ~/.cargo
        // are writable.
        let writable = |path: &str| path.starts_with("/Users/alice/");
        let sources = vec![
            SudoersSource {
                name: "edamame_posture".to_string(),
                text: "alice ALL=(root) NOPASSWD: /Users/alice/Programming/edamame_posture/target/release/edamame_posture\n".to_string(),
            },
            SudoersSource {
                name: "edamame_posture_cursor".to_string(),
                text: "\
alice ALL=(root) NOPASSWD:SETENV: /Users/alice/Programming/edamame_posture/target/release/edamame_posture *
alice ALL=(root) NOPASSWD:SETENV: /Users/alice/.cargo/bin/cargo *
alice ALL=(root) NOPASSWD:SETENV: /usr/bin/env *
alice ALL=(root) NOPASSWD:SETENV: /usr/bin/bash *
".to_string(),
            },
            SudoersSource {
                name: "tcpdump-alice".to_string(),
                text: "alice ALL=(ALL) NOPASSWD: /usr/sbin/tcpdump\n".to_string(),
            },
        ];
        let grants = grade_passwordless_sudo(&sources, &alice(), &params(), &writable);
        assert_eq!(grants.len(), 3);
        assert!(grants.iter().all(SudoFileGrant::reaches_root));
        assert_eq!(
            grants[2].evidence_line(),
            "NOPASSWD for 'alice' in tcpdump-alice: root via /usr/sbin/tcpdump (escalatable binary)"
        );
        assert!(grants[1]
            .evidence_line()
            .starts_with("NOPASSWD for 'alice' in edamame_posture_cursor (4 commands): root via "));
        assert!(grants[1].evidence_line().ends_with(" +1 more"));
        // The evidence names the commands, never a tag.
        let commands: Vec<&str> = grants[1]
            .commands
            .iter()
            .map(|c| c.command.as_str())
            .collect();
        assert_eq!(
            commands,
            vec![
                "/Users/alice/Programming/edamame_posture/target/release/edamame_posture *",
                "/Users/alice/.cargo/bin/cargo *",
                "/usr/bin/env *",
                "/usr/bin/bash *",
            ]
        );
        assert!(!grants[1].evidence_line().contains("SETENV"));
    }

    #[test]
    fn family_suffixes() {
        assert!(family_matches("python3", "python"));
        assert!(family_matches("python3.12", "python"));
        assert!(family_matches("python-3.12", "python"));
        assert!(family_matches("python", "python"));
        assert!(!family_matches("python-config", "python"));
        assert!(!family_matches("python3.12-config", "python"));
        assert!(!family_matches("pythonista", "python"));
        assert!(!family_matches("python-", "python"));
    }

    fn fs<'a>(
        entries: &'a [(&'a str, u32, u32, bool, bool)],
    ) -> impl Fn(&str) -> Option<NodeMeta> + 'a {
        move |path: &str| {
            entries
                .iter()
                .find(|(p, ..)| *p == path)
                .map(|(_, uid, mode, is_dir, is_symlink)| NodeMeta {
                    uid: *uid,
                    mode: *mode,
                    is_dir: *is_dir,
                    is_symlink: *is_symlink,
                })
        }
    }

    #[test]
    fn replaceable_paths() {
        let entries = [
            ("/", 0, 0o755, true, false),
            ("/usr", 0, 0o755, true, false),
            ("/usr/sbin", 0, 0o755, true, false),
            ("/usr/sbin/tcpdump", 0, 0o755, false, false),
            ("/usr/local", 0, 0o2775, true, false),
            ("/usr/local/bin", 0, 0o755, true, false),
            ("/usr/local/bin/tool", 0, 0o755, false, false),
            ("/Users", 0, 0o755, true, false),
            ("/Users/alice", 501, 0o750, true, false),
            ("/Users/alice/bin", 501, 0o755, true, false),
            ("/Users/alice/bin/tool", 501, 0o755, false, false),
            ("/opt", 0, 0o755, true, false),
            ("/opt/app", 0, 0o755, true, false),
            ("/opt/app/run", 0, 0o775, false, false),
            ("/tmp", 0, 0o1777, true, false),
            ("/tmp/rootfile", 0, 0o755, false, false),
            ("/tmp/alicefile", 501, 0o755, false, false),
            ("/var", 0, 0o755, true, true),
        ];
        let lookup = fs(&entries);
        // Root-owned binary in root-owned directories.
        assert!(!path_replaceable_by("/usr/sbin/tcpdump", 501, &lookup));
        // Under the user's home: owned.
        assert!(path_replaceable_by("/Users/alice/bin/tool", 501, &lookup));
        // A group-writable directory above the command counts.
        assert!(path_replaceable_by("/usr/local/bin/tool", 501, &lookup));
        // A group-writable command file counts.
        assert!(path_replaceable_by("/opt/app/run", 501, &lookup));
        // A missing command below a writable (sticky) directory: creatable.
        assert!(path_replaceable_by("/tmp/missing", 501, &lookup));
        // Sticky directory: another owner's entry cannot be replaced ...
        assert!(!path_replaceable_by("/tmp/rootfile", 501, &lookup));
        // ... the user's own can.
        assert!(path_replaceable_by("/tmp/alicefile", 501, &lookup));
        // A missing command below root-only directories cannot be created.
        assert!(!path_replaceable_by("/usr/sbin/missing", 501, &lookup));
        // Relative and `..` paths cannot be pinned down.
        assert!(path_replaceable_by("bin/tool", 501, &lookup));
        assert!(path_replaceable_by(
            "/usr/sbin/../local/bin/tool",
            501,
            &lookup
        ));
        // A symlink node's own mode is ignored.
        assert!(!path_replaceable_by("/var", 501, &lookup));
    }
}
