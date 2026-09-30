//! Which workspace an agent session belongs to, and what to call it.
//!
//! The Agents view groups sessions by workspace. A session's own workspace is
//! the directory its transcript names (`agent_visibility::workspace_slug_for_session`).
//! That is right for a session a person starts, and wrong for one an agent
//! starts: an orchestrating agent that runs `claude -p` or `codex exec` in a
//! throwaway directory produced one workspace per child, each named after the
//! leaf of a directory that no longer exists (`agent1`, `agent3`, `agent3`).
//! [`attribute_session_workspaces`] files every session under one workspace,
//! by the most robust link the transcripts establish:
//!
//! 1. **Launched**: a headless session (see
//!    [`SessionLaunchContext::headless`]) whose working directory is, or is
//!    under, a directory that another session's agent-launching tool call
//!    names, and which started inside that call's time window, belongs to the
//!    launching session's workspace (transitively). The link is read from the
//!    launching session's transcript; nothing in the child's own content is
//!    consulted, so a session cannot attach itself to a workspace by naming a
//!    path, and an interactive session a person started is never re-filed.
//! 2. **Temporary**: otherwise, a session whose own workspace directory lies in
//!    a temporary root joins one temporary-sessions workspace per agent
//!    ([`temporary_workspace_slug`]).
//! 3. **Own**: every other session keeps its own workspace.
//!
//! Kernel process lineage (the child agent process descending from another
//! agent process) would be a stronger link than the transcript, but the
//! lineage table records no working directory for either process, so it
//! cannot say which transcript a process wrote; the transcript link is the
//! strongest one available.
//!
//! Attribution moves evidence, it never drops it: a session's findings,
//! exposure hits and activity count toward the workspace it is filed under.
//!
//! [`unique_workspace_labels`] names the workspaces: the directory leaf,
//! extended with as many parent components as needed to tell two workspaces
//! apart (`edsim-agents/edsim-agent3`, `edsim-agents2/edsim-agent3`), the
//! product name for an agent home, the params' label for the temporary group.
//! Labels depend only on the set of workspaces, never on input order.
//!
//! The temporary roots, path aliases, home parents, time windows and label
//! wording are data from the agent-visibility params
//! ([`WorkspaceAttributionJSON`]); this module keeps the predicates.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::agent_transcripts::launch::{AgentLaunchCall, SessionLaunchContext};
use crate::agent_visibility::{
    agent_type_for_fleet_workspace_ref, canonicalize_project_slug, workspace_slug_for_session,
};
use crate::agent_visibility_params::WorkspaceAttributionJSON;
use crate::supported_agents::fleet_workspace_display_name;

/// Slug prefix of the per-agent temporary-sessions workspace. A colon never
/// appears in a canonical project slug (`-[A-Za-z0-9-]+`).
pub const TEMPORARY_WORKSPACE_PREFIX: &str = "temporary:";

/// Slug components a single path component can split into (a directory name
/// with `_`, `.` or spaces becomes several dash-separated tokens).
const MAX_TOKENS_PER_COMPONENT: usize = 6;

/// Workspace slug of the temporary-sessions group of `agent_type`.
pub fn temporary_workspace_slug(agent_type: &str) -> String {
    format!("{TEMPORARY_WORKSPACE_PREFIX}{agent_type}")
}

/// The agent of a temporary-sessions workspace slug, `None` for any other.
pub fn temporary_workspace_agent(slug: &str) -> Option<&str> {
    slug.strip_prefix(TEMPORARY_WORKSPACE_PREFIX)
        .filter(|agent| !agent.is_empty())
}

/// How a session came to be filed under its workspace.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceLink {
    /// The session's own workspace.
    #[default]
    Own,
    /// The workspace of the session that launched it.
    Launched,
    /// The temporary-sessions workspace of its agent.
    Temporary,
}

/// One session, as the attribution sees it.
#[derive(Debug, Clone, Copy)]
pub struct SessionWorkspaceInput<'a> {
    pub agent_type: &'a str,
    pub session_key: &'a str,
    pub source_path: &'a str,
    pub workspace_hint: &'a str,
    pub launch: &'a SessionLaunchContext,
    pub launches: &'a [AgentLaunchCall],
    /// Transcript file creation time (fallback start for formats without
    /// in-transcript timestamps).
    pub started_at: Option<DateTime<Utc>>,
    /// Transcript file modification time.
    pub modified_at: Option<DateTime<Utc>>,
}

/// Where a session is filed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionWorkspace {
    /// Workspace slug; empty when the session has none (chat surfaces).
    pub slug: String,
    pub link: WorkspaceLink,
    /// Index (into the input slice) of the session that launched this one.
    pub launched_by: Option<usize>,
    /// Exact directory of the workspace when a transcript recorded it (for
    /// labels); empty when only the lossy slug is known.
    pub dir: String,
}

/// File every session under one workspace (see the module docs). `home` is
/// the home directory of the user whose transcripts these are (expands `~`
/// in launch directories); `rules` are the params' workspace attribution
/// rules. The result is index-aligned with `sessions` and independent of
/// their order.
pub fn attribute_session_workspaces(
    sessions: &[SessionWorkspaceInput<'_>],
    home: &str,
    rules: &WorkspaceAttributionJSON,
) -> Vec<SessionWorkspace> {
    let paths = PathRules::new(rules);
    let home = paths.parse(home);
    let owns: Vec<SessionWorkspace> = sessions
        .iter()
        .map(|session| own_workspace(session, &paths))
        .collect();

    // Visit candidates in a canonical order so ties resolve the same way
    // whatever order the caller collected the sessions in.
    let mut order: Vec<usize> = (0..sessions.len()).collect();
    order.sort_by(|a, b| {
        let (x, y) = (&sessions[*a], &sessions[*b]);
        (x.agent_type, x.session_key, x.source_path).cmp(&(
            y.agent_type,
            y.session_key,
            y.source_path,
        ))
    });

    // Every launch call once, directories resolved, in canonical order.
    struct Call {
        parent: usize,
        from: DateTime<Utc>,
        until: DateTime<Utc>,
        at: DateTime<Utc>,
        dirs: Vec<NamedDir>,
    }
    let mut calls: Vec<Call> = Vec::new();
    for &parent in &order {
        for call in sessions[parent].launches {
            let Some((from, until)) = launch_window(call, &sessions[parent], rules) else {
                continue;
            };
            let dirs: Vec<NamedDir> = call
                .dirs
                .iter()
                .filter_map(|dir| NamedDir::resolve(dir, home.as_ref(), &paths))
                .collect();
            if !dirs.is_empty() {
                calls.push(Call {
                    parent,
                    from,
                    until,
                    at: call.at.unwrap_or(from),
                    dirs,
                });
            }
        }
    }

    let mut parent_of: Vec<Option<usize>> = vec![None; sessions.len()];
    if !calls.is_empty() {
        for (child_index, child) in sessions.iter().enumerate() {
            if !child.launch.headless {
                continue;
            }
            let Some(child_dir) = paths.parse(&child.launch.cwd) else {
                continue;
            };
            let Some(child_start) = child.launch.started_at.or(child.started_at) else {
                continue;
            };
            // (specificity of the matched directory, launch time, parent)
            let mut best: Option<(usize, DateTime<Utc>, usize)> = None;
            for call in &calls {
                if call.parent == child_index || child_start < call.from || child_start > call.until
                {
                    continue;
                }
                let Some(specificity) = call
                    .dirs
                    .iter()
                    .filter_map(|dir| dir.covers(&child_dir, home.as_ref(), &paths))
                    .max()
                else {
                    continue;
                };
                let better = match best {
                    None => true,
                    Some((s, t, _)) => (specificity, call.at) > (s, t),
                };
                if better {
                    best = Some((specificity, call.at, call.parent));
                }
            }
            parent_of[child_index] = best.map(|(_, _, parent)| parent);
        }
    }

    let max_chain = usize::try_from(rules.max_launch_chain).unwrap_or(usize::MAX);
    (0..sessions.len())
        .map(|index| {
            let Some(parent) = parent_of[index] else {
                return owns[index].clone();
            };
            // Follow the chain to the session nobody launched.
            let mut chain = vec![index];
            let mut root = parent;
            loop {
                if chain.contains(&root) || chain.len() > max_chain {
                    // A cycle: no session in it was launched by another.
                    return owns[index].clone();
                }
                chain.push(root);
                match parent_of[root] {
                    Some(next) => root = next,
                    None => break,
                }
            }
            let rooted = &owns[root];
            if rooted.slug.is_empty() {
                return owns[index].clone();
            }
            SessionWorkspace {
                slug: rooted.slug.clone(),
                link: WorkspaceLink::Launched,
                launched_by: Some(parent),
                dir: rooted.dir.clone(),
            }
        })
        .collect()
}

/// The workspace a session is filed under when nobody launched it.
fn own_workspace(session: &SessionWorkspaceInput<'_>, paths: &PathRules) -> SessionWorkspace {
    let slug =
        workspace_slug_for_session(session.source_path, session.workspace_hint).unwrap_or_default();
    if slug.is_empty() {
        return SessionWorkspace::default();
    }
    // The exact directory, when one the transcript recorded is the one the
    // slug encodes (the slug alone is lossy: `edamame_core` -> `edamame-core`).
    let dir = [session.launch.cwd.as_str(), session.workspace_hint]
        .into_iter()
        .map(str::trim)
        .find(|dir| !dir.is_empty() && canonicalize_project_slug(dir) == slug)
        .unwrap_or("")
        .to_string();
    let temporary = match paths.parse(&dir) {
        Some(path) => paths.temp_root_len(&path).is_some(),
        None => paths.slug_names_temp_root(&slug),
    };
    if temporary {
        return SessionWorkspace {
            slug: temporary_workspace_slug(session.agent_type),
            link: WorkspaceLink::Temporary,
            launched_by: None,
            dir: String::new(),
        };
    }
    SessionWorkspace {
        slug,
        link: WorkspaceLink::Own,
        launched_by: None,
        dir,
    }
}

/// When a child launched by `call` may start.
fn launch_window(
    call: &AgentLaunchCall,
    parent: &SessionWorkspaceInput<'_>,
    rules: &WorkspaceAttributionJSON,
) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
    let seconds = |s: u64| Duration::seconds(i64::try_from(s).unwrap_or(i64::MAX / 1000));
    let slack = seconds(rules.launch_clock_slack_secs);
    let background = seconds(rules.background_launch_window_secs);
    match call.at {
        Some(at) => {
            let until = match (call.background, call.finished_at) {
                (false, Some(finished)) => finished + slack,
                _ => at + background,
            };
            Some((at - slack, until))
        }
        // No per-call timestamp (Cursor): the launching session's lifetime.
        None => {
            let from = parent.launch.started_at.or(parent.started_at)?;
            let until = parent.modified_at.unwrap_or(from);
            Some((from - slack, until + background))
        }
    }
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/// An absolute path, normalized for comparison: `/` separators, a lower-cased
/// drive (`C:\x` and the Git Bash spelling `/c/x` both give drive `c`), and
/// the params' path aliases applied (macOS `/private/tmp` is `/tmp`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct NormPath {
    drive: Option<char>,
    comps: Vec<String>,
}

impl NormPath {
    fn join(&self, tail: &[String]) -> NormPath {
        let mut comps = self.comps.clone();
        comps.extend(tail.iter().cloned());
        NormPath {
            drive: self.drive,
            comps,
        }
    }

    fn comp_eq(&self, a: &str, b: &str) -> bool {
        // Windows paths compare case-insensitively.
        if self.drive.is_some() {
            a.eq_ignore_ascii_case(b)
        } else {
            a == b
        }
    }

    fn starts_with(&self, prefix: &NormPath) -> bool {
        self.drive == prefix.drive
            && self.comps.len() >= prefix.comps.len()
            && prefix
                .comps
                .iter()
                .zip(&self.comps)
                .all(|(a, b)| self.comp_eq(a, b))
    }
}

/// One component of a root pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CompPattern {
    /// Any single component (`*`).
    Any,
    Literal(String),
}

/// A root pattern from the params: `/var/folders/*/*/T`, `?:/Windows/Temp`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RootPattern {
    /// `?:` (any drive) rather than a Unix root.
    on_drive: bool,
    comps: Vec<CompPattern>,
}

impl RootPattern {
    fn parse(pattern: &str) -> Option<RootPattern> {
        let (on_drive, rest) = match pattern.strip_prefix("?:") {
            Some(rest) => (true, rest),
            None if pattern.starts_with('/') => (false, pattern),
            None => return None,
        };
        let comps = rest
            .split('/')
            .filter(|c| !c.is_empty())
            .map(|c| {
                if c == "*" {
                    CompPattern::Any
                } else {
                    CompPattern::Literal(c.to_string())
                }
            })
            .collect();
        Some(RootPattern { on_drive, comps })
    }

    /// Components of `path` this root spans, when `path` is it or lies in it.
    fn matches(&self, path: &NormPath) -> Option<usize> {
        if self.on_drive != path.drive.is_some() || path.comps.len() < self.comps.len() {
            return None;
        }
        self.comps
            .iter()
            .zip(&path.comps)
            .all(|(pattern, comp)| match pattern {
                CompPattern::Any => true,
                CompPattern::Literal(literal) => path.comp_eq(literal, comp),
            })
            .then_some(self.comps.len())
    }

    /// Tokens of a canonical slug this root spans, when the slug's directory
    /// is it or lies in it. A path component can have become several tokens.
    fn matches_tokens(&self, tokens: &[String], ignore_case: bool) -> bool {
        fn walk(pattern: &[Vec<String>], tokens: &[String], ignore_case: bool) -> bool {
            let Some((first, rest)) = pattern.split_first() else {
                return true;
            };
            if first.is_empty() {
                // `*`: one component, one or more tokens.
                return (1..=MAX_TOKENS_PER_COMPONENT.min(tokens.len()))
                    .any(|n| walk(rest, &tokens[n..], ignore_case));
            }
            tokens.len() >= first.len()
                && first.iter().zip(tokens).all(|(a, b)| {
                    if ignore_case {
                        a.eq_ignore_ascii_case(b)
                    } else {
                        a == b
                    }
                })
                && walk(rest, &tokens[first.len()..], ignore_case)
        }
        let pattern: Vec<Vec<String>> = self
            .comps
            .iter()
            .map(|c| match c {
                CompPattern::Any => Vec::new(),
                CompPattern::Literal(literal) => slug_tokens(literal),
            })
            .collect();
        walk(&pattern, tokens, ignore_case)
    }
}

/// Dash-separated tokens of a canonical slug (or of a name, canonicalized).
fn slug_tokens(text: &str) -> Vec<String> {
    canonicalize_project_slug(text)
        .split('-')
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect()
}

/// The params' path rules, decoded once per attribution or labelling run.
struct PathRules {
    temp_roots: Vec<RootPattern>,
    home_parents: Vec<RootPattern>,
    /// (prefix, canonical) component lists of the path aliases.
    aliases: Vec<(Vec<String>, Vec<String>)>,
}

impl PathRules {
    fn new(rules: &WorkspaceAttributionJSON) -> Self {
        let split = |p: &str| -> Vec<String> {
            p.split('/')
                .filter(|c| !c.is_empty())
                .map(str::to_string)
                .collect()
        };
        PathRules {
            temp_roots: rules
                .temp_roots
                .iter()
                .filter_map(|r| RootPattern::parse(r))
                .collect(),
            home_parents: rules
                .home_parent_directories
                .iter()
                .filter_map(|r| RootPattern::parse(r))
                .collect(),
            aliases: rules
                .path_aliases
                .iter()
                .map(|a| (split(&a.prefix), split(&a.canonical)))
                .filter(|(prefix, _)| !prefix.is_empty())
                .collect(),
        }
    }

    /// Normalize an absolute path; `None` for a relative or empty one.
    fn parse(&self, path: &str) -> Option<NormPath> {
        let path = path.trim();
        if path.is_empty() {
            return None;
        }
        let unified = path.replace('\\', "/");
        let bytes = unified.as_bytes();
        let (mut drive, rest) =
            if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
                (Some((bytes[0] as char).to_ascii_lowercase()), &unified[2..])
            } else if unified.starts_with('/') {
                (None, unified.as_str())
            } else {
                return None;
            };
        let mut comps: Vec<String> = rest
            .split('/')
            .filter(|c| !c.is_empty() && *c != ".")
            .map(str::to_string)
            .collect();
        // Git Bash / MSYS: `/c/Users/me` is `C:\Users\me`.
        if drive.is_none()
            && comps.len() >= 2
            && comps[0].len() == 1
            && comps[0].chars().all(|c| c.is_ascii_alphabetic())
        {
            drive = comps[0].chars().next().map(|c| c.to_ascii_lowercase());
            comps.remove(0);
        }
        if drive.is_none() {
            if let Some((prefix, canonical)) = self.aliases.iter().find(|(prefix, _)| {
                comps.len() >= prefix.len() && comps[..prefix.len()] == prefix[..]
            }) {
                comps.splice(..prefix.len(), canonical.iter().cloned());
            }
        }
        Some(NormPath { drive, comps })
    }

    /// Length of the temporary root `path` lies in (or is).
    fn temp_root_len(&self, path: &NormPath) -> Option<usize> {
        self.temp_roots.iter().filter_map(|r| r.matches(path)).max()
    }

    /// A canonical slug whose directory lies in a temporary root (when no
    /// exact directory is known, e.g. Cursor).
    fn slug_names_temp_root(&self, slug: &str) -> bool {
        let tokens = slug_tokens(slug);
        let Some(first) = tokens.first() else {
            return false;
        };
        // `C--Users-me-AppData-Local-Temp-x`: a drive, then Windows rules.
        if first.len() == 1 && first.chars().all(|c| c.is_ascii_alphabetic()) {
            return self
                .temp_roots
                .iter()
                .filter(|r| r.on_drive)
                .any(|r| r.matches_tokens(&tokens[1..], true));
        }
        let mut unix = tokens.clone();
        for (prefix, canonical) in &self.aliases {
            let prefix_tokens: Vec<String> = prefix.iter().flat_map(|c| slug_tokens(c)).collect();
            if !prefix_tokens.is_empty()
                && unix.len() >= prefix_tokens.len()
                && unix[..prefix_tokens.len()] == prefix_tokens[..]
            {
                let canonical_tokens: Vec<String> =
                    canonical.iter().flat_map(|c| slug_tokens(c)).collect();
                unix.splice(..prefix_tokens.len(), canonical_tokens);
                break;
            }
        }
        self.temp_roots
            .iter()
            .filter(|r| !r.on_drive)
            .any(|r| r.matches_tokens(&unix, false))
    }

    /// Specific enough to name one workspace's surroundings: deeper than a
    /// temporary root, than the home directory, than a top-level directory,
    /// and not somebody's home (a home parent's child).
    fn is_specific(&self, dir: &NormPath, home: Option<&NormPath>) -> bool {
        if let Some(root) = self.temp_root_len(dir) {
            return dir.comps.len() > root;
        }
        if let Some(home) = home {
            if dir.starts_with(home) {
                return dir.comps.len() > home.comps.len();
            }
        }
        if dir.comps.len() < 2 {
            return false;
        }
        !self
            .home_parents
            .iter()
            .filter_map(|p| p.matches(dir))
            .any(|len| dir.comps.len() <= len + 1)
    }
}

/// A directory a launch command names.
enum NamedDir {
    Path(NormPath),
    /// `$TMPDIR/<tail>`: `<tail>` under whichever temporary root the child is
    /// in (the launching shell's `$TMPDIR` is not recorded).
    UnderTemp(Vec<String>),
}

impl NamedDir {
    fn resolve(dir: &str, home: Option<&NormPath>, paths: &PathRules) -> Option<NamedDir> {
        let split = |rest: &str| -> Vec<String> {
            rest.split(['/', '\\'])
                .filter(|c| !c.is_empty())
                .map(str::to_string)
                .collect()
        };
        if let Some(rest) = dir.strip_prefix("$TMPDIR") {
            let tail = split(rest);
            return (!tail.is_empty()).then_some(NamedDir::UnderTemp(tail));
        }
        if let Some(rest) = dir.strip_prefix('~') {
            return Some(NamedDir::Path(home?.join(&split(rest))));
        }
        paths.parse(dir).map(NamedDir::Path)
    }

    /// How many components of `child` this directory pins down, when `child`
    /// is it or lies under it.
    fn covers(
        &self,
        child: &NormPath,
        home: Option<&NormPath>,
        paths: &PathRules,
    ) -> Option<usize> {
        match self {
            NamedDir::Path(dir) => {
                (paths.is_specific(dir, home) && child.starts_with(dir)).then_some(dir.comps.len())
            }
            NamedDir::UnderTemp(tail) => {
                let root = paths.temp_root_len(child)?;
                let rest = &child.comps[root..];
                (rest.len() >= tail.len()
                    && tail.iter().zip(rest).all(|(a, b)| child.comp_eq(a, b)))
                .then_some(root + tail.len())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Labels
// ---------------------------------------------------------------------------

/// One workspace to name.
#[derive(Debug, Clone, Copy)]
pub struct WorkspaceLabelInput<'a> {
    pub slug: &'a str,
    /// Exact directory when known (an inventory root, a recorded working
    /// directory); empty to name it from the slug.
    pub dir: &'a str,
}

/// Unique labels for a set of workspaces (index-aligned with `inputs`; pass
/// each slug once). An agent home is named after its product; the
/// temporary-sessions group gets the params' label, with the agent in
/// parentheses when more than one agent has one; any other workspace is named
/// after its directory leaf, extended with parent components until no other
/// workspace in the set carries the same label (case-insensitively). A slug
/// without a known directory is named from its dash-separated tokens.
pub fn unique_workspace_labels(
    inputs: &[WorkspaceLabelInput<'_>],
    rules: &WorkspaceAttributionJSON,
) -> Vec<String> {
    enum Kind {
        Fixed(String),
        Temporary(String),
        Path(Vec<String>),
    }
    let paths = PathRules::new(rules);
    let kinds: Vec<Kind> = inputs
        .iter()
        .map(|input| {
            if let Some(agent) = temporary_workspace_agent(input.slug) {
                return Kind::Temporary(agent.to_string());
            }
            // An exact directory decides; the slug only when there is none
            // (the slug of a project named `codex` ends like the Codex home's).
            let reference = if input.dir.trim().is_empty() {
                input.slug
            } else {
                input.dir
            };
            let fleet = agent_type_for_fleet_workspace_ref(reference)
                .and_then(|agent| fleet_workspace_display_name(&agent));
            if let Some(name) = fleet {
                return Kind::Fixed(name.to_string());
            }
            let comps: Vec<String> = match paths.parse(input.dir) {
                Some(path) if !path.comps.is_empty() => path.comps,
                _ => input
                    .slug
                    .trim_start_matches('-')
                    .split('-')
                    .filter(|t| !t.is_empty())
                    .map(str::to_string)
                    .collect(),
            };
            Kind::Path(comps)
        })
        .collect();

    let temporary_count = kinds
        .iter()
        .filter(|k| matches!(k, Kind::Temporary(_)))
        .count();
    let mut labels: Vec<String> = kinds
        .iter()
        .map(|kind| match kind {
            Kind::Fixed(name) => name.clone(),
            Kind::Temporary(agent) if temporary_count > 1 => {
                let agent_label = rules
                    .agent_labels
                    .get(agent)
                    .cloned()
                    .unwrap_or_else(|| agent.clone());
                format!("{} ({})", rules.temporary_workspace_label, agent_label)
            }
            Kind::Temporary(_) => rules.temporary_workspace_label.clone(),
            Kind::Path(_) => String::new(),
        })
        .collect();
    let taken: std::collections::BTreeSet<String> = kinds
        .iter()
        .zip(&labels)
        .filter(|(kind, _)| !matches!(kind, Kind::Path(_)))
        .map(|(_, label)| label.to_ascii_lowercase())
        .collect();

    // Grow each colliding path label by one parent component per round until
    // every label is unique or cannot grow.
    let mut depth: Vec<usize> = vec![1; inputs.len()];
    loop {
        for (i, kind) in kinds.iter().enumerate() {
            if let Kind::Path(comps) = kind {
                let k = depth[i].min(comps.len());
                labels[i] = comps[comps.len() - k..].join("/");
            }
        }
        let mut groups: std::collections::BTreeMap<String, Vec<usize>> = Default::default();
        for (i, kind) in kinds.iter().enumerate() {
            if matches!(kind, Kind::Path(_)) {
                groups
                    .entry(labels[i].to_ascii_lowercase())
                    .or_default()
                    .push(i);
            }
        }
        let mut grew = false;
        for (label, members) in groups {
            if members.len() < 2 && !taken.contains(&label) {
                continue;
            }
            for i in members {
                if let Kind::Path(comps) = &kinds[i] {
                    if depth[i] < comps.len() {
                        depth[i] += 1;
                        grew = true;
                    }
                }
            }
        }
        if !grew {
            break;
        }
    }
    labels
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rules production reads.
    fn rules() -> WorkspaceAttributionJSON {
        crate::agent_visibility_params::workspace_attribution()
            .workspace_attribution
            .clone()
    }

    fn ts(s: &str) -> Option<DateTime<Utc>> {
        Some(DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc))
    }

    struct Fixture {
        agent_type: &'static str,
        session_key: &'static str,
        source_path: String,
        workspace_hint: String,
        launch: SessionLaunchContext,
        launches: Vec<AgentLaunchCall>,
    }

    impl Fixture {
        fn new(agent_type: &'static str, session_key: &'static str, source_path: &str) -> Self {
            Fixture {
                agent_type,
                session_key,
                source_path: source_path.to_string(),
                workspace_hint: String::new(),
                launch: SessionLaunchContext::default(),
                launches: Vec::new(),
            }
        }
        fn cwd(mut self, cwd: &str, started: &str, headless: bool) -> Self {
            self.launch = SessionLaunchContext {
                cwd: cwd.to_string(),
                started_at: ts(started),
                headless,
            };
            self
        }
        fn hint(mut self, hint: &str) -> Self {
            self.workspace_hint = hint.to_string();
            self
        }
        fn launch(
            mut self,
            at: &str,
            finished: Option<&str>,
            background: bool,
            dirs: &[&str],
        ) -> Self {
            self.launches.push(AgentLaunchCall {
                at: ts(at),
                finished_at: finished.and_then(ts),
                background,
                dirs: dirs.iter().map(|d| d.to_string()).collect(),
            });
            self
        }
        fn input(&self) -> SessionWorkspaceInput<'_> {
            SessionWorkspaceInput {
                agent_type: self.agent_type,
                session_key: self.session_key,
                source_path: &self.source_path,
                workspace_hint: &self.workspace_hint,
                launch: &self.launch,
                launches: &self.launches,
                started_at: self.launch.started_at,
                modified_at: self.launch.started_at.map(|t| t + Duration::minutes(30)),
            }
        }
    }

    fn attribute(fixtures: &[Fixture], home: &str) -> Vec<SessionWorkspace> {
        let inputs: Vec<SessionWorkspaceInput<'_>> = fixtures.iter().map(Fixture::input).collect();
        attribute_session_workspaces(&inputs, home, &rules())
    }

    const HOME: &str = "/Users/me";
    const PROJECTS: &str = "/Users/me/.claude/projects";
    const CORE: &str = "-Users-me-Programming-edamame-core";

    /// The 2026-09-28 simulation on the development Mac, paths sanitized: an
    /// orchestrator subagent in edamame_core wrote agents.sh (which runs
    /// `claude -p` in `$BASE/edsim-agent$N`) and ran it in the background for
    /// five Claude Code children and a Codex one, spread over /private/tmp,
    /// /private/var/tmp, the per-user $TMPDIR and ~/Library/Caches.
    fn edsim() -> Vec<Fixture> {
        let tmpdir = "/private/var/folders/7t/sg03pq8s3cs_cdqz92n1zs680000gn/T";
        vec![
            Fixture::new("claude_code", "60ebf757", &format!("{PROJECTS}/{CORE}/60ebf757.jsonl"))
                .cwd("/Users/me/Programming/edamame_core", "2026-09-28T14:00:00Z", false)
                .launch(
                    "2026-09-28T19:22:30.509Z",
                    Some("2026-09-28T19:22:32.094Z"),
                    true,
                    &[
                        "/Users/me/Programming/edamame_core",
                        "~/Library/Caches/edamame-agents/fp-sim",
                        "/private/tmp/edsim-agents",
                        "/private/var/tmp/edsim-agents",
                        "$TMPDIR/edsim-agents",
                        "~/Library/Caches/edamame-agents/sim-home/agents",
                    ],
                )
                .launch(
                    "2026-09-28T19:24:57.489Z",
                    Some("2026-09-28T19:25:21.500Z"),
                    false,
                    &[
                        "/Users/me/Programming/edamame_core",
                        "~/Library/Caches/edamame-agents/fp-sim",
                        "/private/var/tmp/edsim-agents",
                    ],
                ),
            Fixture::new(
                "claude_code",
                "af803020",
                &format!("{PROJECTS}/-private-tmp-edsim-agents-edsim-agent1/af803020.jsonl"),
            )
            .cwd("/private/tmp/edsim-agents/edsim-agent1", "2026-09-28T19:22:33.370Z", true),
            Fixture::new(
                "claude_code",
                "6b50b607",
                &format!(
                    "{PROJECTS}/-private-var-folders-7t-sg03pq8s3cs-cdqz92n1zs680000gn-T-edsim-agents-edsim-agent2/6b50b607.jsonl"
                ),
            )
            .cwd(
                &format!("{tmpdir}/edsim-agents/edsim-agent2"),
                "2026-09-28T19:22:48.710Z",
                true,
            ),
            Fixture::new(
                "claude_code",
                "5b5b738e",
                &format!("{PROJECTS}/-private-var-tmp-edsim-agents-edsim-agent3/5b5b738e.jsonl"),
            )
            .cwd("/private/var/tmp/edsim-agents/edsim-agent3", "2026-09-28T19:23:13.829Z", true),
            Fixture::new(
                "claude_code",
                "8c173b20",
                &format!("{PROJECTS}/-private-var-tmp-edsim-agents-edsim-agent3/8c173b20.jsonl"),
            )
            .cwd("/private/var/tmp/edsim-agents/edsim-agent3", "2026-09-28T19:25:00.767Z", true),
            Fixture::new(
                "claude_code",
                "67abf14b",
                &format!("{PROJECTS}/-private-tmp-edsim-agents-edsim-agent4/67abf14b.jsonl"),
            )
            .cwd("/private/tmp/edsim-agents/edsim-agent4", "2026-09-28T19:23:39.082Z", true),
            Fixture::new(
                "claude_code",
                "8a99f90c",
                &format!(
                    "{PROJECTS}/-Users-me-Library-Caches-edamame-agents-sim-home-agents-edsim-agent5/8a99f90c.jsonl"
                ),
            )
            .cwd(
                "/Users/me/Library/Caches/edamame-agents/sim-home/agents/edsim-agent5",
                "2026-09-28T19:24:04.927Z",
                true,
            ),
            Fixture::new(
                "codex",
                "01a0e979",
                "/Users/me/.codex/sessions/2026/09/28/rollout-01a0e979.jsonl",
            )
            .hint("/Users/me/.codex")
            .cwd("/private/tmp/edsim-agents/edsim-agent6", "2026-09-28T19:24:20.886Z", true),
        ]
    }

    #[test]
    fn edsim_children_fold_into_the_launching_workspace() {
        let fixtures = edsim();
        let out = attribute(&fixtures, HOME);
        assert_eq!(out[0].slug, CORE);
        assert_eq!(out[0].link, WorkspaceLink::Own);
        assert_eq!(out[0].dir, "/Users/me/Programming/edamame_core");
        for (i, ws) in out.iter().enumerate().skip(1) {
            assert_eq!(ws.slug, CORE, "child {} ({})", i, fixtures[i].session_key);
            assert_eq!(ws.link, WorkspaceLink::Launched);
            assert_eq!(ws.launched_by, Some(0));
            assert_eq!(ws.dir, "/Users/me/Programming/edamame_core");
        }
    }

    #[test]
    fn a_task_subagent_stays_in_its_parent_workspace() {
        // Subagent transcripts live under the parent's project directory and
        // carry the parent's (interactive) entrypoint: their own slug is the
        // parent's workspace, launch links never apply.
        let fixtures = vec![
            Fixture::new(
                "claude_code",
                "main",
                &format!("{PROJECTS}/{CORE}/main.jsonl"),
            )
            .cwd(
                "/Users/me/Programming/edamame_core",
                "2026-09-28T10:00:00Z",
                false,
            ),
            Fixture::new(
                "claude_code",
                "agent-a1",
                &format!("{PROJECTS}/{CORE}/main/subagents/agent-a1.jsonl"),
            )
            .cwd(
                "/Users/me/Programming/edamame_core",
                "2026-09-28T10:05:00Z",
                false,
            ),
        ];
        let out = attribute(&fixtures, HOME);
        assert_eq!(out[1].slug, CORE);
        assert_eq!(out[1].link, WorkspaceLink::Own);
    }

    #[test]
    fn a_transcript_link_needs_the_time_window_and_a_named_directory() {
        let parent = Fixture::new("claude_code", "p", &format!("{PROJECTS}/{CORE}/p.jsonl"))
            .cwd(
                "/Users/me/Programming/edamame_core",
                "2026-09-28T10:00:00Z",
                false,
            )
            .launch(
                "2026-09-28T10:10:00Z",
                Some("2026-09-28T10:12:00Z"),
                false,
                &["/Users/me/Programming/edamame_core", "/Users/me/work/runs"],
            );
        let child = |key: &'static str, cwd: &str, started: &str, headless: bool| {
            let slug = canonicalize_project_slug(cwd);
            Fixture::new(
                "claude_code",
                key,
                &format!("{PROJECTS}/{slug}/{key}.jsonl"),
            )
            .cwd(cwd, started, headless)
        };
        let fixtures = vec![
            parent,
            // In the window, under a named directory: launched.
            child("in", "/Users/me/work/runs/a", "2026-09-28T10:11:00Z", true),
            // After the foreground call returned: its own.
            child(
                "late",
                "/Users/me/work/runs/b",
                "2026-09-28T10:30:00Z",
                true,
            ),
            // Before the call: its own.
            child(
                "early",
                "/Users/me/work/runs/c",
                "2026-09-28T10:09:00Z",
                true,
            ),
            // Not under a named directory: its own.
            child(
                "elsewhere",
                "/Users/me/other/d",
                "2026-09-28T10:11:00Z",
                true,
            ),
            // A person's interactive session in the named directory: its own.
            child(
                "person",
                "/Users/me/work/runs/e",
                "2026-09-28T10:11:00Z",
                false,
            ),
        ];
        let out = attribute(&fixtures, HOME);
        assert_eq!(out[1].link, WorkspaceLink::Launched);
        assert_eq!(out[1].slug, CORE);
        for i in 2..=5 {
            assert_eq!(
                out[i].link,
                WorkspaceLink::Own,
                "{}",
                fixtures[i].session_key
            );
            assert_eq!(
                out[i].slug,
                canonicalize_project_slug(&fixtures[i].launch.cwd)
            );
        }
    }

    #[test]
    fn broad_directories_do_not_link() {
        // Naming only the home, a temp root or somebody's home links nothing.
        let parent = Fixture::new("claude_code", "p", &format!("{PROJECTS}/{CORE}/p.jsonl"))
            .cwd(
                "/Users/me/Programming/edamame_core",
                "2026-09-28T10:00:00Z",
                false,
            )
            .launch(
                "2026-09-28T10:10:00Z",
                None,
                true,
                &[
                    "~",
                    "/tmp",
                    "/private/tmp",
                    "/Users/other",
                    "/Users",
                    "$TMPDIR",
                ],
            );
        let fixtures = vec![
            parent,
            Fixture::new(
                "claude_code",
                "c",
                &format!("{PROJECTS}/-Users-me-code-x/c.jsonl"),
            )
            .cwd("/Users/me/code/x", "2026-09-28T10:11:00Z", true),
            Fixture::new(
                "claude_code",
                "t",
                &format!("{PROJECTS}/-private-tmp-y/t.jsonl"),
            )
            .cwd("/private/tmp/y", "2026-09-28T10:11:00Z", true),
        ];
        let out = attribute(&fixtures, HOME);
        assert_eq!(out[1].link, WorkspaceLink::Own);
        assert_eq!(out[2].link, WorkspaceLink::Temporary);
    }

    #[test]
    fn unlinked_temp_sessions_group_per_agent() {
        let fixtures = vec![
            // No launching session: headless children in temp roots group.
            Fixture::new(
                "claude_code",
                "a",
                &format!("{PROJECTS}/-private-tmp-edsim-agents-edsim-agent1/a.jsonl"),
            )
            .cwd("/private/tmp/edsim-agents/edsim-agent1", "2026-09-28T19:22:33Z", true),
            Fixture::new(
                "claude_code",
                "b",
                &format!(
                    "{PROJECTS}/-private-var-folders-7t-sg03pq8s3cs-cdqz92n1zs680000gn-T-x/b.jsonl"
                ),
            )
            .cwd(
                "/private/var/folders/7t/sg03pq8s3cs_cdqz92n1zs680000gn/T/x",
                "2026-09-28T19:22:48Z",
                true,
            ),
            // A person's session in /tmp groups too.
            Fixture::new("claude_code", "c", &format!("{PROJECTS}/-tmp-scratch/c.jsonl"))
                .cwd("/tmp/scratch", "2026-09-28T19:00:00Z", false),
            // Cursor: no recorded cwd, the slug names the temp root.
            Fixture::new(
                "cursor",
                "d",
                "/Users/me/.cursor/projects/private-tmp-demo/agent-transcripts/d/d.jsonl",
            ),
            // Windows Claude Code session in %TEMP%.
            // (Transcript paths use `/` here: `Path` splits `\\` only on a
            // Windows host; the working directory keeps its native spelling.)
            Fixture::new(
                "claude_code",
                "e",
                "C:/Users/me/.claude/projects/C--Users-me-AppData-Local-Temp-run1/e.jsonl",
            )
            .cwd(
                "C:\\Users\\me\\AppData\\Local\\Temp\\run1",
                "2026-09-28T19:00:00Z",
                true,
            ),
            // Linux Codex session in /var/tmp (SQLite thread cwd as the hint).
            Fixture::new(
                "codex",
                "f",
                "/home/me/.codex/sessions/2026/09/28/rollout-f.jsonl",
            )
            .hint("/var/tmp/job-7"),
            // Not temporary: the macOS per-user cache sibling, a project named tmp.
            Fixture::new(
                "claude_code",
                "g",
                &format!(
                    "{PROJECTS}/-private-var-folders-7t-sg03pq8s3cs-cdqz92n1zs680000gn-C-x/g.jsonl"
                ),
            )
            .cwd(
                "/private/var/folders/7t/sg03pq8s3cs_cdqz92n1zs680000gn/C/x",
                "2026-09-28T19:00:00Z",
                true,
            ),
            Fixture::new("claude_code", "h", &format!("{PROJECTS}/-Users-me-tmp-app/h.jsonl"))
                .cwd("/Users/me/tmp/app", "2026-09-28T19:00:00Z", true),
            // Cursor on Windows, slug only: `%TEMP%` and the per-user macOS
            // temp by slug tokens.
            Fixture::new(
                "cursor",
                "i",
                "C:/Users/me/.cursor/projects/c-Users-me-AppData-Local-Temp-w/agent-transcripts/i/i.jsonl",
            ),
            Fixture::new(
                "cursor",
                "j",
                "/Users/me/.cursor/projects/private-var-folders-7t-sg03pq8s3cs-cdqz92n1zs680000gn-T-w/agent-transcripts/j/j.jsonl",
            ),
        ];
        let out = attribute(&fixtures, HOME);
        for i in [0, 1, 2, 4] {
            assert_eq!(
                out[i].link,
                WorkspaceLink::Temporary,
                "{}",
                fixtures[i].session_key
            );
            assert_eq!(out[i].slug, "temporary:claude_code");
        }
        assert_eq!(out[3].slug, "temporary:cursor");
        assert_eq!(out[5].slug, "temporary:codex");
        assert_eq!(out[6].link, WorkspaceLink::Own);
        assert_eq!(out[7].link, WorkspaceLink::Own);
        assert_eq!(out[8].slug, "temporary:cursor");
        assert_eq!(out[9].slug, "temporary:cursor");
    }

    #[test]
    fn launched_sessions_follow_the_chain_and_cycles_fall_back() {
        let fixtures = vec![
            Fixture::new(
                "claude_code",
                "root",
                &format!("{PROJECTS}/{CORE}/root.jsonl"),
            )
            .cwd(
                "/Users/me/Programming/edamame_core",
                "2026-09-28T10:00:00Z",
                false,
            )
            .launch("2026-09-28T10:01:00Z", None, true, &["/private/tmp/orch"]),
            // Launched by root, launches a grandchild.
            Fixture::new(
                "codex",
                "mid",
                "/Users/me/.codex/sessions/2026/09/28/rollout-mid.jsonl",
            )
            .hint("/Users/me/.codex")
            .cwd("/private/tmp/orch/mid", "2026-09-28T10:02:00Z", true)
            .launch(
                "2026-09-28T10:03:00Z",
                None,
                true,
                &["/private/tmp/orch/mid/leaf"],
            ),
            Fixture::new(
                "claude_code",
                "leaf",
                &format!("{PROJECTS}/-private-tmp-orch-mid-leaf/leaf.jsonl"),
            )
            .cwd("/private/tmp/orch/mid/leaf", "2026-09-28T10:04:00Z", true),
            // Two headless sessions that name each other: neither is launched.
            Fixture::new(
                "claude_code",
                "x",
                &format!("{PROJECTS}/-Users-me-a-x/x.jsonl"),
            )
            .cwd("/Users/me/a/x", "2026-09-28T10:10:00Z", true)
            .launch("2026-09-28T10:09:00Z", None, true, &["/Users/me/b"]),
            Fixture::new(
                "claude_code",
                "y",
                &format!("{PROJECTS}/-Users-me-b-y/y.jsonl"),
            )
            .cwd("/Users/me/b/y", "2026-09-28T10:10:00Z", true)
            .launch("2026-09-28T10:09:00Z", None, true, &["/Users/me/a"]),
        ];
        let out = attribute(&fixtures, HOME);
        assert_eq!(out[1].slug, CORE);
        assert_eq!(out[1].launched_by, Some(0));
        assert_eq!(out[2].slug, CORE);
        assert_eq!(out[2].launched_by, Some(1));
        assert_eq!(out[3].link, WorkspaceLink::Own);
        assert_eq!(out[4].link, WorkspaceLink::Own);
    }

    #[test]
    fn windows_and_linux_path_shapes_link() {
        // Cursor on Windows (no timestamps: the parent's lifetime is the
        // window) launching Claude Code through PowerShell in %TEMP%.
        let mut cursor_parent = Fixture::new(
            "cursor",
            "cp",
            "C:/Users/me/.cursor/projects/c-Users-me-src-app/agent-transcripts/cp/cp.jsonl",
        );
        cursor_parent.launch = SessionLaunchContext {
            cwd: String::new(),
            started_at: ts("2026-09-28T09:00:00Z"),
            headless: false,
        };
        cursor_parent.launches.push(AgentLaunchCall {
            at: None,
            finished_at: None,
            background: true,
            dirs: vec!["$TMPDIR/agents".to_string()],
        });
        let fixtures =
            vec![
            cursor_parent,
            Fixture::new(
                "claude_code",
                "wc",
                "C:/Users/me/.claude/projects/C--Users-me-AppData-Local-Temp-agents-a1/wc.jsonl",
            )
            .cwd(
                "C:\\Users\\me\\AppData\\Local\\Temp\\agents\\a1",
                "2026-09-28T09:10:00Z",
                true,
            ),
            // Codex on Linux launching Claude Code in a subdirectory.
            Fixture::new(
                "codex",
                "lp",
                "/home/me/.codex/sessions/2026/09/28/rollout-lp.jsonl",
            )
            .hint("/home/me/src/svc")
            .cwd("/home/me/src/svc", "2026-09-28T11:00:00Z", false)
            .launch(
                "2026-09-28T11:01:00Z",
                Some("2026-09-28T11:05:00Z"),
                false,
                &["/home/me/src/svc/tools"],
            ),
            Fixture::new(
                "claude_code",
                "lc",
                "/home/me/.claude/projects/-home-me-src-svc-tools/lc.jsonl",
            )
            .cwd("/home/me/src/svc/tools", "2026-09-28T11:02:00Z", true),
            // Git Bash spelling of a Windows directory in the launch command.
            Fixture::new(
                "claude_code",
                "gp",
                "C:/Users/me/.claude/projects/C--Users-me-src-web/gp.jsonl",
            )
            .cwd("C:\\Users\\me\\src\\web", "2026-09-28T12:00:00Z", false)
            .launch(
                "2026-09-28T12:01:00Z",
                None,
                true,
                &["/c/Users/me/src/web/jobs"],
            ),
            Fixture::new(
                "claude_code",
                "gc",
                "C:/Users/me/.claude/projects/C--Users-me-src-web-jobs-1/gc.jsonl",
            )
            .cwd("C:\\Users\\me\\src\\web\\jobs\\1", "2026-09-28T12:02:00Z", true),
        ];
        let out = attribute(&fixtures, "/home/me");
        assert_eq!(out[1].link, WorkspaceLink::Launched);
        assert_eq!(out[1].slug, canonicalize_project_slug("c-Users-me-src-app"));
        assert_eq!(out[3].link, WorkspaceLink::Launched);
        assert_eq!(out[3].slug, canonicalize_project_slug("/home/me/src/svc"));
        assert_eq!(out[3].dir, "/home/me/src/svc");
        assert_eq!(out[5].link, WorkspaceLink::Launched);
        assert_eq!(
            out[5].slug,
            canonicalize_project_slug("C--Users-me-src-web")
        );
    }

    #[test]
    fn attribution_does_not_depend_on_input_order() {
        let fixtures = edsim();
        let forward = attribute(&fixtures, HOME);
        let reversed_fixtures: Vec<Fixture> = edsim().into_iter().rev().collect();
        let mut reversed = attribute(&reversed_fixtures, HOME);
        reversed.reverse();
        let n = fixtures.len();
        for (a, b) in forward.iter().zip(&reversed) {
            assert_eq!(a.slug, b.slug);
            assert_eq!(a.link, b.link);
            assert_eq!(a.launched_by, b.launched_by.map(|i| n - 1 - i));
        }
    }

    #[test]
    fn a_wider_background_window_in_the_params_reaches_later_children() {
        let fixtures = vec![
            Fixture::new("claude_code", "p", &format!("{PROJECTS}/{CORE}/p.jsonl"))
                .cwd(
                    "/Users/me/Programming/edamame_core",
                    "2026-09-28T10:00:00Z",
                    false,
                )
                .launch("2026-09-28T10:01:00Z", None, true, &["/private/tmp/batch"]),
            Fixture::new(
                "claude_code",
                "late",
                &format!("{PROJECTS}/-private-tmp-batch-9/late.jsonl"),
            )
            .cwd("/private/tmp/batch/9", "2026-09-28T13:00:00Z", true),
        ];
        let inputs: Vec<SessionWorkspaceInput<'_>> = fixtures.iter().map(Fixture::input).collect();
        let mut narrow = rules();
        narrow.background_launch_window_secs = 3600;
        assert_eq!(
            attribute_session_workspaces(&inputs, HOME, &narrow)[1].link,
            WorkspaceLink::Temporary
        );
        let mut wide = rules();
        wide.background_launch_window_secs = 6 * 3600;
        assert_eq!(
            attribute_session_workspaces(&inputs, HOME, &wide)[1].link,
            WorkspaceLink::Launched
        );
    }

    #[test]
    fn path_normalization_folds_platform_spellings() {
        let r = rules();
        let paths = PathRules::new(&r);
        // Git Bash and native spellings of one Windows directory.
        assert_eq!(
            paths.parse("/c/Users/me/AppData/Local/Temp/x"),
            paths.parse("C:\\Users\\me\\AppData\\Local\\Temp\\x")
        );
        // macOS firmlinks.
        assert_eq!(paths.parse("/private/tmp/x"), paths.parse("/tmp/x"));
        assert_eq!(paths.parse("/private/var/tmp/x"), paths.parse("/var/tmp/x"));
        assert_eq!(paths.parse("relative/x"), None);
        let win = paths.parse("C:\\Users\\Me\\Src").unwrap();
        assert!(win.starts_with(&paths.parse("c:/users/me").unwrap()));
        let mac = paths.parse("/Users/Me/src").unwrap();
        assert!(!mac.starts_with(&paths.parse("/users/me").unwrap()));
        // Temporary roots, from the params.
        for temp in [
            "/tmp/x",
            "/private/tmp/x",
            "/var/tmp/x",
            "/private/var/folders/7t/abc/T/x",
            "C:\\Windows\\Temp\\x",
            "C:\\Users\\me\\AppData\\Local\\Temp\\x",
        ] {
            assert!(
                paths.temp_root_len(&paths.parse(temp).unwrap()).is_some(),
                "{temp}"
            );
        }
        for not_temp in [
            "/private/var/folders/7t/abc/C/x",
            "/Users/me/tmp/x",
            "C:\\Users\\me\\AppData\\Local\\Programs\\x",
        ] {
            assert!(
                paths
                    .temp_root_len(&paths.parse(not_temp).unwrap())
                    .is_none(),
                "{not_temp}"
            );
        }
    }

    #[test]
    fn vanished_workspaces_get_unique_labels() {
        let r = rules();
        let inputs = [
            WorkspaceLabelInput {
                slug: "-private-var-tmp-edsim-agents-edsim-agent3",
                dir: "/private/var/tmp/edsim-agents/edsim-agent3",
            },
            WorkspaceLabelInput {
                slug: "-private-var-tmp-edsim-agents2-edsim-agent3",
                dir: "/private/var/tmp/edsim-agents2/edsim-agent3",
            },
            WorkspaceLabelInput {
                slug: "-Users-me-Programming-edamame-core",
                dir: "/Users/me/Programming/edamame_core",
            },
            // No recorded directory: named from the slug tokens.
            WorkspaceLabelInput {
                slug: "-Users-me-Library-Caches-sim-home-agents-edsim-agent5",
                dir: "",
            },
            WorkspaceLabelInput {
                slug: "-Users-me-Library-Caches-sim-home-agents2-edsim-agent5",
                dir: "",
            },
            WorkspaceLabelInput {
                slug: "-Users-me-.codex",
                dir: "/Users/me/.codex",
            },
            WorkspaceLabelInput {
                slug: "-Users-me-code-codex",
                dir: "/Users/me/code/codex",
            },
            WorkspaceLabelInput {
                slug: "temporary:claude_code",
                dir: "",
            },
        ];
        let labels = unique_workspace_labels(&inputs, &r);
        assert_eq!(labels[0], "edsim-agents/edsim-agent3");
        assert_eq!(labels[1], "edsim-agents2/edsim-agent3");
        assert_eq!(labels[2], "edamame_core");
        assert_eq!(labels[3], "agents/edsim/agent5");
        assert_eq!(labels[4], "agents2/edsim/agent5");
        assert_eq!(labels[5], "Codex");
        // A project named like an agent home is told apart from it.
        assert_eq!(labels[6], "code/codex");
        assert_eq!(labels[7], r.temporary_workspace_label);
        let unique: std::collections::BTreeSet<String> =
            labels.iter().map(|l| l.to_ascii_lowercase()).collect();
        assert_eq!(unique.len(), labels.len());
    }

    #[test]
    fn labels_are_stable_and_order_independent() {
        let r = rules();
        let inputs = [
            WorkspaceLabelInput {
                slug: "-data-x-edsim-agent3",
                dir: "/data/x/edsim-agent3",
            },
            WorkspaceLabelInput {
                slug: "-data-y-edsim-agent3",
                dir: "/data/y/edsim-agent3",
            },
            WorkspaceLabelInput {
                slug: "temporary:codex",
                dir: "",
            },
            WorkspaceLabelInput {
                slug: "temporary:claude_code",
                dir: "",
            },
            WorkspaceLabelInput {
                slug: "-srv-solo",
                dir: "/srv/solo",
            },
        ];
        let first = unique_workspace_labels(&inputs, &r);
        assert_eq!(first, unique_workspace_labels(&inputs, &r));
        let mut reversed_inputs = inputs;
        reversed_inputs.reverse();
        let mut reversed = unique_workspace_labels(&reversed_inputs, &r);
        reversed.reverse();
        assert_eq!(first, reversed);
        assert_eq!(first[0], "x/edsim-agent3");
        assert_eq!(first[1], "y/edsim-agent3");
        assert_eq!(
            first[2],
            format!(
                "{} ({})",
                r.temporary_workspace_label, r.agent_labels["codex"]
            )
        );
        assert_eq!(
            first[3],
            format!(
                "{} ({})",
                r.temporary_workspace_label, r.agent_labels["claude_code"]
            )
        );
        assert_eq!(first[4], "solo");
    }
}
