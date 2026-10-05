//! Agent-visibility tunables (CloudModel).
//!
//! Owns the `CloudModel<AgentVisibilityParams>` backed by
//! `agent-visibility-params-db.json` in the threatmodels repo: everything the
//! Agents tab visibility surface consumes that is NOT attack-pattern
//! detection. This is a separate model from `vuln_detector_params` /
//! `cve-detection-params-db.json` so agent-visibility wording, catalogs,
//! pricing, and history-retention policy can be refreshed independently of
//! the detection tunables.
//!
//! Contents:
//! - transcript secret / prompt-injection signatures (BR-1 / BR-2)
//! - critical-subprocess catalog + tool-privilege keywords + recursion
//!   thresholds (exposure / blast radius)
//! - model-id extraction keys and the per-model price table (economics)
//! - augmentation next-step prompt templates + Enlightenment Coach templates
//! - unified history-retention policy (age + entry caps) for the agent
//!   history stores
//! - workspace attribution: the agent-CLI launch vocabulary, programmatic
//!   start markers, temporary roots, path conventions, time windows and label
//!   wording `agent_workspaces` and `agent_transcripts::launch` read, plus the
//!   transcript store's project directory and the references that name a
//!   single-workspace agent's home (`agent_visibility`)
//! - instruction inventory: the instruction directories, file names,
//!   extensions and skill package markers `agent_visibility` walks and
//!   recognizes
//! - instruction references: what makes a path in an instruction body a
//!   reference to another instruction artifact (the skill reference graph)
//! - agent-governance harness catalog: the products, their footprint markers,
//!   CLI names, identity files, and the bin and config directories searched
//! - agent confinement: the container, VM-bundle and confined-app directories
//!   and name needles of OS confinement, the agents' own config files, and
//!   the approval-mode ranking of the control-config weakening check
//! - host privilege: the elevated users, administrator groups, group
//!   database and sudoers policy locations the host blast-radius assessment
//!   reads
//! - MCP discovery: where the servers an agent acquires outside its global
//!   MCP config are declared (plugin trees, project configs, installed-plugin
//!   manifests, extensions)
//! - MCP credential markers: the header and environment-variable names that
//!   make a server's authentication a shared secret
//! - delegation markers: the tool names and keys that mark a sub-agent spawn
//!   in a transcript (recursion / delegation finding)
//! - agent model traffic: per agent type, the model traffic the transcript
//!   parser declares (`agent_transcripts`) and the agent's own provider
//!   endpoints, to which a declared not-expected traffic pattern never
//!   applies (the divergence engine's correlation plane)
//!
//! Unlike the CVE params struct, `AgentVisibilityParamsJSON` carries NO
//! `#[serde(default)]` fields: this model was born complete, the published
//! JSON always contains every field, and a missing field is a publishing bug
//! that must fail the parse (falling back to the embedded snapshot, which has
//! all fields).

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use threatmodels_rs::*;
use tracing::{info, warn};

use crate::agent_visibility_params_db::AGENT_VISIBILITY_PARAMS_DB;
use crate::vuln_detector_params::SecretContentSignatureJSON;

const AGENT_VISIBILITY_PARAMS_NAME: &str = "agent-visibility-params-db.json";

/// One critical-subprocess class for the agent subprocess visibility surface.
/// Maps a set of binary basenames to a category slug, inherent criticality,
/// and the OWASP GenAI crosswalk tags.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CriticalSubprocessClassJSON {
    /// Lowercased binary basenames this class matches (e.g. `ssh`, `kubectl`).
    pub names: Vec<String>,
    /// Category slug (e.g. `remote_access`, `shell`, `container`).
    pub category: String,
    /// Inherent criticality: `"routine"`, `"elevated"`, or `"critical"`.
    pub criticality: String,
    /// Comma-separated OWASP GenAI crosswalk references (metadata only).
    pub owasp_refs: String,
}

/// Per-class keyword lists used to classify MCP tool privileges from a tool's
/// name / description / URL. Each list is matched (substring) against a
/// lowercased haystack.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AgentToolPrivilegeKeywordsJSON {
    pub shell: Vec<String>,
    pub filesystem_write: Vec<String>,
    pub filesystem_read: Vec<String>,
    pub browser: Vec<String>,
    pub git: Vec<String>,
    pub database: Vec<String>,
    pub secret_access: Vec<String>,
    pub network: Vec<String>,
}

/// Thresholds for the agent recursion / delegation visibility finding.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AgentRecursionThresholdsJSON {
    /// Delegation depth at/above which depth alone is a finding.
    pub depth_high: u32,
    /// Sub-agent fan-out at/above which fan-out alone is a finding.
    pub fanout_high: u32,
    /// Same-goal re-delegations at/above which a same-purpose loop is flagged.
    pub loop_min_repeats: u32,
}

/// One per-model price row used by the agent-transcript economics parser.
/// All four rates are USD per 1M tokens. `match_substring` is a lowercased
/// substring tested against the lowercased model id; among all matching
/// entries the one with the LONGEST `match_substring` wins (most-specific
/// match). The `default` entry's `match_substring` is structurally present
/// but ignored at runtime -- the default is the fallback applied only when
/// no entry matched.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ModelPriceEntryJSON {
    /// USD per 1M input (prompt) tokens.
    pub input: f64,
    /// USD per 1M output (completion) tokens.
    pub output: f64,
    /// USD per 1M tokens written to the prompt cache (Anthropic
    /// cache-creation). Providers without a cache-write surcharge set 0.
    pub cache_write: f64,
    /// USD per 1M tokens served from the prompt cache (cache read / hit).
    pub cache_read: f64,
    /// Lowercased substring matched against the lowercased model id.
    pub match_substring: String,
}

/// Per-model USD-per-1M-token price table. Resolution is by longest
/// matching `match_substring`; `default` is the fallback for unrecognized
/// model ids. Sourced from `agent-visibility-params-db.json` so prices can
/// be refreshed via CloudModel without a release.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ModelPricingJSON {
    pub default: ModelPriceEntryJSON,
    pub entries: Vec<ModelPriceEntryJSON>,
}

/// Resolved per-model price (USD per 1M tokens) plus provenance. Returned by
/// [`resolve_model_price`]. `is_fallback` is true when no `match_substring`
/// entry matched and the `default` rate was used -- the model family was not
/// recognized, so the derived cost is a coarse estimate (G3).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ResolvedModelPrice {
    pub input: f64,
    pub output: f64,
    pub cache_write: f64,
    pub cache_read: f64,
    pub is_fallback: bool,
}

/// One next-step prompt template for the augmentation path. The deterministic
/// augmentation engine detects the issue (dead skills, context tax, recurring
/// no-skill failure clusters, ...); the template turns that finding into a
/// ready-to-paste prompt the operator hands to their own coding agent to
/// analyse and fix it. `prompt` carries `{placeholder}` tokens filled
/// client-side from the report data (counts, names, paths); the engine never
/// calls an LLM itself. CloudModel-refreshable so prompt wording can be tuned
/// without a binary release.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AugmentationPromptTemplateJSON {
    /// Stable issue-kind id the UI keys on (`skill_opportunity`,
    /// `context_tax`, `duplicate_skill`, ...).
    pub id: String,
    /// Short operator-facing action title.
    pub title: String,
    /// The prompt body with `{placeholder}` tokens.
    pub prompt: String,
}

/// One Enlightenment Coach template. Unlike
/// [`AugmentationPromptTemplateJSON`] (deterministic findings rendered into
/// copy-paste fix prompts, no LLM involved), a coach template drives one
/// guardrailed LLM call: the `focus` text is embedded in the coach system
/// prompt to steer which slice of the deterministic aggregate payload the
/// model should analyse. The LLM only ever sees the aggregate JSON -- never
/// raw transcripts -- and its output must pass strict envelope validation
/// (schema + evidence-ref allowlist) or the insight is discarded.
/// CloudModel-refreshable so coaching focus wording can be tuned without a
/// binary release; `version` participates in the insight cache key so a
/// template bump invalidates cached envelopes.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AugmentationCoachTemplateJSON {
    /// Stable coach-kind id the UI and cache key on
    /// (`prompt_maturity_review`, `security_hygiene_review`, ...).
    pub id: String,
    /// Coaching domain this template belongs to: `"security"` or
    /// `"augmentation"`. The core builds a domain-scoped coach payload from
    /// this field -- a `"security"` template gets the security-only payload
    /// (posture + exposure + security transcript signals) and an
    /// `"augmentation"` template gets the augmentation-only payload (no
    /// security sections). Keeps the Security Coach and Enlightenment Coach
    /// evidence surfaces disjoint so enlightenment coaching never bleeds
    /// security signals and vice versa.
    pub domain: String,
    /// Monotonic template version; part of the insight cache key.
    pub version: u32,
    /// Short operator-facing card title.
    pub title: String,
    /// Focus instruction embedded in the coach prompt: which aggregate
    /// sections to weigh and what kind of recommendations to produce.
    pub focus: String,
}

/// Unified history-retention policy for the agent history stores
/// (divergence verdicts / incidents, behavioral models, subprocess
/// observations, visibility operator log, coach insight cache). Every store
/// applies BOTH limits: entries older than `history_retention_days` are
/// pruned regardless of count, and each store is additionally capped at its
/// `*_max_entries` so a burst cannot balloon persisted state.
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct HistoryRetentionJSON {
    /// Age cap in days applied uniformly across the agent history stores.
    pub history_retention_days: u64,
    /// Max retained divergence verdicts per agent instance.
    pub divergence_verdict_max_entries: usize,
    /// Max retained divergence incidents.
    pub divergence_incident_max_entries: usize,
    /// Max retained behavioral-model snapshots.
    pub behavioral_model_max_entries: usize,
    /// Max retained subprocess observations per agent instance.
    pub subprocess_max_observations: usize,
    /// Max retained agent-visibility operator log entries.
    pub visibility_log_max_entries: usize,
    /// Max cached Enlightenment Coach insight envelopes.
    pub coach_max_cached_insights: usize,
}

/// A program and the options of it the launch recognizer treats specially.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ProgramOptionsJSON {
    /// Lowercased program basename.
    pub program: String,
    /// Options, matched as written (POSIX options are case-sensitive;
    /// PowerShell ones are compared case-insensitively by the caller).
    pub options: Vec<String>,
}

/// A program whose subcommand starts an agent (`cursor agent`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ProgramSubcommandJSON {
    pub program: String,
    pub subcommand: String,
}

/// A suffix that names a workspace only when the reference also contains a
/// marker (`-claude` in a slug that contains `library`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ConditionalSuffixJSON {
    pub suffix: String,
    pub when_contains: String,
}

/// How a root path, dash-encoded slug or label names the home of a
/// single-workspace agent (its fleet workspace). Matched against the
/// lowercased reference with `/` separators; any matcher decides. The
/// agent's product label (`Codex`) is the supported-agents registry's
/// (`supported_agents::fleet_workspace_display_name`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct FleetWorkspaceReferenceJSON {
    pub agent_type: String,
    /// The whole reference (`.codex`).
    pub equals: Vec<String>,
    /// Anywhere in the reference (`/.codex`, `/documents/codex/`).
    pub contains: Vec<String>,
    /// At the end of the reference (`-codex`).
    pub ends_with: Vec<String>,
    /// At the end, only when the reference also contains a marker.
    pub conditional_suffixes: Vec<ConditionalSuffixJSON>,
}

/// A path prefix another spelling of the same directory uses (macOS
/// `/private/tmp` is `/tmp`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct PathAliasJSON {
    pub prefix: String,
    pub canonical: String,
}

/// Which workspace an agent session is filed under on the Agents view
/// (`agent_workspaces::attribute_session_workspaces`) and what the
/// transcript scanner (`agent_transcripts::launch`) recognizes as an agent
/// launch. Program names, extensions and markers are lowercased by
/// [`AgentVisibilityParams::new_from_json`]; keys, options, roots and
/// labels are kept as written.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct WorkspaceAttributionJSON {
    /// Agent CLIs whose invocation starts a session EDAMAME observes.
    pub agent_cli_programs: Vec<String>,
    /// `program subcommand` pairs that start an agent (`cursor agent`).
    pub agent_cli_subcommands: Vec<ProgramSubcommandJSON>,
    /// Package names / paths that start an agent through a package runner.
    pub agent_cli_package_markers: Vec<String>,
    /// Programs that run a package or script named by their first argument.
    pub package_runner_programs: Vec<String>,
    /// Package managers that run a package through a subcommand.
    pub package_exec_programs: Vec<String>,
    /// Those subcommands (`dlx`, `exec`).
    pub package_exec_subcommands: Vec<String>,
    /// Shells (`bash -c '<script>'` runs `<script>`).
    pub shell_programs: Vec<String>,
    /// The PowerShell shells among them.
    pub powershell_programs: Vec<String>,
    /// PowerShell options whose value is a script (`-Command`).
    pub powershell_script_options: Vec<String>,
    /// Interpreter names by prefix (`python` covers `python3.12`).
    pub interpreter_program_prefixes: Vec<String>,
    /// Programs that run a script in the current shell (`source`, `.`).
    pub source_programs: Vec<String>,
    /// Programs that run the command that follows them (`env`, `nohup`,
    /// `timeout`, `sudo`, ...), and shell keywords that precede a command.
    pub wrapper_programs: Vec<String>,
    /// Wrapper options that take a value as the next word.
    pub wrapper_value_options: Vec<ProgramOptionsJSON>,
    /// Wrappers whose options start with `/` (`cmd /c`).
    pub wrapper_slash_option_programs: Vec<String>,
    /// Wrappers followed by a duration before the command (`timeout 900`).
    pub wrapper_duration_programs: Vec<String>,
    /// Wrappers followed by a window title before the command (`start ""`).
    pub wrapper_title_programs: Vec<String>,
    /// Wrapper options whose value is the command (`Start-Process
    /// -FilePath`).
    pub wrapper_program_options: Vec<ProgramOptionsJSON>,
    /// Options that make a wrapper a lookup, not a run (`command -v`).
    pub lookup_options: Vec<ProgramOptionsJSON>,
    /// Programs that detach what they run from the calling shell.
    pub detaching_programs: Vec<String>,
    /// Programs that change the shell's working directory.
    pub change_directory_programs: Vec<String>,
    /// Extensions a Windows launcher adds to a program name (without dot).
    pub executable_extensions: Vec<String>,
    /// Extensions of files a command can run as a program (without dot).
    pub script_extensions: Vec<String>,
    /// Tool-call argument keys carrying the shell command.
    pub command_keys: Vec<String>,
    /// Tool-call argument keys carrying the command's working directory.
    pub working_directory_keys: Vec<String>,
    /// Tool-call argument keys carrying the path a file write targets.
    pub write_path_keys: Vec<String>,
    /// Tool-call argument keys carrying the written text.
    pub write_content_keys: Vec<String>,
    /// Tool-call argument keys carrying a list of edits (each `new_string`).
    pub write_edit_list_keys: Vec<String>,
    /// Tool-call argument keys whose `true` runs the command in the
    /// background.
    pub background_flag_keys: Vec<String>,
    /// Tool-call argument keys whose `0` returns before the command ends.
    pub background_wait_keys: Vec<String>,
    /// Patch lines naming a file the patch writes.
    pub patch_file_headers: Vec<String>,
    /// Spellings of the home directory in a command (`$HOME`,
    /// `%USERPROFILE%`), matched case-insensitively as a prefix.
    pub home_variables: Vec<String>,
    /// Spellings of the per-user temporary directory (`$TMPDIR`, `%TEMP%`).
    pub temp_variables: Vec<String>,
    /// Claude Code `entrypoint` prefixes of a programmatic start
    /// (`sdk-cli`, `sdk-ts`).
    pub headless_entrypoint_prefixes: Vec<String>,
    /// Codex `session_meta.originator` values of a programmatic start.
    pub headless_originators: Vec<String>,
    /// Codex `session_meta.source` values of a programmatic start.
    pub headless_sources: Vec<String>,
    /// Directory next to a session transcript holding its Task subagents'.
    pub subagent_directory: String,
    /// Temporary roots, `/`-separated: `*` is one path component, `?:` any
    /// drive (`?:/Users/*/AppData/Local/Temp`).
    pub temp_roots: Vec<String>,
    /// Prefixes another spelling of the same directory uses.
    pub path_aliases: Vec<PathAliasJSON>,
    /// Directories whose children are users' homes (`/Users`, `/home`).
    pub home_parent_directories: Vec<String>,
    /// Clock slack around a launch window, in seconds.
    pub launch_clock_slack_secs: u64,
    /// How long after a background launch (or one whose result was never
    /// seen) a child may start and still be attributed to it, in seconds.
    pub background_launch_window_secs: u64,
    /// Subagent transcripts older than the collection window by more than
    /// this are not scanned, in seconds.
    pub subagent_lookback_margin_secs: u64,
    /// Longest launch chain followed (child, parent, grandparent, ...).
    pub max_launch_chain: u64,
    /// Label of the temporary-sessions workspace.
    pub temporary_workspace_label: String,
    /// Short agent names, for labels that name an agent.
    pub agent_labels: std::collections::BTreeMap<String, String>,
    /// Transcript store directories whose child names a project's workspace
    /// slug (`~/.claude/projects/<slug>/...`), matched exactly against path
    /// components.
    pub project_directories: Vec<String>,
    /// References to single-workspace agents' homes, in match order (the
    /// first agent whose matchers hit wins).
    pub fleet_workspace_references: Vec<FleetWorkspaceReferenceJSON>,
}

/// An instruction directory and the component kind its artifacts project to.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct InstructionDirectoryJSON {
    /// One lowercase path component (`skills`), joined as written and
    /// compared with lowercased path components.
    pub directory: String,
    /// Component kind: `rule`, `skill`, `command`, `subagent`, `memory`,
    /// `prompt`, `instruction` or `hook`.
    pub kind: String,
}

/// A workspace-relative instruction file and its component kind.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct InstructionFileJSON {
    /// Path relative to the workspace root (`.github/copilot-instructions.md`).
    pub path: String,
    pub kind: String,
}

/// What the instruction inventory (`agent_visibility`) walks and recognizes:
/// the directories under an agent's own instruction root and under a
/// workspace root, the file names and extensions of instruction artifacts,
/// and the skill package markers. The walk itself (depth, count and size
/// bounds, hidden-entry skipping, symlink handling) stays in code. Extensions
/// and compared file names are lowercased by
/// [`AgentVisibilityParams::new_from_json`]; directories and paths joined
/// onto a root are kept as written.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct InstructionInventoryJSON {
    /// Subdirectories of an agent's instruction root (`~/.cursor`,
    /// `~/.claude`, ...) that hold instruction artifacts. An allowlist: only
    /// these are walked, so transcript and session stores never are.
    pub agent_subdirectories: Vec<InstructionDirectoryJSON>,
    /// Extensions (without the dot) of files the content drill-down may read
    /// under an instruction subdirectory: documents plus the config files a
    /// skill ships.
    pub artifact_extensions: Vec<String>,
    /// Extensions of the instruction documents enumerated into the inventory
    /// (a skill's bundled data, license and state files are not artifacts).
    pub document_extensions: Vec<String>,
    /// File names of top-level instruction files (`claude.md`,
    /// `.cursorrules`), compared lowercased; always loaded.
    pub toplevel_instruction_files: Vec<String>,
    /// Extensions of top-level rule files (`mdc`).
    pub toplevel_rule_extensions: Vec<String>,
    /// Skill entry file names (`skill.md`), instruction-shaped wherever they
    /// resolve.
    pub skill_entry_files: Vec<String>,
    /// Directories whose whole tree is a skill package: any file under them
    /// is readable (a skill bundles scripts and fixtures the agent reads).
    pub skill_tree_directories: Vec<String>,
    /// Instruction roots nested under an agent's instruction root, per agent
    /// type, `/`-separated with `*` for one directory level
    /// (`local-agent-mode-sessions/skills-plugin/*/*`).
    pub nested_roots: std::collections::BTreeMap<String, Vec<String>>,
    /// Instruction files at a workspace root.
    pub workspace_toplevel_files: Vec<InstructionFileJSON>,
    /// Config directories at a workspace root walked like an agent's
    /// instruction root (`.cursor`, `.claude`).
    pub workspace_config_directories: Vec<String>,
    /// Instruction subdirectories directly under a workspace root (narrower
    /// than [`Self::agent_subdirectories`], so ordinary project docs stay
    /// out).
    pub workspace_subdirectories: Vec<InstructionDirectoryJSON>,
}

/// What makes a path-like token in an instruction body a reference to
/// another instruction artifact (`agent_visibility::extract_instruction_refs`,
/// the edges of the skill reference graph). The tokenizer, fenced-block
/// skipping and URL rejection stay in code. All values are lowercased by
/// [`AgentVisibilityParams::new_from_json`].
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct InstructionReferencesJSON {
    /// Well-known instruction file names that are a reference when written
    /// with a path or as an explicit `@` mention (`agents.md`).
    pub basenames: Vec<String>,
    /// Directory segments whose artifacts are folders (`skills/`): the folder
    /// name, or a document under it, is a reference.
    pub folder_segments: Vec<String>,
    /// Directory segments whose artifacts are files (`rules/`): only a
    /// document file under them is a reference.
    pub file_segments: Vec<String>,
    /// Extensions (without the dot) of documents a reference can name. An
    /// artifact extension outside this set is a config file a skill reads,
    /// never a reference.
    pub document_extensions: Vec<String>,
}

/// One agent-governance harness product detected from its per-user footprint
/// (`agent_visibility::detect_agent_harnesses`). Cloud-only control planes
/// with no local footprint are out of scope: there is nothing on the host to
/// detect.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AgentHarnessJSON {
    /// Stable lowercase product slug; also fills `{slug}` in
    /// [`AgentHarnessesJSON::config_directories`].
    pub slug: String,
    pub display_name: String,
    /// Public homepage, where an operator without a harness installs one.
    pub homepage: String,
    /// Extra `$HOME`-relative files or directories of the product's footprint.
    pub markers: Vec<String>,
    /// CLI names looked up in the per-user and system bin directories and on
    /// `$PATH`.
    pub binaries: Vec<String>,
    /// `$HOME`-relative files whose name signals a governed-agent identity
    /// (a W3C DID, a project id), read only when the footprint is present.
    pub identity_files: Vec<String>,
}

/// A directory holding one directory per installed tool version, each with
/// its own bin directory (nvm: `~/.nvm/versions/node/<v>/bin`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct VersionedBinDirectoryJSON {
    /// `$HOME`-relative, `/`-separated.
    pub root: String,
    /// The bin directory inside each version directory.
    pub bin: String,
}

/// One list per desktop platform.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct PlatformListsJSON {
    pub macos: Vec<String>,
    pub linux: Vec<String>,
    pub windows: Vec<String>,
}

/// The agent-governance harness catalog and where their footprints live.
/// Kept as written: slugs, paths, names and keys are matched or joined
/// exactly.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AgentHarnessesJSON {
    pub catalog: Vec<AgentHarnessJSON>,
    /// Standard per-user config locations of every harness, `$HOME`-relative
    /// and `/`-separated, with `{slug}` for the product slug
    /// (`.config/{slug}`, `AppData/Roaming/{slug}`). Checked on every
    /// platform: another platform's directory simply does not exist.
    pub config_directories: Vec<String>,
    /// Per-user bin directories (`$HOME`-relative) where a harness CLI may
    /// live without being on the privileged helper's `$PATH`.
    pub home_bin_directories: Vec<String>,
    /// Version managers' per-version bin directories, newest version name
    /// first.
    pub versioned_bin_directories: Vec<VersionedBinDirectoryJSON>,
    /// System package-manager bin directories searched regardless of
    /// `$PATH` (the helper runs with a minimal one), per platform.
    pub system_bin_directories: PlatformListsJSON,
    /// Extensions (without the dot) a Windows CLI name may carry, tried in
    /// order before the bare name.
    pub windows_binary_extensions: Vec<String>,
    /// JSON keys of an identity file that carry the identity, in order.
    pub identity_keys: Vec<String>,
}

/// A `$HOME`-relative directory whose children are confined apps' data, and
/// the confinement mechanism it implies (`flatpak`, `snap`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ConfinementDirectoryJSON {
    pub directory: String,
    pub mechanism: String,
}

/// Where the OS confinement of an agent shows on disk
/// (`agent_visibility::assess_agent_sandboxes`), where each agent declares
/// its own confinement and enforcement plane, and how Claude Code's approval
/// modes rank. Needles are lowercased by
/// [`AgentVisibilityParams::new_from_json`]; paths, modes and file names are
/// kept as written.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AgentConfinementJSON {
    /// Needles matched against lowercased container / confined-app directory
    /// names, per agent type. Explicit per agent, never derived from the
    /// agent type (`claude` would match Claude Desktop's container for the
    /// Claude Code CLI); a CLI agent has none, a terminal process is never in
    /// an app-sandbox container.
    pub container_name_needles: std::collections::BTreeMap<String, Vec<String>>,
    /// macOS: `$HOME`-relative directories of app-sandbox containers (a
    /// container exists only for an app declaring
    /// `com.apple.security.app-sandbox`).
    pub macos_container_directories: Vec<String>,
    /// macOS: `$HOME`-relative VM bundles that confine an agent's runtime,
    /// per agent type.
    pub macos_vm_bundles: std::collections::BTreeMap<String, Vec<String>>,
    /// Linux: `$HOME`-relative directories of confined apps' data.
    pub linux_confinement_directories: Vec<ConfinementDirectoryJSON>,
    /// The agent's own config file declaring its confinement, approval policy
    /// and enforcement plane, relative to its instruction root
    /// (`SupportedAgentDefinition::resolve_instruction_root_with_home`), per
    /// agent type. The format of each is code.
    pub config_files: std::collections::BTreeMap<String, String>,
    /// Claude Code `permissions.defaultMode` values ranked by how much they
    /// ask the operator (higher is stricter).
    pub permission_mode_ranks: std::collections::BTreeMap<String, u8>,
    /// Rank of a mode missing from `permission_mode_ranks` (an upstream
    /// addition ranks with the default mode, so it never reads as a
    /// weakening on its own).
    pub default_permission_mode_rank: u8,
    /// Per agent type, the values of the agent's own sandbox setting (Cursor
    /// `sandbox.mode`, Codex `sandbox_mode`) that turn command confinement on
    /// ...
    pub sandbox_modes_on: std::collections::BTreeMap<String, Vec<String>>,
    /// ... and off. A value in neither list leaves the sandbox state
    /// unknown, so it never reads as a weakening on its own.
    pub sandbox_modes_off: std::collections::BTreeMap<String, Vec<String>>,
}

/// What the macOS / Linux host-privilege assessment
/// (`agent_visibility::assess_host_privilege`) reads and matches: who is
/// already elevated, which groups make a user an administrator, where the
/// group database and the sudoers policy live, and which commands a
/// passwordless sudo rule may allow before it counts as root
/// (`sudoers_grading`). The sudoers grammar (`NOPASSWD`, tags, aliases,
/// `%group`, `ALL`, `Defaults`) and the Windows well-known SIDs stay in code.
/// Binary names and environment-variable names are lowercased / uppercased
/// by [`AgentVisibilityParams::new_from_json`], the rest kept as written.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct HostPrivilegeJSON {
    /// Users whose session is already elevated (`root`).
    pub elevated_users: Vec<String>,
    /// macOS groups whose members are administrators (`admin`).
    pub macos_admin_groups: Vec<String>,
    /// Linux groups whose members may use sudo (`sudo`, `wheel`, `admin`).
    pub linux_admin_groups: Vec<String>,
    /// Group databases (`name:passwd:gid:members`) read for memberships.
    pub group_files: Vec<String>,
    /// sudoers policy files scanned for a `NOPASSWD` rule.
    pub sudoers_files: Vec<String>,
    /// Directories whose files are sudoers drop-ins scanned the same way.
    pub sudoers_directories: Vec<String>,
    /// Basenames of binaries that reach root when sudo runs them without a
    /// password, whatever arguments the rule names: they open a shell, run a
    /// command, load code, or write / replace / re-permission any file as root
    /// (the GTFOBins sudo set, restricted to those; pure file readers are not
    /// listed). A passwordless rule for one of them grades as passwordless
    /// root; a rule for any other specific command is the lower "passwordless
    /// sudo for N commands" signal. Compared with the lowercased basename.
    pub escalatable_binaries: Vec<String>,
    /// Interpreter and toolchain families that are escalatable under a
    /// version suffix too: `python` covers `python3`, `python3.12` and
    /// `python-3.12` (digits and dots after the name, optionally after a
    /// dash). Compared with the lowercased basename.
    pub escalatable_binary_families: Vec<String>,
    /// Environment variables that let the caller run code inside any command
    /// (`LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `BASH_ENV`, ...). A sudoers
    /// `Defaults env_keep` that keeps one of them makes every passwordless
    /// command root-equivalent. Compared uppercased.
    pub escalatable_environment_variables: Vec<String>,
}

/// Where the MCP servers an agent acquires outside its global MCP config are
/// declared (`agent_visibility::discover_mcp_endpoints`): plugin trees,
/// project-scoped configs, installed-plugin manifests and extensions. Paths
/// are `/`-separated and relative to the named agent's instruction root (the
/// supported-agents registry's `resolve_instruction_root_with_home`, which
/// owns the roots and the global MCP configs); the config formats stay in
/// code. Suffixes are lowercased by [`AgentVisibilityParams::new_from_json`],
/// the rest kept as written.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct McpDiscoveryJSON {
    /// Suffixes of plugin-tree files that declare MCP servers (`mcp.json`
    /// covers `.mcp.json` and `.cursor-mcp.json`), compared with the
    /// lowercased file name.
    pub plugin_config_suffixes: Vec<String>,
    /// Directory names pruned from a plugin-tree walk (vendored and VCS
    /// trees that never carry a plugin's own MCP config).
    pub plugin_skip_directories: Vec<String>,
    /// Cursor plugin trees, walked for MCP configs.
    pub cursor_plugin_directories: Vec<String>,
    /// Claude Code installed-plugins manifests naming each installed plugin's
    /// path (its marketplace catalog is never walked blind).
    pub claude_code_plugin_manifests: Vec<String>,
    /// Claude Code project directories whose dash-encoded children name
    /// project roots.
    pub claude_code_project_directories: Vec<String>,
    /// Project-scoped MCP config files, relative to a project root.
    pub claude_code_project_config_files: Vec<String>,
    /// Claude Desktop extension directories.
    pub claude_desktop_extension_directories: Vec<String>,
    /// The manifest inside each Claude Desktop extension.
    pub claude_desktop_extension_manifest: String,
    /// OpenClaw extension directories.
    pub openclaw_extension_directories: Vec<String>,
    /// The manifest inside each OpenClaw extension.
    pub openclaw_extension_manifest: String,
}

/// The header and environment-variable names that mark an MCP server entry
/// as carrying a credential, so its authentication is a shared secret
/// (`agent_visibility::classify_auth`). Header markers are lowercased and
/// environment-variable needles uppercased by
/// [`AgentVisibilityParams::new_from_json`].
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct McpCredentialMarkersJSON {
    /// Header names that carry a credential (`authorization`), compared whole
    /// with the lowercased header name.
    pub header_names: Vec<String>,
    /// Substrings of a header name that carries a credential (`api-key`,
    /// `token`).
    pub header_needles: Vec<String>,
    /// Substrings of an environment-variable name passed to the server that
    /// make it a credential (`TOKEN`, `SECRET`). A plain substring test, unlike
    /// the `_`-bounded [`AgentVisibilityParamsJSON::agent_secret_env_key_needles`]
    /// of the component inventory.
    pub env_key_needles: Vec<String>,
}

/// The agent vocabulary that marks a sub-agent spawn in a transcript, for the
/// recursion / delegation visibility finding
/// (`agent_visibility::extract_spawn_markers`). The transcript line structure
/// (`uuid` / `parentUuid` linkage, the `isSidechain` flag, `tool_use` content
/// blocks, `name` / `input`) stays in code. Tool names and text markers are
/// lowercased by [`AgentVisibilityParams::new_from_json`]; keys are matched
/// as written.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct DelegationMarkersJSON {
    /// Tool names whose call spawns a sub-agent (`task`), compared with the
    /// lowercased tool name.
    pub spawn_tool_names: Vec<String>,
    /// Tool-call input keys (and top-level record keys) naming the sub-agent
    /// or delegate (`subagent_type`); their presence marks a spawn, and the
    /// first present one is the spawn reason.
    pub spawn_target_keys: Vec<String>,
    /// Tool-call input keys carrying the delegated goal, in order.
    pub spawn_goal_keys: Vec<String>,
    /// Markers of a spawn in a plain-text transcript line, compared with the
    /// lowercased line.
    pub text_markers: Vec<String>,
    /// Keys whose value follows them in a plain-text line and names the
    /// spawn reason, in order.
    pub text_reason_keys: Vec<String>,
}

/// One agent type's own model traffic.
///
/// `llm_hosts` is what the transcript parser declares as the agent's model
/// traffic on every session it collects (`agent_transcripts::parsing::
/// extract_traffic`): `host:port` (a bare host means `:443`), shared cloud
/// suffixes the provider is reached through, and `asn:OWNER` entries, kept
/// as written. `provider_endpoints` are the dedicated model-API endpoints
/// among them (`host:port`, lowercased by
/// [`AgentVisibilityParams::new_from_json`]): the divergence engine never
/// applies a declared not-expected traffic pattern to the agent's session
/// to one of them or to a subdomain of one, because a human's "do not access
/// the network" governs the agent's task, not the harness talking to its own
/// model provider. Shared cloud suffixes and ASN owners stay out of
/// `provider_endpoints`, so a prohibition still covers the agent's tool
/// traffic to them.
///
/// Claude Code's `llm_hosts` cover Bedrock (`amazonaws.com`, and
/// `asn:AMAZON` for sessions that resolve only to an address without
/// reverse DNS) and Vertex AI (`googleapis.com`, `asn:GOOGLE`); Cursor's
/// mirror `cursorLlmHosts` in `edamame_cursor/service/config.mjs`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AgentLlmTrafficJSON {
    pub llm_hosts: Vec<String>,
    pub provider_endpoints: Vec<String>,
}

/// Raw JSON shape of `agent-visibility-params-db.json`. No serde defaults:
/// the published JSON always carries every field; a missing field fails the
/// parse and the embedded snapshot (which has all fields) stays in effect.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AgentVisibilityParamsJSON {
    pub date: String,
    pub signature: String,
    /// High-precision, vendor-anchored secret signatures for agent
    /// TRANSCRIPT text (BR-1). Tighter than the file-scan list: transcripts
    /// legitimately discuss keys all day, so only vendor prefixes and PEM
    /// headers qualify.
    pub transcript_secret_signatures: Vec<SecretContentSignatureJSON>,
    /// Deterministic prompt-injection bait phrase signatures for agent
    /// TRANSCRIPT text (BR-2).
    pub prompt_injection_signatures: Vec<SecretContentSignatureJSON>,
    /// Critical-subprocess classes for the agent subprocess visibility
    /// surface (blast-radius computation).
    pub agent_critical_subprocess_catalog: Vec<CriticalSubprocessClassJSON>,
    /// Needles that mark an agent environment-variable key as
    /// secret-bearing (matched uppercased).
    pub agent_secret_env_key_needles: Vec<String>,
    /// Model-id prefixes used to recognize an LLM model family (lowercased).
    pub agent_model_family_prefixes: Vec<String>,
    /// Case-sensitive JSON field keys carrying the model identifier.
    pub agent_model_field_keys: Vec<String>,
    /// Case-sensitive JSON container keys the model-id extractor descends into.
    pub agent_model_container_keys: Vec<String>,
    /// Per-class keyword lists used to classify MCP tool privileges.
    pub agent_tool_privilege_keywords: AgentToolPrivilegeKeywordsJSON,
    /// Thresholds for the recursion / delegation visibility finding.
    pub agent_recursion_thresholds: AgentRecursionThresholdsJSON,
    /// Per-model USD-per-1M-token price table (agent-transcript economics).
    pub model_pricing: ModelPricingJSON,
    /// Next-step prompt templates for the augmentation path (verbatim).
    pub augmentation_prompt_templates: Vec<AugmentationPromptTemplateJSON>,
    /// Enlightenment Coach templates (verbatim).
    pub augmentation_coach_templates: Vec<AugmentationCoachTemplateJSON>,
    /// Unified history-retention policy for the agent history stores.
    pub history_retention: HistoryRetentionJSON,
    /// Workspace attribution of agent sessions (see
    /// [`WorkspaceAttributionJSON`]).
    pub workspace_attribution: WorkspaceAttributionJSON,
    /// Instruction inventory rules (see [`InstructionInventoryJSON`]).
    pub instruction_inventory: InstructionInventoryJSON,
    /// Instruction reference rules (see [`InstructionReferencesJSON`]).
    pub instruction_references: InstructionReferencesJSON,
    /// Agent-governance harness catalog (see [`AgentHarnessesJSON`]).
    pub agent_harnesses: AgentHarnessesJSON,
    /// Agent confinement rules (see [`AgentConfinementJSON`]).
    pub agent_confinement: AgentConfinementJSON,
    /// Host-privilege assessment rules (see [`HostPrivilegeJSON`]).
    pub host_privilege: HostPrivilegeJSON,
    /// MCP discovery locations (see [`McpDiscoveryJSON`]).
    pub mcp_discovery: McpDiscoveryJSON,
    /// MCP credential markers (see [`McpCredentialMarkersJSON`]).
    pub mcp_credential_markers: McpCredentialMarkersJSON,
    /// Sub-agent spawn markers (see [`DelegationMarkersJSON`]).
    pub delegation_markers: DelegationMarkersJSON,
    /// Per agent type, the agent's own model traffic (see
    /// [`AgentLlmTrafficJSON`]).
    pub agent_llm_traffic: std::collections::BTreeMap<String, AgentLlmTrafficJSON>,
}

/// Normalized runtime snapshot of the agent-visibility params.
#[derive(Clone)]
pub struct AgentVisibilityParams {
    pub date: String,
    pub signature: String,
    pub transcript_secret_signatures: Vec<SecretContentSignatureJSON>,
    pub prompt_injection_signatures: Vec<SecretContentSignatureJSON>,
    pub agent_critical_subprocess_catalog: Vec<CriticalSubprocessClassJSON>,
    pub agent_secret_env_key_needles: Vec<String>,
    pub agent_model_family_prefixes: Vec<String>,
    pub agent_model_field_keys: Vec<String>,
    pub agent_model_container_keys: Vec<String>,
    pub agent_tool_privilege_keywords: AgentToolPrivilegeKeywordsJSON,
    pub agent_recursion_thresholds: AgentRecursionThresholdsJSON,
    /// Per-model price table with `match_substring` lowercased for matching.
    pub model_pricing: ModelPricingJSON,
    /// Next-step prompt templates for the augmentation path (verbatim).
    pub augmentation_prompt_templates: Vec<AugmentationPromptTemplateJSON>,
    /// Enlightenment Coach templates (verbatim).
    pub augmentation_coach_templates: Vec<AugmentationCoachTemplateJSON>,
    /// Unified history-retention policy for the agent history stores.
    pub history_retention: HistoryRetentionJSON,
    /// Workspace attribution, program names / extensions / markers
    /// lowercased.
    pub workspace_attribution: WorkspaceAttributionJSON,
    /// Instruction inventory rules, extensions and compared names lowercased.
    pub instruction_inventory: InstructionInventoryJSON,
    /// Instruction reference rules, lowercased.
    pub instruction_references: InstructionReferencesJSON,
    /// Agent-governance harness catalog, as written.
    pub agent_harnesses: AgentHarnessesJSON,
    /// Agent confinement rules, needles lowercased.
    pub agent_confinement: AgentConfinementJSON,
    /// Host-privilege assessment rules, binary names lowercased and
    /// environment-variable names uppercased.
    pub host_privilege: HostPrivilegeJSON,
    /// MCP discovery locations, suffixes lowercased.
    pub mcp_discovery: McpDiscoveryJSON,
    /// MCP credential markers, header markers lowercased and
    /// environment-variable needles uppercased.
    pub mcp_credential_markers: McpCredentialMarkersJSON,
    /// Sub-agent spawn markers, tool names and text markers lowercased.
    pub delegation_markers: DelegationMarkersJSON,
    /// Per agent type, its own model traffic: `llm_hosts` as written (the
    /// parser declares them verbatim), `provider_endpoints` lowercased.
    pub agent_llm_traffic: std::collections::BTreeMap<String, AgentLlmTrafficJSON>,
}

impl CloudSignature for AgentVisibilityParams {
    fn get_signature(&self) -> String {
        self.signature.clone()
    }
    fn set_signature(&mut self, signature: String) {
        self.signature = signature;
    }
}

fn normalize_signature_list(
    signatures: &[SecretContentSignatureJSON],
) -> Vec<SecretContentSignatureJSON> {
    signatures
        .iter()
        .map(|sig| SecretContentSignatureJSON {
            label: sig.label.clone(),
            mode: sig.mode.to_ascii_lowercase(),
            hits: sig.hits,
            per_marker: sig.per_marker,
            markers: sig.markers.iter().map(|m| m.to_ascii_lowercase()).collect(),
        })
        .collect()
}

fn normalize_agent_tool_privilege_keywords(
    keywords: &AgentToolPrivilegeKeywordsJSON,
) -> AgentToolPrivilegeKeywordsJSON {
    let lower =
        |xs: &[String]| -> Vec<String> { xs.iter().map(|x| x.to_ascii_lowercase()).collect() };
    AgentToolPrivilegeKeywordsJSON {
        shell: lower(&keywords.shell),
        filesystem_write: lower(&keywords.filesystem_write),
        filesystem_read: lower(&keywords.filesystem_read),
        browser: lower(&keywords.browser),
        git: lower(&keywords.git),
        database: lower(&keywords.database),
        secret_access: lower(&keywords.secret_access),
        network: lower(&keywords.network),
    }
}

/// Lowercases every entry's `match_substring` so resolution against a
/// lowercased model id is consistent regardless of how the JSON was cased.
/// The `default` entry's `match_substring` is ignored at runtime but is
/// lowercased too for uniformity.
fn normalize_model_pricing(pricing: &ModelPricingJSON) -> ModelPricingJSON {
    let lower_entry = |e: &ModelPriceEntryJSON| ModelPriceEntryJSON {
        input: e.input,
        output: e.output,
        cache_write: e.cache_write,
        cache_read: e.cache_read,
        match_substring: e.match_substring.to_ascii_lowercase(),
    };
    ModelPricingJSON {
        default: lower_entry(&pricing.default),
        entries: pricing.entries.iter().map(lower_entry).collect(),
    }
}

/// Lowercases what the launch recognizer compares case-insensitively:
/// program names, extensions, package markers, variable spellings and the
/// start markers, and the fleet-workspace matchers (compared with a
/// lowercased reference). Keys, options, roots, project directories and
/// labels are kept as written.
fn normalize_workspace_attribution(w: &WorkspaceAttributionJSON) -> WorkspaceAttributionJSON {
    let lower =
        |xs: &[String]| -> Vec<String> { xs.iter().map(|x| x.to_ascii_lowercase()).collect() };
    let lower_programs = |xs: &[ProgramOptionsJSON]| -> Vec<ProgramOptionsJSON> {
        xs.iter()
            .map(|p| ProgramOptionsJSON {
                program: p.program.to_ascii_lowercase(),
                options: p.options.clone(),
            })
            .collect()
    };
    WorkspaceAttributionJSON {
        agent_cli_programs: lower(&w.agent_cli_programs),
        agent_cli_subcommands: w
            .agent_cli_subcommands
            .iter()
            .map(|c| ProgramSubcommandJSON {
                program: c.program.to_ascii_lowercase(),
                subcommand: c.subcommand.to_ascii_lowercase(),
            })
            .collect(),
        agent_cli_package_markers: lower(&w.agent_cli_package_markers),
        package_runner_programs: lower(&w.package_runner_programs),
        package_exec_programs: lower(&w.package_exec_programs),
        package_exec_subcommands: lower(&w.package_exec_subcommands),
        shell_programs: lower(&w.shell_programs),
        powershell_programs: lower(&w.powershell_programs),
        powershell_script_options: lower(&w.powershell_script_options),
        interpreter_program_prefixes: lower(&w.interpreter_program_prefixes),
        source_programs: lower(&w.source_programs),
        wrapper_programs: lower(&w.wrapper_programs),
        wrapper_value_options: lower_programs(&w.wrapper_value_options),
        wrapper_slash_option_programs: lower(&w.wrapper_slash_option_programs),
        wrapper_duration_programs: lower(&w.wrapper_duration_programs),
        wrapper_title_programs: lower(&w.wrapper_title_programs),
        wrapper_program_options: lower_programs(&w.wrapper_program_options),
        lookup_options: lower_programs(&w.lookup_options),
        detaching_programs: lower(&w.detaching_programs),
        change_directory_programs: lower(&w.change_directory_programs),
        executable_extensions: lower(&w.executable_extensions),
        script_extensions: lower(&w.script_extensions),
        command_keys: w.command_keys.clone(),
        working_directory_keys: w.working_directory_keys.clone(),
        write_path_keys: w.write_path_keys.clone(),
        write_content_keys: w.write_content_keys.clone(),
        write_edit_list_keys: w.write_edit_list_keys.clone(),
        background_flag_keys: w.background_flag_keys.clone(),
        background_wait_keys: w.background_wait_keys.clone(),
        patch_file_headers: w.patch_file_headers.clone(),
        home_variables: lower(&w.home_variables),
        temp_variables: lower(&w.temp_variables),
        headless_entrypoint_prefixes: lower(&w.headless_entrypoint_prefixes),
        headless_originators: lower(&w.headless_originators),
        headless_sources: lower(&w.headless_sources),
        subagent_directory: w.subagent_directory.clone(),
        temp_roots: w.temp_roots.clone(),
        path_aliases: w.path_aliases.clone(),
        home_parent_directories: w.home_parent_directories.clone(),
        launch_clock_slack_secs: w.launch_clock_slack_secs,
        background_launch_window_secs: w.background_launch_window_secs,
        subagent_lookback_margin_secs: w.subagent_lookback_margin_secs,
        max_launch_chain: w.max_launch_chain,
        temporary_workspace_label: w.temporary_workspace_label.clone(),
        agent_labels: w.agent_labels.clone(),
        project_directories: w.project_directories.clone(),
        fleet_workspace_references: w
            .fleet_workspace_references
            .iter()
            .map(|r| FleetWorkspaceReferenceJSON {
                agent_type: r.agent_type.clone(),
                equals: lower(&r.equals),
                contains: lower(&r.contains),
                ends_with: lower(&r.ends_with),
                conditional_suffixes: r
                    .conditional_suffixes
                    .iter()
                    .map(|c| ConditionalSuffixJSON {
                        suffix: c.suffix.to_ascii_lowercase(),
                        when_contains: c.when_contains.to_ascii_lowercase(),
                    })
                    .collect(),
            })
            .collect(),
    }
}

/// Lowercases the extensions and the file and directory names the inventory
/// compares with lowercased names. Directories and paths joined onto a root
/// are kept as written.
fn normalize_instruction_inventory(i: &InstructionInventoryJSON) -> InstructionInventoryJSON {
    let lower =
        |xs: &[String]| -> Vec<String> { xs.iter().map(|x| x.to_ascii_lowercase()).collect() };
    InstructionInventoryJSON {
        agent_subdirectories: i.agent_subdirectories.clone(),
        artifact_extensions: lower(&i.artifact_extensions),
        document_extensions: lower(&i.document_extensions),
        toplevel_instruction_files: lower(&i.toplevel_instruction_files),
        toplevel_rule_extensions: lower(&i.toplevel_rule_extensions),
        skill_entry_files: lower(&i.skill_entry_files),
        skill_tree_directories: lower(&i.skill_tree_directories),
        nested_roots: i.nested_roots.clone(),
        workspace_toplevel_files: i.workspace_toplevel_files.clone(),
        workspace_config_directories: i.workspace_config_directories.clone(),
        workspace_subdirectories: i.workspace_subdirectories.clone(),
    }
}

/// Lowercases the container name needles (compared with lowercased directory
/// names); everything else is kept as written.
fn normalize_agent_confinement(c: &AgentConfinementJSON) -> AgentConfinementJSON {
    AgentConfinementJSON {
        container_name_needles: c
            .container_name_needles
            .iter()
            .map(|(agent, needles)| {
                (
                    agent.clone(),
                    needles.iter().map(|n| n.to_ascii_lowercase()).collect(),
                )
            })
            .collect(),
        ..c.clone()
    }
}

/// Lowercases the escalatable binary names and families (compared with a
/// lowercased basename) and uppercases the escalatable environment variables;
/// users, groups and paths are kept as written.
fn normalize_host_privilege(h: &HostPrivilegeJSON) -> HostPrivilegeJSON {
    let lower =
        |xs: &[String]| -> Vec<String> { xs.iter().map(|x| x.to_ascii_lowercase()).collect() };
    HostPrivilegeJSON {
        escalatable_binaries: lower(&h.escalatable_binaries),
        escalatable_binary_families: lower(&h.escalatable_binary_families),
        escalatable_environment_variables: h
            .escalatable_environment_variables
            .iter()
            .map(|v| v.to_ascii_uppercase())
            .collect(),
        ..h.clone()
    }
}

/// Lowercases every reference rule: tokens are compared lowercased.
fn normalize_instruction_references(r: &InstructionReferencesJSON) -> InstructionReferencesJSON {
    let lower =
        |xs: &[String]| -> Vec<String> { xs.iter().map(|x| x.to_ascii_lowercase()).collect() };
    InstructionReferencesJSON {
        basenames: lower(&r.basenames),
        folder_segments: lower(&r.folder_segments),
        file_segments: lower(&r.file_segments),
        document_extensions: lower(&r.document_extensions),
    }
}

impl AgentVisibilityParams {
    pub fn new_from_json(json: &AgentVisibilityParamsJSON) -> Self {
        let lower =
            |xs: &[String]| -> Vec<String> { xs.iter().map(|x| x.to_ascii_lowercase()).collect() };
        Self {
            date: json.date.clone(),
            signature: json.signature.clone(),
            transcript_secret_signatures: normalize_signature_list(
                &json.transcript_secret_signatures,
            ),
            prompt_injection_signatures: normalize_signature_list(
                &json.prompt_injection_signatures,
            ),
            agent_critical_subprocess_catalog: json
                .agent_critical_subprocess_catalog
                .iter()
                .map(|class| CriticalSubprocessClassJSON {
                    names: class.names.iter().map(|n| n.to_ascii_lowercase()).collect(),
                    category: class.category.clone(),
                    criticality: class.criticality.to_ascii_lowercase(),
                    owasp_refs: class.owasp_refs.clone(),
                })
                .collect(),
            agent_secret_env_key_needles: json
                .agent_secret_env_key_needles
                .iter()
                .map(|n| n.to_ascii_uppercase())
                .collect(),
            agent_model_family_prefixes: json
                .agent_model_family_prefixes
                .iter()
                .map(|p| p.to_ascii_lowercase())
                .collect(),
            // Field/container keys are matched case-sensitively against raw
            // JSON keys (`modelId`), so they are NOT normalized.
            agent_model_field_keys: json.agent_model_field_keys.clone(),
            agent_model_container_keys: json.agent_model_container_keys.clone(),
            agent_tool_privilege_keywords: normalize_agent_tool_privilege_keywords(
                &json.agent_tool_privilege_keywords,
            ),
            agent_recursion_thresholds: json.agent_recursion_thresholds.clone(),
            model_pricing: normalize_model_pricing(&json.model_pricing),
            augmentation_prompt_templates: json.augmentation_prompt_templates.clone(),
            augmentation_coach_templates: json.augmentation_coach_templates.clone(),
            history_retention: json.history_retention,
            workspace_attribution: normalize_workspace_attribution(&json.workspace_attribution),
            instruction_inventory: normalize_instruction_inventory(&json.instruction_inventory),
            instruction_references: normalize_instruction_references(&json.instruction_references),
            agent_harnesses: json.agent_harnesses.clone(),
            agent_confinement: normalize_agent_confinement(&json.agent_confinement),
            host_privilege: normalize_host_privilege(&json.host_privilege),
            mcp_discovery: McpDiscoveryJSON {
                plugin_config_suffixes: json
                    .mcp_discovery
                    .plugin_config_suffixes
                    .iter()
                    .map(|suffix| suffix.to_ascii_lowercase())
                    .collect(),
                ..json.mcp_discovery.clone()
            },
            mcp_credential_markers: McpCredentialMarkersJSON {
                header_names: lower(&json.mcp_credential_markers.header_names),
                header_needles: lower(&json.mcp_credential_markers.header_needles),
                env_key_needles: json
                    .mcp_credential_markers
                    .env_key_needles
                    .iter()
                    .map(|n| n.to_ascii_uppercase())
                    .collect(),
            },
            delegation_markers: DelegationMarkersJSON {
                spawn_tool_names: lower(&json.delegation_markers.spawn_tool_names),
                spawn_target_keys: json.delegation_markers.spawn_target_keys.clone(),
                spawn_goal_keys: json.delegation_markers.spawn_goal_keys.clone(),
                text_markers: lower(&json.delegation_markers.text_markers),
                text_reason_keys: lower(&json.delegation_markers.text_reason_keys),
            },
            agent_llm_traffic: json
                .agent_llm_traffic
                .iter()
                .map(|(agent, traffic)| {
                    (
                        agent.clone(),
                        AgentLlmTrafficJSON {
                            llm_hosts: traffic.llm_hosts.clone(),
                            provider_endpoints: lower(&traffic.provider_endpoints),
                        },
                    )
                })
                .collect(),
        }
    }
}

fn build_fallback_params() -> AgentVisibilityParams {
    let json: AgentVisibilityParamsJSON = serde_json::from_str(&AGENT_VISIBILITY_PARAMS_DB)
        .expect("Built-in agent-visibility-params-db.json must be valid");
    AgentVisibilityParams::new_from_json(&json)
}

lazy_static! {
    pub static ref AGENT_VISIBILITY_PARAMS: CloudModel<AgentVisibilityParams> = {
        let model = CloudModel::initialize(
            AGENT_VISIBILITY_PARAMS_NAME.to_string(),
            &AGENT_VISIBILITY_PARAMS_DB,
            |data| {
                let json: AgentVisibilityParamsJSON = serde_json::from_str(data)
                    .with_context(|| "Failed to parse agent visibility params JSON")?;
                Ok(AgentVisibilityParams::new_from_json(&json))
            },
        );
        match model {
            Ok(m) => m,
            Err(e) => {
                eprintln!(
                    "FATAL: Failed to initialize CloudModel for agent visibility params: {:?}",
                    e
                );
                panic!(
                    "Failed to initialize CloudModel for agent visibility params: {:?}",
                    e
                );
            }
        }
    };
    static ref PARAMS_SNAPSHOT: ArcSwap<AgentVisibilityParams> =
        ArcSwap::from_pointee(build_fallback_params());
}

async fn refresh_params_snapshot() {
    let db = AGENT_VISIBILITY_PARAMS.data.read().await;
    PARAMS_SNAPSHOT.store(Arc::new(db.clone()));
}

pub async fn update(branch: &str, force: bool) -> Result<UpdateStatus> {
    info!("Starting agent visibility params update from backend");

    let status = AGENT_VISIBILITY_PARAMS
        .update(branch, force, |data| {
            let json: AgentVisibilityParamsJSON = serde_json::from_str(data)?;
            Ok(AgentVisibilityParams::new_from_json(&json))
        })
        .await?;

    match status {
        UpdateStatus::Updated => {
            info!("Agent visibility params were successfully updated.");
            refresh_params_snapshot().await;
        }
        UpdateStatus::NotUpdated => info!("Agent visibility params are already up to date."),
        UpdateStatus::FormatError => {
            warn!("There was a format error in the agent visibility params data.")
        }
        UpdateStatus::SkippedCustom => {
            info!("Update skipped because custom agent visibility params are in use.")
        }
    }

    Ok(status)
}

pub fn params() -> Arc<AgentVisibilityParams> {
    PARAMS_SNAPSHOT.load().clone()
}

/// High-precision, vendor-anchored secret signatures for agent TRANSCRIPT
/// text (BR-1). Markers already lowercased. Every entry is "definite" tier:
/// one hit marks the session as secret-exposed.
pub fn transcript_secret_signatures() -> Vec<SecretContentSignatureJSON> {
    PARAMS_SNAPSHOT.load().transcript_secret_signatures.clone()
}

/// Deterministic prompt-injection bait phrase signatures for agent
/// TRANSCRIPT text (BR-2). Markers already lowercased. A hit means bait
/// text entered the agent's context window (OWASP ASI01/LLM01 leading
/// indicator).
pub fn prompt_injection_signatures() -> Vec<SecretContentSignatureJSON> {
    PARAMS_SNAPSHOT.load().prompt_injection_signatures.clone()
}

/// Critical-subprocess catalog (names + criticality lowercased) for the
/// agent subprocess visibility surface (blast-radius computation).
pub fn agent_critical_subprocess_catalog() -> Vec<CriticalSubprocessClassJSON> {
    PARAMS_SNAPSHOT
        .load()
        .agent_critical_subprocess_catalog
        .clone()
}

/// Uppercased needles that mark an agent environment-variable key as
/// secret-bearing.
pub fn agent_secret_env_key_needles() -> Vec<String> {
    PARAMS_SNAPSHOT.load().agent_secret_env_key_needles.clone()
}

/// Lowercased model-id prefixes used to recognize an LLM model family.
pub fn agent_model_family_prefixes() -> Vec<String> {
    PARAMS_SNAPSHOT.load().agent_model_family_prefixes.clone()
}

/// Case-sensitive JSON field keys carrying the model identifier.
pub fn agent_model_field_keys() -> Vec<String> {
    PARAMS_SNAPSHOT.load().agent_model_field_keys.clone()
}

/// Case-sensitive JSON container keys the model-id extractor descends into.
pub fn agent_model_container_keys() -> Vec<String> {
    PARAMS_SNAPSHOT.load().agent_model_container_keys.clone()
}

/// Per-class keyword lists (lowercased) used to classify MCP tool
/// privileges from a tool's name/description/URL.
pub fn agent_tool_privilege_keywords() -> AgentToolPrivilegeKeywordsJSON {
    PARAMS_SNAPSHOT.load().agent_tool_privilege_keywords.clone()
}

/// Thresholds for the agent recursion / delegation visibility finding.
pub fn agent_recursion_thresholds() -> AgentRecursionThresholdsJSON {
    PARAMS_SNAPSHOT.load().agent_recursion_thresholds.clone()
}

/// The full per-model price table (match substrings already lowercased).
pub fn model_pricing() -> ModelPricingJSON {
    PARAMS_SNAPSHOT.load().model_pricing.clone()
}

/// Next-step prompt templates for the augmentation path: per-issue-kind
/// ready-to-paste agent prompts with `{placeholder}` tokens the caller fills
/// deterministically from report data (CloudModel-refreshable wording).
pub fn augmentation_prompt_templates() -> Vec<AugmentationPromptTemplateJSON> {
    PARAMS_SNAPSHOT.load().augmentation_prompt_templates.clone()
}

/// Enlightenment Coach templates: per-lens focus instructions for the
/// guardrailed LLM coaching layer (CloudModel-refreshable; `version` is part
/// of the insight cache key so a wording bump invalidates cached envelopes).
pub fn augmentation_coach_templates() -> Vec<AugmentationCoachTemplateJSON> {
    PARAMS_SNAPSHOT.load().augmentation_coach_templates.clone()
}

/// Unified history-retention policy (age cap in days + per-store entry caps)
/// applied by the agent history stores.
pub fn history_retention() -> HistoryRetentionJSON {
    PARAMS_SNAPSHOT.load().history_retention
}

/// Workspace attribution rules: the agent-CLI launch vocabulary, start
/// markers, temporary roots, path conventions, windows and labels (program
/// names, extensions and markers lowercased). One snapshot per call, so a
/// caller reads a consistent set while it scans.
pub fn workspace_attribution() -> Arc<AgentVisibilityParams> {
    PARAMS_SNAPSHOT.load().clone()
}

/// Instruction inventory rules: the instruction directories, file names,
/// extensions and skill package markers the Agents view's inventory walks
/// and recognizes (extensions and compared names lowercased).
pub fn instruction_inventory() -> InstructionInventoryJSON {
    PARAMS_SNAPSHOT.load().instruction_inventory.clone()
}

/// Instruction reference rules: what makes a path in an instruction body a
/// reference to another instruction artifact (lowercased).
pub fn instruction_references() -> InstructionReferencesJSON {
    PARAMS_SNAPSHOT.load().instruction_references.clone()
}

/// The agent-governance harness catalog: products, footprint markers, CLI
/// names, identity files, and the bin and config directories searched.
pub fn agent_harnesses() -> AgentHarnessesJSON {
    PARAMS_SNAPSHOT.load().agent_harnesses.clone()
}

/// Agent confinement rules: OS confinement markers, the agents' own config
/// files, and Claude Code's approval-mode ranking (needles lowercased).
pub fn agent_confinement() -> AgentConfinementJSON {
    PARAMS_SNAPSHOT.load().agent_confinement.clone()
}

/// Host-privilege assessment rules: elevated users, administrator groups, the
/// group database and sudoers policy locations, and the escalatable binaries
/// and environment variables a passwordless sudo rule is graded against.
pub fn host_privilege() -> HostPrivilegeJSON {
    PARAMS_SNAPSHOT.load().host_privilege.clone()
}

/// MCP discovery locations: plugin trees, project configs, installed-plugin
/// manifests and extensions (suffixes lowercased).
pub fn mcp_discovery() -> McpDiscoveryJSON {
    PARAMS_SNAPSHOT.load().mcp_discovery.clone()
}

/// MCP credential markers: header and environment-variable names that make a
/// server's authentication a shared secret.
pub fn mcp_credential_markers() -> McpCredentialMarkersJSON {
    PARAMS_SNAPSHOT.load().mcp_credential_markers.clone()
}

/// Sub-agent spawn markers of a transcript: spawn tool names, target and
/// goal keys, and the plain-text markers (names and markers lowercased).
pub fn delegation_markers() -> DelegationMarkersJSON {
    PARAMS_SNAPSHOT.load().delegation_markers.clone()
}

/// The model traffic the transcript parser declares for `agent_type` (the
/// collector's agent type, `claude_code`, `codex`, ...), as written: hosts,
/// shared cloud suffixes and `asn:OWNER` entries. Empty for an agent type the
/// params do not list.
pub fn agent_llm_hosts(agent_type: &str) -> Vec<String> {
    PARAMS_SNAPSHOT
        .load()
        .agent_llm_traffic
        .get(agent_type)
        .map(|traffic| traffic.llm_hosts.clone())
        .unwrap_or_default()
}

/// `agent_type`'s own model-provider endpoints (lowercased `host:port`): a
/// declared not-expected traffic pattern never applies to the agent's
/// session to one of them. Empty for an agent type the params do not list.
pub fn agent_provider_endpoints(agent_type: &str) -> Vec<String> {
    PARAMS_SNAPSHOT
        .load()
        .agent_llm_traffic
        .get(agent_type)
        .map(|traffic| traffic.provider_endpoints.clone())
        .unwrap_or_default()
}

/// The params signature of the current snapshot: a scan state computed under
/// another vocabulary is recomputed.
pub fn params_signature() -> String {
    PARAMS_SNAPSHOT.load().signature.clone()
}

/// Resolve the USD-per-1M-token price for a model id using longest /
/// most-specific `match_substring` matching against the lowercased id.
///
/// Among all entries whose lowercased `match_substring` is a substring of
/// the lowercased model id, the entry with the LONGEST `match_substring`
/// wins (so `gpt-4o` beats a hypothetical `gpt`); ties keep the
/// earlier-declared entry. When nothing matches, the `default` rate is
/// returned with `is_fallback = true` so the caller can flag the derived
/// cost as a coarse estimate for an unrecognized model (G3).
pub fn resolve_model_price(model: &str) -> ResolvedModelPrice {
    let snapshot = PARAMS_SNAPSHOT.load();
    let pricing = &snapshot.model_pricing;
    let m = model.to_ascii_lowercase();

    let mut best: Option<&ModelPriceEntryJSON> = None;
    for entry in &pricing.entries {
        if entry.match_substring.is_empty() {
            continue;
        }
        if m.contains(entry.match_substring.as_str()) {
            let longer_than_best = match best {
                Some(b) => entry.match_substring.len() > b.match_substring.len(),
                None => true,
            };
            if longer_than_best {
                best = Some(entry);
            }
        }
    }

    match best {
        Some(e) => ResolvedModelPrice {
            input: e.input,
            output: e.output,
            cache_write: e.cache_write,
            cache_read: e.cache_read,
            is_fallback: false,
        },
        None => {
            let d = &pricing.default;
            ResolvedModelPrice {
                input: d.input,
                output: d.output,
                cache_write: d.cache_write,
                cache_read: d.cache_read,
                is_fallback: true,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn model_price_entry(
        input: f64,
        output: f64,
        cache_write: f64,
        cache_read: f64,
        match_substring: &str,
    ) -> ModelPriceEntryJSON {
        ModelPriceEntryJSON {
            input,
            output,
            cache_write,
            cache_read,
            match_substring: match_substring.to_string(),
        }
    }

    /// The embedded snapshot MUST parse and carry every top-level section:
    /// signatures, catalog, keywords, pricing, templates, retention.
    #[test]
    fn test_embedded_snapshot_is_complete() {
        let params = build_fallback_params();
        assert!(!params.transcript_secret_signatures.is_empty());
        assert!(!params.prompt_injection_signatures.is_empty());
        assert!(!params.agent_critical_subprocess_catalog.is_empty());
        assert!(!params.agent_secret_env_key_needles.is_empty());
        assert!(!params.agent_model_family_prefixes.is_empty());
        assert!(!params.agent_model_field_keys.is_empty());
        assert!(!params.agent_model_container_keys.is_empty());
        assert!(!params.agent_tool_privilege_keywords.shell.is_empty());
        assert!(params.agent_recursion_thresholds.depth_high > 0);
        assert!(!params.model_pricing.entries.is_empty());
        assert!(!params.augmentation_prompt_templates.is_empty());
        assert!(!params.augmentation_coach_templates.is_empty());
        assert!(params.history_retention.history_retention_days > 0);
        assert!(params.history_retention.divergence_verdict_max_entries > 0);
        assert!(params.history_retention.coach_max_cached_insights > 0);
        let w = &params.workspace_attribution;
        assert!(!w.agent_cli_programs.is_empty());
        assert!(!w.shell_programs.is_empty());
        assert!(!w.temp_roots.is_empty());
        assert!(!w.headless_entrypoint_prefixes.is_empty());
        assert!(!w.subagent_directory.is_empty());
        assert!(w.background_launch_window_secs > 0);
        assert!(!w.temporary_workspace_label.is_empty());
        assert!(!w.project_directories.is_empty());
        assert!(!w.fleet_workspace_references.is_empty());
        assert!(w
            .agent_cli_programs
            .iter()
            .all(|p| p == &p.to_ascii_lowercase()));
        let inv = &params.instruction_inventory;
        assert!(!inv.agent_subdirectories.is_empty());
        assert!(!inv.artifact_extensions.is_empty());
        assert!(!inv.document_extensions.is_empty());
        assert!(!inv.toplevel_instruction_files.is_empty());
        assert!(!inv.toplevel_rule_extensions.is_empty());
        assert!(!inv.skill_entry_files.is_empty());
        assert!(!inv.skill_tree_directories.is_empty());
        assert!(!inv.nested_roots.is_empty());
        assert!(!inv.workspace_toplevel_files.is_empty());
        assert!(!inv.workspace_config_directories.is_empty());
        assert!(!inv.workspace_subdirectories.is_empty());
        let delegation = &params.delegation_markers;
        assert!(!delegation.spawn_tool_names.is_empty());
        assert!(!delegation.spawn_target_keys.is_empty());
        assert!(!delegation.spawn_goal_keys.is_empty());
        assert!(!delegation.text_markers.is_empty());
        assert!(!delegation.text_reason_keys.is_empty());
        let credentials = &params.mcp_credential_markers;
        assert!(!credentials.header_names.is_empty());
        assert!(!credentials.header_needles.is_empty());
        assert!(!credentials.env_key_needles.is_empty());
        let discovery = &params.mcp_discovery;
        assert!(!discovery.plugin_config_suffixes.is_empty());
        assert!(!discovery.plugin_skip_directories.is_empty());
        assert!(!discovery.cursor_plugin_directories.is_empty());
        assert!(!discovery.claude_code_plugin_manifests.is_empty());
        assert!(!discovery.claude_code_project_directories.is_empty());
        assert!(!discovery.claude_code_project_config_files.is_empty());
        assert!(!discovery.claude_desktop_extension_directories.is_empty());
        assert!(!discovery.claude_desktop_extension_manifest.is_empty());
        assert!(!discovery.openclaw_extension_directories.is_empty());
        assert!(!discovery.openclaw_extension_manifest.is_empty());
        let privilege = &params.host_privilege;
        assert!(!privilege.elevated_users.is_empty());
        assert!(!privilege.macos_admin_groups.is_empty());
        assert!(!privilege.linux_admin_groups.is_empty());
        assert!(!privilege.group_files.is_empty());
        assert!(!privilege.sudoers_files.is_empty());
        assert!(!privilege.sudoers_directories.is_empty());
        assert!(!privilege.escalatable_binaries.is_empty());
        assert!(!privilege.escalatable_binary_families.is_empty());
        assert!(!privilege.escalatable_environment_variables.is_empty());
        assert!(privilege
            .escalatable_binaries
            .iter()
            .chain(&privilege.escalatable_binary_families)
            .all(|name| name == &name.to_ascii_lowercase() && !name.contains('/')));
        assert!(privilege
            .escalatable_environment_variables
            .iter()
            .all(|name| name == &name.to_ascii_uppercase()));
        let confinement = &params.agent_confinement;
        assert!(!confinement.container_name_needles.is_empty());
        assert!(!confinement.macos_container_directories.is_empty());
        assert!(!confinement.macos_vm_bundles.is_empty());
        assert!(!confinement.linux_confinement_directories.is_empty());
        assert!(!confinement.config_files.is_empty());
        assert!(!confinement.permission_mode_ranks.is_empty());
        let harnesses = &params.agent_harnesses;
        assert!(!harnesses.catalog.is_empty());
        assert!(harnesses.catalog.iter().all(|h| !h.slug.is_empty()));
        assert!(harnesses
            .config_directories
            .iter()
            .all(|d| d.contains("{slug}")));
        assert!(!harnesses.home_bin_directories.is_empty());
        assert!(!harnesses.versioned_bin_directories.is_empty());
        assert!(!harnesses.windows_binary_extensions.is_empty());
        assert!(!harnesses.identity_keys.is_empty());
        let refs = &params.instruction_references;
        assert!(!refs.basenames.is_empty());
        assert!(!refs.folder_segments.is_empty());
        assert!(!refs.file_segments.is_empty());
        assert!(!refs.document_extensions.is_empty());
        // Every collector agent declares its model traffic, and its provider
        // endpoints are exact host:port entries the parser also declares.
        for agent in [
            "claude_code",
            "claude_desktop",
            "codex",
            "cursor",
            "hermes",
            "openclaw",
        ] {
            let traffic = params
                .agent_llm_traffic
                .get(agent)
                .unwrap_or_else(|| panic!("agent_llm_traffic lacks {agent}"));
            assert!(!traffic.llm_hosts.is_empty(), "{agent}: llm_hosts");
            assert!(
                !traffic.provider_endpoints.is_empty(),
                "{agent}: provider_endpoints"
            );
            for endpoint in &traffic.provider_endpoints {
                assert!(
                    !endpoint.starts_with("asn:")
                        && !endpoint.contains('*')
                        && endpoint.contains(':')
                        && endpoint == &endpoint.to_ascii_lowercase(),
                    "{agent}: provider endpoint {endpoint} must be an exact host:port"
                );
                assert!(
                    traffic
                        .llm_hosts
                        .iter()
                        .any(|h| h.eq_ignore_ascii_case(endpoint)),
                    "{agent}: provider endpoint {endpoint} is not in llm_hosts"
                );
            }
        }
    }

    /// The accessors serve the snapshot by agent type, and an agent type the
    /// params do not list has no declared traffic and no exempt endpoint.
    #[test]
    #[serial]
    fn test_agent_llm_traffic_accessors() {
        let hosts = agent_llm_hosts("claude_code");
        assert!(hosts.iter().any(|h| h == "api.anthropic.com:443"));
        // ASN owners are declared as written (the parser hints keep them).
        assert!(hosts.iter().any(|h| h == "asn:ANTHROPIC"));
        let endpoints = agent_provider_endpoints("claude_code");
        assert!(endpoints.iter().any(|e| e == "api.anthropic.com:443"));
        // A shared cloud suffix is declared traffic, never an exempt endpoint.
        assert!(hosts.iter().any(|h| h == "amazonaws.com:443"));
        assert!(!endpoints.iter().any(|e| e.contains("amazonaws.com")));
        assert!(agent_provider_endpoints("cursor")
            .iter()
            .any(|e| e == "cursor.sh:443"));
        assert!(agent_llm_hosts("no_such_agent").is_empty());
        assert!(agent_provider_endpoints("no_such_agent").is_empty());
    }

    /// Catalog names and criticality are lowercased by `new_from_json` so
    /// runtime matching against lowercased basenames is exact.
    #[test]
    #[serial]
    fn test_subprocess_catalog_is_normalized() {
        let catalog = agent_critical_subprocess_catalog();
        assert!(!catalog.is_empty());
        for class in &catalog {
            for name in &class.names {
                assert_eq!(name, &name.to_ascii_lowercase());
            }
            assert!(matches!(
                class.criticality.as_str(),
                "routine" | "elevated" | "critical"
            ));
        }
    }

    // --- Model pricing (agent-transcript economics) ---------------------

    /// The embedded snapshot MUST ship a usable price table: a non-empty
    /// `entries` list and a positive default input/output rate.
    #[test]
    #[serial]
    fn test_model_pricing_table_is_populated() {
        let pricing = model_pricing();
        assert!(
            !pricing.entries.is_empty(),
            "model pricing entries must be non-empty"
        );
        assert!(pricing.default.input > 0.0 && pricing.default.output > 0.0);
        // Every entry except the (ignored) default must carry a non-empty
        // match substring, already lowercased by normalize_model_pricing.
        for e in &pricing.entries {
            assert!(!e.match_substring.is_empty());
            assert_eq!(e.match_substring, e.match_substring.to_ascii_lowercase());
            assert!(e.input >= 0.0 && e.output >= 0.0);
        }
    }

    /// Longest / most-specific match wins: `claude-opus-4` must resolve to the
    /// `opus` row (75.0 output), not the generic Sonnet-class default, and is
    /// not flagged as a fallback.
    #[test]
    #[serial]
    fn test_resolve_model_price_anthropic_specific() {
        let opus = resolve_model_price("claude-opus-4-20250514");
        assert!(!opus.is_fallback);
        assert_eq!(opus.input, 15.0);
        assert_eq!(opus.output, 75.0);
        // Anthropic four-bucket: cache_write and cache_read are distinct rates.
        assert!(opus.cache_write > 0.0);
        assert!(opus.cache_read > 0.0);

        let sonnet = resolve_model_price("claude-3-5-sonnet-20241022");
        assert!(!sonnet.is_fallback);
        assert_eq!(sonnet.output, 15.0);

        let haiku = resolve_model_price("claude-3-5-haiku-latest");
        assert!(!haiku.is_fallback);
        assert_eq!(haiku.output, 4.0);
    }

    /// OpenAI / Codex rows carry no cache-write surcharge (cache_write == 0)
    /// and resolve case-insensitively.
    #[test]
    #[serial]
    fn test_resolve_model_price_openai_no_cache_write() {
        let gpt5 = resolve_model_price("gpt-5-codex");
        assert!(!gpt5.is_fallback);
        assert_eq!(gpt5.cache_write, 0.0);
        assert!(gpt5.cache_read > 0.0);

        // Case-insensitive: uppercased id resolves identically.
        let gpt5_upper = resolve_model_price("GPT-5-CODEX");
        assert_eq!(gpt5_upper.input, gpt5.input);
        assert_eq!(gpt5_upper.output, gpt5.output);
    }

    /// Unrecognized models fall back to the default rate and are flagged so the
    /// caller can present the derived cost as a coarse estimate (G3).
    #[test]
    #[serial]
    fn test_resolve_model_price_unknown_is_fallback() {
        let unknown = resolve_model_price("some-future-model-v9");
        assert!(unknown.is_fallback);
        let d = model_pricing().default;
        assert_eq!(unknown.input, d.input);
        assert_eq!(unknown.output, d.output);

        // Empty model id also falls back rather than panicking.
        let empty = resolve_model_price("");
        assert!(empty.is_fallback);
    }

    /// `normalize_model_pricing` lowercases every match substring (including
    /// the ignored default) so resolution against a lowercased id is stable
    /// regardless of source-JSON casing.
    #[test]
    fn test_normalize_model_pricing_lowercases_substrings() {
        let raw = ModelPricingJSON {
            default: model_price_entry(3.0, 15.0, 3.75, 0.30, "DEFAULT"),
            entries: vec![
                model_price_entry(15.0, 75.0, 18.75, 1.5, "OPUS"),
                model_price_entry(1.25, 10.0, 0.0, 0.125, "GPT-5"),
            ],
        };
        let norm = normalize_model_pricing(&raw);
        assert_eq!(norm.default.match_substring, "default");
        assert_eq!(norm.entries[0].match_substring, "opus");
        assert_eq!(norm.entries[1].match_substring, "gpt-5");
    }

    #[tokio::test]
    #[serial]
    #[ignore] // requires network access to GitHub
    async fn test_update_runs() {
        let status = update("main", false).await.expect("Update failed");
        assert!(matches!(
            status,
            UpdateStatus::Updated | UpdateStatus::NotUpdated | UpdateStatus::SkippedCustom
        ));
    }
}
