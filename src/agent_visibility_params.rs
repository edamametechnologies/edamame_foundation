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

impl AgentVisibilityParams {
    pub fn new_from_json(json: &AgentVisibilityParamsJSON) -> Self {
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
