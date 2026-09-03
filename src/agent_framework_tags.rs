//! Framework crosswalk for the AI Agent Posture checks (read-only, derived).
//!
//! Single source for two consumers that must never disagree:
//!
//! - the `tags` the threat models carry on every AI check (`"<Framework>,<Id>-<Title>"`,
//!   the same shape the CIS / SOC 2 / ISO 27001 tags already use, which the Hub
//!   groups into Compliance frameworks, per-check chips, per-framework ratios
//!   and policy conditions by the prefix before the first comma), and
//! - the check-level `references` on the AI detail bundle
//!   (`CheckDetailBackend::references`), the token form the Hub can attribute
//!   live failing checks to categories with.
//!
//! Everything here is derived from catalogs and params that already exist and
//! are already what the app's OWASP / ATLAS / Trust Controls scorecards render:
//!
//! | Check | OWASP GenAI ids come from | ATLAS ids come from |
//! |---|---|---|
//! | `vulnerabilities` | every attack-pattern check's `reference` string in `cve-detection-params-db.json` (`checks.<name>.reference`) | same strings |
//! | `divergence` | the `drift_goal_divergence` visibility rule refs | same rule |
//! | `escalated` | ASI09 (the advisor escalation IS the human checkpoint; see `OWASPGENAI.md` ASI09) | none |
//! | `mcp_risk` | the `mcp_*` visibility rule refs | same rules |
//! | `agents_with_blast_radius` | the critical-subprocess catalog (`agent-visibility-params-db.json`) plus ASI10 (`OWASPGENAI.md` harness / blast-radius row) | none |
//! | `agents_without_harness`, `harness_divergence` | `OWASPGENAI.md` harness / blast-radius row | none |
//! | `unsecured_<agent>` | ASI10 (an unobserved agent is the rogue-agent visibility gap) | none |
//!
//! Trust controls follow from the OWASP ids: a control is tagged on a check
//! when its `owasp_refs` intersect the check's OWASP ids -- exactly how the
//! Trust Controls scorecard attributes findings. The publisher's ISO/IEC 42001
//! and ISO 27001:2022 clause mappings ride along with each tagged control.
//!
//! Invariants:
//! - Metadata only. Nothing here changes a check's severity, status, or
//!   alertability; tags and references only group and label.
//! - Pure and deterministic given the params snapshots; no I/O.
//! - Titles containing a comma are re-punctuated with `;` so the Hub's
//!   "framework is the text before the first comma" rule holds.

use crate::agent_atlas::{atlas_catalog_rows, extract_atlas_ids};
use crate::agent_owasp::{extract_owasp_ids, owasp_catalog_rows, OwaspFramework};
use crate::agent_trust_controls::trust_controls_catalog_rows;
use crate::agent_visibility::{atlas_refs_for_rule, owasp_refs_for_rule};
use crate::agent_visibility_params::agent_critical_subprocess_catalog;
use crate::vuln_detector_params;
use std::collections::{BTreeMap, BTreeSet};

/// Hub-facing framework names (the text before the first comma of a tag).
pub const FRAMEWORK_OWASP_AGENTIC: &str = "OWASP GenAI Agentic Top 10";
pub const FRAMEWORK_OWASP_LLM: &str = "OWASP GenAI LLM Top 10";
pub const FRAMEWORK_MITRE_ATLAS: &str = "MITRE ATLAS";
pub const FRAMEWORK_TRUST_CONTROLS: &str = "Agentic Trust Controls";
/// ISO frameworks are named exactly as the trust-controls publisher maps them
/// (`ISO/IEC 42001:2023`, `ISO 27001:2022`), distinct from the pre-existing
/// `ISO 27001/2` (2013 numbering) prefix used by the OS hygiene checks.
pub const AI_FRAMEWORK_PREFIXES: &[&str] = &[
    FRAMEWORK_OWASP_AGENTIC,
    FRAMEWORK_OWASP_LLM,
    FRAMEWORK_MITRE_ATLAS,
    FRAMEWORK_TRUST_CONTROLS,
    "ISO/IEC 42001:2023",
    "ISO 27001:2022",
];

/// The structural AI checks with a fixed name (the observation checks are
/// `unsecured_<agent>` and are matched by prefix).
pub const AI_STRUCTURAL_CHECKS: &[&str] = &[
    "agents_with_blast_radius",
    "agents_without_harness",
    "harness_divergence",
    "mcp_risk",
    "vulnerabilities",
    "divergence",
    "escalated",
];

/// Whether `check` is one of the AI Agent Posture checks this module crosswalks.
/// Same predicate as `edamame_core::ai_governance::is_ai_governance_check`.
pub fn is_ai_check(check: &str) -> bool {
    AI_STRUCTURAL_CHECKS.contains(&check) || check.starts_with("unsecured_")
}

/// One framework mapping for a check.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FrameworkTag {
    /// Hub framework name (tag prefix).
    pub framework: String,
    /// Control / technique / category id (`ASI03`, `LLM02`, `AML.T0055`, `AID-01`, `A.4.5`).
    pub id: String,
    /// Human title, comma-free.
    pub title: String,
    /// Canonical reference token for the detail bundle
    /// (`OWASP-ASI03`, `AML.T0055`, `TC-AID-01`, `ISO42001-A.4.5`, `ISO27001-A.8.31`).
    pub token: String,
}

impl FrameworkTag {
    /// `"<Framework>,<Id>-<Title>"`, the threat-model tag shape.
    pub fn to_tag(&self) -> String {
        format!("{},{}-{}", self.framework, self.id, self.title)
    }
}

fn comma_free(title: &str) -> String {
    title.trim().replace(',', ";")
}

/// The OWASP GenAI ids (bare `ASI03` / `LLM02`) a check evidences.
fn owasp_ids_for_check(check: &str) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    let mut add_refs = |s: &str| {
        for id in extract_owasp_ids(s) {
            ids.insert(id);
        }
    };
    match check {
        "vulnerabilities" => {
            for reference in vuln_detector_params::all_check_references() {
                add_refs(&reference);
            }
        }
        "divergence" => {
            if let Some(refs) = owasp_refs_for_rule("drift_goal_divergence") {
                add_refs(refs);
            }
        }
        "escalated" => {
            ids.insert("ASI09".to_string());
        }
        "mcp_risk" => {
            if let Some(refs) = owasp_refs_for_rule("mcp_risk") {
                add_refs(refs);
            }
        }
        "agents_with_blast_radius" => {
            for class in agent_critical_subprocess_catalog() {
                add_refs(&class.owasp_refs);
            }
            ids.insert("ASI10".to_string());
        }
        "agents_without_harness" | "harness_divergence" => {
            for id in ["ASI02", "ASI03", "ASI05", "ASI10", "LLM06"] {
                ids.insert(id.to_string());
            }
        }
        _ if check.starts_with("unsecured_") => {
            ids.insert("ASI10".to_string());
        }
        _ => {}
    }
    ids
}

/// The MITRE ATLAS parent technique ids a check evidences, limited to the
/// runtime-observable catalog.
fn atlas_ids_for_check(check: &str) -> BTreeSet<String> {
    let catalog: BTreeSet<&str> = atlas_catalog_rows().map(|(id, _)| id).collect();
    let mut ids = BTreeSet::new();
    let mut add_refs = |s: &str| {
        for id in extract_atlas_ids(s) {
            if catalog.contains(id.as_str()) {
                ids.insert(id);
            }
        }
    };
    match check {
        "vulnerabilities" => {
            for reference in vuln_detector_params::all_check_references() {
                add_refs(&reference);
            }
        }
        "divergence" => {
            if let Some(refs) = atlas_refs_for_rule("drift_goal_divergence") {
                add_refs(refs);
            }
        }
        "mcp_risk" => {
            if let Some(refs) = atlas_refs_for_rule("mcp_risk") {
                add_refs(refs);
            }
        }
        _ => {}
    }
    ids
}

/// Every framework mapping for `check`, sorted and deduped. Empty for a
/// non-AI check.
pub fn framework_tags_for_ai_check(check: &str) -> Vec<FrameworkTag> {
    if !is_ai_check(check) {
        return Vec::new();
    }
    let owasp_ids = owasp_ids_for_check(check);
    let atlas_ids = atlas_ids_for_check(check);
    let mut out: BTreeSet<FrameworkTag> = BTreeSet::new();

    for (id, framework, title) in owasp_catalog_rows() {
        if !owasp_ids.contains(id) {
            continue;
        }
        let framework_name = match framework {
            OwaspFramework::Agentic => FRAMEWORK_OWASP_AGENTIC,
            OwaspFramework::Llm => FRAMEWORK_OWASP_LLM,
        };
        out.insert(FrameworkTag {
            framework: framework_name.to_string(),
            id: id.to_string(),
            title: comma_free(title),
            token: format!("OWASP-{id}"),
        });
    }

    for (id, name) in atlas_catalog_rows() {
        if !atlas_ids.contains(id) {
            continue;
        }
        out.insert(FrameworkTag {
            framework: FRAMEWORK_MITRE_ATLAS.to_string(),
            id: id.to_string(),
            title: comma_free(name),
            token: id.to_string(),
        });
    }

    for row in trust_controls_catalog_rows() {
        if !row.owasp_refs.iter().any(|r| owasp_ids.contains(*r)) {
            continue;
        }
        out.insert(FrameworkTag {
            framework: FRAMEWORK_TRUST_CONTROLS.to_string(),
            id: row.id.to_string(),
            title: comma_free(row.title),
            token: format!("TC-{}", row.id),
        });
        // Publisher mapping: "A.4.5 System and computing resources".
        let (clause, clause_title) = match row.framework_mapping.trim().split_once(' ') {
            Some((clause, rest)) => (clause.to_string(), rest.to_string()),
            None => (row.framework_mapping.trim().to_string(), String::new()),
        };
        if clause.is_empty() {
            continue;
        }
        let iso_prefix = if row.framework.contains("42001") {
            "ISO42001"
        } else {
            "ISO27001"
        };
        out.insert(FrameworkTag {
            framework: row.framework.to_string(),
            id: clause.clone(),
            title: comma_free(&clause_title),
            token: format!("{iso_prefix}-{clause}"),
        });
    }

    out.into_iter().collect()
}

/// Threat-model tag strings for `check` (excluding the product tag
/// `AI Agent Posture`, which the threat model keeps on its own).
pub fn framework_tag_strings_for_ai_check(check: &str) -> Vec<String> {
    framework_tags_for_ai_check(check)
        .iter()
        .map(FrameworkTag::to_tag)
        .collect()
}

/// Detail-bundle reference tokens for `check`.
pub fn framework_reference_tokens_for_ai_check(check: &str) -> Vec<String> {
    framework_tags_for_ai_check(check)
        .into_iter()
        .map(|tag| tag.token)
        .collect()
}

/// True when `tag` belongs to one of the frameworks this module owns, i.e. it
/// is safe to regenerate (the product tag and any operator-added tag are not).
pub fn is_ai_framework_tag(tag: &str) -> bool {
    let prefix = tag.split(',').next().unwrap_or("").trim();
    AI_FRAMEWORK_PREFIXES.contains(&prefix)
}

/// The full crosswalk for every AI check the threat models carry, keyed by
/// check name: the seven structural / runtime checks plus one
/// `unsecured_<agent>` row per supported agent.
pub fn ai_framework_tag_catalog(agent_slugs: &[&str]) -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();
    for check in AI_STRUCTURAL_CHECKS {
        out.insert(
            (*check).to_string(),
            framework_tag_strings_for_ai_check(check),
        );
    }
    for slug in agent_slugs {
        let check = format!("unsecured_{slug}");
        out.insert(check.clone(), framework_tag_strings_for_ai_check(&check));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Not an assertion: prints the full crosswalk as JSON so the threatmodels
    /// sync script and a human can see exactly what each AI check is tagged.
    /// `cargo test -- --ignored dump_ai_framework_tag_catalog --nocapture`
    #[test]
    #[ignore]
    fn dump_ai_framework_tag_catalog() {
        let catalog = ai_framework_tag_catalog(AGENTS);
        println!("{}", serde_json::to_string_pretty(&catalog).unwrap());
    }

    const AGENTS: &[&str] = &[
        "cursor",
        "claude_code",
        "claude_desktop",
        "openclaw",
        "codex",
        "hermes",
    ];

    #[test]
    fn every_ai_check_gets_at_least_one_owasp_tag() {
        let catalog = ai_framework_tag_catalog(AGENTS);
        assert_eq!(catalog.len(), AI_STRUCTURAL_CHECKS.len() + AGENTS.len());
        for (check, tags) in &catalog {
            assert!(
                tags.iter().any(|t| t.starts_with(FRAMEWORK_OWASP_AGENTIC)
                    || t.starts_with(FRAMEWORK_OWASP_LLM)),
                "{check}: no OWASP tag in {tags:?}"
            );
        }
    }

    #[test]
    fn tags_follow_the_hub_prefix_convention() {
        for tag in framework_tag_strings_for_ai_check("vulnerabilities") {
            let (framework, rest) = tag.split_once(',').expect("comma");
            assert!(AI_FRAMEWORK_PREFIXES.contains(&framework), "{tag}");
            assert!(rest.contains('-'), "{tag}: id-title");
            assert!(!rest.contains(','), "{tag}: title must be comma-free");
        }
    }

    #[test]
    fn non_ai_checks_get_nothing() {
        assert!(framework_tags_for_ai_check("encrypted disk disabled").is_empty());
        assert!(framework_reference_tokens_for_ai_check("pwned").is_empty());
    }

    #[test]
    fn runtime_checks_follow_their_reference_tokens() {
        // credential_harvest / token_exfiltration references carry OWASP-LLM02
        // and AML.T0055; both must land on the umbrella `vulnerabilities` check.
        let tokens = framework_reference_tokens_for_ai_check("vulnerabilities");
        assert!(tokens.contains(&"OWASP-LLM02".to_string()), "{tokens:?}");
        assert!(tokens.contains(&"AML.T0055".to_string()), "{tokens:?}");
        // Goal drift is the divergence engine's home category.
        let div = framework_reference_tokens_for_ai_check("divergence");
        assert!(div.contains(&"OWASP-ASI01".to_string()), "{div:?}");
        assert!(div.contains(&"AML.T0051".to_string()), "{div:?}");
    }

    #[test]
    fn trust_controls_and_iso_follow_owasp_ids() {
        let tags = framework_tags_for_ai_check("mcp_risk");
        assert!(tags.iter().any(|t| t.framework == FRAMEWORK_TRUST_CONTROLS));
        assert!(tags
            .iter()
            .any(|t| t.framework.contains("42001") && t.token.starts_with("ISO42001-")));
    }

    #[test]
    fn tag_and_token_forms_agree() {
        for tag in framework_tags_for_ai_check("agents_with_blast_radius") {
            assert_eq!(
                tag.to_tag(),
                format!("{},{}-{}", tag.framework, tag.id, tag.title)
            );
            assert!(!tag.token.is_empty());
        }
        assert!(is_ai_framework_tag(
            "MITRE ATLAS,AML.T0053-AI Agent Tool Invocation"
        ));
        assert!(!is_ai_framework_tag("AI Agent Posture"));
        assert!(!is_ai_framework_tag(
            "CIS Benchmark Level 1,Enable Firewall"
        ));
    }
}
