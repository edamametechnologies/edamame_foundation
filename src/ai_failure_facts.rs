//! Build [`FailureFactBackend`] sets for Active AI posture checks, plus the
//! `agent` [`CoverageRowBackend`] rows that carry the tri-state observation
//! coverage. Both end up in the `ai` bundle of
//! `DetailedScoreBackend.details`.
//!
//! Facts are metadata-only (process basenames, harness slugs, secret labels,
//! MCP server names and rule ids). MCP facts belong to the `mcp_risk` check
//! only -- they are intentionally **not** emitted from blast-radius checks, so
//! a "this MCP server is fine" exception cannot silently widen into a
//! blast-radius exception -- see `edamame_core/AIGOVERNANCE.md` §4. Coverage
//! rows are inventory rather than evidence and are never whitelist-matched --
//! see §6.

use crate::agent_subprocess::normalize_process_basename;
use crate::agent_visibility::{
    known_agent_harness_slugs, BlastRadiusAgent, McpRiskEndpoint, KNOWN_AGENT_HARNESS_SLUGS,
};
use edamame_backend::detail_backend::{
    CoverageKindBackend, CoverageRowBackend, FailureFactBackend, FailureFactKindBackend,
    MAX_FAILURE_FACTS,
};
use std::collections::{BTreeMap, BTreeSet};

/// Result of building a capped fact set for one Active check.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FailureFactSet {
    pub facts: Vec<FailureFactBackend>,
    pub truncated: bool,
}

fn push_unique(
    out: &mut Vec<FailureFactBackend>,
    seen: &mut BTreeSet<String>,
    fact: FailureFactBackend,
) {
    let dedup = format!("{}|{}|{}", fact.kind.as_str(), fact.key, fact.scope);
    if seen.insert(dedup) {
        out.push(fact);
    }
}

fn finalize(mut facts: Vec<FailureFactBackend>) -> FailureFactSet {
    facts.sort();
    facts.dedup();
    let truncated = facts.len() > MAX_FAILURE_FACTS;
    if truncated {
        facts.truncate(MAX_FAILURE_FACTS);
    }
    FailureFactSet { facts, truncated }
}

/// Facts for an Active `agents_with_blast_radius` check.
///
/// `critical_processes` maps `agent_type ->` normalized process basenames that
/// were observed as Critical for that agent.
pub fn facts_for_blast_radius(
    agents: &[BlastRadiusAgent],
    critical_processes: &BTreeMap<String, Vec<String>>,
) -> FailureFactSet {
    let mut facts = Vec::new();
    let mut seen = BTreeSet::new();
    for agent in agents {
        push_unique(
            &mut facts,
            &mut seen,
            FailureFactBackend::new(FailureFactKindBackend::Agent, &agent.agent_type)
                .with_scope(&agent.agent_type),
        );
        if agent.passwordless_root {
            push_unique(
                &mut facts,
                &mut seen,
                FailureFactBackend::new(FailureFactKindBackend::Amplifier, "passwordless_root")
                    .with_scope(&agent.agent_type),
            );
        }
        if agent.critical_subprocess {
            push_unique(
                &mut facts,
                &mut seen,
                FailureFactBackend::new(FailureFactKindBackend::Amplifier, "critical_subprocess")
                    .with_scope(&agent.agent_type),
            );
            if let Some(procs) = critical_processes.get(&agent.agent_type) {
                for proc in procs {
                    let key = normalize_process_basename(proc);
                    if key.is_empty() {
                        continue;
                    }
                    push_unique(
                        &mut facts,
                        &mut seen,
                        FailureFactBackend::new(FailureFactKindBackend::CriticalProcess, key)
                            .with_scope(&agent.agent_type),
                    );
                }
            }
        }
        if agent.secret_exposure {
            push_unique(
                &mut facts,
                &mut seen,
                FailureFactBackend::new(FailureFactKindBackend::Amplifier, "secret_exposure")
                    .with_scope(&agent.agent_type),
            );
            for label in &agent.secret_exposure_labels {
                let key = label.trim().to_ascii_lowercase();
                if key.is_empty() {
                    continue;
                }
                push_unique(
                    &mut facts,
                    &mut seen,
                    FailureFactBackend::new(FailureFactKindBackend::SecretLabel, key)
                        .with_scope(&agent.agent_type),
                );
            }
        }
    }
    finalize(facts)
}

/// Facts for an Active `harness_divergence` check.
pub fn facts_for_harness_divergence(
    diverging_agent_types: &[String],
    harness_slugs: &[String],
    blast_agents: &[BlastRadiusAgent],
    critical_processes: &BTreeMap<String, Vec<String>>,
) -> FailureFactSet {
    let diverging: BTreeSet<&str> = diverging_agent_types.iter().map(|s| s.as_str()).collect();
    let filtered: Vec<BlastRadiusAgent> = blast_agents
        .iter()
        .filter(|a| diverging.contains(a.agent_type.as_str()))
        .cloned()
        .collect();
    let mut set = facts_for_blast_radius(&filtered, critical_processes);
    let mut seen: BTreeSet<String> = set
        .facts
        .iter()
        .map(|f| format!("{}|{}|{}", f.kind.as_str(), f.key, f.scope))
        .collect();
    for slug in harness_slugs {
        let key = slug.trim().to_ascii_lowercase();
        if key.is_empty() {
            continue;
        }
        push_unique(
            &mut set.facts,
            &mut seen,
            FailureFactBackend::new(FailureFactKindBackend::Harness, key),
        );
    }
    finalize(set.facts)
}

/// Facts for an Active `agents_without_harness` check.
pub fn facts_for_agents_without_harness(discovered_agent_types: &[String]) -> FailureFactSet {
    let mut facts = Vec::new();
    let mut seen = BTreeSet::new();
    for agent in discovered_agent_types {
        let key = agent.trim().to_ascii_lowercase();
        if key.is_empty() {
            continue;
        }
        push_unique(
            &mut facts,
            &mut seen,
            FailureFactBackend::new(FailureFactKindBackend::Agent, &key).with_scope(&key),
        );
    }
    for slug in known_agent_harness_slugs() {
        push_unique(
            &mut facts,
            &mut seen,
            FailureFactBackend::new(FailureFactKindBackend::ExpectedHarness, slug),
        );
    }
    finalize(facts)
}

/// Facts for an Active `mcp_risk` check.
///
/// Three kinds per exposure so a Hub whitelist can be written at whichever
/// granularity the fleet needs: `mcp_rule` (accept this class of exposure
/// everywhere), `mcp_server` (accept this one server), `agent` (context --
/// which agent declares it). `scope` carries the agent slug when the finding
/// names one, matching every other AI check, so a server-level exception can
/// still be narrowed to a single agent.
pub fn facts_for_mcp_risk(risks: &[McpRiskEndpoint]) -> FailureFactSet {
    let mut facts = Vec::new();
    let mut seen = BTreeSet::new();
    for risk in risks {
        let agent = risk.agent_type.trim().to_ascii_lowercase();
        let rule = risk.rule_id.trim().to_ascii_lowercase();
        let server = risk.server_name.trim().to_ascii_lowercase();
        if !rule.is_empty() {
            let mut fact = FailureFactBackend::new(FailureFactKindBackend::McpRule, &rule);
            if !agent.is_empty() {
                fact = fact.with_scope(&agent);
            }
            push_unique(&mut facts, &mut seen, fact);
        }
        if !server.is_empty() {
            let mut fact = FailureFactBackend::new(FailureFactKindBackend::McpServer, &server);
            if !agent.is_empty() {
                fact = fact.with_scope(&agent);
            }
            push_unique(&mut facts, &mut seen, fact);
        }
        if !agent.is_empty() {
            push_unique(
                &mut facts,
                &mut seen,
                FailureFactBackend::new(FailureFactKindBackend::Agent, &agent).with_scope(&agent),
            );
        }
    }
    finalize(facts)
}

/// Facts for an Active `unsecured_<agent>` check.
pub fn facts_for_unsecured_agent(agent_type: &str) -> FailureFactSet {
    let key = agent_type.trim().to_ascii_lowercase();
    if key.is_empty() {
        return FailureFactSet::default();
    }
    finalize(vec![
        FailureFactBackend::new(FailureFactKindBackend::Agent, &key).with_scope(&key),
        FailureFactBackend::new(FailureFactKindBackend::Observer, "paused").with_scope(&key),
    ])
}

/// Build the `agent` coverage rows from the observer runner snapshot.
///
/// The row set is the union of both maps' keys so an agent stays reported even
/// if only one side knows about it. Absent `discovered` means not on this host;
/// absent `observer_enabled` means enabled, matching the `unsecured_<agent>`
/// check's default (the observer runs unless the operator paused it).
pub fn agent_coverage_rows(
    discovered: &BTreeMap<String, bool>,
    observer_enabled: &BTreeMap<String, bool>,
) -> Vec<CoverageRowBackend> {
    // (present, monitored) per normalized slug, defaults applied last so an
    // agent present in only one map still gets a full row.
    let mut rows: BTreeMap<String, (Option<bool>, Option<bool>)> = BTreeMap::new();
    for (raw, value) in discovered {
        let slug = raw.trim().to_ascii_lowercase();
        if !slug.is_empty() {
            rows.entry(slug).or_default().0 = Some(*value);
        }
    }
    for (raw, value) in observer_enabled {
        let slug = raw.trim().to_ascii_lowercase();
        if !slug.is_empty() {
            rows.entry(slug).or_default().1 = Some(*value);
        }
    }
    rows.into_iter()
        .map(|(slug, (found, enabled))| {
            CoverageRowBackend::new(
                CoverageKindBackend::Agent,
                slug,
                found.unwrap_or(false),
                enabled.unwrap_or(true),
            )
        })
        .collect()
}

/// Re-export for callers that need the known harness slug list without pulling
/// the full visibility module surface.
pub fn expected_harness_slugs() -> Vec<&'static str> {
    KNOWN_AGENT_HARNESS_SLUGS.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(
        agent_type: &str,
        passwordless_root: bool,
        critical_subprocess: bool,
        secrets: &[&str],
    ) -> BlastRadiusAgent {
        BlastRadiusAgent {
            agent_type: agent_type.to_string(),
            unsandboxed: true,
            passwordless_root,
            critical_subprocess,
            secret_exposure: !secrets.is_empty(),
            secret_exposure_labels: secrets.iter().map(|s| s.to_string()).collect(),
            reasons: vec![],
        }
    }

    #[test]
    fn blast_radius_emits_process_and_amplifier_facts() {
        let agents = vec![agent("cursor", false, true, &[])];
        let mut procs = BTreeMap::new();
        procs.insert(
            "cursor".to_string(),
            vec!["/usr/bin/ssh".to_string(), "SSH.EXE".to_string()],
        );
        let set = facts_for_blast_radius(&agents, &procs);
        let tokens: Vec<String> = set.facts.iter().map(|f| f.token()).collect();
        assert!(tokens.contains(&"agent:cursor".to_string()));
        assert!(tokens.contains(&"amplifier:critical_subprocess".to_string()));
        assert!(tokens.contains(&"critical_process:ssh".to_string()));
        // Deduped basename
        assert_eq!(
            tokens
                .iter()
                .filter(|t| t.as_str() == "critical_process:ssh")
                .count(),
            1
        );
        assert!(!set.truncated);
    }

    #[test]
    fn unsecured_emits_observer_paused() {
        let set = facts_for_unsecured_agent("claude_code");
        let tokens: Vec<String> = set.facts.iter().map(|f| f.token()).collect();
        assert_eq!(
            tokens,
            vec![
                "agent:claude_code".to_string(),
                "observer:paused".to_string()
            ]
        );
    }

    #[test]
    fn mcp_risk_emits_rule_server_and_agent_facts() {
        let risks = vec![McpRiskEndpoint {
            rule_id: "mcp_public_no_strong_auth".to_string(),
            server_name: "Gojiberry".to_string(),
            agent_type: "cursor".to_string(),
            critical: true,
        }];
        let set = facts_for_mcp_risk(&risks);
        let tokens: Vec<String> = set.facts.iter().map(|f| f.token()).collect();
        assert!(tokens.contains(&"mcp_rule:mcp_public_no_strong_auth".to_string()));
        assert!(tokens.contains(&"mcp_server:gojiberry".to_string()));
        assert!(tokens.contains(&"agent:cursor".to_string()));
        // Every fact is scoped to the declaring agent so a server-level Hub
        // exception can still be narrowed to one agent.
        assert!(set.facts.iter().all(|f| f.scope == "cursor"));
        assert!(!set.truncated);
    }

    #[test]
    fn mcp_risk_tolerates_a_finding_with_no_agent() {
        let risks = vec![McpRiskEndpoint {
            rule_id: "mcp_lan_privileged_no_auth".to_string(),
            server_name: "shell-runner".to_string(),
            agent_type: String::new(),
            critical: false,
        }];
        let set = facts_for_mcp_risk(&risks);
        let tokens: Vec<String> = set.facts.iter().map(|f| f.token()).collect();
        assert_eq!(
            tokens,
            vec![
                "mcp_rule:mcp_lan_privileged_no_auth".to_string(),
                "mcp_server:shell-runner".to_string(),
            ]
        );
        assert!(set.facts.iter().all(|f| f.scope.is_empty()));
    }

    #[test]
    fn without_harness_lists_expected_slugs() {
        let set = facts_for_agents_without_harness(&["cursor".to_string()]);
        let tokens: Vec<String> = set.facts.iter().map(|f| f.token()).collect();
        assert!(tokens.contains(&"expected_harness:nono".to_string()));
        assert!(tokens.contains(&"agent:cursor".to_string()));
    }

    #[test]
    fn coverage_rows_map_the_three_states() {
        let discovered = BTreeMap::from([
            ("cursor".to_string(), true),
            ("claude_code".to_string(), true),
            ("codex".to_string(), false),
        ]);
        let observer_enabled = BTreeMap::from([
            ("cursor".to_string(), true),
            ("claude_code".to_string(), false),
            ("codex".to_string(), true),
        ]);
        let rows = agent_coverage_rows(&discovered, &observer_enabled);
        let states: Vec<(&str, &str)> = rows.iter().map(|r| (r.key.as_str(), r.state())).collect();
        assert_eq!(
            states,
            vec![
                ("claude_code", "unmonitored"),
                ("codex", "absent"),
                ("cursor", "monitored"),
            ]
        );
        assert!(rows.iter().all(|r| r.kind == "agent"));
    }

    #[test]
    fn coverage_rows_default_observer_to_running() {
        let discovered = BTreeMap::from([("hermes".to_string(), true)]);
        let rows = agent_coverage_rows(&discovered, &BTreeMap::new());
        assert_eq!(rows.len(), 1);
        assert!(rows[0].monitored);
        assert_eq!(rows[0].state(), "monitored");
    }

    #[test]
    fn coverage_rows_normalize_and_union_keys() {
        let discovered = BTreeMap::from([("  Cursor ".to_string(), true), (String::new(), true)]);
        let observer_enabled = BTreeMap::from([("openclaw".to_string(), false)]);
        let rows = agent_coverage_rows(&discovered, &observer_enabled);
        let slugs: Vec<&str> = rows.iter().map(|r| r.key.as_str()).collect();
        assert_eq!(slugs, vec!["cursor", "openclaw"]);
        // openclaw is known only to the observer map: paused but not discovered.
        assert_eq!(rows[1].state(), "absent");
    }
}
