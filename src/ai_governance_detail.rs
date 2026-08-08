//! Build the governance evidence carried by the `ai` bundle of
//! `DetailedScoreBackend.details`: grouped [`FailureCauseBackend`] rows for
//! Active AI posture checks, the display-only [`CheckContextBackend`] rows that
//! explain them, and the per-agent [`CoverageRowBackend`] inventory.
//!
//! Three rules shape everything here, all of them enforced at emit time:
//!
//! 1. **A cause is the unit of acceptance.** Each cause groups the alternative
//!    ways to name *one* condition (`critical_process:ssh` and the broader
//!    `amplifier:critical_subprocess` that subsumes it). Accepting either
//!    clears that cause and nothing else, so a narrow exception can never widen
//!    into a different failure on the same agent.
//! 2. **The subject is never a selector.** The agent slug lives in
//!    [`FailureCauseBackend::scope`]; there is no `agent:` selector, because
//!    "accept cursor" would accept every future cursor failure.
//! 3. **Context is not evidence.** A detected harness explains *why* a check
//!    fired but is not a reason to accept it, so harness slugs ship as
//!    [`CheckContextBackend`] and are never whitelist-matched.
//!
//! Everything emitted is metadata: process basenames, MCP server names and rule
//! ids, secret-signature labels, agent and harness slugs. Never content.
//! MCP selectors belong to the `mcp_risk` check only -- a "this MCP server is
//! fine" exception must not silently clear a blast-radius cause.
//!
//! See `edamame_core/AIGOVERNANCE.md`.

use crate::agent_subprocess::normalize_process_basename;
use crate::agent_visibility::{BlastRadiusAgent, McpRiskEndpoint};
use edamame_backend::detail_backend::{
    CheckContextBackend, CheckContextKindBackend, CheckDetailBackend, CoverageKindBackend,
    CoverageRowBackend, FailureCauseBackend, FailureSelectorBackend, FailureSelectorKindBackend,
    MAX_FAILURE_CAUSES,
};
use std::collections::{BTreeMap, BTreeSet};

use FailureSelectorKindBackend as Kind;

/// Evidence for one Active check, before it is keyed by its metric name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CheckEvidence {
    /// Independent reasons the check failed. Each must be covered before the
    /// Hub may derive a passing governance status.
    pub causes: Vec<FailureCauseBackend>,
    /// Display-only diagnostics. Never whitelist-matched.
    pub context: Vec<CheckContextBackend>,
    /// True when emit-time capping dropped causes, which makes "every cause is
    /// covered" unprovable and must therefore fail closed on the Hub.
    pub truncated: bool,
}

impl CheckEvidence {
    pub fn is_empty(&self) -> bool {
        self.causes.is_empty() && self.context.is_empty()
    }

    /// Key this evidence by the failing check's metric name.
    pub fn into_detail(self, check: impl Into<String>) -> CheckDetailBackend {
        CheckDetailBackend::new(check, self.causes, self.context, self.truncated)
    }
}

fn norm(raw: &str) -> String {
    raw.trim().to_ascii_lowercase()
}

/// Accumulates causes and context for one check, then hands them to
/// [`finalize`] for dedup and fair capping.
#[derive(Default)]
struct EvidenceBuilder {
    causes: Vec<FailureCauseBackend>,
    context: Vec<CheckContextBackend>,
}

impl EvidenceBuilder {
    /// Record one condition under `scope`, named by every selector that applies
    /// to it. Selectors with an empty key are dropped; a cause left with no
    /// selector is dropped entirely, since it could never be accepted.
    fn cause(&mut self, scope: &str, selectors: Vec<(Kind, String)>) {
        let mut selectors: Vec<FailureSelectorBackend> = selectors
            .into_iter()
            .filter(|(_, key)| !key.is_empty())
            .map(|(kind, key)| FailureSelectorBackend::new(kind, key))
            .collect();
        if selectors.is_empty() {
            return;
        }
        selectors.sort();
        selectors.dedup();
        self.causes
            .push(FailureCauseBackend::new(scope, selectors));
    }

    fn context(&mut self, kind: CheckContextKindBackend, key: &str, scope: &str) {
        if key.is_empty() {
            return;
        }
        let mut row = CheckContextBackend::new(kind, key);
        if !scope.is_empty() {
            row = row.with_scope(scope);
        }
        self.context.push(row);
    }

    fn finish(self) -> CheckEvidence {
        finalize(self.causes, self.context)
    }
}

/// Drop invalid causes, dedup by fingerprint, then cap fairly across scopes.
///
/// The cap is applied round-robin per scope rather than by truncating a sorted
/// list: one agent with two hundred critical subprocesses must not push a
/// second failing agent out of the report entirely, or the operator would never
/// learn the second agent is failing at all.
fn finalize(
    causes: Vec<FailureCauseBackend>,
    mut context: Vec<CheckContextBackend>,
) -> CheckEvidence {
    let mut by_scope: BTreeMap<String, BTreeMap<String, FailureCauseBackend>> = BTreeMap::new();
    let mut total = 0usize;
    for cause in causes {
        if !cause.is_valid() {
            continue;
        }
        let fingerprint = cause.fingerprint();
        if by_scope
            .entry(cause.scope.clone())
            .or_default()
            .insert(fingerprint, cause)
            .is_none()
        {
            total += 1;
        }
    }

    let lanes: Vec<Vec<FailureCauseBackend>> = by_scope
        .into_values()
        .map(|scoped| scoped.into_values().collect())
        .collect();

    let mut kept: Vec<FailureCauseBackend> = Vec::with_capacity(total.min(MAX_FAILURE_CAUSES));
    let mut round = 0usize;
    'outer: loop {
        let mut progressed = false;
        for lane in &lanes {
            let Some(cause) = lane.get(round) else {
                continue;
            };
            progressed = true;
            kept.push(cause.clone());
            if kept.len() >= MAX_FAILURE_CAUSES {
                break 'outer;
            }
        }
        if !progressed {
            break;
        }
        round += 1;
    }
    kept.sort();

    context.sort();
    context.dedup();
    context.truncate(MAX_FAILURE_CAUSES);

    CheckEvidence {
        truncated: total > kept.len(),
        causes: kept,
        context,
    }
}

/// Normalized, deduped, deterministic list preserving nothing but the keys.
fn normalized_set<'a>(raw: impl IntoIterator<Item = &'a String>, basename: bool) -> Vec<String> {
    let set: BTreeSet<String> = raw
        .into_iter()
        .map(|value| {
            if basename {
                normalize_process_basename(value)
            } else {
                norm(value)
            }
        })
        .filter(|value| !value.is_empty())
        .collect();
    set.into_iter().collect()
}

/// Blast-radius causes for `agents`, shared by `agents_with_blast_radius` and
/// `harness_divergence` so the two checks can never disagree about what makes
/// an agent dangerous.
fn push_blast_radius_causes(
    builder: &mut EvidenceBuilder,
    agents: &[BlastRadiusAgent],
    critical_processes: &BTreeMap<String, Vec<String>>,
) {
    for agent in agents {
        let scope = norm(&agent.agent_type);
        if scope.is_empty() {
            continue;
        }
        let mut amplified = false;

        if agent.passwordless_root {
            builder.cause(&scope, vec![(Kind::Amplifier, "passwordless_root".into())]);
            amplified = true;
        }

        if agent.critical_subprocess {
            let processes = critical_processes
                .get(&agent.agent_type)
                .or_else(|| critical_processes.get(&scope))
                .map(|procs| normalized_set(procs, true))
                .unwrap_or_default();
            if processes.is_empty() {
                // Observed but unattributed: the amplifier is the only name we
                // have for the condition.
                builder.cause(&scope, vec![(Kind::Amplifier, "critical_subprocess".into())]);
            } else {
                for process in processes {
                    // Pairing the leaf with the amplifier is what makes
                    // "accept critical subprocesses for this agent" a single
                    // rule instead of one rule per binary.
                    builder.cause(
                        &scope,
                        vec![
                            (Kind::CriticalProcess, process),
                            (Kind::Amplifier, "critical_subprocess".into()),
                        ],
                    );
                }
            }
            amplified = true;
        }

        if agent.secret_exposure {
            let labels = normalized_set(&agent.secret_exposure_labels, false);
            if labels.is_empty() {
                builder.cause(&scope, vec![(Kind::Amplifier, "secret_exposure".into())]);
            } else {
                for label in labels {
                    builder.cause(
                        &scope,
                        vec![
                            (Kind::SecretLabel, label),
                            (Kind::Amplifier, "secret_exposure".into()),
                        ],
                    );
                }
            }
            amplified = true;
        }

        if !amplified {
            // The rule flagged this agent on confinement alone. Without a cause
            // here "every cause is covered" would be vacuously true and the Hub
            // could pass a check that is actively failing.
            builder.cause(&scope, vec![(Kind::Amplifier, "unsandboxed".into())]);
        }
    }
}

/// Evidence for an Active `agents_with_blast_radius` check.
///
/// `critical_processes` maps `agent_type ->` process paths observed as Critical
/// for that agent; they are reduced to normalized basenames here.
pub fn detail_for_blast_radius(
    agents: &[BlastRadiusAgent],
    critical_processes: &BTreeMap<String, Vec<String>>,
) -> CheckEvidence {
    let mut builder = EvidenceBuilder::default();
    push_blast_radius_causes(&mut builder, agents, critical_processes);
    builder.finish()
}

/// Evidence for an Active `harness_divergence` check.
///
/// The causes are the diverging agents' blast-radius conditions: what has to be
/// accepted is the reach the agent kept despite the harness. The harness slugs
/// themselves ship as context -- a harness being installed explains the check
/// but is not a reason to accept an agent escaping it.
pub fn detail_for_harness_divergence(
    diverging_agent_types: &[String],
    harness_slugs: &[String],
    blast_agents: &[BlastRadiusAgent],
    critical_processes: &BTreeMap<String, Vec<String>>,
) -> CheckEvidence {
    let diverging: BTreeSet<String> = normalized_set(diverging_agent_types, false)
        .into_iter()
        .collect();

    let flagged: Vec<BlastRadiusAgent> = blast_agents
        .iter()
        .filter(|agent| diverging.contains(&norm(&agent.agent_type)))
        .cloned()
        .collect();

    let mut builder = EvidenceBuilder::default();
    push_blast_radius_causes(&mut builder, &flagged, critical_processes);

    // An agent the divergence reducer flagged but the blast-radius snapshot no
    // longer lists still needs an acceptable cause, or it would silently vanish
    // from the evidence while the check stays Active.
    let covered: BTreeSet<String> = flagged
        .iter()
        .map(|agent| norm(&agent.agent_type))
        .collect();
    for agent in diverging.difference(&covered) {
        builder.cause(agent, vec![(Kind::HarnessState, "diverging".into())]);
    }

    for slug in normalized_set(harness_slugs, false) {
        builder.context(CheckContextKindBackend::Harness, &slug, "");
    }
    builder.finish()
}

/// Evidence for an Active `agents_without_harness` check.
///
/// One cause per discovered agent. The roster of harnesses EDAMAME knows how to
/// detect is static product knowledge, not per-host evidence, so it is not
/// emitted: it would be identical on every report and would compete with real
/// causes for the cap.
pub fn detail_for_agents_without_harness(discovered_agent_types: &[String]) -> CheckEvidence {
    let mut builder = EvidenceBuilder::default();
    for agent in normalized_set(discovered_agent_types, false) {
        builder.cause(&agent, vec![(Kind::HarnessState, "missing".into())]);
    }
    builder.finish()
}

/// Evidence for an Active `mcp_risk` check.
///
/// One cause per exposure, named two ways so a Hub rule can be written at
/// whichever granularity the fleet needs: `mcp_rule` accepts the exposure class
/// wherever it appears, `mcp_server` accepts one server. The declaring agent is
/// the scope, so a rule-level exception can still be narrowed to one agent.
pub fn detail_for_mcp_risk(risks: &[McpRiskEndpoint]) -> CheckEvidence {
    let mut builder = EvidenceBuilder::default();
    for risk in risks {
        builder.cause(
            &norm(&risk.agent_type),
            vec![
                (Kind::McpRule, norm(&risk.rule_id)),
                (Kind::McpServer, norm(&risk.server_name)),
            ],
        );
    }
    builder.finish()
}

/// Evidence for an Active `unsecured_<agent>` check.
pub fn detail_for_unsecured_agent(agent_type: &str) -> CheckEvidence {
    let scope = norm(agent_type);
    if scope.is_empty() {
        return CheckEvidence::default();
    }
    let mut builder = EvidenceBuilder::default();
    builder.cause(&scope, vec![(Kind::Observer, "paused".into())]);
    builder.finish()
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
        let slug = norm(raw);
        if !slug.is_empty() {
            rows.entry(slug).or_default().0 = Some(*value);
        }
    }
    for (raw, value) in observer_enabled {
        let slug = norm(raw);
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

    fn tokens(cause: &FailureCauseBackend) -> Vec<String> {
        cause.selectors.iter().map(|s| s.token()).collect()
    }

    fn cause_for<'a>(
        evidence: &'a CheckEvidence,
        scope: &str,
        token: &str,
    ) -> Option<&'a FailureCauseBackend> {
        evidence
            .causes
            .iter()
            .find(|c| c.scope == scope && tokens(c).iter().any(|t| t == token))
    }

    #[test]
    fn critical_process_cause_also_carries_the_amplifier() {
        let agents = vec![agent("cursor", false, true, &[])];
        let procs = BTreeMap::from([(
            "cursor".to_string(),
            vec!["/usr/bin/ssh".to_string(), "SSH.EXE".to_string()],
        )]);
        let evidence = detail_for_blast_radius(&agents, &procs);

        // Both paths normalize to the same basename: one cause, not two.
        assert_eq!(evidence.causes.len(), 1);
        let cause = &evidence.causes[0];
        assert_eq!(cause.scope, "cursor");
        assert_eq!(
            tokens(cause),
            vec![
                "amplifier:critical_subprocess".to_string(),
                "critical_process:ssh".to_string(),
            ]
        );
        assert!(!evidence.truncated);
    }

    #[test]
    fn amplifiers_are_independent_causes() {
        let agents = vec![agent("cursor", true, false, &["github_token"])];
        let evidence = detail_for_blast_radius(&agents, &BTreeMap::new());

        // passwordless_root and secret_exposure are separate conditions:
        // accepting one must not clear the other.
        assert_eq!(evidence.causes.len(), 2);
        assert!(cause_for(&evidence, "cursor", "amplifier:passwordless_root").is_some());
        let secret = cause_for(&evidence, "cursor", "secret_label:github_token").unwrap();
        assert!(tokens(secret).contains(&"amplifier:secret_exposure".to_string()));
    }

    #[test]
    fn agent_slug_is_never_a_selector() {
        let agents = vec![agent("cursor", true, false, &[])];
        let evidence = detail_for_blast_radius(&agents, &BTreeMap::new());
        assert!(evidence
            .causes
            .iter()
            .flat_map(tokens)
            .all(|t| !t.starts_with("agent:")));
        assert!(evidence.causes.iter().all(|c| c.scope == "cursor"));
    }

    #[test]
    fn flagged_agent_with_no_amplifier_still_has_a_cause() {
        // Otherwise "every cause covered" would be vacuously true for an agent
        // the blast-radius rule did flag.
        let agents = vec![agent("codex", false, false, &[])];
        let evidence = detail_for_blast_radius(&agents, &BTreeMap::new());
        assert_eq!(evidence.causes.len(), 1);
        assert_eq!(tokens(&evidence.causes[0]), vec!["amplifier:unsandboxed"]);
    }

    #[test]
    fn truncation_is_fair_across_scopes() {
        // One noisy agent must not push the other out of the report.
        let noisy: Vec<String> = (0..MAX_FAILURE_CAUSES * 2)
            .map(|i| format!("proc{i}"))
            .collect();
        let procs = BTreeMap::from([
            ("cursor".to_string(), noisy),
            ("codex".to_string(), vec!["ssh".to_string()]),
        ]);
        let agents = vec![agent("cursor", false, true, &[]), agent("codex", false, true, &[])];
        let evidence = detail_for_blast_radius(&agents, &procs);

        assert_eq!(evidence.causes.len(), MAX_FAILURE_CAUSES);
        assert!(evidence.truncated);
        assert!(cause_for(&evidence, "codex", "critical_process:ssh").is_some());
    }

    #[test]
    fn untruncated_evidence_is_not_flagged() {
        let evidence = detail_for_unsecured_agent("claude_code");
        assert_eq!(evidence.causes.len(), 1);
        assert_eq!(evidence.causes[0].scope, "claude_code");
        assert_eq!(tokens(&evidence.causes[0]), vec!["observer:paused"]);
        assert!(!evidence.truncated);
    }

    #[test]
    fn unsecured_agent_ignores_blank_slug() {
        assert!(detail_for_unsecured_agent("   ").is_empty());
    }

    #[test]
    fn mcp_exposure_is_one_cause_named_two_ways() {
        let risks = vec![McpRiskEndpoint {
            rule_id: "mcp_public_no_strong_auth".to_string(),
            server_name: "Gojiberry".to_string(),
            agent_type: "cursor".to_string(),
            critical: true,
        }];
        let evidence = detail_for_mcp_risk(&risks);
        assert_eq!(evidence.causes.len(), 1);
        assert_eq!(evidence.causes[0].scope, "cursor");
        assert_eq!(
            tokens(&evidence.causes[0]),
            vec![
                "mcp_rule:mcp_public_no_strong_auth".to_string(),
                "mcp_server:gojiberry".to_string(),
            ]
        );
    }

    #[test]
    fn mcp_exposures_on_one_agent_stay_separate_causes() {
        let risks = vec![
            McpRiskEndpoint {
                rule_id: "mcp_public_no_strong_auth".to_string(),
                server_name: "gojiberry".to_string(),
                agent_type: "cursor".to_string(),
                critical: true,
            },
            McpRiskEndpoint {
                rule_id: "mcp_remote_cleartext_transport".to_string(),
                server_name: "shell-runner".to_string(),
                agent_type: "cursor".to_string(),
                critical: false,
            },
        ];
        let evidence = detail_for_mcp_risk(&risks);
        assert_eq!(evidence.causes.len(), 2);
    }

    #[test]
    fn mcp_risk_tolerates_a_finding_with_no_agent() {
        let risks = vec![McpRiskEndpoint {
            rule_id: "mcp_lan_privileged_no_auth".to_string(),
            server_name: "shell-runner".to_string(),
            agent_type: String::new(),
            critical: false,
        }];
        let evidence = detail_for_mcp_risk(&risks);
        assert_eq!(evidence.causes.len(), 1);
        assert!(evidence.causes[0].scope.is_empty());
    }

    #[test]
    fn without_harness_emits_one_cause_per_agent_and_no_roster() {
        let evidence =
            detail_for_agents_without_harness(&["Cursor".to_string(), "codex".to_string()]);
        let scopes: Vec<&str> = evidence.causes.iter().map(|c| c.scope.as_str()).collect();
        assert_eq!(scopes, vec!["codex", "cursor"]);
        assert!(evidence
            .causes
            .iter()
            .all(|c| tokens(c) == vec!["harness_state:missing"]));
        // The static harness roster is product knowledge, not host evidence.
        assert!(evidence.context.is_empty());
    }

    #[test]
    fn divergence_puts_harness_in_context_not_causes() {
        let evidence = detail_for_harness_divergence(
            &["cursor".to_string()],
            &["nono".to_string(), "SRT".to_string()],
            &[agent("cursor", true, false, &[])],
            &BTreeMap::new(),
        );

        assert_eq!(tokens(&evidence.causes[0]), vec!["amplifier:passwordless_root"]);
        let context: Vec<String> = evidence.context.iter().map(|c| c.token()).collect();
        assert_eq!(context, vec!["harness:nono", "harness:srt"]);
        // A harness cannot be whitelisted, so it must not look like a selector.
        assert!(evidence
            .causes
            .iter()
            .flat_map(tokens)
            .all(|t| !t.starts_with("harness:")));
    }

    #[test]
    fn divergence_keeps_agents_absent_from_the_blast_snapshot() {
        let evidence = detail_for_harness_divergence(
            &["cursor".to_string(), "codex".to_string()],
            &["nono".to_string()],
            &[agent("cursor", true, false, &[])],
            &BTreeMap::new(),
        );
        assert_eq!(tokens(cause_for(&evidence, "codex", "harness_state:diverging").unwrap()).len(), 1);
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
