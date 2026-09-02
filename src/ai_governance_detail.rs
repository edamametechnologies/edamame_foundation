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
use crate::agent_visibility::{
    AgentHarness, AgentSandbox, AuthStrength, BlastRadiusAgent, ExposureScope, HostPrivilege,
    McpEndpoint, McpRiskEndpoint, VisibilityFinding, VisibilitySeverity,
};
#[cfg(test)]
use edamame_backend::detail_backend::MAX_CONTEXT_TEXT_LEN;
use edamame_backend::detail_backend::{
    AiAgentInventoryBackend, AiAmplifiersInventoryBackend, AiHarnessInventoryBackend,
    AiHostInventoryBackend, AiInventoryBackend, AiMcpServerInventoryBackend,
    AiSandboxInventoryBackend, CheckContextBackend, CheckContextKindBackend, CheckDetailBackend,
    ContextDetailBackend, ContextFactBackend, CoverageKindBackend, CoverageRowBackend,
    FailureCauseBackend, FailureSelectorBackend, FailureSelectorKindBackend,
    MAX_CHECK_CONTEXT_ROWS, MAX_FAILURE_CAUSES, MAX_INVENTORY_AGENTS,
    MAX_INVENTORY_CRITICAL_PROCESSES_PER_AGENT, MAX_INVENTORY_HARNESSES,
    MAX_INVENTORY_MCP_SERVERS_PER_AGENT, MAX_INVENTORY_RULE_IDS_PER_SERVER,
    MAX_INVENTORY_SECRET_LABELS_PER_AGENT,
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
        self.causes.push(FailureCauseBackend::new(scope, selectors));
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

    /// Record a context row carrying the full on-device card (level 3).
    fn context_rich(
        &mut self,
        kind: CheckContextKindBackend,
        key: &str,
        scope: &str,
        detail: ContextDetailBackend,
    ) {
        if key.is_empty() {
            return;
        }
        let mut row = CheckContextBackend::new(kind, key);
        if !scope.is_empty() {
            row = row.with_scope(scope);
        }
        self.context.push(row.with_detail(detail));
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
    // Context has its own cap: it is display-only, so unlike the cause cap this
    // one is cosmetic and never feeds `truncated`.
    context.truncate(MAX_CHECK_CONTEXT_ROWS);

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
                builder.cause(
                    &scope,
                    vec![(Kind::Amplifier, "critical_subprocess".into())],
                );
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

// ---------------------------------------------------------------------------
// Runtime-plane checks: attack detection, divergence, escalated actions
//
// These three were originally outside the AI governance class -- they shipped
// as bare booleans with no causes, which meant an administrator could neither
// review nor accept them, and could not tell "the engine found something" from
// "the engine is switched off". They now emit causes like every other AI check,
// plus the level-3 context that carries the card the device user already sees.
//
// Selector-kind boundary (mirrors the MCP rule in AIGOVERNANCE.md §7): the
// `attack_*`, `divergence_*` and `escalated_*` kinds are emitted ONLY by their
// own check. Accepting `attack_process:ssh` must never clear a blast-radius
// cause naming the same binary through `critical_process:ssh`, because the two
// say different things -- one accepts a spawn, the other accepts an attack.
// ---------------------------------------------------------------------------

/// One attack finding, flattened to metadata the governance surface may carry.
///
/// Deliberately NOT the detector's `VulnerabilityFinding`: foundation cannot
/// depend on core, and the narrower shape is also the privacy boundary. Full
/// file paths, open-file lists and LLM rationales are excluded by construction
/// rather than by remembering to strip them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AttackFindingSlice {
    /// Detector family (`credential_harvest`, `token_exfiltration`, ...).
    pub check_family: String,
    pub finding_key: String,
    pub severity: String,
    /// Deterministic description. Never an LLM rationale.
    pub description: String,
    pub process_name: String,
    pub parent_process_name: String,
    pub destination_domain: String,
    pub destination_ip: String,
    pub destination_port: Option<u16>,
    pub detection_basis: Vec<String>,
    pub reference: String,
    pub dismissed: bool,
    /// Agent slug when the finding is attributable to one; empty otherwise.
    pub agent_type: String,
}

/// One divergence evidence row, flattened the same way.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DivergenceEvidenceSlice {
    pub category: String,
    pub finding_key: String,
    pub severity: String,
    pub description: String,
    pub process_name: String,
    pub agent_type: String,
    pub trigger_reason: String,
    /// Count only. The paths themselves are sensitive by definition.
    pub unexpected_sensitive_count: usize,
    pub dismissed: bool,
}

/// One escalated advisor action awaiting operator review.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EscalatedActionSlice {
    pub action_id: String,
    pub action_class: String,
    pub advice_type: String,
    pub title: String,
    pub severity: String,
}

/// `credential_harvest` -> `Credential harvest`.
fn humanize(raw: &str) -> String {
    let cleaned = raw.trim().replace(['_', '-'], " ");
    let mut chars = cleaned.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

fn destination_of(domain: &str, ip: &str) -> String {
    let domain = norm(domain);
    if !domain.is_empty() {
        return domain;
    }
    norm(ip)
}

/// The engine behind a runtime check is stopped.
///
/// Emitted as its own cause so a stopped engine is never a cause-less Active
/// check -- which the Hub would be free to derive `Passed` for, exactly the
/// vacuous-pass bug `amplifier:unsandboxed` exists to prevent on blast radius.
fn push_engine_stopped(builder: &mut EvidenceBuilder) {
    builder.cause("", vec![(Kind::EngineState, "stopped".into())]);
}

/// Evidence for an Active `vulnerabilities` (attack detection) check.
///
/// One cause per non-dismissed finding, named four ways so an administrator
/// picks their own blast radius: the whole detector family, one exact finding,
/// the process, or the destination. Dismissed findings ship as context only --
/// they are not why the check is failing, but the Hub should be able to see
/// that a condition was reviewed on the device rather than never observed.
pub fn detail_for_attack_findings(
    findings: &[AttackFindingSlice],
    engine_running: bool,
) -> CheckEvidence {
    let mut builder = EvidenceBuilder::default();

    if !engine_running {
        push_engine_stopped(&mut builder);
    }

    for finding in findings {
        let scope = norm(&finding.agent_type);
        let family = norm(&finding.check_family);
        let process = normalize_process_basename(&finding.process_name);
        let destination = destination_of(&finding.destination_domain, &finding.destination_ip);
        let key = finding.finding_key.trim().to_string();

        if !finding.dismissed {
            builder.cause(
                &scope,
                vec![
                    (Kind::AttackFamily, family.clone()),
                    (Kind::AttackFinding, key.clone()),
                    (Kind::AttackProcess, process.clone()),
                    (Kind::AttackDestination, destination.clone()),
                ],
            );
        }

        let mut facts = vec![ContextFactBackend::new("Detector", humanize(&family))];
        if !process.is_empty() {
            facts.push(ContextFactBackend::new("Process", process.clone()));
        }
        let parent = normalize_process_basename(&finding.parent_process_name);
        if !parent.is_empty() {
            facts.push(ContextFactBackend::new("Parent", parent));
        }
        if !destination.is_empty() {
            let shown = match finding.destination_port {
                Some(port) => format!("{destination}:{port}"),
                None => destination.clone(),
            };
            facts.push(ContextFactBackend::new("Destination", shown));
        }
        let basis = normalized_set(finding.detection_basis.iter(), false);
        if !basis.is_empty() {
            facts.push(ContextFactBackend::new("Detection basis", basis.join(", ")));
        }
        if !scope.is_empty() {
            facts.push(ContextFactBackend::new("Agent", scope.clone()));
        }

        let detail = ContextDetailBackend::new(
            format!("Attack pattern: {}", humanize(&family)),
            &finding.severity,
            &finding.description,
        )
        .with_subject(if process.is_empty() {
            scope.clone()
        } else {
            process
        })
        .with_facts(facts)
        .with_references(if finding.reference.trim().is_empty() {
            Vec::new()
        } else {
            vec![finding.reference.clone()]
        })
        .with_dismissed(finding.dismissed);

        builder.context_rich(CheckContextKindBackend::AttackFinding, &key, &scope, detail);
    }

    builder.finish()
}

/// Evidence for an Active `divergence` check.
///
/// Scoped to the agent whose declared intent the behaviour diverged from, which
/// is what makes a per-agent acceptance meaningful: "this agent is expected to
/// reach there" is a statement about that agent, not about the category.
pub fn detail_for_divergence(
    evidence: &[DivergenceEvidenceSlice],
    engine_running: bool,
) -> CheckEvidence {
    let mut builder = EvidenceBuilder::default();

    if !engine_running {
        push_engine_stopped(&mut builder);
    }

    for row in evidence {
        let scope = norm(&row.agent_type);
        let category = norm(&row.category);
        let process = normalize_process_basename(&row.process_name);
        let key = row.finding_key.trim().to_string();

        if !row.dismissed {
            builder.cause(
                &scope,
                vec![
                    (Kind::DivergenceCategory, category.clone()),
                    (Kind::DivergenceFinding, key.clone()),
                    (Kind::DivergenceProcess, process.clone()),
                ],
            );
        }

        let mut facts = vec![ContextFactBackend::new("Category", humanize(&category))];
        if !process.is_empty() {
            facts.push(ContextFactBackend::new("Process", process.clone()));
        }
        if !scope.is_empty() {
            facts.push(ContextFactBackend::new("Agent", scope.clone()));
        }
        let trigger = row.trigger_reason.trim();
        if !trigger.is_empty() {
            facts.push(ContextFactBackend::new("Trigger", trigger));
        }
        if row.unexpected_sensitive_count > 0 {
            facts.push(ContextFactBackend::new(
                "Unexpected sensitive files",
                row.unexpected_sensitive_count.to_string(),
            ));
        }

        let detail = ContextDetailBackend::new(
            format!("Divergence: {}", humanize(&category)),
            &row.severity,
            &row.description,
        )
        .with_subject(if scope.is_empty() {
            process
        } else {
            scope.clone()
        })
        .with_facts(facts)
        .with_dismissed(row.dismissed);

        builder.context_rich(
            CheckContextKindBackend::DivergenceFinding,
            &key,
            &scope,
            detail,
        );
    }

    builder.finish()
}

/// Evidence for an Active `escalated` check.
///
/// The unit of acceptance is the action class, not the individual action: an
/// administrator decides "this agent may escalate port closures for review",
/// and each new action of that class is then expected rather than a new
/// exception to approve.
pub fn detail_for_escalated(actions: &[EscalatedActionSlice], loop_running: bool) -> CheckEvidence {
    let mut builder = EvidenceBuilder::default();

    if !loop_running {
        push_engine_stopped(&mut builder);
    }

    for action in actions {
        let class = norm(&action.action_class);
        builder.cause("", vec![(Kind::EscalatedAction, class.clone())]);

        let mut facts = vec![ContextFactBackend::new("Action class", humanize(&class))];
        let advice = norm(&action.advice_type);
        if !advice.is_empty() {
            facts.push(ContextFactBackend::new("Advice", humanize(&advice)));
        }

        let detail = ContextDetailBackend::new(
            if action.title.trim().is_empty() {
                format!("Escalated action: {}", humanize(&class))
            } else {
                action.title.clone()
            },
            &action.severity,
            format!(
                "An agentic action of class \"{}\" was escalated for operator review instead of being applied automatically.",
                humanize(&class)
            ),
        )
        .with_subject(class)
        .with_facts(facts);

        builder.context_rich(
            CheckContextKindBackend::EscalatedAction,
            action.action_id.trim(),
            "",
            detail,
        );
    }

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

// ---------------------------------------------------------------------------
// Always-on posture inventory
// ---------------------------------------------------------------------------

/// Everything `build_ai_inventory` needs, gathered from the visibility bundle
/// and the agent-observer state at capture time.
pub struct AiInventoryInputs<'a> {
    pub host_privilege: &'a HostPrivilege,
    /// Full known harness roster (detected and not).
    pub harnesses: &'a [AgentHarness],
    pub sandboxes: &'a [AgentSandbox],
    pub mcp_endpoints: &'a [McpEndpoint],
    /// Visibility findings; only those whose `subject_id` is an endpoint id are
    /// used, so passing the whole set is safe.
    pub mcp_findings: &'a [VisibilityFinding],
    pub discovered: &'a BTreeMap<String, bool>,
    pub observer_enabled: &'a BTreeMap<String, bool>,
    /// Critical subprocess basenames per agent (unfiltered).
    pub critical_processes: &'a BTreeMap<String, Vec<String>>,
    /// Secret-exposure labels per agent (unfiltered).
    pub secret_labels: &'a BTreeMap<String, Vec<String>>,
}

/// Always-on AI posture snapshot, emitted whether or not any check is failing.
///
/// Every key here uses the *same* normalization as [`FailureCauseBackend`]
/// scopes and [`FailureSelectorBackend`] values, so the Hub can join an
/// inventory row to the cause an Accept would resolve -- inventory itself is
/// never the matched surface (see `checks[]`), only the authoring surface.
///
/// Blast radius is derivable from what is reported: an agent is in blast radius
/// exactly when `amplifiers.unsandboxed` and at least one other amplifier hold.
pub fn build_ai_inventory(inputs: AiInventoryInputs<'_>) -> AiInventoryBackend {
    let mut truncated = false;

    let host = AiHostInventoryBackend {
        assessed: inputs.host_privilege.assessed,
        passwordless_root: inputs.host_privilege.passwordless_root,
        admin_user: inputs.host_privilege.admin_user,
        elevated_session: inputs.host_privilege.elevated_session,
        user: inputs.host_privilege.user.trim().to_string(),
        platform: norm(&inputs.host_privilege.platform),
    };

    let mut harnesses: Vec<AiHarnessInventoryBackend> = inputs
        .harnesses
        .iter()
        .filter_map(|harness| {
            let slug = norm(&harness.slug);
            if slug.is_empty() {
                return None;
            }
            Some(AiHarnessInventoryBackend {
                slug,
                display_name: harness.display_name.trim().to_string(),
                detected: harness.detected,
            })
        })
        .collect();
    harnesses.sort();
    harnesses.dedup();
    if harnesses.len() > MAX_INVENTORY_HARNESSES {
        harnesses.truncate(MAX_INVENTORY_HARNESSES);
        truncated = true;
    }

    let critical_processes = normalize_agent_map(inputs.critical_processes, true);
    let secret_labels = normalize_agent_map(inputs.secret_labels, false);
    let sandboxes = normalize_sandboxes(inputs.sandboxes);
    let (mut mcp_by_agent, mcp_truncated) =
        normalize_mcp_servers(inputs.mcp_endpoints, inputs.mcp_findings);
    truncated |= mcp_truncated;

    // Union of every source so an agent stays visible even when only one
    // subsystem knows about it.
    let mut keys: BTreeSet<String> = BTreeSet::new();
    for raw in inputs
        .discovered
        .keys()
        .chain(inputs.observer_enabled.keys())
    {
        let key = norm(raw);
        if !key.is_empty() {
            keys.insert(key);
        }
    }
    keys.extend(critical_processes.keys().cloned());
    keys.extend(secret_labels.keys().cloned());
    keys.extend(sandboxes.keys().cloned());
    keys.extend(mcp_by_agent.keys().cloned());

    if keys.len() > MAX_INVENTORY_AGENTS {
        truncated = true;
    }

    let host_passwordless_root =
        inputs.host_privilege.assessed && inputs.host_privilege.passwordless_root;

    let agents = keys
        .into_iter()
        .take(MAX_INVENTORY_AGENTS)
        .map(|key| {
            let sandbox = sandboxes.get(&key).cloned().unwrap_or_default();
            let mut processes = critical_processes.get(&key).cloned().unwrap_or_default();
            if processes.len() > MAX_INVENTORY_CRITICAL_PROCESSES_PER_AGENT {
                processes.truncate(MAX_INVENTORY_CRITICAL_PROCESSES_PER_AGENT);
                truncated = true;
            }
            let mut labels = secret_labels.get(&key).cloned().unwrap_or_default();
            if labels.len() > MAX_INVENTORY_SECRET_LABELS_PER_AGENT {
                labels.truncate(MAX_INVENTORY_SECRET_LABELS_PER_AGENT);
                truncated = true;
            }
            let mcp_servers = mcp_by_agent.remove(&key).unwrap_or_default();

            AiAgentInventoryBackend {
                present: lookup_flag(inputs.discovered, &key).unwrap_or(false),
                // Absent means enabled, matching the `unsecured_<agent>` check.
                monitored: lookup_flag(inputs.observer_enabled, &key).unwrap_or(true),
                amplifiers: AiAmplifiersInventoryBackend {
                    unsandboxed: sandbox.sandboxed == Some(false),
                    passwordless_root: host_passwordless_root,
                    critical_subprocess: !processes.is_empty(),
                    secret_exposure: !labels.is_empty(),
                },
                key,
                sandbox,
                critical_processes: processes,
                secret_exposure_labels: labels,
                mcp_servers,
            }
        })
        .collect();

    AiInventoryBackend {
        host,
        harnesses,
        agents,
        truncated,
    }
}

/// Re-key a per-agent map by normalized agent slug, normalizing the values too.
fn normalize_agent_map(
    raw: &BTreeMap<String, Vec<String>>,
    basename: bool,
) -> BTreeMap<String, Vec<String>> {
    let mut merged: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (agent, values) in raw {
        let key = norm(agent);
        if key.is_empty() {
            continue;
        }
        merged
            .entry(key)
            .or_default()
            .extend(normalized_set(values, basename));
    }
    merged
        .into_iter()
        .map(|(key, values)| (key, values.into_iter().collect()))
        .collect()
}

fn normalize_sandboxes(sandboxes: &[AgentSandbox]) -> BTreeMap<String, AiSandboxInventoryBackend> {
    sandboxes
        .iter()
        .filter_map(|sandbox| {
            let key = norm(&sandbox.agent_type);
            if key.is_empty() {
                return None;
            }
            Some((
                key,
                AiSandboxInventoryBackend {
                    sandboxed: sandbox.sandboxed,
                    mechanism: norm(&sandbox.mechanism),
                    file_access_scope: norm(&sandbox.file_access_scope),
                },
            ))
        })
        .collect()
}

/// Per-agent MCP rows, merging every endpoint that normalizes to the same
/// identity so `rule_ids` / `max_severity` describe the whole server row the
/// Hub would offer an Accept on.
fn normalize_mcp_servers(
    endpoints: &[McpEndpoint],
    findings: &[VisibilityFinding],
) -> (BTreeMap<String, Vec<AiMcpServerInventoryBackend>>, bool) {
    // endpoint id -> (rule ids, max severity rank)
    let mut by_endpoint: BTreeMap<&str, (BTreeSet<String>, u8)> = BTreeMap::new();
    for finding in findings {
        let entry = by_endpoint
            .entry(finding.subject_id.as_str())
            .or_insert_with(|| (BTreeSet::new(), 0));
        let rule = norm(&finding.rule_id);
        if !rule.is_empty() {
            entry.0.insert(rule);
        }
        entry.1 = entry.1.max(severity_rank(finding.severity));
    }

    // (agent, server_name, transport, exposure, auth, is_edamame) -> merged findings
    type RowKey = (String, String, String, String, String, bool);
    let mut rows: BTreeMap<RowKey, (BTreeSet<String>, u8)> = BTreeMap::new();
    for endpoint in endpoints {
        let agent = norm(&endpoint.agent_type);
        let server_name = norm(&endpoint.server_name);
        if agent.is_empty() || server_name.is_empty() {
            continue;
        }
        let key = (
            agent,
            server_name,
            norm(&endpoint.transport),
            exposure_scope_slug(endpoint.exposure_scope).to_string(),
            auth_strength_slug(endpoint.auth_strength).to_string(),
            endpoint.is_edamame_server,
        );
        let entry = rows.entry(key).or_insert_with(|| (BTreeSet::new(), 0));
        if let Some((rules, rank)) = by_endpoint.get(endpoint.id.as_str()) {
            entry.0.extend(rules.iter().cloned());
            entry.1 = entry.1.max(*rank);
        }
    }

    let mut truncated = false;
    let mut by_agent: BTreeMap<String, Vec<AiMcpServerInventoryBackend>> = BTreeMap::new();
    for (
        (agent, server_name, transport, exposure_scope, auth_strength, is_edamame),
        (rules, rank),
    ) in rows
    {
        let bucket = by_agent.entry(agent).or_default();
        if bucket.len() >= MAX_INVENTORY_MCP_SERVERS_PER_AGENT {
            truncated = true;
            continue;
        }
        let mut rule_ids: Vec<String> = rules.into_iter().collect();
        if rule_ids.len() > MAX_INVENTORY_RULE_IDS_PER_SERVER {
            rule_ids.truncate(MAX_INVENTORY_RULE_IDS_PER_SERVER);
            truncated = true;
        }
        bucket.push(AiMcpServerInventoryBackend {
            server_name,
            transport,
            exposure_scope,
            auth_strength,
            is_edamame_server: is_edamame,
            max_severity: severity_slug(rank).to_string(),
            alertable: rank >= severity_rank(VisibilitySeverity::High),
            rule_ids,
        });
    }
    (by_agent, truncated)
}

/// Read a per-agent flag by normalized slug, tolerating unnormalized keys.
fn lookup_flag(map: &BTreeMap<String, bool>, key: &str) -> Option<bool> {
    map.get(key).copied().or_else(|| {
        map.iter()
            .find(|(raw, _)| norm(raw) == key)
            .map(|(_, v)| *v)
    })
}

/// Rank so severities merge deterministically; `0` means "no finding".
fn severity_rank(severity: VisibilitySeverity) -> u8 {
    match severity {
        VisibilitySeverity::Info => 1,
        VisibilitySeverity::Low => 2,
        VisibilitySeverity::Medium => 3,
        VisibilitySeverity::High => 4,
        VisibilitySeverity::Critical => 5,
    }
}

fn severity_slug(rank: u8) -> &'static str {
    match rank {
        1 => "info",
        2 => "low",
        3 => "medium",
        4 => "high",
        5 => "critical",
        _ => "",
    }
}

fn exposure_scope_slug(scope: ExposureScope) -> &'static str {
    match scope {
        ExposureScope::Stdio => "stdio",
        ExposureScope::Loopback => "loopback",
        ExposureScope::Lan => "lan",
        ExposureScope::Remote => "remote",
        ExposureScope::Public => "public",
        ExposureScope::Unknown => "unknown",
    }
}

fn auth_strength_slug(auth: AuthStrength) -> &'static str {
    match auth {
        AuthStrength::None => "none",
        AuthStrength::Shared => "shared",
        AuthStrength::OAuth => "oauth",
        AuthStrength::Mtls => "mtls",
        AuthStrength::Unknown => "unknown",
    }
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
        let agents = vec![
            agent("cursor", false, true, &[]),
            agent("codex", false, true, &[]),
        ];
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

        assert_eq!(
            tokens(&evidence.causes[0]),
            vec!["amplifier:passwordless_root"]
        );
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
        assert_eq!(
            tokens(cause_for(&evidence, "codex", "harness_state:diverging").unwrap()).len(),
            1
        );
    }

    fn attack_slice() -> AttackFindingSlice {
        AttackFindingSlice {
            check_family: "credential_harvest".into(),
            finding_key: "fk-1".into(),
            severity: "HIGH".into(),
            description: "Process read AWS credentials and opened a socket".into(),
            process_name: "/usr/bin/Curl.exe".into(),
            parent_process_name: "bash".into(),
            destination_domain: "Evil.example.com".into(),
            destination_ip: "203.0.113.9".into(),
            destination_port: Some(443),
            detection_basis: vec!["temp_origin".into(), "sensitive_read".into()],
            reference: "OWASP-LLM06".into(),
            dismissed: false,
            agent_type: "Cursor".into(),
        }
    }

    #[test]
    fn attack_finding_emits_four_selector_granularities() {
        let ev = detail_for_attack_findings(&[attack_slice()], true);
        assert_eq!(ev.causes.len(), 1);
        let cause = &ev.causes[0];
        assert_eq!(cause.scope, "cursor");
        let tokens: Vec<String> = cause.selectors.iter().map(|s| s.token()).collect();
        assert!(tokens.contains(&"attack_family:credential_harvest".to_string()));
        assert!(tokens.contains(&"attack_finding:fk-1".to_string()));
        assert!(tokens.contains(&"attack_process:curl".to_string()));
        assert!(tokens.contains(&"attack_destination:evil.example.com".to_string()));
    }

    #[test]
    fn attack_context_carries_the_card_without_leaking_content() {
        let ev = detail_for_attack_findings(&[attack_slice()], true);
        let row = ev.context.iter().find(|c| c.key == "fk-1").expect("row");
        let detail = row.detail.as_ref().expect("level-3 detail");
        assert_eq!(detail.title, "Attack pattern: Credential harvest");
        assert_eq!(detail.severity, "high");
        assert_eq!(detail.subject, "curl");
        assert!(!detail.dismissed);
        assert_eq!(detail.references, vec!["OWASP-LLM06".to_string()]);
        let facts: Vec<(String, String)> = detail
            .facts
            .iter()
            .map(|f| (f.label.clone(), f.value.clone()))
            .collect();
        assert!(facts.contains(&("Destination".into(), "evil.example.com:443".into())));
        assert!(facts.contains(&("Parent".into(), "bash".into())));
        assert!(facts
            .iter()
            .any(|(l, v)| l == "Detection basis" && v.contains("temp_origin")));
    }

    #[test]
    fn dismissed_attack_finding_ships_as_context_but_never_as_a_cause() {
        let mut slice = attack_slice();
        slice.dismissed = true;
        let ev = detail_for_attack_findings(&[slice], true);
        assert!(
            ev.causes.is_empty(),
            "a dismissed finding is not why the check fails"
        );
        let row = ev.context.iter().find(|c| c.key == "fk-1").expect("row");
        assert!(row.detail.as_ref().expect("detail").dismissed);
    }

    #[test]
    fn stopped_engine_emits_its_own_cause_so_it_can_never_pass_vacuously() {
        for ev in [
            detail_for_attack_findings(&[], false),
            detail_for_divergence(&[], false),
            detail_for_escalated(&[], false),
        ] {
            let tokens: Vec<String> = ev
                .causes
                .iter()
                .flat_map(|c| c.selectors.iter().map(|s| s.token()))
                .collect();
            assert_eq!(tokens, vec!["engine_state:stopped".to_string()]);
        }
    }

    #[test]
    fn running_engine_with_no_findings_emits_nothing() {
        assert!(detail_for_attack_findings(&[], true).is_empty());
        assert!(detail_for_divergence(&[], true).is_empty());
        assert!(detail_for_escalated(&[], true).is_empty());
    }

    #[test]
    fn divergence_scopes_to_the_agent_and_counts_sensitive_paths() {
        let ev = detail_for_divergence(
            &[DivergenceEvidenceSlice {
                category: "correlation:unexplained".into(),
                finding_key: "dk-1".into(),
                severity: "MEDIUM".into(),
                description: "Egress not explained by declared intent".into(),
                process_name: "node".into(),
                agent_type: "Claude_Code".into(),
                trigger_reason: "unexplained_destination".into(),
                unexpected_sensitive_count: 3,
                dismissed: false,
            }],
            true,
        );
        assert_eq!(ev.causes[0].scope, "claude_code");
        let tokens: Vec<String> = ev.causes[0].selectors.iter().map(|s| s.token()).collect();
        assert!(tokens.contains(&"divergence_category:correlation:unexplained".to_string()));
        assert!(tokens.contains(&"divergence_process:node".to_string()));
        let detail = ev.context[0].detail.as_ref().expect("detail");
        assert_eq!(detail.subject, "claude_code");
        // The paths themselves must never ship -- only how many there were.
        assert!(detail
            .facts
            .iter()
            .any(|f| f.label == "Unexpected sensitive files" && f.value == "3"));
    }

    #[test]
    fn escalated_accepts_the_class_not_the_individual_action() {
        let ev = detail_for_escalated(
            &[
                EscalatedActionSlice {
                    action_id: "a1".into(),
                    action_class: "network_port".into(),
                    advice_type: "NetworkPort".into(),
                    title: String::new(),
                    severity: "high".into(),
                },
                EscalatedActionSlice {
                    action_id: "a2".into(),
                    action_class: "network_port".into(),
                    advice_type: "NetworkPort".into(),
                    title: String::new(),
                    severity: "high".into(),
                },
            ],
            true,
        );
        // Two actions of one class collapse to one reviewable cause...
        assert_eq!(ev.causes.len(), 1);
        assert_eq!(
            ev.causes[0].selectors[0].token(),
            "escalated_action:network_port"
        );
        // ...but both remain individually visible as context.
        assert_eq!(ev.context.len(), 2);
    }

    #[test]
    fn context_text_is_clamped_on_a_char_boundary() {
        let mut slice = attack_slice();
        slice.description = "é".repeat(MAX_CONTEXT_TEXT_LEN);
        let ev = detail_for_attack_findings(&[slice], true);
        let summary = &ev.context[0].detail.as_ref().expect("detail").summary;
        assert!(summary.len() <= MAX_CONTEXT_TEXT_LEN + 4);
        assert!(summary.ends_with('…'));
    }

    #[test]
    fn runtime_context_is_capped_without_flagging_truncated() {
        // Context is display-only, so its cap must never make a check
        // unprovable the way a dropped cause does.
        let findings: Vec<AttackFindingSlice> = (0..MAX_CHECK_CONTEXT_ROWS + 10)
            .map(|i| {
                let mut f = attack_slice();
                f.finding_key = format!("fk-{i}");
                f.dismissed = true;
                f
            })
            .collect();
        let ev = detail_for_attack_findings(&findings, true);
        assert_eq!(ev.context.len(), MAX_CHECK_CONTEXT_ROWS);
        assert!(!ev.truncated);
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

    // -- inventory ---------------------------------------------------------

    fn host(assessed: bool, passwordless_root: bool) -> HostPrivilege {
        HostPrivilege {
            elevated_session: false,
            admin_user: true,
            passwordless_root,
            evidence: vec![],
            platform: "macOS".to_string(),
            user: "alice".to_string(),
            assessed,
        }
    }

    fn sandbox(agent_type: &str, sandboxed: Option<bool>) -> AgentSandbox {
        AgentSandbox {
            agent_type: agent_type.to_string(),
            sandboxed,
            mechanism: if sandboxed == Some(true) {
                "app-sandbox".to_string()
            } else {
                "none".to_string()
            },
            detail: String::new(),
            file_access_scope: "user_files".to_string(),
            file_access_detail: String::new(),
            can_launch_arbitrary_commands: None,
            command_execution_detail: String::new(),
            declared_confinement: None,
            declared_approval: None,
            declared_source: None,
        }
    }

    fn endpoint(id: &str, agent_type: &str, server_name: &str) -> McpEndpoint {
        McpEndpoint {
            id: id.to_string(),
            agent_type: agent_type.to_string(),
            server_name: server_name.to_string(),
            transport: "stdio".to_string(),
            command: None,
            args: vec![],
            url: None,
            bind_host: None,
            exposure_scope: ExposureScope::Stdio,
            auth_strength: AuthStrength::None,
            oauth_metadata_uri: None,
            tool_privilege_classes: vec![],
            is_edamame_server: false,
            config_path: String::new(),
            env_keys: vec![],
        }
    }

    fn finding(subject_id: &str, rule_id: &str, severity: VisibilitySeverity) -> VisibilityFinding {
        VisibilityFinding::new("mcp", rule_id, severity, subject_id, "t", "d")
    }

    fn inputs<'a>(
        host_privilege: &'a HostPrivilege,
        sandboxes: &'a [AgentSandbox],
        endpoints: &'a [McpEndpoint],
        findings: &'a [VisibilityFinding],
        discovered: &'a BTreeMap<String, bool>,
        observer_enabled: &'a BTreeMap<String, bool>,
        critical_processes: &'a BTreeMap<String, Vec<String>>,
        secret_labels: &'a BTreeMap<String, Vec<String>>,
    ) -> AiInventoryInputs<'a> {
        AiInventoryInputs {
            host_privilege,
            harnesses: &[],
            sandboxes,
            mcp_endpoints: endpoints,
            mcp_findings: findings,
            discovered,
            observer_enabled,
            critical_processes,
            secret_labels,
        }
    }

    #[test]
    fn inventory_reports_green_agents_with_no_findings() {
        let host = host(true, false);
        let sandboxes = [sandbox("cursor", Some(true))];
        let discovered = BTreeMap::from([("cursor".to_string(), true)]);
        let inventory = build_ai_inventory(inputs(
            &host,
            &sandboxes,
            &[],
            &[],
            &discovered,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeMap::new(),
        ));

        assert!(!inventory.truncated);
        assert_eq!(inventory.agents.len(), 1);
        let agent = &inventory.agents[0];
        assert_eq!(agent.key, "cursor");
        assert!(agent.present);
        // Absent from the observer map means running, not paused.
        assert!(agent.monitored);
        assert_eq!(agent.sandbox.sandboxed, Some(true));
        assert_eq!(agent.amplifiers, AiAmplifiersInventoryBackend::default());
    }

    #[test]
    fn inventory_amplifiers_make_blast_radius_derivable() {
        let host = host(true, true);
        let sandboxes = [sandbox("cursor", Some(false)), sandbox("codex", Some(true))];
        let discovered =
            BTreeMap::from([("cursor".to_string(), true), ("codex".to_string(), true)]);
        let critical = BTreeMap::from([("cursor".to_string(), vec!["/usr/bin/ssh".to_string()])]);
        let secrets = BTreeMap::from([("cursor".to_string(), vec!["AWS_Credentials".to_string()])]);
        let inventory = build_ai_inventory(inputs(
            &host,
            &sandboxes,
            &[],
            &[],
            &discovered,
            &BTreeMap::new(),
            &critical,
            &secrets,
        ));

        let cursor = &inventory.agents[1];
        assert_eq!(cursor.key, "cursor");
        assert!(cursor.amplifiers.unsandboxed);
        assert!(cursor.amplifiers.passwordless_root);
        assert!(cursor.amplifiers.critical_subprocess);
        assert!(cursor.amplifiers.secret_exposure);
        // Selector-key parity with checks[].causes.
        assert_eq!(cursor.critical_processes, vec!["ssh".to_string()]);
        assert_eq!(
            cursor.secret_exposure_labels,
            vec!["aws_credentials".to_string()]
        );

        // Sandboxed agent inherits the host condition but is not in blast radius.
        let codex = &inventory.agents[0];
        assert!(!codex.amplifiers.unsandboxed);
        assert!(codex.amplifiers.passwordless_root);
    }

    #[test]
    fn inventory_omits_host_amplifier_when_unassessed() {
        let host = host(false, true);
        let discovered = BTreeMap::from([("cursor".to_string(), true)]);
        let inventory = build_ai_inventory(inputs(
            &host,
            &[],
            &[],
            &[],
            &discovered,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeMap::new(),
        ));
        assert!(!inventory.host.assessed);
        assert!(!inventory.agents[0].amplifiers.passwordless_root);
    }

    #[test]
    fn inventory_lists_every_mcp_server_and_merges_findings() {
        let host = host(true, false);
        let endpoints = [
            endpoint("e1", "cursor", "filesystem"),
            endpoint("e2", "cursor", "Quiet"),
        ];
        let findings = [
            finding("e1", "mcp_public_no_auth", VisibilitySeverity::High),
            finding("e1", "mcp_shell_tools", VisibilitySeverity::Low),
        ];
        let inventory = build_ai_inventory(inputs(
            &host,
            &[],
            &endpoints,
            &findings,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeMap::new(),
        ));

        let servers = &inventory.agents[0].mcp_servers;
        assert_eq!(servers.len(), 2);
        let fs = servers
            .iter()
            .find(|s| s.server_name == "filesystem")
            .expect("filesystem row");
        assert_eq!(fs.max_severity, "high");
        assert!(fs.alertable);
        assert_eq!(
            fs.rule_ids,
            vec![
                "mcp_public_no_auth".to_string(),
                "mcp_shell_tools".to_string()
            ]
        );
        // A server with no finding is still listed, quiet.
        let quiet = servers
            .iter()
            .find(|s| s.server_name == "quiet")
            .expect("quiet row");
        assert!(quiet.max_severity.is_empty());
        assert!(!quiet.alertable);
        assert!(quiet.rule_ids.is_empty());
    }

    #[test]
    fn inventory_caps_agents_and_flags_truncated() {
        let host = host(true, false);
        let discovered: BTreeMap<String, bool> = (0..MAX_INVENTORY_AGENTS + 5)
            .map(|i| (format!("agent{:03}", i), true))
            .collect();
        let inventory = build_ai_inventory(inputs(
            &host,
            &[],
            &[],
            &[],
            &discovered,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeMap::new(),
        ));
        assert_eq!(inventory.agents.len(), MAX_INVENTORY_AGENTS);
        assert!(inventory.truncated);
    }

    #[test]
    fn inventory_normalizes_harness_roster() {
        let host = host(true, false);
        let harnesses = vec![
            AgentHarness {
                slug: " NoNo ".to_string(),
                display_name: "nono".to_string(),
                detected: true,
                evidence: vec![],
                identity: None,
            },
            AgentHarness {
                slug: "srt".to_string(),
                display_name: "SRT".to_string(),
                detected: false,
                evidence: vec![],
                identity: None,
            },
        ];
        let empty_flags = BTreeMap::new();
        let empty_lists = BTreeMap::new();
        let inventory = build_ai_inventory(AiInventoryInputs {
            host_privilege: &host,
            harnesses: &harnesses,
            sandboxes: &[],
            mcp_endpoints: &[],
            mcp_findings: &[],
            discovered: &empty_flags,
            observer_enabled: &empty_flags,
            critical_processes: &empty_lists,
            secret_labels: &empty_lists,
        });
        let slugs: Vec<&str> = inventory
            .harnesses
            .iter()
            .map(|h| h.slug.as_str())
            .collect();
        // Undetected harnesses stay on the roster so the Hub can show coverage.
        assert_eq!(slugs, vec!["nono", "srt"]);
        assert!(inventory.harnesses[0].detected);
    }
}
