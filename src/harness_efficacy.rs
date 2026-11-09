//! INC-17 Harness Efficacy Attestation.
//!
//! `agent_visibility::agents_with_harness_divergence` answers a per-host
//! question: "is a governance harness installed, yet does an agent still show
//! host blast-radius escape?". This module answers the per-finding question
//! behind it: when the attack pattern detector fires on a harnessed host, which
//! harness was present, and was the action class of that finding something the
//! harness *declared* it confines? A finding inside a harness's declared scope
//! is direct evidence that the deployed control did not bound the agent; a
//! finding outside its scope says nothing about the harness at all.
//!
//! Everything here is pure and deterministic: the declared confinement scope
//! is a static per-product table (what the product documents itself as
//! enforcing, not a runtime assessment of its configuration), the
//! check -> action-class map is fixed, and the efficacy roll-up only counts
//! findings the caller hands it. The output is an attestation signal per
//! harness, never a block and never an exculpation: a harness being present
//! does not lower a finding's severity (see `build_vulnerability_prompt`), and
//! the absence of in-scope findings is reported as `Unobserved`, not as proof
//! that the harness confines -- prevented actions are invisible to a
//! post-hoc observer.

use crate::agent_visibility::AgentHarness;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Coarse action classes a governance harness can declare it confines. The
/// granularity is deliberately the one the attack pattern checks already
/// speak (`action_class_for_check`), so attribution needs no new telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HarnessActionClass {
    /// Running arbitrary commands / spawning shells and tools.
    ShellExec,
    /// Writing outside the workspace (agent config, system binaries, temp
    /// droppers, instruction artifacts).
    FilesystemWrite,
    /// Reading credential stores and key material.
    CredentialAccess,
    /// Off-host network egress.
    NetworkEgress,
    /// Becoming root / bypassing OS confinement.
    PrivilegeEscalation,
}

impl HarnessActionClass {
    pub const ALL: [HarnessActionClass; 5] = [
        HarnessActionClass::ShellExec,
        HarnessActionClass::FilesystemWrite,
        HarnessActionClass::CredentialAccess,
        HarnessActionClass::NetworkEgress,
        HarnessActionClass::PrivilegeEscalation,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            HarnessActionClass::ShellExec => "shell_exec",
            HarnessActionClass::FilesystemWrite => "filesystem_write",
            HarnessActionClass::CredentialAccess => "credential_access",
            HarnessActionClass::NetworkEgress => "network_egress",
            HarnessActionClass::PrivilegeEscalation => "privilege_escalation",
        }
    }
}

impl std::fmt::Display for HarnessActionClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The confinement scope each known harness (see the harness catalog,
/// `agent_visibility_params::agent_harnesses`) documents itself as enforcing.
/// Declared scope, not measured scope: a harness may be installed and not
/// configured, which is exactly what an in-scope finding then exposes.
///
/// | slug | confines | rationale |
/// |---|---|---|
/// | `agentfield` | shell_exec | tool allow-lists / budgets / turn caps govern which tools and commands the governed agent may invoke; no OS-level filesystem or network boundary |
/// | `rippletide` | shell_exec, filesystem_write, network_egress | validates every proposed agent action against policy before it executes; runs above the OS, so privilege and raw credential reads are out of scope |
/// | `nono` | filesystem_write, credential_access, network_egress, privilege_escalation | least-privilege OS sandbox: filesystem and network restrictions plus no privilege gain |
/// | `srt` | filesystem_write, credential_access, network_egress | OS-level filesystem and network restrictions (sandbox-exec / Bubblewrap / Windows primitives) |
///
/// Unknown slugs declare nothing, so every finding on such a host is
/// out-of-scope and the harness stays `Unobserved`.
pub fn declared_confinement_scope(slug: &str) -> &'static [HarnessActionClass] {
    use HarnessActionClass::*;
    match slug {
        "agentfield" => &[ShellExec],
        "rippletide" => &[ShellExec, FilesystemWrite, NetworkEgress],
        "nono" => &[
            FilesystemWrite,
            CredentialAccess,
            NetworkEgress,
            PrivilegeEscalation,
        ],
        "srt" => &[FilesystemWrite, CredentialAccess, NetworkEgress],
        _ => &[],
    }
}

/// Map an attack pattern check name to the action class a harness would have
/// had to confine to prevent it. `None` for checks that do not correspond to a
/// confinable agent action (they then never count against any harness).
pub fn action_class_for_check(check: &str) -> Option<HarnessActionClass> {
    use HarnessActionClass::*;
    match check {
        "credential_harvest" => Some(CredentialAccess),
        "token_exfiltration" | "sensitive_material_egress" => Some(NetworkEgress),
        // An install-time lifecycle script is a tool execution the harness
        // let through.
        "sandbox_exploitation" | "agent_denylist_bypass" | "package_install_lifecycle" => {
            Some(ShellExec)
        }
        // Agent config / system binary writes and dropped skills are writes
        // outside the workspace an OS sandbox or action policy would bound.
        "file_system_tampering" | "agent_control_tampering" | "skill_supply_chain" => {
            Some(FilesystemWrite)
        }
        // Reading another process's memory / task port is the OS-confinement
        // boundary an OS sandbox is meant to hold.
        "process_memory_scrape" => Some(PrivilegeEscalation),
        _ => None,
    }
}

/// Per-finding harness attribution: which harnesses were present when the
/// finding fired, whether the finding's action class fell inside each
/// harness's declared scope, and whether the finding's process descends
/// from a governed agent at all.
///
/// A harness confines the agent it governs, so a finding counts against it
/// only when the process behind the finding is measured to descend from an
/// AI agent (`agent_subtree`, the kernel lineage). A finding of a process
/// with no measured agent lineage (a user's own tool, a service, a process
/// the lineage sensor did not see start) says nothing about the harness:
/// it is unmeasured, never a failure.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessAttribution {
    /// Slugs of every harness detected on the host, sorted.
    pub harnesses_present: Vec<String>,
    /// Action class of the finding's check (`None` when unmapped).
    pub action_class: Option<HarnessActionClass>,
    /// The AI agent the finding's process descends from, when measured.
    pub agent_subtree: Option<String>,
    /// Present harnesses whose declared scope covers `action_class` while the
    /// finding's process descends from an agent -- the finding fired
    /// *despite* them (efficacy failure evidence).
    pub in_scope_harnesses: Vec<String>,
    /// Present harnesses whose declared scope does not cover `action_class`
    /// (the finding says nothing about them).
    pub out_of_scope_harnesses: Vec<String>,
    /// Present harnesses whose declared scope covers `action_class` but the
    /// finding's process has no measured agent lineage: unmeasured, not
    /// counted either way.
    pub unattributed_harnesses: Vec<String>,
}

impl HarnessAttribution {
    /// True when at least one present harness declared it confines this
    /// finding's action class.
    pub fn fired_despite_in_scope_harness(&self) -> bool {
        !self.in_scope_harnesses.is_empty()
    }
}

/// Attribute one finding (by check name and the agent its process descends
/// from, when measured) to the detected harnesses. Pure.
pub fn attribute_finding(
    check: &str,
    agent_subtree: Option<&str>,
    harnesses: &[AgentHarness],
) -> HarnessAttribution {
    let action_class = action_class_for_check(check);
    let agent_subtree = agent_subtree
        .map(str::trim)
        .filter(|agent| !agent.is_empty())
        .map(str::to_string);
    let mut present: Vec<&AgentHarness> = harnesses.iter().filter(|h| h.detected).collect();
    present.sort_by(|a, b| a.slug.cmp(&b.slug));
    present.dedup_by(|a, b| a.slug == b.slug);

    let mut attribution = HarnessAttribution {
        harnesses_present: present.iter().map(|h| h.slug.clone()).collect(),
        action_class,
        agent_subtree: agent_subtree.clone(),
        ..Default::default()
    };
    for h in present {
        let class_in_scope = action_class
            .map(|class| declared_confinement_scope(&h.slug).contains(&class))
            .unwrap_or(false);
        if !class_in_scope {
            attribution.out_of_scope_harnesses.push(h.slug.clone());
        } else if agent_subtree.is_some() {
            attribution.in_scope_harnesses.push(h.slug.clone());
        } else {
            attribution.unattributed_harnesses.push(h.slug.clone());
        }
    }
    attribution
}

/// Efficacy verdict for one harness on this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HarnessEfficacyVerdict {
    /// The harness footprint is not on this host.
    NotDetected,
    /// Present, and no active alertable finding fell inside its declared
    /// scope. Deliberately NOT "confining": prevented actions leave no trace
    /// for a post-hoc observer, so the absence of evidence is reported as
    /// such.
    Unobserved,
    /// Present, yet at least one active alertable finding fired inside its
    /// declared scope -- the deployed control did not bound the agent.
    Failed,
}

/// One finding as the efficacy roll-up sees it: the check name, whether
/// the finding currently counts (active, non-dismissed, HIGH/CRITICAL -- the
/// same alertable gate `VulnerabilityReport::active_alertable_findings_count`
/// uses, decided by the caller so this module stays free of severity policy)
/// and the agent its process descends from, when measured. A finding
/// without one never counts in scope: a harness confines its agent, and a
/// process with no measured agent lineage is unmeasured, not a failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EfficacyFindingInput {
    pub check: String,
    pub finding_key: String,
    pub alertable: bool,
    pub agent_subtree: Option<String>,
}

/// Efficacy attestation for one harness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessEfficacy {
    pub slug: String,
    pub display_name: String,
    pub detected: bool,
    /// Governed-agent identity token when the harness exposes one (see
    /// `AgentHarness::identity`), so the attestation joins the harness's own
    /// audit trail.
    pub identity: Option<String>,
    /// What the product documents itself as confining.
    pub declared_scope: Vec<HarnessActionClass>,
    /// Active alertable findings whose action class is inside the declared
    /// scope (evidence the harness failed to confine).
    pub in_scope_findings: usize,
    /// Active alertable findings outside the declared scope (no bearing on
    /// this harness).
    pub out_of_scope_findings: usize,
    /// Active alertable findings inside the declared scope whose process has
    /// no measured agent lineage: unmeasured, counted neither as failure nor
    /// as out of scope.
    pub unattributed_findings: usize,
    /// Sorted, de-duplicated check names behind `in_scope_findings`.
    pub in_scope_checks: Vec<String>,
    /// Finding keys behind `in_scope_findings`, sorted, so the UI / CLI can
    /// deep-link from the attestation to the findings.
    pub in_scope_finding_keys: Vec<String>,
    pub verdict: HarnessEfficacyVerdict,
}

/// Roll the current findings up into one efficacy row per known harness.
/// Absent harnesses are included (`NotDetected`) so the operator surface can
/// show the full roster like `detect_agent_harnesses` does. Only findings with
/// `alertable == true` and a mapped action class are counted, and only a
/// finding with a measured agent lineage (`agent_subtree`) counts in scope.
/// Pure and sorted by slug.
pub fn harness_efficacy(
    harnesses: &[AgentHarness],
    findings: &[EfficacyFindingInput],
) -> Vec<HarnessEfficacy> {
    let mut out: Vec<HarnessEfficacy> = harnesses
        .iter()
        .map(|h| {
            let scope = declared_confinement_scope(&h.slug);
            let mut in_scope = 0usize;
            let mut out_of_scope = 0usize;
            let mut unattributed = 0usize;
            let mut checks: BTreeSet<String> = BTreeSet::new();
            let mut keys: BTreeSet<String> = BTreeSet::new();
            if h.detected {
                for f in findings.iter().filter(|f| f.alertable) {
                    let Some(class) = action_class_for_check(&f.check) else {
                        continue;
                    };
                    if !scope.contains(&class) {
                        out_of_scope += 1;
                    } else if f
                        .agent_subtree
                        .as_deref()
                        .is_some_and(|agent| !agent.trim().is_empty())
                    {
                        in_scope += 1;
                        checks.insert(f.check.clone());
                        keys.insert(f.finding_key.clone());
                    } else {
                        unattributed += 1;
                    }
                }
            }
            let verdict = if !h.detected {
                HarnessEfficacyVerdict::NotDetected
            } else if in_scope > 0 {
                HarnessEfficacyVerdict::Failed
            } else {
                HarnessEfficacyVerdict::Unobserved
            };
            HarnessEfficacy {
                slug: h.slug.clone(),
                display_name: h.display_name.clone(),
                detected: h.detected,
                identity: h.identity.clone(),
                declared_scope: scope.to_vec(),
                in_scope_findings: in_scope,
                out_of_scope_findings: out_of_scope,
                unattributed_findings: unattributed,
                in_scope_checks: checks.into_iter().collect(),
                in_scope_finding_keys: keys.into_iter().collect(),
                verdict,
            }
        })
        .collect();
    out.sort_by(|a, b| a.slug.cmp(&b.slug));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn harness(slug: &str, detected: bool) -> AgentHarness {
        AgentHarness {
            slug: slug.to_string(),
            display_name: slug.to_uppercase(),
            detected,
            homepage: String::new(),
            evidence: if detected {
                vec![format!("~/.{slug}")]
            } else {
                Vec::new()
            },
            identity: None,
        }
    }

    fn finding(check: &str, key: &str, alertable: bool) -> EfficacyFindingInput {
        EfficacyFindingInput {
            check: check.to_string(),
            finding_key: key.to_string(),
            alertable,
            agent_subtree: Some("claude_code".to_string()),
        }
    }

    fn unattributed(check: &str, key: &str, alertable: bool) -> EfficacyFindingInput {
        EfficacyFindingInput {
            agent_subtree: None,
            ..finding(check, key, alertable)
        }
    }

    #[test]
    fn every_check_maps_to_a_class_or_is_deliberately_unmapped() {
        for check in [
            "credential_harvest",
            "token_exfiltration",
            "sensitive_material_egress",
            "sandbox_exploitation",
            "agent_denylist_bypass",
            "file_system_tampering",
            "agent_control_tampering",
            "skill_supply_chain",
            "package_install_lifecycle",
            "process_memory_scrape",
        ] {
            assert!(action_class_for_check(check).is_some(), "{check} unmapped");
        }
        assert_eq!(action_class_for_check("test"), None);
        assert_eq!(action_class_for_check("critical_test_finding"), None);
    }

    #[test]
    fn every_known_harness_declares_a_scope() {
        for slug in ["agentfield", "rippletide", "nono", "srt"] {
            assert!(
                !declared_confinement_scope(slug).is_empty(),
                "{slug} declares nothing"
            );
        }
        assert!(declared_confinement_scope("unknown-product").is_empty());
    }

    #[test]
    fn attribution_splits_present_harnesses_by_declared_scope() {
        let harnesses = vec![
            harness("agentfield", true),
            harness("srt", true),
            harness("nono", false),
        ];
        let a = attribute_finding("sandbox_exploitation", Some("claude_code"), &harnesses);
        assert_eq!(a.harnesses_present, vec!["agentfield", "srt"]);
        assert_eq!(a.action_class, Some(HarnessActionClass::ShellExec));
        assert_eq!(a.agent_subtree.as_deref(), Some("claude_code"));
        assert_eq!(a.in_scope_harnesses, vec!["agentfield"]);
        assert_eq!(a.out_of_scope_harnesses, vec!["srt"]);
        assert!(a.unattributed_harnesses.is_empty());
        assert!(a.fired_despite_in_scope_harness());

        let b = attribute_finding("credential_harvest", Some("cursor"), &harnesses);
        assert_eq!(b.in_scope_harnesses, vec!["srt"]);
        assert_eq!(b.out_of_scope_harnesses, vec!["agentfield"]);
    }

    #[test]
    fn attribution_without_an_agent_lineage_is_unmeasured_not_a_failure() {
        let harnesses = vec![harness("agentfield", true), harness("srt", true)];
        for subtree in [None, Some(""), Some("  ")] {
            let a = attribute_finding("sandbox_exploitation", subtree, &harnesses);
            assert_eq!(a.harnesses_present, vec!["agentfield", "srt"]);
            assert_eq!(a.action_class, Some(HarnessActionClass::ShellExec));
            assert_eq!(a.agent_subtree, None);
            assert!(a.in_scope_harnesses.is_empty());
            assert_eq!(a.unattributed_harnesses, vec!["agentfield"]);
            assert_eq!(a.out_of_scope_harnesses, vec!["srt"]);
            assert!(!a.fired_despite_in_scope_harness());
        }
    }

    #[test]
    fn attribution_is_empty_without_a_detected_harness() {
        let harnesses = vec![harness("agentfield", false)];
        let a = attribute_finding("credential_harvest", Some("claude_code"), &harnesses);
        assert!(a.harnesses_present.is_empty());
        assert!(!a.fired_despite_in_scope_harness());
        assert_eq!(a.action_class, Some(HarnessActionClass::CredentialAccess));
    }

    #[test]
    fn unmapped_check_is_out_of_scope_for_every_harness() {
        let harnesses = vec![harness("nono", true)];
        let a = attribute_finding("test", Some("claude_code"), &harnesses);
        assert_eq!(a.action_class, None);
        assert!(a.in_scope_harnesses.is_empty());
        assert_eq!(a.out_of_scope_harnesses, vec!["nono"]);
    }

    #[test]
    fn efficacy_fails_only_on_active_alertable_in_scope_findings() {
        let harnesses = vec![
            harness("agentfield", true),
            harness("srt", true),
            harness("nono", false),
        ];
        let findings = vec![
            finding("sandbox_exploitation", "k1", true),
            // LOW / dismissed findings arrive as non-alertable and never count.
            finding("credential_harvest", "k2", false),
            finding("token_exfiltration", "k3", true),
            // An alertable in-class finding of a process with no measured
            // agent lineage is unmeasured: neither a failure nor out of scope.
            unattributed("agent_denylist_bypass", "k4", true),
        ];
        let rows = harness_efficacy(&harnesses, &findings);
        assert_eq!(rows.len(), 3);
        let by_slug = |s: &str| rows.iter().find(|r| r.slug == s).unwrap().clone();

        let af = by_slug("agentfield");
        assert_eq!(af.verdict, HarnessEfficacyVerdict::Failed);
        assert_eq!(af.in_scope_findings, 1);
        assert_eq!(af.out_of_scope_findings, 1);
        assert_eq!(af.unattributed_findings, 1);
        assert_eq!(af.in_scope_checks, vec!["sandbox_exploitation"]);
        assert_eq!(af.in_scope_finding_keys, vec!["k1"]);

        let srt = by_slug("srt");
        assert_eq!(srt.verdict, HarnessEfficacyVerdict::Failed);
        assert_eq!(srt.in_scope_checks, vec!["token_exfiltration"]);
        assert_eq!(srt.out_of_scope_findings, 2);
        assert_eq!(srt.unattributed_findings, 0);

        let nono = by_slug("nono");
        assert_eq!(nono.verdict, HarnessEfficacyVerdict::NotDetected);
        assert_eq!(nono.in_scope_findings, 0);
        assert_eq!(nono.out_of_scope_findings, 0);
    }

    #[test]
    fn efficacy_is_unobserved_not_confining_without_in_scope_evidence() {
        let harnesses = vec![harness("agentfield", true)];
        let findings = vec![finding("credential_harvest", "k1", true)];
        let rows = harness_efficacy(&harnesses, &findings);
        assert_eq!(rows[0].verdict, HarnessEfficacyVerdict::Unobserved);
        assert_eq!(rows[0].out_of_scope_findings, 1);
        let empty = harness_efficacy(&harnesses, &[]);
        assert_eq!(empty[0].verdict, HarnessEfficacyVerdict::Unobserved);
    }

    /// In-class findings without a measured agent lineage never fail a
    /// harness, however many of them there are.
    #[test]
    fn efficacy_stays_unobserved_on_unattributed_in_scope_findings() {
        let harnesses = vec![harness("agentfield", true)];
        let findings = vec![
            unattributed("sandbox_exploitation", "k1", true),
            unattributed("package_install_lifecycle", "k2", true),
        ];
        let rows = harness_efficacy(&harnesses, &findings);
        assert_eq!(rows[0].verdict, HarnessEfficacyVerdict::Unobserved);
        assert_eq!(rows[0].in_scope_findings, 0);
        assert_eq!(rows[0].unattributed_findings, 2);
        assert!(rows[0].in_scope_finding_keys.is_empty());
    }

    #[test]
    fn serde_uses_snake_case_labels() {
        let v = serde_json::to_value(HarnessActionClass::CredentialAccess).unwrap();
        assert_eq!(v, serde_json::json!("credential_access"));
        let v = serde_json::to_value(HarnessEfficacyVerdict::NotDetected).unwrap();
        assert_eq!(v, serde_json::json!("not_detected"));
    }
}
