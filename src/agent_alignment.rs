//! Agent alignment rollup (INC-12, Stage D -- read-only composite scoring).
//!
//! A single deterministic **alignment score** (0-100, 100 == fully aligned)
//! rolled up from every visibility / explainability domain plus the runtime
//! attack-pattern findings. This is the pure-function analogue of the
//! attack-pattern severity scorer: it takes per-domain signals (already
//! computed elsewhere) and produces a composite score, a band, a per-domain
//! decomposition (so the UX can show *why* the score is what it is), and a
//! deterministic hard-fail gate (any CRITICAL domain fails outright).
//!
//! Invariants:
//! - **I3 Deterministic-first**: the score is a fixed function of its inputs;
//!   no LLM is consulted. The per-domain inputs MAY be LLM-adjudicated upstream.
//! - **I2 Core as source of truth**: this rolls up signals core already owns.
//! - Pure: no I/O, no clock except the caller-supplied `generated_at` is set by
//!   the builder via `chrono::Utc::now()` (the only impurity, matching the
//!   other domain builders).

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

/// One domain's contribution signal. `worst_severity` is the upstream severity
/// string (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`INFO`/`NONE`); `alertable_findings`
/// counts the HIGH/CRITICAL non-dismissed findings in that domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainSignal {
    pub domain: String,
    pub total_findings: u32,
    pub alertable_findings: u32,
    pub worst_severity: String,
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

/// Alignment band derived from the composite score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlignmentBand {
    /// >= 85: behavior matches declared intent; no alertable drift.
    Aligned,
    /// >= 60: minor drift / watch items.
    Watch,
    /// >= 30: material drift across one or more domains.
    Drifting,
    /// < 30 or any CRITICAL domain: severe misalignment.
    Critical,
}

impl AlignmentBand {
    pub fn as_str(&self) -> &'static str {
        match self {
            AlignmentBand::Aligned => "aligned",
            AlignmentBand::Watch => "watch",
            AlignmentBand::Drifting => "drifting",
            AlignmentBand::Critical => "critical",
        }
    }
}

/// Per-domain decomposition of the composite score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlignmentComponent {
    pub domain: String,
    pub alertable_findings: u32,
    pub worst_severity: String,
    /// Points this domain deducted from the perfect score of 100.
    pub deduction: f64,
}

/// The composite alignment rollup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlignmentRollup {
    pub generated_at: chrono::DateTime<chrono::Utc>,
    /// Composite alignment score in `[0, 100]` (100 == fully aligned).
    pub score: f64,
    pub band: AlignmentBand,
    /// True when any domain is CRITICAL -- a deterministic hard-fail gate that
    /// is independent of the numeric score.
    pub hard_fail: bool,
    /// Total alertable findings across all domains.
    pub alertable_total: u32,
    /// Per-domain decomposition, highest deduction first.
    pub components: Vec<AlignmentComponent>,
    /// Human-readable one-line rationale.
    pub rationale: String,
}

// ---------------------------------------------------------------------------
// Scoring (deterministic)
// ---------------------------------------------------------------------------

/// Base deduction for a domain's worst severity.
fn severity_deduction(sev: &str) -> f64 {
    match sev.trim().to_ascii_uppercase().as_str() {
        "CRITICAL" => 40.0,
        "HIGH" => 20.0,
        "MEDIUM" => 8.0,
        "LOW" => 3.0,
        _ => 0.0,
    }
}

/// Extra deduction per additional alertable finding beyond the first, capped so
/// one noisy domain cannot zero the whole score on count alone.
fn breadth_deduction(alertable: u32) -> f64 {
    let extra = alertable.saturating_sub(1);
    (extra as f64 * 2.0).min(12.0)
}

fn is_critical(sev: &str) -> bool {
    sev.trim().eq_ignore_ascii_case("critical")
}

fn band_for(score: f64, hard_fail: bool) -> AlignmentBand {
    if hard_fail {
        return AlignmentBand::Critical;
    }
    if score >= 85.0 {
        AlignmentBand::Aligned
    } else if score >= 60.0 {
        AlignmentBand::Watch
    } else if score >= 30.0 {
        AlignmentBand::Drifting
    } else {
        AlignmentBand::Critical
    }
}

/// Roll up per-domain signals into a composite alignment score. Pure.
pub fn build_alignment_rollup(signals: &[DomainSignal]) -> AlignmentRollup {
    let mut components: Vec<AlignmentComponent> = Vec::new();
    let mut hard_fail = false;
    let mut alertable_total = 0u32;
    let mut total_deduction = 0.0_f64;

    for s in signals {
        let base = severity_deduction(&s.worst_severity);
        let breadth = breadth_deduction(s.alertable_findings);
        let deduction = base + breadth;
        if is_critical(&s.worst_severity) {
            hard_fail = true;
        }
        alertable_total += s.alertable_findings;
        total_deduction += deduction;
        components.push(AlignmentComponent {
            domain: s.domain.clone(),
            alertable_findings: s.alertable_findings,
            worst_severity: s.worst_severity.trim().to_ascii_uppercase(),
            deduction: round2(deduction),
        });
    }

    let score = (100.0 - total_deduction).clamp(0.0, 100.0);
    let band = band_for(score, hard_fail);

    components.sort_by(|a, b| {
        b.deduction
            .partial_cmp(&a.deduction)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.domain.cmp(&b.domain))
    });

    let rationale = build_rationale(score, band, hard_fail, &components);

    AlignmentRollup {
        generated_at: chrono::Utc::now(),
        score: round2(score),
        band,
        hard_fail,
        alertable_total,
        components,
        rationale,
    }
}

fn build_rationale(
    score: f64,
    band: AlignmentBand,
    hard_fail: bool,
    components: &[AlignmentComponent],
) -> String {
    if hard_fail {
        let crit: Vec<&str> = components
            .iter()
            .filter(|c| c.worst_severity == "CRITICAL")
            .map(|c| c.domain.as_str())
            .collect();
        return format!(
            "Hard fail: CRITICAL finding(s) in [{}] (score {:.0}/100).",
            crit.join(", "),
            score
        );
    }
    let drivers: Vec<String> = components
        .iter()
        .filter(|c| c.deduction > 0.0)
        .take(3)
        .map(|c| format!("{} ({:.0})", c.domain, c.deduction))
        .collect();
    if drivers.is_empty() {
        format!(
            "Aligned: no alertable drift across domains (score {:.0}/100).",
            score
        )
    } else {
        format!(
            "{} alignment {:.0}/100; top drivers: {}.",
            band.as_str(),
            score,
            drivers.join(", ")
        )
    }
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(domain: &str, total: u32, alertable: u32, worst: &str) -> DomainSignal {
        DomainSignal {
            domain: domain.to_string(),
            total_findings: total,
            alertable_findings: alertable,
            worst_severity: worst.to_string(),
        }
    }

    #[test]
    fn clean_fleet_is_aligned_100() {
        let signals = vec![
            sig("mcp", 0, 0, "NONE"),
            sig("drift", 0, 0, "INFO"),
            sig("dataflow", 0, 0, "NONE"),
        ];
        let r = build_alignment_rollup(&signals);
        assert_eq!(r.score, 100.0);
        assert_eq!(r.band, AlignmentBand::Aligned);
        assert!(!r.hard_fail);
        assert_eq!(r.alertable_total, 0);
    }

    #[test]
    fn any_critical_hard_fails() {
        let signals = vec![sig("memory", 1, 1, "CRITICAL"), sig("mcp", 0, 0, "NONE")];
        let r = build_alignment_rollup(&signals);
        assert!(r.hard_fail);
        assert_eq!(r.band, AlignmentBand::Critical);
        assert!(r.rationale.contains("Hard fail"));
    }

    #[test]
    fn high_findings_deduct_and_band_watch() {
        // One HIGH domain (-20) -> 80 -> watch.
        let signals = vec![sig("dataflow", 1, 1, "HIGH")];
        let r = build_alignment_rollup(&signals);
        assert_eq!(r.score, 80.0);
        assert_eq!(r.band, AlignmentBand::Watch);
        assert!(!r.hard_fail);
    }

    #[test]
    fn breadth_penalty_is_capped() {
        // 100 alertable HIGH findings: base 20 + capped breadth 12 = 32 -> 68.
        let signals = vec![sig("drift", 100, 100, "HIGH")];
        let r = build_alignment_rollup(&signals);
        assert_eq!(r.score, 68.0);
    }

    #[test]
    fn components_sorted_by_deduction_desc() {
        let signals = vec![
            sig("mcp", 1, 1, "LOW"),
            sig("dataflow", 1, 1, "HIGH"),
            sig("memory", 1, 1, "MEDIUM"),
        ];
        let r = build_alignment_rollup(&signals);
        assert_eq!(r.components[0].domain, "dataflow");
        assert!(r.components[0].deduction >= r.components[1].deduction);
    }
}
