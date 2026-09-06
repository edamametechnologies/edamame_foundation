//! INC-20 prompt-injection eval corpus (corpus first, semantics later).
//!
//! `secret_content_scan::scan_transcript_text_for_prompt_injection` is a
//! literal-signature scanner: four marker classes from
//! `agent-visibility-params-db.json`, matched as case-insensitive substrings
//! with citation / user-directed-instruction exclusions. Before any semantic
//! detector replaces or augments it, its behaviour has to be measurable, so
//! this module carries a labelled corpus in
//! `src/prompt_injection_corpus/*.json` and the evaluation that scores a
//! scanner against it. Four tiers, in the fail-closed style of the posture
//! security gate:
//!
//! | tier | meaning | test policy |
//! |---|---|---|
//! | `must_fire` | literal bait the shipped scanner is contractually expected to catch, with the exact label set | any miss fails the build |
//! | `should_fire` | paraphrased / encoded / multilingual bait beyond the literal catalog | measured; coverage must not drop below the recorded floor |
//! | `must_not_fire` | ordinary task text, security tooling, the detector's own alert text | any hit fails the build (clean-idle-baseline discipline) |
//! | `should_not_fire` | benign text that cites or resembles a marker | measured; the false-positive count must not rise above the recorded ceiling |
//!
//! The recorded floor / ceiling are the numbers the literal scanner produced
//! when the corpus landed (2026-09-07): `must_fire` 9/9, `should_fire` 0/16
//! (no paraphrase, encoding, or non-English sample is caught -- the literal
//! catalog is exactly as evadable as COMPETITION.md G3 says), `must_not_fire`
//! 10/10 silent, `should_not_fire` 3/5 silent (two user-directed sentences
//! that reuse a marker phrase about an *instructions file* still fire).
//! The same day, obfuscation folding in `secret_content_scan` (zero-width
//! strip, in-word leetspeak, printable base64 decode) lifted `should_fire`
//! to 3/16 with the strict tiers and the false-positive count unchanged;
//! the remaining misses are genuine paraphrases and non-English bait. A semantic detector is "better" only
//! if it raises `should_fire` coverage without raising the
//! `should_not_fire` false-positive count -- prompt text is high-volume and a
//! naive matcher is a false-positive generator. `evaluate` is pure so a
//! future `edamame_cli` eval command or CI job can run the same scoring.

use crate::secret_content_scan::{
    scan_transcript_text_for_prompt_injection, TranscriptSecretExposure,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorpusTier {
    MustFire,
    ShouldFire,
    MustNotFire,
    ShouldNotFire,
}

impl CorpusTier {
    /// Whether samples in this tier are bait (expected to fire).
    pub fn is_attack(self) -> bool {
        matches!(self, CorpusTier::MustFire | CorpusTier::ShouldFire)
    }
    /// Whether a mismatch in this tier is a hard failure.
    pub fn is_strict(self) -> bool {
        matches!(self, CorpusTier::MustFire | CorpusTier::MustNotFire)
    }
}

/// One labelled sample. `expected_labels` is the full label set for attack
/// samples (order-insensitive) and empty for benign ones.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusSample {
    pub id: String,
    pub family: String,
    pub text: String,
    pub expected_labels: Vec<String>,
    /// Provenance (`null` when the sample is synthetic); always present in
    /// the fixture files so the corpus format needs no serde defaults.
    pub source: Option<String>,
    pub note: Option<String>,
}

/// One corpus file: a tier and its samples.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusFile {
    pub tier: CorpusTier,
    pub samples: Vec<CorpusSample>,
}

/// The outcome for one sample.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SampleOutcome {
    pub id: String,
    pub tier: CorpusTier,
    pub family: String,
    pub expected_labels: Vec<String>,
    pub observed_labels: Vec<String>,
    pub fired: bool,
    /// Attack sample that fired with exactly the expected labels, or benign
    /// sample that stayed silent.
    pub correct: bool,
}

/// Per-tier roll-up.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierReport {
    pub total: usize,
    /// Attack tiers: samples that fired with the expected label set.
    /// Benign tiers: samples that stayed silent.
    pub correct: usize,
    /// Attack tiers: samples that fired but with a different label set.
    pub partial: usize,
    pub failures: Vec<String>,
}

impl TierReport {
    /// Correct / total in percent, 100 for an empty tier.
    pub fn coverage_percent(&self) -> u32 {
        if self.total == 0 {
            100
        } else {
            ((self.correct * 100) / self.total) as u32
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusReport {
    pub must_fire: TierReport,
    pub should_fire: TierReport,
    pub must_not_fire: TierReport,
    pub should_not_fire: TierReport,
    pub outcomes: Vec<SampleOutcome>,
}

impl CorpusReport {
    pub fn tier(&self, tier: CorpusTier) -> &TierReport {
        match tier {
            CorpusTier::MustFire => &self.must_fire,
            CorpusTier::ShouldFire => &self.should_fire,
            CorpusTier::MustNotFire => &self.must_not_fire,
            CorpusTier::ShouldNotFire => &self.should_not_fire,
        }
    }
    fn tier_mut(&mut self, tier: CorpusTier) -> &mut TierReport {
        match tier {
            CorpusTier::MustFire => &mut self.must_fire,
            CorpusTier::ShouldFire => &mut self.should_fire,
            CorpusTier::MustNotFire => &mut self.must_not_fire,
            CorpusTier::ShouldNotFire => &mut self.should_not_fire,
        }
    }
    /// Human-readable summary line per tier.
    pub fn summary(&self) -> String {
        format!(
            "must_fire {}/{} ({}%), should_fire {}/{} ({}%, {} partial), must_not_fire {}/{} silent, should_not_fire {}/{} silent",
            self.must_fire.correct,
            self.must_fire.total,
            self.must_fire.coverage_percent(),
            self.should_fire.correct,
            self.should_fire.total,
            self.should_fire.coverage_percent(),
            self.should_fire.partial,
            self.must_not_fire.correct,
            self.must_not_fire.total,
            self.should_not_fire.correct,
            self.should_not_fire.total,
        )
    }
}

/// Score a scanner against corpus files. Pure: the scanner is injected so the
/// same corpus can grade the literal scanner, a future semantic detector, or
/// both side by side.
pub fn evaluate(
    files: &[CorpusFile],
    scan: impl Fn(&str) -> TranscriptSecretExposure,
) -> CorpusReport {
    let mut report = CorpusReport::default();
    for file in files {
        for sample in &file.samples {
            let exposure = scan(&sample.text);
            let observed: BTreeSet<String> = exposure.labels.iter().cloned().collect();
            let expected: BTreeSet<String> = sample.expected_labels.iter().cloned().collect();
            let fired = !observed.is_empty();
            let correct = if file.tier.is_attack() {
                fired && observed == expected
            } else {
                !fired
            };
            let partial = file.tier.is_attack() && fired && observed != expected;
            let tier = report.tier_mut(file.tier);
            tier.total += 1;
            if correct {
                tier.correct += 1;
            } else {
                if partial {
                    tier.partial += 1;
                }
                tier.failures.push(format!(
                    "{} [{}] expected {:?} observed {:?}",
                    sample.id,
                    sample.family,
                    sample.expected_labels,
                    observed.iter().cloned().collect::<Vec<_>>()
                ));
            }
            report.outcomes.push(SampleOutcome {
                id: sample.id.clone(),
                tier: file.tier,
                family: sample.family.clone(),
                expected_labels: sample.expected_labels.clone(),
                observed_labels: observed.into_iter().collect(),
                fired,
                correct,
            });
        }
    }
    report
}

/// Score the shipped literal scanner.
pub fn evaluate_literal_scanner(files: &[CorpusFile]) -> CorpusReport {
    evaluate(files, scan_transcript_text_for_prompt_injection)
}

/// Coverage the literal scanner recorded on the `should_fire` tier when the
/// corpus landed. A change that lowers it fails `corpus_should_fire_floor`.
pub const SHOULD_FIRE_COVERAGE_FLOOR_PERCENT: u32 = 18;

/// False positives the literal scanner recorded on the `should_not_fire`
/// tier when the corpus landed. A change that raises it fails
/// `corpus_should_not_fire_ceiling`.
pub const SHOULD_NOT_FIRE_FALSE_POSITIVE_CEILING: usize = 2;

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    fn corpus_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/prompt_injection_corpus")
    }

    fn load_corpus() -> Vec<CorpusFile> {
        let mut files = Vec::new();
        for entry in std::fs::read_dir(corpus_root()).expect("read prompt_injection_corpus") {
            let path = entry.expect("corpus dir entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let raw = std::fs::read_to_string(&path).expect("read corpus file");
            let file: CorpusFile = serde_json::from_str(&raw)
                .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
            files.push(file);
        }
        files.sort_by_key(|f| f.tier);
        files
    }

    fn report() -> CorpusReport {
        let files = load_corpus();
        assert_eq!(files.len(), 4, "one file per tier");
        let report = evaluate_literal_scanner(&files);
        eprintln!("prompt-injection corpus: {}", report.summary());
        for f in report
            .should_fire
            .failures
            .iter()
            .chain(report.should_not_fire.failures.iter())
        {
            eprintln!("  measured miss: {f}");
        }
        report
    }

    #[test]
    fn corpus_samples_have_unique_ids_and_consistent_labels() {
        let files = load_corpus();
        let mut ids = BTreeSet::new();
        for file in &files {
            assert!(!file.samples.is_empty(), "{:?} tier is empty", file.tier);
            for s in &file.samples {
                assert!(ids.insert(s.id.clone()), "duplicate sample id {}", s.id);
                assert!(!s.text.trim().is_empty(), "{} has empty text", s.id);
                if file.tier.is_attack() {
                    assert!(
                        !s.expected_labels.is_empty(),
                        "{} attack sample needs labels",
                        s.id
                    );
                } else {
                    assert!(
                        s.expected_labels.is_empty(),
                        "{} benign sample must not expect labels",
                        s.id
                    );
                }
            }
        }
    }

    #[test]
    fn corpus_must_fire_is_fully_covered() {
        let r = report();
        assert!(
            r.must_fire.failures.is_empty(),
            "literal bait missed or mislabelled:\n  {}",
            r.must_fire.failures.join("\n  ")
        );
    }

    #[test]
    fn corpus_must_not_fire_stays_silent() {
        let r = report();
        assert!(
            r.must_not_fire.failures.is_empty(),
            "benign text flagged as bait:\n  {}",
            r.must_not_fire.failures.join("\n  ")
        );
    }

    #[test]
    fn corpus_should_fire_floor() {
        let r = report();
        assert!(
            r.should_fire.coverage_percent() >= SHOULD_FIRE_COVERAGE_FLOOR_PERCENT,
            "semantic coverage regressed below the recorded floor: {}",
            r.summary()
        );
    }

    #[test]
    fn corpus_should_not_fire_ceiling() {
        let r = report();
        let false_positives = r.should_not_fire.total - r.should_not_fire.correct;
        assert!(
            false_positives <= SHOULD_NOT_FIRE_FALSE_POSITIVE_CEILING,
            "ambiguous-benign false positives rose above the recorded ceiling: {}",
            r.summary()
        );
    }

    #[test]
    fn evaluate_is_scanner_agnostic() {
        let files = vec![CorpusFile {
            tier: CorpusTier::ShouldFire,
            samples: vec![CorpusSample {
                id: "x".into(),
                family: "instruction_override".into(),
                text: "anything".into(),
                expected_labels: vec!["instruction_override".into()],
                source: None,
                note: None,
            }],
        }];
        let perfect = evaluate(&files, |_| TranscriptSecretExposure {
            labels: vec!["instruction_override".into()],
            hits: 2,
            matched_markers: Vec::new(),
        });
        assert_eq!(perfect.should_fire.coverage_percent(), 100);
        let wrong = evaluate(&files, |_| TranscriptSecretExposure {
            labels: vec!["role_override".into()],
            hits: 2,
            matched_markers: Vec::new(),
        });
        assert_eq!(wrong.should_fire.correct, 0);
        assert_eq!(wrong.should_fire.partial, 1);
    }
}
