//! EDAMAME's own divergence alert wording.
//!
//! The core renders every divergence finding as a sentence
//! (`edamame_core::agentic::divergence_policy`) and shows it on an evidence
//! card that adds the evidence category, the adjudication and the model's
//! reasoning (`edamame_core::agentic::divergence::divergence_evidence_reasoning`).
//! A human who pastes that card back into a conversation ("what is this?")
//! writes EDAMAME's words into the human's turn: the agent's own self-grant
//! (`'test-mint'`) and the human grant as EDAMAME rendered it
//! (`github.com:*, fmba-3`). Read as the human's words, the alert would
//! authorize exactly what it reports (FP-DIV-14). The transcript parser drops
//! those lines from the human's text by the markers below
//! (`agent_transcripts::parsing`), and the core renders its sentences from
//! the same constants, so a rewording cannot leave the parser behind.
//!
//! Product constants, not detection data: they are EDAMAME's own rendering,
//! which ships with the code that renders it.

/// Opens a scope-escalation sentence: `Agent granted itself {dimension}
/// '{value}' for session '{key}', which the human request does not authorize
/// (human grant -- ...)`.
pub const SELF_GRANT_OPENING: &str = "Agent granted itself ";

/// The dimension wording of the local-port scope escalation:
/// `Agent granted itself local open port {port} for session '{key}', ...`.
pub const SELF_GRANT_LOCAL_PORT: &str = "local open port ";

/// Opens a blacklisted-declaration sentence: `Agent declared blacklisted
/// destination '{host:port}' for session '{key}', ...`.
pub const DECLARED_BLACKLISTED_OPENING: &str = "Agent declared blacklisted destination '";

/// Closes the claim of every sentence that grades a claim against the
/// human's grant (scope escalation, blacklisted declaration).
pub const NOT_AUTHORIZED_BY_HUMAN: &str = ", which the human request does not authorize";

/// Opens the human-grant rendering a policy sentence ends with. Kept out of
/// the finding key: the rendering is re-distilled on every model push.
pub const HUMAN_GRANT_OPENING: &str = " (human ";

/// Labels the per-dimension human grant after [`HUMAN_GRANT_OPENING`]:
/// `(human grant -- network destinations: ...; LAN devices: ...)`.
pub const HUMAN_GRANT_LABEL: &str = "grant -- ";

/// Opens the human's operations list of an operation escalation:
/// `Mutating operation '{op}' observed against '{destination}' for session
/// '{key}'; the human request authorizes only [...]`. Kept out of the finding
/// key, like [`HUMAN_GRANT_OPENING`].
pub const HUMAN_AUTHORIZES_ONLY: &str = "; the human request authorizes only [";

/// Allowlist growth: `Session '{key}' widened its own {dimension} allowlist
/// with '{value}' after the plan was already declared`.
pub const GROWTH_WIDENED_ITS_OWN: &str = "' widened its own ";
/// See [`GROWTH_WIDENED_ITS_OWN`].
pub const GROWTH_ALLOWLIST_WITH: &str = " allowlist with '";
/// See [`GROWTH_WIDENED_ITS_OWN`].
pub const GROWTH_AFTER_THE_PLAN: &str = "' after the plan was already declared";

/// Retroactive declaration: `Session '{key}' declared {dimension} '{value}'
/// at {t}, after the matching activity was already observed at {t} (...)`.
pub const RETROACTIVE_AFTER_OBSERVED: &str =
    ", after the matching activity was already observed at ";

/// Evaluator integrity: `Measurement surface '{path}' was modified by
/// '{writer}' while session '{key}' declared the non-test task '{task}'; the
/// human request does not authorize touching the evaluator`.
pub const EVALUATOR_NOT_AUTHORIZED: &str =
    "; the human request does not authorize touching the evaluator";

/// The evidence card's category line: `Evidence category: {category}.`,
/// rendered after a blank line that follows the finding's sentence.
pub const EVIDENCE_CATEGORY_OPENING: &str = "Evidence category: ";

/// The evidence card's heading of the model's free-text reasoning, which
/// follows it up to the end of its paragraph.
pub const MODEL_REASONING_HEADING: &str = "Model reasoning for this divergence cycle:";

/// The evidence card's adjudication line, one per decision source.
pub const ADJUDICATION_LLM_CONFIRMED: &str =
    "Adjudication: the model confirmed the deterministic verdict for this cycle.";
/// See [`ADJUDICATION_LLM_CONFIRMED`].
pub const ADJUDICATION_LLM_OVERRODE_SOFT_SIGNALS: &str =
    "Adjudication: the model overruled the deterministic soft signals for this cycle.";
/// See [`ADJUDICATION_LLM_CONFIRMED`].
pub const ADJUDICATION_GUARDRAIL_FORCED_DETERMINISTIC: &str =
    "Adjudication: the guardrail rejected the model's position and the deterministic verdict stands.";
/// See [`ADJUDICATION_LLM_CONFIRMED`].
pub const ADJUDICATION_LLM_UNAVAILABLE: &str =
    "Adjudication: no model diagnosis was available, so this is the deterministic verdict.";
/// See [`ADJUDICATION_LLM_CONFIRMED`].
pub const ADJUDICATION_DETERMINISTIC_ONLY: &str =
    "Adjudication: published by the deterministic layer without a model (adjudication mode).";
/// See [`ADJUDICATION_LLM_CONFIRMED`].
pub const ADJUDICATION_NOT_RECORDED: &str =
    "Adjudication: no model diagnosis was recorded for this cycle.";

const ADJUDICATION_LINES: [&str; 6] = [
    ADJUDICATION_LLM_CONFIRMED,
    ADJUDICATION_LLM_OVERRODE_SOFT_SIGNALS,
    ADJUDICATION_GUARDRAIL_FORCED_DETERMINISTIC,
    ADJUDICATION_LLM_UNAVAILABLE,
    ADJUDICATION_DETERMINISTIC_ONLY,
    ADJUDICATION_NOT_RECORDED,
];

/// One line of an evidence card, as the parser reads a pasted one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertLine {
    /// A policy finding's sentence, or a fixed line of the card.
    Sentence,
    /// The card's category line: the finding's sentence (of any category)
    /// is the nearest non-blank line above it.
    Category,
    /// The heading of the model's reasoning: the reasoning runs to the end
    /// of its paragraph.
    ReasoningHeading,
}

/// Which part of EDAMAME's alert rendering `line` is, if any. A sentence is
/// recognized by its fixed wording (a human's own sentence naming the same
/// host carries none of it), the card's lines by their fixed openings.
pub fn classify_alert_line(line: &str) -> Option<AlertLine> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.starts_with(EVIDENCE_CATEGORY_OPENING) {
        return Some(AlertLine::Category);
    }
    if trimmed.starts_with(MODEL_REASONING_HEADING) {
        return Some(AlertLine::ReasoningHeading);
    }
    let sentence = trimmed.contains(SELF_GRANT_OPENING)
        || trimmed.contains(DECLARED_BLACKLISTED_OPENING)
        || trimmed.contains(NOT_AUTHORIZED_BY_HUMAN)
        || trimmed.contains(HUMAN_AUTHORIZES_ONLY)
        || trimmed.contains(EVALUATOR_NOT_AUTHORIZED)
        || trimmed.contains(RETROACTIVE_AFTER_OBSERVED)
        || (trimmed.contains(GROWTH_WIDENED_ITS_OWN) && trimmed.contains(GROWTH_ALLOWLIST_WITH))
        || ADJUDICATION_LINES
            .iter()
            .any(|adjudication| trimmed.starts_with(adjudication));
    sentence.then_some(AlertLine::Sentence)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cards_lines_are_recognized() {
        assert_eq!(
            classify_alert_line(
                "Agent granted itself expected_lan_devices 'test-mint' for session 's', \
                 which the human request does not authorize (human grant -- network \
                 destinations: github.com:*; LAN devices: fmba-3)"
            ),
            Some(AlertLine::Sentence)
        );
        assert_eq!(
            classify_alert_line(
                "Session 's' widened its own expected_traffic allowlist with 'x.example:*' \
                 after the plan was already declared"
            ),
            Some(AlertLine::Sentence)
        );
        assert_eq!(
            classify_alert_line("  Evidence category: policy:scope_escalation."),
            Some(AlertLine::Category)
        );
        assert_eq!(
            classify_alert_line(ADJUDICATION_GUARDRAIL_FORCED_DETERMINISTIC),
            Some(AlertLine::Sentence)
        );
        assert_eq!(
            classify_alert_line(MODEL_REASONING_HEADING),
            Some(AlertLine::ReasoningHeading)
        );
    }

    #[test]
    fn a_humans_sentence_is_not_an_alert_line() {
        for line in [
            "check test-mint and fmba-3",
            "the agent granted itself nothing, github is not a lan device",
            "Session notes: test-mint widened its disk",
            "Adjudication: please look at this",
            "",
        ] {
            assert_eq!(classify_alert_line(line), None, "{line}");
        }
    }
}
