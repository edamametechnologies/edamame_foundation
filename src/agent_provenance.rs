//! Agent flight-recorder provenance model (INC-5, Stage B).
//!
//! This is the **pure, deterministic projection layer** for the agent flight
//! recorder. It owns the serializable data structures (`ProvenanceEvent`,
//! `CausalEdge`, `RunProvenance`, `RunIndexEntry`) plus the hash-chaining /
//! ordering / chain-verification logic. It depends only on `chrono` + `serde`
//! + `sha2`/`hex` -- never on `edamame_core` -- so the correlation join in
//! `edamame_core::core_manager_provenance` can feed it neutral raw events and
//! get back a tamper-evident, replayable record.
//!
//! Design (mirrors the rest of the visibility engine):
//! - **Metadata-first (I5)**: every field is a hash, id, count, label, or
//!   short metadata summary. No transcript or file bodies are ever stored.
//! - **Deterministic-first (I3)**: the projection is a pure function of its
//!   inputs. The LLM (if any) only summarizes; it never mints provenance.
//! - **Append-only + tamper-evident**: each run carries a per-run SHA-256
//!   hash chain (`prev_hash -> hash`) so a replay consumer can prove the
//!   ordered event stream was not edited after the fact.
//!
//! A **run** is one reasoning-plane session (`session_key`) for a given
//! `(agent_type, agent_instance_id)`. `run_id` encodes all three so it is
//! globally unique and decodable (see [`make_run_id`] / [`parse_run_id`]).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The two observation planes plus the correlation plane that stitches them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenancePlane {
    /// Reasoning plane: what the agent transcript declared it intended to do.
    Reasoning,
    /// System plane: what EDAMAME observed on the host (network/file/process).
    System,
    /// Correlation plane: a verdict/decision that joins reasoning to system.
    Correlation,
}

impl ProvenancePlane {
    pub fn slug(&self) -> &'static str {
        match self {
            ProvenancePlane::Reasoning => "reasoning",
            ProvenancePlane::System => "system",
            ProvenancePlane::Correlation => "correlation",
        }
    }
}

/// The kind of a single provenance event. The deterministic engine emits a
/// fixed catalog (no free-form kinds) so the UI and `explain_run_event` can
/// reason about event semantics structurally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceEventKind {
    /// Reasoning: the session began (transcript `started_at`).
    SessionStart,
    /// Reasoning: a tool was invoked in the transcript.
    ToolCall,
    /// Reasoning: a tool result came back flagged as an error (developer
    /// observability; LLM-free, never carries a security severity).
    ToolError,
    /// Reasoning: a shell command was issued in the transcript.
    Command,
    /// Reasoning: the session declared an expected outbound egress (intent).
    ExpectedEgress,
    /// Correlation: a divergence-engine verdict covering this run's window.
    DivergenceVerdict,
    /// System: an unexplained observation (the diverging fact) the engine saw.
    DivergenceEvidence,
    /// Reasoning: the session was last modified (transcript `modified_at`).
    SessionEnd,
}

impl ProvenanceEventKind {
    pub fn slug(&self) -> &'static str {
        match self {
            ProvenanceEventKind::SessionStart => "session_start",
            ProvenanceEventKind::ToolCall => "tool_call",
            ProvenanceEventKind::ToolError => "tool_error",
            ProvenanceEventKind::Command => "command",
            ProvenanceEventKind::ExpectedEgress => "expected_egress",
            ProvenanceEventKind::DivergenceVerdict => "divergence_verdict",
            ProvenanceEventKind::DivergenceEvidence => "divergence_evidence",
            ProvenanceEventKind::SessionEnd => "session_end",
        }
    }

    /// Stable replay ordinal used as the tiebreaker when two events share a
    /// timestamp, so the ordered stream reads naturally
    /// (start -> intent -> verdict -> evidence -> end).
    fn order_rank(&self) -> u8 {
        match self {
            ProvenanceEventKind::SessionStart => 0,
            ProvenanceEventKind::ToolCall => 1,
            ProvenanceEventKind::ToolError => 2,
            ProvenanceEventKind::Command => 3,
            ProvenanceEventKind::ExpectedEgress => 4,
            ProvenanceEventKind::DivergenceVerdict => 5,
            ProvenanceEventKind::DivergenceEvidence => 6,
            ProvenanceEventKind::SessionEnd => 7,
        }
    }
}

/// The causal relation a [`CausalEdge`] expresses. Read as
/// `src --relation--> dst` (forward in causal time): `src` happened and led
/// to / explains `dst`. `explain_run_event` backtracks by walking edges whose
/// `dst` is the target event to recover the proximate causes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CausalRelation {
    /// Generic "src enabled / preceded dst within the run".
    Caused,
    /// A reasoning tool/command/intent preceded an observed egress/evidence.
    PromptedThenEgressed,
    /// A read of a resource preceded a write (reserved for INC-7 data-flow).
    ReadThenWrote,
    /// A retrieval preceded a tool call (reserved for INC-8 memory/RAG).
    RetrievedThenCalled,
    /// A piece of system evidence aggregated into a correlation verdict.
    DivergedFrom,
}

impl CausalRelation {
    pub fn slug(&self) -> &'static str {
        match self {
            CausalRelation::Caused => "caused",
            CausalRelation::PromptedThenEgressed => "prompted_then_egressed",
            CausalRelation::ReadThenWrote => "read_then_wrote",
            CausalRelation::RetrievedThenCalled => "retrieved_then_called",
            CausalRelation::DivergedFrom => "diverged_from",
        }
    }
}

/// Pre-hash event the correlation join emits. The projection builder assigns
/// the `event_id` and computes the hash chain; callers never set those.
#[derive(Debug, Clone)]
pub struct RawProvenanceEvent {
    pub ts: DateTime<Utc>,
    pub plane: ProvenancePlane,
    pub kind: ProvenanceEventKind,
    /// Human-readable, metadata-only one-liner (no bodies, I5).
    pub summary: String,
    /// Structured ids/hashes for cross-referencing (session_uid, finding_key,
    /// process_path, `host:port`, ...). Metadata only.
    pub refs: Vec<String>,
    /// Severity for system/correlation events (`CRITICAL`|`HIGH`|`MEDIUM`|`LOW`).
    pub severity: Option<String>,
}

/// Edge hint the correlation join emits, referencing raw events by their
/// original index in the `raw_events` vector passed to [`build_run_provenance`].
/// The builder remaps these indices to the assigned `event_id`s.
#[derive(Debug, Clone)]
pub struct RawCausalEdgeHint {
    pub src_index: usize,
    pub dst_index: usize,
    pub relation: CausalRelation,
    pub rationale: String,
}

/// A single hash-chained event in a run's append-only provenance log.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvenanceEvent {
    /// Stable id within the run (`evt-<ordinal>-<short content hash>`).
    pub event_id: String,
    pub run_id: String,
    pub ts: DateTime<Utc>,
    pub plane: ProvenancePlane,
    pub kind: ProvenanceEventKind,
    pub summary: String,
    pub refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// Hash of the previous event in the run chain (`GENESIS` for the first).
    pub prev_hash: String,
    /// `sha256(prev_hash | content_hash)` -- the tamper-evident chain link.
    pub hash: String,
}

/// A causal edge in the per-run provenance projection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CausalEdge {
    pub id: String,
    pub src_event_id: String,
    pub dst_event_id: String,
    pub relation: CausalRelation,
    pub rationale: String,
}

/// One full run's flight record: the ordered (replayable) hash-chained event
/// stream plus the causal-edge projection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunProvenance {
    pub run_id: String,
    pub agent_type: String,
    pub agent_instance_id: String,
    pub title: String,
    pub start_ts: DateTime<Utc>,
    pub end_ts: DateTime<Utc>,
    pub events: Vec<ProvenanceEvent>,
    pub edges: Vec<CausalEdge>,
    /// Recomputed-on-build chain validity (always `true` fresh; a replay
    /// consumer re-verifies via [`verify_run_chain`]).
    pub chain_valid: bool,
    /// Least-trusted severity across system/correlation events, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_severity: Option<String>,
    /// Count of `CRITICAL`/`HIGH` events (the alertable subset).
    pub alertable_event_count: u32,
}

impl RunProvenance {
    /// Compact index row for the recorder run list.
    pub fn index_entry(&self) -> RunIndexEntry {
        RunIndexEntry {
            run_id: self.run_id.clone(),
            agent_type: self.agent_type.clone(),
            agent_instance_id: self.agent_instance_id.clone(),
            title: self.title.clone(),
            start_ts: self.start_ts,
            end_ts: self.end_ts,
            event_count: self.events.len() as u32,
            edge_count: self.edges.len() as u32,
            max_severity: self.max_severity.clone(),
            has_divergence: self
                .events
                .iter()
                .any(|e| e.kind == ProvenanceEventKind::DivergenceEvidence),
            alertable_event_count: self.alertable_event_count,
            tool_error_count: self
                .events
                .iter()
                .filter(|e| e.kind == ProvenanceEventKind::ToolError)
                .count() as u32,
            chain_valid: self.chain_valid,
        }
    }

    /// Backtrace (proximate causes) of a target event: every event that has an
    /// edge pointing *into* the target, transitively, plus the edges walked.
    /// This is the "prove-why" payload for `explain_run_event`.
    pub fn backtrace(&self, event_id: &str) -> Option<RunEventExplanation> {
        let target = self.events.iter().find(|e| e.event_id == event_id)?;

        // Reverse adjacency: dst -> (src, edge).
        let mut ancestors: Vec<ProvenanceEvent> = Vec::new();
        let mut path_edges: Vec<CausalEdge> = Vec::new();
        let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut frontier = vec![event_id.to_string()];
        seen.insert(event_id.to_string());
        while let Some(node) = frontier.pop() {
            for edge in self.edges.iter().filter(|e| e.dst_event_id == node) {
                path_edges.push(edge.clone());
                if seen.insert(edge.src_event_id.clone()) {
                    if let Some(src) = self.events.iter().find(|e| e.event_id == edge.src_event_id)
                    {
                        ancestors.push(src.clone());
                    }
                    frontier.push(edge.src_event_id.clone());
                }
            }
        }
        // Descendants (downstream impact): events the target leads to.
        let mut descendants: Vec<ProvenanceEvent> = Vec::new();
        let mut dseen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        dseen.insert(event_id.to_string());
        let mut dfrontier = vec![event_id.to_string()];
        while let Some(node) = dfrontier.pop() {
            for edge in self.edges.iter().filter(|e| e.src_event_id == node) {
                if dseen.insert(edge.dst_event_id.clone()) {
                    if let Some(dst) = self.events.iter().find(|e| e.event_id == edge.dst_event_id)
                    {
                        descendants.push(dst.clone());
                    }
                    dfrontier.push(edge.dst_event_id.clone());
                }
            }
        }

        // Order ancestors/descendants chronologically for a readable trace.
        ancestors.sort_by(|a, b| a.ts.cmp(&b.ts).then(a.event_id.cmp(&b.event_id)));
        descendants.sort_by(|a, b| a.ts.cmp(&b.ts).then(a.event_id.cmp(&b.event_id)));
        path_edges.sort_by(|a, b| a.id.cmp(&b.id));
        path_edges.dedup_by(|a, b| a.id == b.id);

        // A backtrace is "complete" when it reaches the session root.
        let backtrace_complete = ancestors
            .iter()
            .any(|e| e.kind == ProvenanceEventKind::SessionStart)
            || target.kind == ProvenanceEventKind::SessionStart;

        Some(RunEventExplanation {
            run_id: self.run_id.clone(),
            event: target.clone(),
            ancestors,
            descendants,
            edges: path_edges,
            backtrace_complete,
            chain_valid: self.chain_valid,
        })
    }
}

/// Compact run-index row for the flight-recorder run list.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunIndexEntry {
    pub run_id: String,
    pub agent_type: String,
    pub agent_instance_id: String,
    pub title: String,
    pub start_ts: DateTime<Utc>,
    pub end_ts: DateTime<Utc>,
    pub event_count: u32,
    pub edge_count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_severity: Option<String>,
    pub has_divergence: bool,
    pub alertable_event_count: u32,
    /// Count of `tool_error` events (developer-observability failures the
    /// agent itself flagged; carries no security severity so it is not part
    /// of `alertable_event_count`). Lets the recorder index be filtered to
    /// security-evidence runs without fetching each run's full record.
    pub tool_error_count: u32,
    pub chain_valid: bool,
}

/// The "prove-why" explanation payload for a single event (causal backtrace +
/// downstream impact + the edges traversed).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunEventExplanation {
    pub run_id: String,
    pub event: ProvenanceEvent,
    /// Proximate + transitive causes (chronological).
    pub ancestors: Vec<ProvenanceEvent>,
    /// Downstream events this one led to (chronological).
    pub descendants: Vec<ProvenanceEvent>,
    /// The causal edges traversed during the backtrace.
    pub edges: Vec<CausalEdge>,
    /// True when the backtrace reaches the session root.
    pub backtrace_complete: bool,
    pub chain_valid: bool,
}

const GENESIS_HASH: &str = "GENESIS";

/// Build the run_id from its three components. Uses `::` as the separator
/// (none of the components contains `::` in practice; if `session_key` did we
/// would still round-trip the agent fields correctly via [`parse_run_id`]).
pub fn make_run_id(agent_type: &str, agent_instance_id: &str, session_key: &str) -> String {
    format!("{}::{}::{}", agent_type, agent_instance_id, session_key)
}

/// Parse a run_id back into `(agent_type, agent_instance_id, session_key)`.
/// Splits on the first two `::`; the remainder (which may itself contain `::`)
/// is the session_key. Returns `None` if the id is not in the expected shape.
pub fn parse_run_id(run_id: &str) -> Option<(String, String, String)> {
    let (agent_type, rest) = run_id.split_once("::")?;
    let (agent_instance_id, session_key) = rest.split_once("::")?;
    if agent_type.is_empty() || agent_instance_id.is_empty() || session_key.is_empty() {
        return None;
    }
    Some((
        agent_type.to_string(),
        agent_instance_id.to_string(),
        session_key.to_string(),
    ))
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

/// Per-event content hash (order-independent, identity of the event content).
fn content_hash(run_id: &str, idx: usize, ev: &RawProvenanceEvent) -> String {
    let payload = format!(
        "{}|{}|{}|{}|{}|{}|{}",
        run_id,
        idx,
        ev.kind.slug(),
        ev.plane.slug(),
        ev.ts.to_rfc3339(),
        ev.summary,
        ev.refs.join(",")
    );
    sha256_hex(&payload)
}

fn severity_rank(sev: &str) -> u8 {
    match sev.to_ascii_uppercase().as_str() {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0,
    }
}

fn is_alertable_severity(sev: &str) -> bool {
    matches!(sev.to_ascii_uppercase().as_str(), "CRITICAL" | "HIGH")
}

/// Project a list of raw events + edge hints into a tamper-evident, ordered
/// [`RunProvenance`]. Pure and deterministic: events are sorted by
/// `(ts, kind order_rank, content hash)`, assigned stable `event_id`s, and
/// folded into a per-run SHA-256 hash chain. Edge hints are remapped from
/// original indices to `event_id`s; self-edges and dangling hints are dropped.
pub fn build_run_provenance(
    run_id: &str,
    agent_type: &str,
    agent_instance_id: &str,
    title: &str,
    raw_events: Vec<RawProvenanceEvent>,
    edge_hints: Vec<RawCausalEdgeHint>,
) -> RunProvenance {
    // 1. Compute a stable per-event id keyed by original index (guarantees
    //    uniqueness within the run even if two events share content).
    let event_ids: Vec<String> = raw_events
        .iter()
        .enumerate()
        .map(|(idx, ev)| {
            let ch = content_hash(run_id, idx, ev);
            format!("evt-{:03}-{}", idx, &ch[..12])
        })
        .collect();

    // 2. Determine replay order (stable): by ts, then kind order_rank, then id.
    let mut order: Vec<usize> = (0..raw_events.len()).collect();
    order.sort_by(|&a, &b| {
        raw_events[a]
            .ts
            .cmp(&raw_events[b].ts)
            .then(
                raw_events[a]
                    .kind
                    .order_rank()
                    .cmp(&raw_events[b].kind.order_rank()),
            )
            .then(event_ids[a].cmp(&event_ids[b]))
    });

    // 3. Fold the hash chain over the ordered events.
    let mut events: Vec<ProvenanceEvent> = Vec::with_capacity(order.len());
    let mut prev_hash = GENESIS_HASH.to_string();
    let mut max_sev_rank: u8 = 0;
    let mut max_sev_label: Option<String> = None;
    let mut alertable: u32 = 0;
    for &idx in &order {
        let ev = &raw_events[idx];
        let ch = content_hash(run_id, idx, ev);
        let hash = sha256_hex(&format!("{}|{}", prev_hash, ch));
        if let Some(sev) = ev.severity.as_ref() {
            let rank = severity_rank(sev);
            if rank > max_sev_rank {
                max_sev_rank = rank;
                max_sev_label = Some(sev.to_ascii_uppercase());
            }
            if is_alertable_severity(sev) {
                alertable += 1;
            }
        }
        events.push(ProvenanceEvent {
            event_id: event_ids[idx].clone(),
            run_id: run_id.to_string(),
            ts: ev.ts,
            plane: ev.plane,
            kind: ev.kind,
            summary: ev.summary.clone(),
            refs: ev.refs.clone(),
            severity: ev.severity.clone(),
            prev_hash: prev_hash.clone(),
            hash: hash.clone(),
        });
        prev_hash = hash;
    }

    // 4. Remap edge hints (original indices) to assigned event_ids.
    let mut edges: Vec<CausalEdge> = Vec::new();
    let mut seen_edges: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for hint in &edge_hints {
        if hint.src_index >= event_ids.len() || hint.dst_index >= event_ids.len() {
            continue;
        }
        if hint.src_index == hint.dst_index {
            continue;
        }
        let src = &event_ids[hint.src_index];
        let dst = &event_ids[hint.dst_index];
        let id = format!(
            "edge-{}",
            &sha256_hex(&format!("{}|{}|{}", src, dst, hint.relation.slug()))[..12]
        );
        if !seen_edges.insert(id.clone()) {
            continue;
        }
        edges.push(CausalEdge {
            id,
            src_event_id: src.clone(),
            dst_event_id: dst.clone(),
            relation: hint.relation,
            rationale: hint.rationale.clone(),
        });
    }
    edges.sort_by(|a, b| a.id.cmp(&b.id));

    let (start_ts, end_ts) = match (events.first(), events.last()) {
        (Some(first), Some(last)) => (first.ts, last.ts),
        _ => {
            let now = Utc::now();
            (now, now)
        }
    };

    RunProvenance {
        run_id: run_id.to_string(),
        agent_type: agent_type.to_string(),
        agent_instance_id: agent_instance_id.to_string(),
        title: title.to_string(),
        start_ts,
        end_ts,
        events,
        edges,
        chain_valid: true,
        max_severity: max_sev_label,
        alertable_event_count: alertable,
    }
}

/// Recompute and verify the per-run hash chain. A replay consumer calls this
/// to prove the ordered event stream was not edited after projection. Returns
/// `true` iff every link reproduces from `prev_hash | content_hash`.
pub fn verify_run_chain(run: &RunProvenance) -> bool {
    let mut prev_hash = GENESIS_HASH.to_string();
    for ev in &run.events {
        if ev.prev_hash != prev_hash {
            return false;
        }
        // Re-derive the content hash from the persisted event fields. The
        // original index is encoded in the event_id (`evt-<idx>-<...>`); parse
        // it so the recomputation matches the build-time content hash.
        let idx = ev
            .event_id
            .strip_prefix("evt-")
            .and_then(|s| s.split('-').next())
            .and_then(|s| s.parse::<usize>().ok());
        let idx = match idx {
            Some(i) => i,
            None => return false,
        };
        let payload = format!(
            "{}|{}|{}|{}|{}|{}|{}",
            ev.run_id,
            idx,
            ev.kind.slug(),
            ev.plane.slug(),
            ev.ts.to_rfc3339(),
            ev.summary,
            ev.refs.join(",")
        );
        let ch = sha256_hex(&payload);
        let expected = sha256_hex(&format!("{}|{}", prev_hash, ch));
        if ev.hash != expected {
            return false;
        }
        prev_hash = ev.hash.clone();
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(
        ts: DateTime<Utc>,
        plane: ProvenancePlane,
        kind: ProvenanceEventKind,
        summary: &str,
        severity: Option<&str>,
    ) -> RawProvenanceEvent {
        RawProvenanceEvent {
            ts,
            plane,
            kind,
            summary: summary.to_string(),
            refs: Vec::new(),
            severity: severity.map(|s| s.to_string()),
        }
    }

    #[test]
    fn run_id_roundtrips() {
        let id = make_run_id("cursor", "host-abc-observer", "sess:123");
        assert_eq!(
            parse_run_id(&id),
            Some((
                "cursor".to_string(),
                "host-abc-observer".to_string(),
                "sess:123".to_string()
            ))
        );
        // Session key containing the separator still recovers agent fields.
        let id2 = make_run_id("codex", "inst", "a::b::c");
        assert_eq!(
            parse_run_id(&id2),
            Some((
                "codex".to_string(),
                "inst".to_string(),
                "a::b::c".to_string()
            ))
        );
        assert_eq!(parse_run_id("garbage"), None);
    }

    #[test]
    fn builds_ordered_hash_chain_that_verifies() {
        let t0 = Utc::now();
        let t1 = t0 + chrono::Duration::seconds(5);
        let t2 = t0 + chrono::Duration::seconds(10);
        // Intentionally out of order to exercise sorting.
        let raws = vec![
            ev(
                t2,
                ProvenancePlane::System,
                ProvenanceEventKind::DivergenceEvidence,
                "egress to evil.example:443",
                Some("HIGH"),
            ),
            ev(
                t0,
                ProvenancePlane::Reasoning,
                ProvenanceEventKind::SessionStart,
                "session start",
                None,
            ),
            ev(
                t1,
                ProvenancePlane::Reasoning,
                ProvenanceEventKind::ToolCall,
                "run_terminal_cmd",
                None,
            ),
        ];
        let run = build_run_provenance("cursor::inst::s1", "cursor", "inst", "title", raws, vec![]);
        assert_eq!(run.events.len(), 3);
        // Sorted: SessionStart(t0) -> ToolCall(t1) -> Evidence(t2).
        assert_eq!(run.events[0].kind, ProvenanceEventKind::SessionStart);
        assert_eq!(run.events[1].kind, ProvenanceEventKind::ToolCall);
        assert_eq!(run.events[2].kind, ProvenanceEventKind::DivergenceEvidence);
        assert_eq!(run.events[0].prev_hash, GENESIS_HASH);
        assert_eq!(run.events[1].prev_hash, run.events[0].hash);
        assert_eq!(run.events[2].prev_hash, run.events[1].hash);
        assert!(run.chain_valid);
        assert!(verify_run_chain(&run));
        assert_eq!(run.max_severity.as_deref(), Some("HIGH"));
        assert_eq!(run.alertable_event_count, 1);
    }

    #[test]
    fn tampering_breaks_the_chain() {
        let t0 = Utc::now();
        let raws = vec![
            ev(
                t0,
                ProvenancePlane::Reasoning,
                ProvenanceEventKind::SessionStart,
                "session start",
                None,
            ),
            ev(
                t0 + chrono::Duration::seconds(1),
                ProvenancePlane::System,
                ProvenanceEventKind::DivergenceEvidence,
                "leak",
                Some("CRITICAL"),
            ),
        ];
        let mut run = build_run_provenance("a::b::c", "a", "b", "t", raws, vec![]);
        assert!(verify_run_chain(&run));
        // Edit a summary after the fact -> chain no longer reproduces.
        run.events[1].summary = "benign".to_string();
        assert!(!verify_run_chain(&run));
    }

    #[test]
    fn backtrace_recovers_proximate_causes() {
        let t0 = Utc::now();
        let raws = vec![
            ev(
                t0,
                ProvenancePlane::Reasoning,
                ProvenanceEventKind::SessionStart,
                "start",
                None,
            ),
            ev(
                t0 + chrono::Duration::seconds(2),
                ProvenancePlane::Reasoning,
                ProvenanceEventKind::ToolCall,
                "curl",
                None,
            ),
            ev(
                t0 + chrono::Duration::seconds(4),
                ProvenancePlane::System,
                ProvenanceEventKind::DivergenceEvidence,
                "egress",
                Some("HIGH"),
            ),
        ];
        // 0 -> 1 (caused), 1 -> 2 (prompted_then_egressed).
        let hints = vec![
            RawCausalEdgeHint {
                src_index: 0,
                dst_index: 1,
                relation: CausalRelation::Caused,
                rationale: "session enabled tool".into(),
            },
            RawCausalEdgeHint {
                src_index: 1,
                dst_index: 2,
                relation: CausalRelation::PromptedThenEgressed,
                rationale: "tool preceded egress".into(),
            },
        ];
        let run = build_run_provenance("a::b::c", "a", "b", "t", raws, hints);
        assert_eq!(run.edges.len(), 2);
        let evidence_id = run
            .events
            .iter()
            .find(|e| e.kind == ProvenanceEventKind::DivergenceEvidence)
            .unwrap()
            .event_id
            .clone();
        let exp = run.backtrace(&evidence_id).unwrap();
        // Ancestors should include both the tool call and the session start.
        assert!(exp
            .ancestors
            .iter()
            .any(|e| e.kind == ProvenanceEventKind::ToolCall));
        assert!(exp
            .ancestors
            .iter()
            .any(|e| e.kind == ProvenanceEventKind::SessionStart));
        assert!(exp.backtrace_complete);
    }

    #[test]
    fn dangling_and_self_edges_dropped() {
        let t0 = Utc::now();
        let raws = vec![ev(
            t0,
            ProvenancePlane::Reasoning,
            ProvenanceEventKind::SessionStart,
            "start",
            None,
        )];
        let hints = vec![
            RawCausalEdgeHint {
                src_index: 0,
                dst_index: 0,
                relation: CausalRelation::Caused,
                rationale: "self".into(),
            },
            RawCausalEdgeHint {
                src_index: 0,
                dst_index: 9,
                relation: CausalRelation::Caused,
                rationale: "dangling".into(),
            },
        ];
        let run = build_run_provenance("a::b::c", "a", "b", "t", raws, hints);
        assert!(run.edges.is_empty());
    }
}
