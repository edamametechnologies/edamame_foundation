// Unified retention for the agent history stores.
//
// Every agent-facing history store in the workspace (divergence verdicts and
// incidents, behavioral-model snapshots, subprocess observations, the
// visibility operator log, the coach insight cache) applies the SAME
// two-limit policy:
//
//   1. Age cap  -- entries older than `history_retention_days` are pruned
//                  regardless of how few entries the store holds.
//   2. Entry cap -- the store keeps at most `max_entries` of the newest
//                  entries so a burst cannot balloon persisted state.
//
// The limits come from the `history_retention` block of
// `agent-visibility-params-db.json` (CloudModel-tunable, see
// `crate::agent_visibility_params::history_retention()`), so operators can
// tighten or relax retention fleet-wide without a binary release.
//
// Stores that must protect specific entries from age-based pruning (e.g.
// active non-dismissed findings, per the Vulnerability Finding Persistence
// invariant) use `prune_with_keep` with a protect predicate. Protected
// entries are exempt from the age cap but still count toward -- and can be
// displaced by newer protected/unprotected entries under -- the entry cap
// only when the cap would otherwise be exceeded by protected entries alone;
// in practice caps are sized well above realistic protected counts.

use crate::agent_visibility_params::{self, HistoryRetentionJSON};
use chrono::{DateTime, Duration, Utc};

/// A resolved two-limit retention policy for one history store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionPolicy {
    /// Entries whose timestamp is older than `now - max_age` are pruned
    /// (unless protected by a `prune_with_keep` predicate).
    pub max_age: Duration,
    /// The store keeps at most this many of the newest entries.
    pub max_entries: usize,
}

impl RetentionPolicy {
    fn from_days(days: u64, max_entries: usize) -> Self {
        RetentionPolicy {
            max_age: Duration::days(days.min(i64::MAX as u64) as i64),
            max_entries,
        }
    }
}

fn retention() -> HistoryRetentionJSON {
    agent_visibility_params::history_retention()
}

/// Policy for per-agent divergence verdict history.
pub fn divergence_verdict_policy() -> RetentionPolicy {
    let r = retention();
    RetentionPolicy::from_days(r.history_retention_days, r.divergence_verdict_max_entries)
}

/// Policy for divergence incident history.
pub fn divergence_incident_policy() -> RetentionPolicy {
    let r = retention();
    RetentionPolicy::from_days(r.history_retention_days, r.divergence_incident_max_entries)
}

/// Policy for behavioral-model snapshot history.
pub fn behavioral_model_policy() -> RetentionPolicy {
    let r = retention();
    RetentionPolicy::from_days(r.history_retention_days, r.behavioral_model_max_entries)
}

/// Policy for per-agent subprocess observation history.
pub fn subprocess_observation_policy() -> RetentionPolicy {
    let r = retention();
    RetentionPolicy::from_days(r.history_retention_days, r.subprocess_max_observations)
}

/// Policy for the agent-visibility operator log.
pub fn visibility_log_policy() -> RetentionPolicy {
    let r = retention();
    RetentionPolicy::from_days(r.history_retention_days, r.visibility_log_max_entries)
}

/// Policy for the Enlightenment Coach insight cache.
pub fn coach_insight_policy() -> RetentionPolicy {
    let r = retention();
    RetentionPolicy::from_days(r.history_retention_days, r.coach_max_cached_insights)
}

/// Prune `entries` in place under `policy`, using `timestamp` to read each
/// entry's event time. Returns the number of entries removed.
///
/// Semantics:
/// - entries older than `now - policy.max_age` are removed;
/// - if more than `policy.max_entries` remain, the OLDEST surplus entries
///   (by timestamp) are removed;
/// - the relative order of surviving entries is preserved.
pub fn prune<T>(
    entries: &mut Vec<T>,
    policy: RetentionPolicy,
    timestamp: impl Fn(&T) -> DateTime<Utc>,
) -> usize {
    prune_with_keep(entries, policy, timestamp, |_| false)
}

/// Like [`prune`], but entries for which `keep` returns `true` are exempt
/// from the age cap AND from entry-cap displacement. Used by stores with a
/// persistence invariant (e.g. active non-dismissed findings must survive
/// until explicitly dismissed).
pub fn prune_with_keep<T>(
    entries: &mut Vec<T>,
    policy: RetentionPolicy,
    timestamp: impl Fn(&T) -> DateTime<Utc>,
    keep: impl Fn(&T) -> bool,
) -> usize {
    let before = entries.len();
    let cutoff = Utc::now() - policy.max_age;

    // Age cap.
    entries.retain(|e| keep(e) || timestamp(e) >= cutoff);

    // Entry cap: drop the oldest unprotected entries until within the cap.
    let excess = entries.len().saturating_sub(policy.max_entries.max(1));
    if excess > 0 {
        // Collect indices of unprotected entries ordered oldest-first.
        let mut candidates: Vec<(usize, DateTime<Utc>)> = entries
            .iter()
            .enumerate()
            .filter(|(_, e)| !keep(e))
            .map(|(i, e)| (i, timestamp(e)))
            .collect();
        candidates.sort_by_key(|&(_, ts)| ts);
        let mut drop_indices: Vec<usize> =
            candidates.iter().take(excess).map(|&(i, _)| i).collect();
        drop_indices.sort_unstable();
        for &i in drop_indices.iter().rev() {
            entries.remove(i);
        }
    }

    before - entries.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(days_ago: i64) -> DateTime<Utc> {
        Utc::now() - Duration::days(days_ago)
    }

    #[test]
    fn test_age_cap_prunes_old_entries() {
        let policy = RetentionPolicy {
            max_age: Duration::days(30),
            max_entries: 100,
        };
        let mut entries = vec![ts(45), ts(31), ts(29), ts(1)];
        let removed = prune(&mut entries, policy, |t| *t);
        assert_eq!(removed, 2);
        assert_eq!(entries.len(), 2);
        assert!(entries
            .iter()
            .all(|t| *t >= Utc::now() - Duration::days(30)));
    }

    #[test]
    fn test_entry_cap_drops_oldest_first_preserving_order() {
        let policy = RetentionPolicy {
            max_age: Duration::days(30),
            max_entries: 2,
        };
        // Interleaved order: newest is NOT last, so the cap must select by
        // timestamp, not by position.
        let a = ts(10);
        let b = ts(1);
        let c = ts(20);
        let d = ts(2);
        let mut entries = vec![a, b, c, d];
        let removed = prune(&mut entries, policy, |t| *t);
        assert_eq!(removed, 2);
        assert_eq!(entries, vec![b, d]); // survivors keep relative order
    }

    #[test]
    fn test_keep_predicate_protects_from_age_and_cap() {
        let policy = RetentionPolicy {
            max_age: Duration::days(30),
            max_entries: 2,
        };
        // (timestamp, protected)
        let mut entries = vec![
            (ts(60), true),
            (ts(40), false),
            (ts(5), false),
            (ts(1), false),
        ];
        let removed = prune_with_keep(&mut entries, policy, |e| e.0, |e| e.1);
        // ts(40) removed by age; then cap=2 with 3 remaining drops the oldest
        // unprotected (ts(5)).
        assert_eq!(removed, 2);
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|e| e.1)); // protected survivor
        assert!(entries
            .iter()
            .any(|e| !e.1 && e.0 >= Utc::now() - Duration::days(2)));
    }

    #[test]
    fn test_policies_resolve_from_params_snapshot() {
        // The embedded fallback must produce sane, non-zero policies.
        for policy in [
            divergence_verdict_policy(),
            divergence_incident_policy(),
            behavioral_model_policy(),
            subprocess_observation_policy(),
            visibility_log_policy(),
            coach_insight_policy(),
        ] {
            assert!(policy.max_age >= Duration::days(1));
            assert!(policy.max_entries >= 1);
        }
    }
}
