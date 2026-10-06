//! BS-10 per-process credential signals for the attack pattern detector:
//! the cold credential files a process opened recently (the kernel open
//! sensor, `flodbadd::credential_opens`) and the NAMES of wallet-key
//! environment variables set in it. A value is never read past its name.
//!
//! Both are measured where the sensor runs and other processes' environments
//! are readable: in-process for standalone core (posture, root), and in the
//! helper for the app (`process_credential_signals` utility order), whose
//! sandboxed core sees an empty open table and no foreign environment.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Queries measured per batch; the rest are reported as `truncated`.
pub const MAX_QUERIES: usize = 2048;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessQuery {
    pub pid: u32,
    /// The session's process start time: a reused pid is a different
    /// process and its environment is read afresh.
    pub start_time: u64,
    /// When known, the opens must have been made by this image, so a reused
    /// pid never inherits another image's reads.
    pub process_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessCredentialSignals {
    pub query: ProcessQuery,
    pub recent_sensitive_reads: Vec<String>,
    pub wallet_key_env: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessCredentialSignalBatch {
    /// Only the queries with at least one signal.
    pub signals: Vec<ProcessCredentialSignals>,
    /// Queries past `MAX_QUERIES` were not measured.
    pub truncated: bool,
}

/// Wallet-key environment variable prefixes and suffixes (joined with `_`).
/// Chain- or wallet-qualified names only: generic names such as
/// `PRIVATE_KEY`, `SECRET` or `API_KEY` are deliberately absent.
const WALLET_KEY_ENV_PREFIXES: &[&str] = &[
    "SOLANA", "SOL", "ETH", "ETHEREUM", "EVM", "BTC", "BITCOIN", "WALLET",
];
const WALLET_KEY_ENV_SUFFIXES: &[&str] = &[
    "PRIVATE_KEY",
    "SECRET_KEY",
    "KEYPAIR",
    "MNEMONIC",
    "SEED_PHRASE",
];
const WALLET_KEY_ENV_EXACT: &[&str] = &["ANCHOR_WALLET"];

pub fn is_wallet_key_env_name(name: &str) -> bool {
    if WALLET_KEY_ENV_EXACT.contains(&name) {
        return true;
    }
    WALLET_KEY_ENV_PREFIXES.iter().any(|prefix| {
        name.strip_prefix(prefix)
            .and_then(|rest| rest.strip_prefix('_'))
            .is_some_and(|suffix| WALLET_KEY_ENV_SUFFIXES.contains(&suffix))
    })
}

/// Measure each query. This process's own pid is skipped: its reads and
/// environment are the observer's, not material its sessions carry.
pub fn collect_process_credential_signals(
    queries: &[ProcessQuery],
) -> ProcessCredentialSignalBatch {
    let own_pid = std::process::id();
    let mut seen: HashSet<&ProcessQuery> = HashSet::new();
    let unique: Vec<&ProcessQuery> = queries
        .iter()
        .filter(|q| q.pid != 0 && q.pid != own_pid && seen.insert(*q))
        .collect();
    let truncated = unique.len() > MAX_QUERIES;
    let measured = &unique[..unique.len().min(MAX_QUERIES)];

    let env_names = wallet_key_env_names(measured);
    let signals = measured
        .iter()
        .zip(env_names)
        .filter_map(|(query, wallet_key_env)| {
            let recent_sensitive_reads = flodbadd::credential_opens::recent_for_pid(
                query.pid,
                query.process_path.as_deref(),
            );
            (!recent_sensitive_reads.is_empty() || !wallet_key_env.is_empty()).then(|| {
                ProcessCredentialSignals {
                    query: (*query).clone(),
                    recent_sensitive_reads,
                    wallet_key_env,
                }
            })
        })
        .collect();
    ProcessCredentialSignalBatch { signals, truncated }
}

/// Matched wallet-key environment NAMES per query, in query order.
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn wallet_key_env_names(queries: &[&ProcessQuery]) -> Vec<Vec<String>> {
    use std::collections::HashMap;
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
    use undeadlock::CustomMutexExt;

    let keys: Vec<(u32, u64)> = queries.iter().map(|q| (q.pid, q.start_time)).collect();
    let mut names_by_key: HashMap<(u32, u64), Vec<String>> = HashMap::new();
    let mut missing: Vec<(u32, u64)> = Vec::new();
    let cached = WALLET_ENV_CACHE.try_with(|cache| {
        for key in &keys {
            match cache.get(key) {
                Some(names) => {
                    names_by_key.insert(*key, names.clone());
                }
                None if !missing.contains(key) => missing.push(*key),
                None => {}
            }
        }
    });
    if cached.is_none() {
        missing = keys.clone();
        missing.dedup();
    }

    if !missing.is_empty() {
        let pids: Vec<Pid> = missing.iter().map(|(pid, _)| Pid::from_u32(*pid)).collect();
        let mut system = System::new();
        system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&pids),
            true,
            ProcessRefreshKind::nothing().with_environ(UpdateKind::Always),
        );
        for key in &missing {
            let names = system
                .process(Pid::from_u32(key.0))
                .map(|process| {
                    let mut names: Vec<String> = process
                        .environ()
                        .iter()
                        .filter_map(|entry| {
                            let entry = entry.to_string_lossy();
                            let name = entry.split_once('=').map(|(n, _)| n)?;
                            is_wallet_key_env_name(name).then(|| name.to_string())
                        })
                        .collect();
                    names.sort();
                    names.dedup();
                    names
                })
                .unwrap_or_default();
            names_by_key.insert(*key, names);
        }
        WALLET_ENV_CACHE.try_with(|cache| {
            if cache.len() + missing.len() > WALLET_ENV_CACHE_MAX {
                cache.clear();
            }
            for key in &missing {
                if let Some(names) = names_by_key.get(key) {
                    cache.insert(*key, names.clone());
                }
            }
        });
    }

    keys.iter()
        .map(|key| names_by_key.get(key).cloned().unwrap_or_default())
        .collect()
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn wallet_key_env_names(queries: &[&ProcessQuery]) -> Vec<Vec<String>> {
    vec![Vec::new(); queries.len()]
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
const WALLET_ENV_CACHE_MAX: usize = 4096;

/// `(pid, process start time)` -> matched wallet-key env NAMES.
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
static WALLET_ENV_CACHE: once_cell::sync::Lazy<
    undeadlock::CustomMutex<std::collections::HashMap<(u32, u64), Vec<String>>>,
> = once_cell::sync::Lazy::new(|| undeadlock::CustomMutex::new(std::collections::HashMap::new()));

#[cfg(test)]
mod tests {
    use super::*;

    fn query(pid: u32, path: &str) -> ProcessQuery {
        ProcessQuery {
            pid,
            start_time: 1,
            process_path: Some(path.to_string()),
        }
    }

    #[test]
    fn wallet_key_env_names_are_chain_qualified_only() {
        for name in [
            "SOLANA_PRIVATE_KEY",
            "SOLANA_KEYPAIR",
            "ETH_PRIVATE_KEY",
            "WALLET_MNEMONIC",
            "ANCHOR_WALLET",
        ] {
            assert!(is_wallet_key_env_name(name), "{name}");
        }
        for name in [
            "PRIVATE_KEY",
            "SECRET",
            "API_KEY",
            "TOKEN",
            "SOLANA_RPC_URL",
            "MY_SOLANA_PRIVATE_KEY",
        ] {
            assert!(!is_wallet_key_env_name(name), "{name}");
        }
    }

    #[test]
    fn recent_reads_come_from_the_sensor_for_the_same_image_only() {
        let key = "/Users/dev/.config/solana/id.json";
        let node = "/opt/homebrew/bin/node";
        flodbadd::credential_opens::record_open_for_tests(4_310_101, node, key);

        let batch = collect_process_credential_signals(&[
            query(4_310_101, node),
            query(4_310_101, "/usr/bin/curl"),
            query(4_310_102, node),
        ]);

        assert!(!batch.truncated);
        assert_eq!(batch.signals.len(), 1, "{batch:?}");
        assert_eq!(batch.signals[0].query, query(4_310_101, node));
        assert_eq!(
            batch.signals[0].recent_sensitive_reads,
            vec![key.to_string()]
        );
    }

    #[test]
    fn own_pid_duplicates_and_overflow_are_not_measured() {
        let own = std::process::id();
        let mut queries = vec![query(own, "/x"), query(0, "/x")];
        queries.extend((0..MAX_QUERIES as u32 + 5).map(|i| query(4_400_000 + i, "/x")));
        queries.push(query(4_400_000, "/x"));
        let batch = collect_process_credential_signals(&queries);
        assert!(batch.truncated);
        assert!(batch.signals.is_empty());

        let batch = collect_process_credential_signals(&vec![query(4_400_000, "/x"); 3]);
        assert!(!batch.truncated);
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn wallet_key_env_reports_names_never_values() {
        let fake = "FAKE-NOT-A-KEY-4c1d";
        let mut child = std::process::Command::new("sleep")
            .arg("10")
            .env("SOLANA_PRIVATE_KEY", fake)
            .spawn()
            .expect("spawn sleep");
        std::thread::sleep(std::time::Duration::from_millis(200));
        let batch = collect_process_credential_signals(&[ProcessQuery {
            pid: child.id(),
            start_time: 1,
            process_path: None,
        }]);
        let _ = child.kill();
        let _ = child.wait();
        // macOS 26 withholds another process's environment from a non-root
        // caller, even of the same user; earlier releases expose it. The root
        // daemon and helper read it on every release.
        let is_root = std::process::Command::new("id")
            .arg("-u")
            .output()
            .map(|out| String::from_utf8_lossy(&out.stdout).trim() == "0")
            .unwrap_or(false);
        if cfg!(target_os = "linux") || is_root || !batch.signals.is_empty() {
            assert_eq!(batch.signals.len(), 1, "{batch:?}");
            assert_eq!(batch.signals[0].wallet_key_env, vec!["SOLANA_PRIVATE_KEY"]);
        }
        assert!(!serde_json::to_string(&batch).unwrap().contains(fake));
    }
}
