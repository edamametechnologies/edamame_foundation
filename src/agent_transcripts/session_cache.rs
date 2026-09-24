//! Incremental per-file transcript **session** cache.
//!
//! Every agent collector turns a transcript file into a [`CollectedRawSession`]
//! by reading it, parsing user/assistant/raw text, and then running a battery
//! of regex-heavy extractors (`extract_paths`, `extract_tool_names`,
//! `extract_commands`, `extract_traffic`, `extract_ports`, process-path
//! inference, sensitive-path classification). On the desktop app path that work
//! runs inside the privileged helper daemon; a single window switch in the
//! Agents "Path of Enlightenment" view re-collects up to `limit` (500 for the
//! economics/accounting pass) transcripts PER agent.
//!
//! Measurement (debug helper, real `~/.cursor`, 19 sessions / 27 MB, 7d/500):
//! the read+parse of OS-cached bytes is only a few seconds; the **extraction**
//! pass is ~52 s and runs on every call. A parse-only cache is therefore
//! net-negative (it clones a multi-MB `ParsedTranscript` to skip a cheap parse
//! while the dominant extraction cost still runs). Caching the fully-built
//! session instead removes the extraction cost on every unchanged file:
//!   * switching back to a previously-viewed window is near-instant,
//!   * a `24h -> 7d` widen only extracts the NEW files beyond the old window,
//!   * the steady-state 60s observer loop stops re-extracting stable transcripts.
//!
//! The built session is a pure function of the file bytes plus per-host-constant
//! context (the collector's `home`/`workspace_root` and per-agent path
//! constants). The transcript path is always under the collecting `home`, so a
//! different target home yields a different path and therefore a different key --
//! no cross-home contamination. An actively-growing transcript (the current
//! session) changes size/mtime and is correctly treated as a miss and rebuilt in
//! full -- there is no stale read.
//!
//! The cache is byte-bounded so it cannot grow without limit. Eviction is by
//! transcript file **mtime, oldest first** -- NOT by access recency. Every
//! window the app asks for ("last 24h", "last 7d", "last 30d") extends
//! backwards from now, so the recently-modified files are the working set that
//! every window shares, and the oldest files are the ones only the widest
//! window needs. Collectors also visit candidates newest-first, so under plain
//! LRU the newest files were the FIRST touched and therefore the FIRST evicted
//! once a wide window overflowed the budget: a 14-day pass evicted the very
//! files the next 24h / 3d pass needed, and each window switch re-ran the
//! extraction pass over them (observed on a real home: 14d cold 25 s, then a
//! 3d call right after it still 16 s). With mtime-first eviction an overflowing
//! wide window only drops its own oldest tail.
//! The default cap is 256 MiB, overridable with
//! `EDAMAME_TRANSCRIPT_SESSION_CACHE_BYTES`.
//!
//! Lock discipline: the (potentially multi-MB) `CollectedRawSession` clone a
//! caller receives is performed OUTSIDE the cache mutex. Under the lock we only
//! touch the `Arc` refcount and the LRU bookkeeping maps, so the critical
//! section stays O(log n) and never holds across an allocation-heavy copy.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, UNIX_EPOCH};

use once_cell::sync::Lazy;
use parking_lot::Mutex;

use super::parsing::{parse_jsonl_transcript, parse_txt_transcript, ParsedTranscript};
use super::CollectedRawSession;

/// Default byte budget for the session cache when the env override is unset or
/// unparseable. Sized to hold a large working set of stable sessions while
/// bounding helper/core RSS.
/// Default budget. An entry counts its four text copies (`user_text`,
/// `assistant_text`, `raw_text`, `economics_raw_text`), roughly 3x the file
/// size, and a busy operator accumulates ~110 MB of Claude Code transcripts in
/// 14 days, so 256 MB could not hold a two-week window at all. 512 MB holds
/// it; `EDAMAME_TRANSCRIPT_SESSION_CACHE_BYTES` overrides either way.
const DEFAULT_CACHE_BYTES: usize = 512 * 1024 * 1024;

/// Fixed per-entry overhead added to the measured string bytes so tiny entries
/// still count against the budget (keys, `Arc`/struct headers, map slots, and
/// the many small `Vec<String>` derived-signal fields on a session).
const ENTRY_OVERHEAD_BYTES: usize = 8192;

fn cache_capacity_bytes() -> usize {
    std::env::var("EDAMAME_TRANSCRIPT_SESSION_CACHE_BYTES")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_CACHE_BYTES)
}

struct Entry {
    session: Arc<CollectedRawSession>,
    bytes: usize,
    /// Eviction position: `(file mtime, insertion tick)`. The tick only breaks
    /// ties between files sharing an mtime.
    order_key: (u128, u64),
    /// When the session was built: an oversized transcript's entry is served
    /// only while it is younger than [`OVERSIZED_REBUILD_INTERVAL`].
    built_at: Instant,
}

/// How long the session of a transcript larger than the head-only read cap
/// ([`super::MAX_TRANSCRIPT_BYTES`]) is served from the cache while the file
/// keeps growing.
///
/// Such a file is the operator's current very long session (a Claude Code
/// transcript of 57 MB on the development Mac, 2026-09-24). Every append
/// changes its size and mtime, so the `(mtime, size)` key missed on every
/// 60 s observer tick and the helper re-read, re-parsed and re-extracted the
/// same 16 MiB head -- about 2 s of CPU per tick in a release build, several
/// cores for 10-15 s in the helper on the development Mac -- and handed core a
/// session whose only change was `modified_at`, which then re-hashed and
/// re-ingested it. The head never changes while the file grows at its end, so
/// the rebuilds bought nothing but the tail-derived economics and
/// `modified_at`; those now refresh at this interval instead.
const OVERSIZED_REBUILD_INTERVAL: Duration = Duration::from_secs(600);

struct LruCache {
    map: HashMap<String, Entry>,
    /// `(file mtime, insertion tick) -> key`, so the entry backing the OLDEST
    /// transcript file is `order.iter().next()` and goes first.
    order: BTreeMap<(u128, u64), String>,
    total_bytes: usize,
    capacity_bytes: usize,
    tick: u64,
}

impl LruCache {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
            order: BTreeMap::new(),
            total_bytes: 0,
            capacity_bytes: cache_capacity_bytes(),
            tick: 0,
        }
    }

    fn next_tick(&mut self) -> u64 {
        self.tick = self.tick.wrapping_add(1);
        self.tick
    }

    /// Return the cached session (as a cheap `Arc` clone). Access does not
    /// change eviction order: the file's age does, see the module docs.
    #[cfg(test)]
    fn get(&self, key: &str) -> Option<Arc<CollectedRawSession>> {
        self.get_fresh(key, None)
    }

    /// [`Self::get`], treating an entry built longer than `max_age` ago as
    /// absent.
    fn get_fresh(&self, key: &str, max_age: Option<Duration>) -> Option<Arc<CollectedRawSession>> {
        let entry = self.map.get(key)?;
        if max_age.is_some_and(|max_age| entry.built_at.elapsed() >= max_age) {
            return None;
        }
        Some(entry.session.clone())
    }

    fn insert(
        &mut self,
        key: String,
        session: Arc<CollectedRawSession>,
        bytes: usize,
        mtime_nanos: u128,
    ) {
        // A single entry larger than the whole budget is not cached: caching it
        // would evict the entire working set to make room for one outlier.
        if bytes > self.capacity_bytes {
            return;
        }
        if let Some(old) = self.map.remove(&key) {
            self.order.remove(&old.order_key);
            self.total_bytes = self.total_bytes.saturating_sub(old.bytes);
        }
        let order_key = (mtime_nanos, self.next_tick());
        self.order.insert(order_key, key.clone());
        self.total_bytes = self.total_bytes.saturating_add(bytes);
        self.map.insert(
            key,
            Entry {
                session,
                bytes,
                order_key,
                built_at: Instant::now(),
            },
        );
        while self.total_bytes > self.capacity_bytes {
            let oldest = match self.order.keys().next().copied() {
                Some(order_key) => order_key,
                None => break,
            };
            if let Some(victim) = self.order.remove(&oldest) {
                if let Some(entry) = self.map.remove(&victim) {
                    self.total_bytes = self.total_bytes.saturating_sub(entry.bytes);
                }
            }
        }
    }
}

static CACHE: Lazy<Mutex<LruCache>> = Lazy::new(|| Mutex::new(LruCache::new()));

/// Test-only: accounted bytes currently held, for the real-home benchmark.
#[cfg(test)]
pub(crate) fn cache_total_bytes() -> usize {
    CACHE.lock().total_bytes
}

/// Bump when `CollectedRawSession` shape or adapter-derived fields (e.g.
/// `workspace_hint` for Desktop/OpenClaw) change so stale entries rebuild.
const SESSION_CACHE_SCHEMA: u8 = 2;

fn cache_key(path: &Path, mtime_nanos: u128, len: u64, is_jsonl: bool) -> String {
    // Unit-separator joins so no field value can collide across boundaries.
    format!(
        "{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}",
        path.to_string_lossy(),
        mtime_nanos,
        len,
        is_jsonl as u8,
        SESSION_CACHE_SCHEMA
    )
}

/// The key of a transcript over the head-only read cap: the path alone, since
/// what the build reads (the head) does not change while the file grows.
fn oversized_cache_key(path: &Path, is_jsonl: bool) -> String {
    format!(
        "{}\u{1f}oversized\u{1f}{}\u{1f}{}",
        path.to_string_lossy(),
        is_jsonl as u8,
        SESSION_CACHE_SCHEMA
    )
}

fn estimate_bytes(session: &CollectedRawSession) -> usize {
    session
        .user_text
        .len()
        .saturating_add(session.assistant_text.len())
        .saturating_add(session.raw_text.len())
        .saturating_add(session.economics_raw_text.len())
        .saturating_add(ENTRY_OVERHEAD_BYTES)
}

/// Build the [`CollectedRawSession`] for a transcript file, served from the
/// per-file cache when the file's `(mtime, size)` are unchanged since the last
/// build -- or, for a file larger than the head-only read cap, when the last
/// build is younger than [`OVERSIZED_REBUILD_INTERVAL`].
///
/// `build` receives the freshly [`ParsedTranscript`] and returns the fully
/// extracted/derived session. It runs ONLY on a cache miss; on a hit the stored
/// session is returned directly (an `Arc` clone + one payload copy, no disk
/// read, no parse, no extraction).
///
/// Returns `None` only when the transcript cannot be read (the collector's
/// existing `Err(_) => continue` arm becomes `None => continue`). On a file that
/// cannot be `stat`-ed the cache is bypassed and `build` runs directly, so
/// behavior is identical to the uncached path in every edge case; only
/// unchanged, stat-able files are memoized.
pub(crate) fn get_or_build_session<F>(
    path: &Path,
    is_jsonl: bool,
    build: F,
) -> Option<CollectedRawSession>
where
    F: FnOnce(ParsedTranscript) -> CollectedRawSession,
{
    let keyed = std::fs::metadata(path).ok().and_then(|meta| {
        let len = meta.len();
        let mtime_nanos = meta
            .modified()
            .ok()?
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_nanos();
        if len > super::MAX_TRANSCRIPT_BYTES {
            return Some((
                oversized_cache_key(path, is_jsonl),
                Some(OVERSIZED_REBUILD_INTERVAL),
                mtime_nanos,
            ));
        }
        Some((
            cache_key(path, mtime_nanos, len, is_jsonl),
            None,
            mtime_nanos,
        ))
    });
    let key = keyed.as_ref().map(|(key, _, _)| key.clone());
    let max_age = keyed.as_ref().and_then(|(_, max_age, _)| *max_age);
    let mtime_nanos = keyed.as_ref().map(|(_, _, m)| *m).unwrap_or(0);

    if let Some(key) = key.as_ref() {
        // Take the Arc under the lock, then copy the payload after releasing it.
        let hit = CACHE.lock().get_fresh(key, max_age);
        if let Some(arc) = hit {
            return Some((*arc).clone());
        }
    }

    let raw_text = super::read_transcript_capped(path).ok()?;
    let parsed = if is_jsonl {
        parse_jsonl_transcript(&raw_text)
    } else {
        parse_txt_transcript(&raw_text)
    };
    let mut session = build(parsed);
    // Everything derivable from the file is derived here, once, and cached
    // with the session -- see `finish_session`.
    super::finish_session(&mut session);

    if let Some(key) = key {
        let bytes = estimate_bytes(&session);
        // Clone for storage BEFORE taking the lock so the copy is not held
        // across the critical section.
        let stored = Arc::new(session.clone());
        CACHE.lock().insert(key, stored, bytes, mtime_nanos);
    }

    Some(session)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_file(dir: &Path, name: &str, contents: &str) -> std::path::PathBuf {
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        path
    }

    fn session_with_user(user: &str) -> CollectedRawSession {
        // `CollectedRawSession` intentionally has no `Default` (its
        // `DateTime<Utc>` fields don't), so build it explicitly. Only
        // `user_text` matters to these tests; everything else is empty/epoch.
        let epoch = chrono::DateTime::<chrono::Utc>::from_timestamp(0, 0).unwrap();
        CollectedRawSession {
            session_key: String::new(),
            title: String::new(),
            user_text: user.to_string(),
            assistant_text: String::new(),
            raw_text: String::new(),
            tool_names: Vec::new(),
            commands: Vec::new(),
            derived_expected_traffic: Vec::new(),
            derived_expected_local_open_ports: Vec::new(),
            derived_expected_process_paths: Vec::new(),
            derived_expected_parent_paths: Vec::new(),
            derived_expected_grandparent_paths: Vec::new(),
            derived_scope_process_paths: Vec::new(),
            derived_scope_parent_paths: Vec::new(),
            derived_scope_grandparent_paths: Vec::new(),
            derived_scope_any_lineage_paths: Vec::new(),
            derived_expected_open_files: Vec::new(),
            source_path: String::new(),
            started_at: epoch,
            modified_at: epoch,
            economics_raw_text: String::new(),
            economics_truncated: false,
            economics: None,
            tool_error_details: Vec::new(),
            context_tokens_used: None,
            context_token_limit: None,
            context_usage_percent: None,
            workspace_hint: String::new(),
            tool_events: Vec::new(),
            denylist_bypass_events: Vec::new(),
        }
    }

    #[test]
    fn hit_skips_the_build_closure() {
        let dir =
            std::env::temp_dir().join(format!("edamame_session_cache_hit_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = write_file(&dir, "a.jsonl", "{\"role\":\"user\"}\n");

        // First call: miss -> build runs, records the parsed user text length.
        let first = get_or_build_session(&path, true, |parsed| {
            session_with_user(&format!("built:{}", parsed.raw_text.len()))
        })
        .unwrap();

        // Second call (file unchanged): HIT -> the build closure must NOT run.
        // If it did, the panic below would fire.
        let second =
            get_or_build_session(&path, true, |_| panic!("build must not run on a cache hit"))
                .unwrap();

        assert_eq!(first.user_text, second.user_text);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hit_carries_the_finished_derived_data() {
        // The post-pass (`finish_session`) runs on the miss and is cached
        // with the session: a hit must hand back the derived data without
        // rebuilding or re-deriving anything.
        let dir = std::env::temp_dir().join(format!(
            "edamame_session_cache_finished_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = write_file(&dir, "f.jsonl", "{\"role\":\"user\"}\n");
        let first = get_or_build_session(&path, true, |_| session_with_user("u")).unwrap();
        assert!(
            first.economics.is_some(),
            "the miss must derive session economics before caching"
        );
        let second =
            get_or_build_session(&path, true, |_| panic!("build must not run on a cache hit"))
                .unwrap();
        assert!(
            second.economics.is_some(),
            "the hit must carry the derived economics"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn changed_size_is_a_miss_and_rebuilds() {
        let dir =
            std::env::temp_dir().join(format!("edamame_session_cache_chg_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = write_file(&dir, "b.txt", "user:\none\n");

        let a = get_or_build_session(&path, false, |parsed| session_with_user(&parsed.user_text))
            .unwrap();
        assert_eq!(a.user_text, "one");

        // Grow the file so the byte size differs (not just the content). A
        // same-size content swap ("one" -> "two") would only differ by mtime,
        // whose resolution is coarse on some filesystems (NTFS), so two rapid
        // writes could collide on the key and mask a stale hit. Changing the
        // size guarantees a distinct key -> deterministic miss -> rebuild on
        // every platform. A stale HIT would still return "one"; a correct miss
        // re-extracts and yields "twotwo".
        write_file(&dir, "b.txt", "user:\ntwotwo\n");
        let b = get_or_build_session(&path, false, |parsed| session_with_user(&parsed.user_text))
            .unwrap();
        assert_eq!(b.user_text, "twotwo");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A transcript over the head-only read cap that keeps growing (the
    /// operator's current long session) is served from the cache until the
    /// rebuild interval has passed: the head the build reads is unchanged.
    #[test]
    fn a_growing_transcript_over_the_read_cap_is_rebuilt_only_after_the_interval() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!(
            "edamame_session_cache_oversized_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("long.txt");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"user:\nhead\n").unwrap();
            let filler = format!("{}\n", "x".repeat(1023));
            let lines = (super::super::MAX_TRANSCRIPT_BYTES as usize / filler.len()) + 16;
            for _ in 0..lines {
                f.write_all(filler.as_bytes()).unwrap();
            }
        }
        let first = get_or_build_session(&path, false, |parsed| {
            session_with_user(&format!("built:{}", parsed.user_text.len()))
        })
        .unwrap();

        // The session keeps growing: size and mtime change, the head does not.
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            f.write_all(b"user:\nlater turn\n").unwrap();
        }
        let second = get_or_build_session(&path, false, |_| {
            panic!("a growing transcript over the read cap must be served from the cache")
        })
        .unwrap();
        assert_eq!(first.user_text, second.user_text);

        // Past the interval it is rebuilt (the tail-derived economics and
        // `modified_at` refresh then).
        {
            let key = oversized_cache_key(&path, false);
            let mut cache = CACHE.lock();
            let entry = cache
                .map
                .get_mut(&key)
                .expect("the oversized session is cached");
            entry.built_at = Instant::now()
                .checked_sub(OVERSIZED_REBUILD_INTERVAL)
                .expect("the clock is past the interval");
        }
        let mut rebuilt = false;
        get_or_build_session(&path, false, |parsed| {
            rebuilt = true;
            session_with_user(&parsed.user_text)
        })
        .unwrap();
        assert!(rebuilt, "an entry older than the interval must be rebuilt");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn oversized_entry_is_not_cached() {
        let mut cache = LruCache::new();
        cache.capacity_bytes = 1024;
        let big = Arc::new(session_with_user(&"x".repeat(4096)));
        cache.insert("k".to_string(), big, 4096 + ENTRY_OVERHEAD_BYTES, 1);
        assert!(cache.get("k").is_none());
        assert_eq!(cache.total_bytes, 0);
    }

    #[test]
    fn evicts_the_oldest_transcript_file_first_over_budget() {
        let mut cache = LruCache::new();
        cache.capacity_bytes = 3 * (10 + ENTRY_OVERHEAD_BYTES);
        // Inserted newest-first, exactly the order a collector visits files.
        for (i, mtime) in [(0u32, 300u128), (1, 200), (2, 100)] {
            let s = Arc::new(session_with_user(&"y".repeat(10)));
            cache.insert(format!("k{i}"), s, 10 + ENTRY_OVERHEAD_BYTES, mtime);
        }
        // Access does not protect an entry: touch the oldest file (k2).
        assert!(cache.get("k2").is_some());
        // A 4th entry evicts the OLDEST FILE (k2, mtime 100) -- not the
        // least-recently-used (k0), which is the newest file and the one the
        // next narrower window will ask for again.
        let s = Arc::new(session_with_user(&"z".repeat(10)));
        cache.insert("k3".to_string(), s, 10 + ENTRY_OVERHEAD_BYTES, 400);
        assert!(
            cache.get("k2").is_none(),
            "oldest file should have been evicted"
        );
        assert!(cache.get("k0").is_some(), "newest file must survive");
        assert!(cache.get("k1").is_some());
        assert!(cache.get("k3").is_some());
    }

    /// Re-inserting a key (file changed) replaces its slot and keeps
    /// accounting consistent.
    #[test]
    fn reinsert_replaces_without_double_counting() {
        let mut cache = LruCache::new();
        cache.capacity_bytes = 10 * (10 + ENTRY_OVERHEAD_BYTES);
        let s = Arc::new(session_with_user(&"y".repeat(10)));
        cache.insert("k".to_string(), s.clone(), 10 + ENTRY_OVERHEAD_BYTES, 5);
        cache.insert("k".to_string(), s, 10 + ENTRY_OVERHEAD_BYTES, 6);
        assert_eq!(cache.map.len(), 1);
        assert_eq!(cache.order.len(), 1);
        assert_eq!(cache.total_bytes, 10 + ENTRY_OVERHEAD_BYTES);
    }

    /// Not an assertion: times three collection passes over the REAL Claude
    /// Code home (14d, 14d again, 3d) so the cache policy can be checked
    /// against a live corpus. Run with
    /// `cargo test -- --ignored session_cache_real_home_window_switch --nocapture`.
    #[test]
    #[ignore]
    fn session_cache_real_home_window_switch() {
        let home = std::env::var("HOME").map(std::path::PathBuf::from).unwrap();
        use super::super::{claude_code, claude_desktop, codex, cursor, hermes, openclaw};
        let agents: [(
            &str,
            fn(&Path, &super::super::CollectOptions) -> anyhow::Result<super::super::CollectResult>,
        ); 6] = [
            ("claude_code", claude_code::collect),
            ("cursor", cursor::collect),
            ("codex", codex::collect),
            ("openclaw", openclaw::collect),
            ("hermes", hermes::collect),
            ("claude_desktop", claude_desktop::collect),
        ];
        for window in [20160u64, 20160, 4320, 1440] {
            let options = super::super::CollectOptions {
                limit: 500,
                active_window_minutes: window,
                ..Default::default()
            };
            let started = std::time::Instant::now();
            let mut per_agent = Vec::new();
            for (name, collect) in agents {
                let t = std::time::Instant::now();
                let _ = collect;
                let n = super::super::collect(name, &home, &options)
                    .map(|r| r.payload.sessions.len())
                    .unwrap_or(0);
                per_agent.push(format!("{name}={n}/{:?}", t.elapsed()));
            }
            println!(
                "window={window:>6} took {:?} cache={} MB [{}]",
                started.elapsed(),
                cache_total_bytes() / (1024 * 1024),
                per_agent.join(" ")
            );
        }
    }
}
