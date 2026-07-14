//! Throwaway micro-benchmark for the transcript session cache.
//!
//! Usage:
//!   cargo run --release --example bench_session_cache --features packetcapture -- cursor 500 10080
//!
//! Args: <agent_type> <limit> <active_window_minutes>. Runs `collect()` three
//! times back-to-back and prints per-call wall time + session count. With the
//! session cache enabled (default), call #1 is cold (cache empty -> full
//! parse+extract per file) and calls #2/#3 are warm (files unchanged -> the
//! whole extraction pass is skipped and the `CollectedRawSession` is served
//! from memory). Set EDAMAME_TRANSCRIPT_SESSION_CACHE_BYTES=1 to effectively
//! disable the cache and measure the uncached baseline (parse + extract every
//! call) for comparison.

use std::path::PathBuf;
use std::time::Instant;

use edamame_foundation::agent_transcripts::{collect, CollectOptions};

fn main() {
    let home = PathBuf::from(std::env::var("HOME").expect("HOME must be set"));
    let agent = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "cursor".to_string());
    let limit: usize = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(500);
    let window: u64 = std::env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(7 * 24 * 60);

    let opts = CollectOptions {
        limit,
        active_window_minutes: window,
        project_hints: Vec::new(),
    };

    let cap = std::env::var("EDAMAME_TRANSCRIPT_SESSION_CACHE_BYTES")
        .unwrap_or_else(|_| "(default 256MiB)".to_string());
    eprintln!(
        "agent={agent} limit={limit} window_min={window} session_cache_cap={cap}\n\
         home={}",
        home.display()
    );

    for i in 1..=3 {
        let t = Instant::now();
        match collect(&agent, &home, &opts) {
            Ok(res) => {
                let n = res.payload.sessions.len();
                let bytes: usize = res
                    .payload
                    .sessions
                    .iter()
                    .map(|s| s.user_text.len() + s.assistant_text.len() + s.raw_text.len())
                    .sum();
                eprintln!(
                    "call #{i}: {:.3}s  sessions={}  text_bytes={}",
                    t.elapsed().as_secs_f64(),
                    n,
                    bytes
                );
            }
            Err(e) => eprintln!("call #{i}: ERROR {e}"),
        }
    }
}
