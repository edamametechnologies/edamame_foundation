use arc_swap::{ArcSwap, ArcSwapOption};
use fmt::MakeWriter;
use lazy_static::lazy_static;
use regex::Regex;
use sentry_tracing::EventFilter;
use std::{
    collections::HashMap,
    env::{current_exe, var},
    fs::{create_dir_all, read_dir, remove_file, File},
    io::{self, Write},
    mem::forget,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Once, OnceLock,
    },
    time::{Duration, Instant, SystemTime},
};
use tracing::Level;
#[cfg(target_os = "android")]
use tracing_android;
use tracing_appender::non_blocking::NonBlocking;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;

const MAX_LOG_LINES: usize = 20000;

/// Days of rolling log history to keep, matching the `max_log_files` window
/// on the daily appender below.
const LOG_RETENTION_DAYS: u64 = 7;

/// Delete this executable type's rolling log files older than
/// [`LOG_RETENTION_DAYS`], regardless of which PID wrote them.
///
/// `RollingFileAppender::max_log_files` only prunes files matching the
/// appender's own `filename_prefix`, and that prefix carries the PID. Each
/// process therefore sees exactly one file and can never reclaim what earlier
/// PIDs left behind, so a host that restarts the daemon often accumulates them
/// without bound -- a CI runner starting one per job reached 7234 files and
/// 17 GB in a week. The appender's own window still covers the single
/// long-lived process that spans more than a week.
fn prune_stale_logs(log_dir: &Path, stem: &str, current_pid: u32) {
    let cutoff = match SystemTime::now()
        .checked_sub(Duration::from_secs(LOG_RETENTION_DAYS * 24 * 60 * 60))
    {
        Some(cutoff) => cutoff,
        None => return,
    };
    let entries = match read_dir(log_dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let file_name = match file_name.to_str() {
            Some(name) => name,
            None => continue,
        };

        // The appender writes "{stem}_{pid}.{YYYY-MM-DD}". Requiring a
        // digits-only PID segment rather than a bare prefix match keeps the
        // "edamame" stem from sweeping "edamame_posture_*" when both land in
        // the same directory.
        let head = match file_name.split('.').next() {
            Some(head) => head,
            None => continue,
        };
        let pid_segment = match head.strip_prefix(stem).and_then(|r| r.strip_prefix('_')) {
            Some(pid_segment) => pid_segment,
            None => continue,
        };
        if pid_segment.is_empty() || !pid_segment.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        if pid_segment.parse::<u32>() == Ok(current_pid) {
            continue;
        }

        // Another daemon may be pruning the same directory concurrently, so a
        // file vanishing between the scan and the unlink is expected. Logging
        // is not up yet either, so every failure here stays silent.
        match entry.metadata().and_then(|m| m.modified()) {
            Ok(modified) if modified < cutoff => {
                let _ = remove_file(entry.path());
            }
            _ => {}
        }
    }
}

lazy_static! {
    static ref ANSI_ESCAPE_REGEX: Regex =
        Regex::new(r"\x1b\[[0-9;]*m").expect("Failed to compile ANSI escape regex");
}

// No lock in the logging path. Every log line of every thread goes through
// `MemoryWriter`, and the Sentry `before_send` runs on the thread that logged
// an error: a lock there serializes all logging, and an instrumented
// (undeadlock) lock cannot be used at all, because its diagnostics are emitted
// through tracing, i.e. back into this logger. Write-once values are
// `OnceLock`s, the ring is lock-free (`MemoryWriterData`), and the Sentry dedup
// table is a snapshot replaced whole (`SENTRY_DEDUP`).
static LOGGER: OnceLock<Arc<Logger>> = OnceLock::new();
static PANIC_HOOK_INIT: Once = Once::new();
static EXECUTABLE_TYPE: OnceLock<String> = OnceLock::new();

/// The in-memory log ring the `get_*_logs` calls read: the last
/// `MAX_LOG_LINES` lines, newest first.
///
/// A line claims the next index with one `fetch_add` and publishes itself in
/// its slot with one `ArcSwap` store. A reader that races a writer wrapping
/// the ring can read, for an index, the line one lap newer (or the one it
/// replaces, while the store is in flight), never a torn line.
pub struct MemoryWriterData {
    slots: Box<[ArcSwapOption<String>]>,
    /// Lines ever written: the index the next line takes.
    next: AtomicUsize,
    /// Lines below this index were flushed.
    floor: AtomicUsize,
    /// Lines below this index were returned by `get_new_logs`.
    taken: AtomicUsize,
}

impl MemoryWriterData {
    pub fn new() -> Self {
        Self {
            slots: (0..MAX_LOG_LINES).map(|_| ArcSwapOption::empty()).collect(),
            next: AtomicUsize::new(0),
            floor: AtomicUsize::new(0),
            taken: AtomicUsize::new(0),
        }
    }

    fn push(&self, line: String) {
        let index = self.next.fetch_add(1, Ordering::AcqRel);
        self.slots[index % MAX_LOG_LINES].store(Some(Arc::new(line)));
    }

    /// Lines `[from, end)` still in the ring, newest first.
    fn lines_since(&self, from: usize, end: usize) -> Vec<String> {
        let start = from
            .max(self.floor.load(Ordering::Acquire))
            .max(end.saturating_sub(MAX_LOG_LINES));
        (start..end)
            .rev()
            .filter_map(|index| self.slots[index % MAX_LOG_LINES].load_full())
            .map(|line| (*line).clone())
            .collect()
    }

    /// Every line in the ring, newest first.
    fn all(&self) -> Vec<String> {
        self.lines_since(0, self.next.load(Ordering::Acquire))
    }

    /// The lines written since the previous call, newest first (at most the
    /// ring's size).
    fn take_new(&self) -> Vec<String> {
        let end = self.next.load(Ordering::Acquire);
        let from = self.taken.swap(end, Ordering::AcqRel);
        self.lines_since(from, end)
    }

    /// Forget every line written so far and free them.
    fn flush(&self) {
        let end = self.next.load(Ordering::Acquire);
        self.floor.fetch_max(end, Ordering::AcqRel);
        self.taken.fetch_max(end, Ordering::AcqRel);
        for slot in self.slots.iter() {
            slot.store(None);
        }
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.all().is_empty()
    }
}

#[derive(Clone)]
pub struct MemoryWriter {
    data: Arc<MemoryWriterData>,
}

impl MemoryWriter {
    pub fn new() -> Self {
        Self {
            data: Arc::new(MemoryWriterData::new()),
        }
    }

    fn handle_log(&self, log_line: &str) -> io::Result<()> {
        // Sanitize the log line (not in debug mode) through the shared
        // redaction module (secret shapes, secret-named fields, privacy keys).
        let log_line_sanitized = if cfg!(debug_assertions) {
            log_line.to_string()
        } else {
            sanitize_keywords(log_line, &[])
        };
        // Remove all escape codes (x1b\[[0-9;]*m) from the log line before storing it in the log buffer x1b\[[0-9;]*m
        let log_line_formatted = ANSI_ESCAPE_REGEX.replace_all(&log_line_sanitized, "");
        let log_line_formatted = log_line_formatted.trim().to_string();

        self.data.push(log_line_formatted);

        Ok(())
    }
}

impl<'a> MakeWriter<'a> for MemoryWriter {
    type Writer = MemoryWriterGuard<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        MemoryWriterGuard { writer: self }
    }
}

pub struct MemoryWriterGuard<'a> {
    writer: &'a MemoryWriter,
}

impl<'a> Write for MemoryWriterGuard<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let log = String::from_utf8_lossy(buf).to_string();
        self.writer.handle_log(&log)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Clone)]
struct SanitizingMakeWriter<M> {
    inner: M,
}

impl<M> SanitizingMakeWriter<M> {
    fn new(inner: M) -> Self {
        Self { inner }
    }
}

struct SanitizingWriter<W> {
    inner: W,
}

impl<'a, M> MakeWriter<'a> for SanitizingMakeWriter<M>
where
    M: MakeWriter<'a>,
{
    type Writer = SanitizingWriter<M::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        SanitizingWriter {
            inner: self.inner.make_writer(),
        }
    }
}

impl<W> Write for SanitizingWriter<W>
where
    W: Write,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if cfg!(debug_assertions) {
            self.inner.write(buf)
        } else {
            let log = String::from_utf8_lossy(buf);
            let sanitized = sanitize_keywords(&log, &[]);
            self.inner.write_all(sanitized.as_bytes())?;
            Ok(buf.len())
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Log-line scrubbing: secret shapes, secret-named fields and the privacy
/// keys, all owned by the shared `redaction` module.
fn sanitize_keywords(input: &str, _keywords: &[&str]) -> String {
    crate::redaction::redact_log_line(input)
}

fn build_log_output(logs: &[String]) -> String {
    if logs.is_empty() {
        return String::new();
    }
    let mut capacity = 0;
    for line in logs {
        capacity += line.len() + 1;
    }
    let mut output = String::with_capacity(capacity);
    for line in logs {
        output.push('\n');
        output.push_str(line);
    }
    output
}

pub struct Logger {
    memory_writer: MemoryWriter,
}

impl Logger {
    pub fn new() -> Self {
        Self {
            memory_writer: MemoryWriter::new(),
        }
    }

    pub fn get_new_logs(&self) -> String {
        build_log_output(&self.memory_writer.data.take_new())
    }

    pub fn get_all_logs(&self) -> String {
        build_log_output(&self.memory_writer.data.all())
    }

    pub fn flush_logs(&self) {
        self.memory_writer.data.flush();
    }
}

fn create_panic_artifact(
    executable_type: &str,
    msg: &str,
    location: &str,
    backtrace: &std::backtrace::Backtrace,
) {
    let _ = std::panic::catch_unwind(|| {
        // Get current executable path and directory
        let exe_path = current_exe().unwrap_or_else(|_| PathBuf::from(""));
        let exe_dir = exe_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));

        // Daemon types write panic artifacts to /var/log/edamame/ on Unix
        // (matches rolling log location) instead of beside the executable.
        // Falls back to beside the executable if the directory can't be created.
        let artifact_dir = if cfg!(unix) && matches!(executable_type, "helper" | "posture") {
            let dir = PathBuf::from("/var/log/edamame");
            if create_dir_all(&dir).is_ok() {
                dir
            } else {
                exe_dir.to_path_buf()
            }
        } else {
            exe_dir.to_path_buf()
        };

        // Create timestamp for filename
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_else(|_| std::time::Duration::from_secs(0))
            .as_secs();

        // Format: {executable_type}_panic_{timestamp}
        let panic_filename = format!("{}_panic_{}.txt", executable_type, now);
        let panic_file_path = artifact_dir.join(panic_filename);

        // Create panic content
        let panic_content = format!(
            "PANIC REPORT\n\
            =============\n\
            Timestamp: {}\n\
            Executable: {:?}\n\
            Type: {}\n\
            PID: {}\n\
            \n\
            PANIC DETAILS\n\
            =============\n\
            Message: {}\n\
            Location: {}\n\
            \n\
            BACKTRACE\n\
            =========\n\
            {}\n\
            \n\
            ENVIRONMENT\n\
            ===========\n\
            RUST_BACKTRACE: {}\n\
            OS: {}\n\
            ARCH: {}\n",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            exe_path,
            executable_type,
            std::process::id(),
            msg,
            location,
            backtrace,
            std::env::var("RUST_BACKTRACE").unwrap_or_else(|_| "unset".to_string()),
            std::env::consts::OS,
            std::env::consts::ARCH
        );

        // Write to file
        match File::create(&panic_file_path) {
            Ok(mut file) => {
                if let Err(e) = file.write_all(panic_content.as_bytes()) {
                    eprintln!("Failed to write panic artifact: {}", e);
                } else {
                    eprintln!("Panic artifact written to: {:?}", panic_file_path);
                }
            }
            Err(e) => {
                eprintln!(
                    "Failed to create panic artifact file {:?}: {}",
                    panic_file_path, e
                );
            }
        }
    });
}

const SENTRY_DEDUP_WINDOW_SECS: u64 = 60;
const SENTRY_DEDUP_MAX_ENTRIES: usize = 500;

lazy_static! {
    /// Fingerprint -> last time an event with it was sent. Replaced whole on
    /// each error event (`rcu`): error events are rare, and this runs inside
    /// Sentry's `before_send`, on the thread that logged the error, where no
    /// lock may be taken (see `LOGGER`).
    static ref SENTRY_DEDUP: ArcSwap<HashMap<u64, Instant>> = ArcSwap::from_pointee(HashMap::new());
}

/// Whether an event with `fingerprint` seen at `now` is a repeat inside the
/// dedup window; records it otherwise (and prunes the table past its size).
fn sentry_event_is_repeat(fingerprint: u64, now: Instant) -> bool {
    let mut repeat = false;
    SENTRY_DEDUP.rcu(|seen| {
        repeat = seen
            .get(&fingerprint)
            .is_some_and(|last| now.duration_since(*last).as_secs() < SENTRY_DEDUP_WINDOW_SECS);
        let mut next = HashMap::clone(seen);
        if !repeat {
            next.insert(fingerprint, now);
            if next.len() > SENTRY_DEDUP_MAX_ENTRIES {
                let cutoff = now - Duration::from_secs(SENTRY_DEDUP_WINDOW_SECS);
                next.retain(|_, ts| *ts > cutoff);
            }
        }
        next
    });
    repeat
}

fn sentry_event_fingerprint(event: &sentry::protocol::Event) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for exc in &event.exception.values {
        exc.ty.hash(&mut hasher);
        if let Some(ref v) = exc.value {
            v.hash(&mut hasher);
        }
    }
    if let Some(ref msg) = event.message {
        msg.hash(&mut hasher);
    }
    if let Some(ref logentry) = event.logentry {
        logentry.message.hash(&mut hasher);
    }
    event.level.hash(&mut hasher);
    hasher.finish()
}

fn scrub_sentry_value(value: &mut serde_json::Value) {
    use crate::redaction::{is_secret_field_name, redact_log_line, REDACTED};
    match value {
        serde_json::Value::String(text) => {
            let scrubbed = redact_log_line(text);
            if scrubbed != *text {
                *text = scrubbed;
            }
        }
        serde_json::Value::Object(map) => {
            for (name, field) in map.iter_mut() {
                if is_secret_field_name(name) && !field.is_null() {
                    *field = serde_json::Value::String(REDACTED.to_string());
                } else {
                    scrub_sentry_value(field);
                }
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(scrub_sentry_value),
        _ => {}
    }
}

fn scrub_sentry_map(map: &mut sentry::protocol::Map<String, serde_json::Value>) {
    use crate::redaction::{is_secret_field_name, REDACTED};
    for (name, field) in map.iter_mut() {
        if is_secret_field_name(name) && !field.is_null() {
            *field = serde_json::Value::String(REDACTED.to_string());
        } else {
            scrub_sentry_value(field);
        }
    }
}

/// Defence in depth for the Sentry path: every free-text and structured field
/// of an event goes through the shared redaction module before it leaves the
/// process. The log writers already scrub what they write, but the
/// sentry_tracing layer builds its event from the raw tracing record.
pub(crate) fn scrub_sentry_event(
    mut event: sentry::protocol::Event<'static>,
) -> sentry::protocol::Event<'static> {
    use crate::redaction::redact_log_line;
    let scrub = |text: &mut String| {
        let scrubbed = redact_log_line(text);
        if scrubbed != *text {
            *text = scrubbed;
        }
    };
    if let Some(message) = event.message.as_mut() {
        scrub(message);
    }
    if let Some(logentry) = event.logentry.as_mut() {
        scrub(&mut logentry.message);
        logentry.params.iter_mut().for_each(scrub_sentry_value);
    }
    if let Some(culprit) = event.culprit.as_mut() {
        scrub(culprit);
    }
    if let Some(transaction) = event.transaction.as_mut() {
        scrub(transaction);
    }
    for exception in event.exception.values.iter_mut() {
        if let Some(value) = exception.value.as_mut() {
            scrub(value);
        }
    }
    for breadcrumb in event.breadcrumbs.values.iter_mut() {
        if let Some(message) = breadcrumb.message.as_mut() {
            scrub(message);
        }
        scrub_sentry_map(&mut breadcrumb.data);
    }
    scrub_sentry_map(&mut event.extra);
    for value in event.tags.values_mut() {
        scrub(value);
    }
    for context in event.contexts.values_mut() {
        if let sentry::protocol::Context::Other(map) = context {
            scrub_sentry_map(map);
        }
    }
    event
}

fn init_sentry(url: &str, release: &str) {
    let release = release.to_string();
    let sentry_guard = sentry::init((
        url,
        sentry::ClientOptions {
            release: if release.is_empty() {
                sentry::release_name!()
            } else {
                Some(release.into())
            },
            traces_sample_rate: 0.2,
            before_send: Some(Arc::new(|event| {
                // Scrub before anything else: an ERROR log can carry an LLM
                // provider's error body or a credential-bearing argument, and
                // the sentry_tracing layer sees the raw event, not the
                // sanitized writer output. Always on, debug builds included.
                let event = scrub_sentry_event(event);
                let fp = sentry_event_fingerprint(&event);
                if sentry_event_is_repeat(fp, Instant::now()) {
                    return None;
                }
                Some(event)
            })),
            ..Default::default()
        },
    ));

    if !sentry_guard.is_enabled() {
        eprintln!("Sentry initialization failed");
    }

    forget(sentry_guard);
}

/// Serializes `init_logger`: the first call sets everything up while any
/// concurrent call waits, and every later call only flushes the ring.
static LOGGER_INIT: Once = Once::new();

pub fn init_logger(
    executable_type: &str,
    url: &str,
    release: &str,
    provided_env_log_spec: &str,
    sentry_error_filter: &[&str],
) {
    let mut initialized_now = false;
    // `call_once_force`: an initialization that panicked is run again by
    // the next call instead of poisoning every later one.
    LOGGER_INIT.call_once_force(|_| {
        initialized_now = true;
        init_logger_once(
            executable_type,
            url,
            release,
            provided_env_log_spec,
            sentry_error_filter,
        );
    });
    if !initialized_now {
        eprintln!("Logger already initialized, flushing logs");
        if let Some(logger) = LOGGER.get() {
            logger.flush_logs();
        }
    }
}

fn init_logger_once(
    executable_type: &str,
    url: &str,
    release: &str,
    provided_env_log_spec: &str,
    sentry_error_filter: &[&str],
) {
    let logger = LOGGER.get_or_init(|| Arc::new(Logger::new()));

    // Store executable type for panic handler
    let _ = EXECUTABLE_TYPE.set(executable_type.to_string());

    // Force backtrace
    std::env::set_var("RUST_BACKTRACE", "1");

    // Set a panic hook that logs to tracing and stderr (only once to avoid replacement)
    PANIC_HOOK_INIT.call_once(|| {
        std::panic::set_hook(Box::new(|panic_info| {
            let payload = panic_info.payload();
            let msg = if let Some(s) = payload.downcast_ref::<&str>() {
                *s
            } else if let Some(s) = payload.downcast_ref::<String>() {
                s.as_str()
            } else {
                "Box<Any>"
            };
            let location = panic_info
                .location()
                .map(|l| l.to_string())
                .unwrap_or_else(|| "unknown location".to_string());
            let backtrace = std::backtrace::Backtrace::force_capture();

            // Create panic artifact file
            let executable_type = EXECUTABLE_TYPE
                .get()
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            create_panic_artifact(&executable_type, msg, &location, &backtrace);

            // Log to stderr first (safer, less likely to panic)
            eprintln!("PANIC: {} at {}\nBacktrace:\n{}", msg, location, backtrace);

            // Then try to log through tracing (could potentially panic)
            use tracing::error;
            let _ = std::panic::catch_unwind(|| {
                error!(
                    "panic occurred: {} at {}\nBacktrace:\n{}",
                    msg, location, backtrace
                );
            });
        }));
    });

    if !url.is_empty() {
        init_sentry(url, release);
    }

    let default_log_spec = "info";
    // Set the default log level from the environment variable if provided
    let mut env_log_spec = var("EDAMAME_LOG_LEVEL").unwrap_or(default_log_spec.to_string());
    // Add the provided log level to the env variable log level
    env_log_spec.push_str(format!(",{}", provided_env_log_spec).as_str());

    // Set filter. A malformed `EDAMAME_LOG_LEVEL` (operator-supplied) must NOT
    // abort daemon startup, so fall back to the always-valid default directive
    // on a parse error instead of unwrapping.
    let filter_layer = EnvFilter::try_new(&env_log_spec).unwrap_or_else(|e| {
        eprintln!(
            "EDAMAME_LOG_LEVEL filter '{}' is invalid ({}); falling back to '{}'",
            env_log_spec, e, default_log_spec
        );
        EnvFilter::new(default_log_spec)
    });

    // Check if we are installed in /usr or /opt
    let exe_path = current_exe().unwrap_or_else(|_| PathBuf::from(""));
    let exe_path_str = exe_path.to_str().unwrap_or("");
    let is_installed = exe_path_str.starts_with("/usr") || exe_path_str.starts_with("/opt/");

    // Optional file writer
    // Duplicate to file for daemons (helper + posture) on all platforms,
    // edamame_cli (when not installed in /usr or /opt), and all executables on Windows.
    let (file_writer, file_guard) = if matches!(executable_type, "helper" | "posture")
        || (matches!(executable_type, "cli") && !is_installed)
        || (cfg!(target_os = "windows"))
    {
        let log_dir = if matches!(executable_type, "helper" | "posture") {
            if cfg!(unix) {
                let preferred = PathBuf::from("/var/log/edamame");
                if create_dir_all(&preferred).is_ok() {
                    preferred
                } else {
                    let exe_path: PathBuf = current_exe().expect("Failed to get current exe");
                    exe_path
                        .parent()
                        .expect("Failed to get parent of current exe")
                        .to_path_buf()
                }
            } else {
                let exe_path: PathBuf = current_exe().expect("Failed to get current exe");
                exe_path
                    .parent()
                    .expect("Failed to get parent of current exe")
                    .to_path_buf()
            }
        } else if matches!(executable_type, "cli") {
            let exe_path: PathBuf = current_exe().expect("Failed to get current exe");
            exe_path
                .parent()
                .expect("Failed to get parent of current exe")
                .to_path_buf()
        } else {
            // Windows app
            let appdata = var("APPDATA").expect("Failed to get APPDATA");
            let appdata_path = format!("{}/com.edamametech/EDAMAME Security", appdata);
            create_dir_all(&appdata_path).expect("Failed to create directory");
            PathBuf::from(appdata_path)
        };
        let basename = if matches!(executable_type, "helper") {
            "edamame_helper"
        } else if matches!(executable_type, "posture") {
            "edamame_posture"
        } else if matches!(executable_type, "cli") {
            "edamame_cli"
        } else {
            "edamame"
        };
        // Add the PID to the basename
        let pid = std::process::id();
        prune_stale_logs(&log_dir, basename, pid);
        let basename = format!("{}_{}", basename, pid);
        match RollingFileAppender::builder()
            .rotation(Rotation::DAILY)
            .filename_prefix(basename)
            .max_log_files(7)
            .build(log_dir.clone())
        {
            Ok(file_appender) => tracing_appender::non_blocking(file_appender),
            Err(e) => {
                eprintln!(
                    "Warning: Failed to initialize rolling file appender in {}: {}. File logging disabled.",
                    log_dir.display(),
                    e
                );
                NonBlocking::new(io::sink())
            }
        }
    } else {
        NonBlocking::new(io::sink())
    };

    // Suppress stdout for non-verbose daemons and CLI (they use rolling files or are silent).
    // Verbose types (posture_verbose, cli_verbose, app) emit to stdout for
    // service managers (systemd/OpenRC journal) or interactive use.
    let (stdout_writer, stdout_guard) = if matches!(executable_type, "cli" | "helper" | "posture") {
        NonBlocking::new(io::sink())
    } else {
        NonBlocking::new(io::stdout())
    };

    let file_make_writer = SanitizingMakeWriter::new(file_writer);
    let stdout_make_writer = SanitizingMakeWriter::new(stdout_writer);

    // Register the proper layers based on sentry availability and platform
    if !url.is_empty() {
        let filter_strings: Vec<String> =
            sentry_error_filter.iter().map(|&s| s.to_string()).collect();
        let sentry_layer = sentry_tracing::layer().event_filter(move |md| {
            if let &Level::ERROR = md.level() {
                if filter_strings
                    .iter()
                    .any(|s| md.target().contains(s) || md.name().contains(s))
                {
                    EventFilter::Ignore
                } else {
                    EventFilter::Event
                }
            } else {
                EventFilter::Ignore
            }
        });
        if cfg!(target_os = "macos") || cfg!(target_os = "ios") {
            #[cfg(any(target_os = "ios", target_os = "macos"))]
            {
                if !matches!(executable_type, "helper") && !matches!(executable_type, "cli") {
                    #[cfg(feature = "tokio-console")]
                    match tracing_subscriber::registry()
                        .with(filter_layer)
                        .with(fmt::layer().with_writer(file_make_writer.clone()))
                        .with(fmt::layer().with_writer(logger.memory_writer.clone()))
                        .with(sentry_layer)
                        // Must be here when using sentry
                        .with(fmt::layer().with_writer(stdout_make_writer.clone()))
                        .with(console_subscriber::spawn())
                        .try_init()
                    {
                        Ok(_) => {}
                        Err(e) => eprintln!("Logger initialization failed: {}", e),
                    }
                    #[cfg(not(feature = "tokio-console"))]
                    match tracing_subscriber::registry()
                        .with(filter_layer)
                        .with(fmt::layer().with_writer(file_make_writer.clone()))
                        .with(fmt::layer().with_writer(logger.memory_writer.clone()))
                        .with(sentry_layer)
                        // Must be here when using sentry
                        .with(fmt::layer().with_writer(stdout_make_writer.clone()))
                        .try_init()
                    {
                        Ok(_) => {}
                        Err(e) => eprintln!("Logger initialization failed: {}", e),
                    }
                } else {
                    // Tokio Console
                    #[cfg(feature = "tokio-console")]
                    match tracing_subscriber::registry()
                        .with(filter_layer)
                        .with(fmt::layer().with_writer(file_make_writer.clone()))
                        .with(fmt::layer().with_writer(logger.memory_writer.clone()))
                        .with(sentry_layer)
                        // Must be here when using sentry
                        .with(fmt::layer().with_writer(stdout_make_writer.clone()))
                        // Use console layer for edamame_helper
                        .with(console_subscriber::spawn())
                        .try_init()
                    {
                        Ok(_) => {}
                        Err(e) => {
                            eprintln!("Logger initialization with tokio console failed: {}", e)
                        }
                    }
                    #[cfg(not(feature = "tokio-console"))]
                    match tracing_subscriber::registry()
                        .with(filter_layer)
                        .with(fmt::layer().with_writer(file_make_writer.clone()))
                        .with(fmt::layer().with_writer(logger.memory_writer.clone()))
                        .with(sentry_layer)
                        // Must be here when using sentry
                        .with(fmt::layer().with_writer(stdout_make_writer.clone()))
                        .try_init()
                    {
                        Ok(_) => {}
                        Err(e) => eprintln!("Logger initialization failed: {}", e),
                    }
                }
            }
        } else if cfg!(target_os = "android") {
            #[cfg(target_os = "android")]
            {
                let android_layer = tracing_android::layer("edamametech.edamame").unwrap();

                match tracing_subscriber::registry()
                    .with(filter_layer)
                    .with(fmt::layer().with_writer(stdout_make_writer.clone()))
                    .with(fmt::layer().with_writer(logger.memory_writer.clone()))
                    .with(sentry_layer)
                    .with(android_layer)
                    .try_init()
                {
                    Ok(_) => {}
                    Err(e) => eprintln!("Logger initialization failed: {}", e),
                }
            }
        } else if cfg!(target_os = "windows") {
            // Windows
            match tracing_subscriber::registry()
                .with(filter_layer)
                .with(fmt::layer().with_writer(file_make_writer.clone()))
                .with(fmt::layer().with_writer(logger.memory_writer.clone()))
                .with(sentry_layer)
                // Must be here when using sentry
                .with(fmt::layer().with_writer(stdout_make_writer.clone()))
                .try_init()
            {
                Ok(_) => {}
                Err(e) => eprintln!("Logger initialization failed: {}", e),
            }
        } else {
            // Linux
            match tracing_subscriber::registry()
                .with(filter_layer)
                .with(fmt::layer().with_writer(file_make_writer.clone()))
                .with(fmt::layer().with_writer(logger.memory_writer.clone()))
                .with(sentry_layer)
                // Must be here when using sentry
                .with(fmt::layer().with_writer(stdout_make_writer.clone()))
                .try_init()
            {
                Ok(_) => {}
                Err(e) => eprintln!("Logger initialization failed: {}", e),
            }
        }
    } else {
        // Without sentry
        if cfg!(target_os = "macos") || cfg!(target_os = "ios") {
            #[cfg(any(target_os = "ios", target_os = "macos"))]
            {
                if !matches!(executable_type, "helper") && !matches!(executable_type, "cli") {
                    match tracing_subscriber::registry()
                        .with(filter_layer)
                        .with(fmt::layer().with_writer(stdout_make_writer.clone()))
                        .with(fmt::layer().with_writer(file_make_writer.clone()))
                        .with(fmt::layer().with_writer(logger.memory_writer.clone()))
                        .try_init()
                    {
                        Ok(_) => {}
                        Err(e) => eprintln!("Logger initialization failed: {}", e),
                    }
                } else {
                    match tracing_subscriber::registry()
                        .with(filter_layer)
                        .with(fmt::layer().with_writer(stdout_make_writer.clone()))
                        .with(fmt::layer().with_writer(file_make_writer.clone()))
                        .with(fmt::layer().with_writer(logger.memory_writer.clone()))
                        .try_init()
                    {
                        Ok(_) => {}
                        Err(e) => eprintln!("Logger initialization failed: {}", e),
                    }
                }
            }
        } else if cfg!(target_os = "android") {
            #[cfg(target_os = "android")]
            {
                let android_layer = tracing_android::layer("edamametech.edamame").unwrap();

                match tracing_subscriber::registry()
                    .with(filter_layer)
                    .with(fmt::layer().with_writer(stdout_make_writer.clone()))
                    .with(fmt::layer().with_writer(logger.memory_writer.clone()))
                    .with(android_layer)
                    .try_init()
                {
                    Ok(_) => {}
                    Err(e) => eprintln!("Logger initialization failed: {}", e),
                }
            }
        } else if cfg!(target_os = "windows") {
            // Windows
            match tracing_subscriber::registry()
                .with(filter_layer)
                .with(fmt::layer().with_writer(stdout_make_writer.clone()))
                .with(fmt::layer().with_writer(file_make_writer.clone()))
                .with(fmt::layer().with_writer(logger.memory_writer.clone()))
                .try_init()
            {
                Ok(_) => {}
                Err(e) => eprintln!("Logger initialization failed: {}", e),
            }
        } else {
            // Linux
            match tracing_subscriber::registry()
                .with(filter_layer)
                .with(fmt::layer().with_writer(stdout_make_writer.clone()))
                .with(fmt::layer().with_writer(file_make_writer.clone()))
                .with(fmt::layer().with_writer(logger.memory_writer.clone()))
                .try_init()
            {
                Ok(_) => {}
                Err(e) => eprintln!("Logger initialization failed: {}", e),
            }
        }
    }

    forget(stdout_guard);
    forget(file_guard);
}

pub fn get_new_logs() -> String {
    LOGGER
        .get()
        .map(|logger| logger.get_new_logs())
        .unwrap_or_default()
}

pub fn get_all_logs() -> String {
    LOGGER
        .get()
        .map(|logger| logger.get_all_logs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::{debug, error, info, trace, warn};

    #[test]
    fn test_prune_stale_logs() {
        use std::fs::{self, FileTimes};

        let dir = std::env::temp_dir().join(format!("edamame_prune_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let stale = SystemTime::now() - Duration::from_secs((LOG_RETENTION_DAYS + 1) * 86_400);
        let write = |name: &str, aged: bool| {
            let path = dir.join(name);
            let file = File::create(&path).unwrap();
            if aged {
                file.set_times(FileTimes::new().set_modified(stale))
                    .unwrap();
            }
            path
        };

        let old = write("edamame_posture_111.2026-01-01", true);
        let recent = write("edamame_posture_222.2026-07-27", false);
        let mine = write(&format!("edamame_posture_{}.2026-01-01", 999), true);
        // A different executable type sharing the directory, and a name whose
        // segment after the stem is not a PID: neither is ours to delete.
        let other_stem = write("edamame_helper_333.2026-01-01", true);
        let not_a_pid = write("edamame_posture_backup.2026-01-01", true);

        prune_stale_logs(&dir, "edamame_posture", 999);

        assert!(!old.exists(), "aged log of a dead PID should be pruned");
        assert!(recent.exists(), "log inside the retention window must stay");
        assert!(
            mine.exists(),
            "the current PID's own log must never be pruned"
        );
        assert!(
            other_stem.exists(),
            "another executable type must be left alone"
        );
        assert!(
            not_a_pid.exists(),
            "non-PID segment must not match the stem"
        );

        // The "edamame" stem must not sweep the longer "edamame_posture_*"
        // names that share its prefix.
        prune_stale_logs(&dir, "edamame", 0);
        assert!(
            not_a_pid.exists() && other_stem.exists(),
            "shorter stem must not cross-match longer executable names"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_logger_functionality() {
        // Initialize logger
        init_logger("cli", "", "", "", &[]);

        // Test MemoryWriter initialization
        let writer = MemoryWriter::new();
        assert!(writer.data.is_empty());

        // Test log storage in memory writer
        {
            let logger = LOGGER.get().expect("logger initialized");

            let log_line = "This is a test log";
            logger.memory_writer.handle_log(log_line).unwrap();

            let lines = logger.memory_writer.data.all();
            assert!(lines.iter().any(|line| line.contains("This is a test log")));
        }

        // Test get_new_logs
        info!("New log entry");

        let log_data = get_new_logs();
        assert!(!log_data.is_empty());
        assert!(log_data.contains("New log entry"));

        // Step 6: Test get_all_logs
        info!("First log entry");
        info!("Second log entry");

        let log_data = get_all_logs();
        assert!(log_data.contains("First log entry"));
        assert!(log_data.contains("Second log entry"));

        // Step 7: Test log levels
        info!("This is an info log");
        error!("This is an error log");
        warn!("This is a warn log");
        debug!("This is a debug log");
        trace!("This is a trace log");

        let log_data = get_all_logs();
        assert!(log_data.contains("This is an info log"));
        assert!(log_data.contains("This is an error log"));
        assert!(log_data.contains("This is a warn log"));
        // Note: Depending on the log level set, debug and trace logs may not be captured
    }

    #[test]
    fn test_sanitize_keywords() {
        let test_log = r#"{"id": "12345", "password": "secret"}"#;
        let sanitized_log = sanitize_keywords(test_log, &["id", "password"]);
        assert_eq!(sanitized_log, r#"{"id": "*****", "password": "******"}"#);
    }

    #[test]
    fn test_sanitize_keywords_masks_compound_secret_names() {
        let log = r#"{"edamame_api_key": "edm_abc123", "mcp_psk": "0123456789abcdef", "oauth_refresh_token": "rt-xyz", "client_secret": "s3"}"#;
        let sanitized = sanitize_keywords(log, &[]);
        for secret in ["edm_abc123", "0123456789abcdef", "rt-xyz", "\"s3\""] {
            assert!(!sanitized.contains(secret), "{secret} leaked: {sanitized}");
        }
        assert!(
            sanitized.contains(r#""edamame_api_key": "**********""#),
            "{sanitized}"
        );
    }

    #[test]
    fn test_sanitize_keywords_masks_json_escaped_values() {
        let log = r#"args: ["{\"pin\":\"123456\",\"api_key\":\"edm_secret\"}"]"#;
        let sanitized = sanitize_keywords(log, &[]);
        assert!(!sanitized.contains("123456"), "{sanitized}");
        assert!(!sanitized.contains("edm_secret"), "{sanitized}");
        assert!(sanitized.contains(r#"\"pin\":\"******\""#), "{sanitized}");
    }

    #[test]
    fn test_sanitize_keywords_masks_plain_values() {
        let log = r#"{"password": "hunter2", "client_secret": "p\"w", "user": "bob"}"#;
        assert_eq!(
            sanitize_keywords(log, &[]),
            r#"{"password": "*******", "client_secret": "****", "user": "bob"}"#
        );
    }

    #[test]
    fn test_sanitize_keywords_masks_values_holding_a_backslash() {
        // A JSON-escaped backslash, then a lone one.
        let log = r#"{"password": "a\\b", "user": "bob"} password: "c\d""#;
        assert_eq!(
            sanitize_keywords(log, &[]),
            r#"{"password": "****", "user": "bob"} password: "***""#
        );
        // A bare value keeps everything after its backslash masked too.
        assert_eq!(
            sanitize_keywords(r#"login password=abc\def user=bob"#, &[]),
            r#"login password=******* user=bob"#
        );
    }

    #[test]
    fn test_sanitize_keywords_masks_a_pem_value_whole() {
        let pem =
            r#"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0B\n-----END PRIVATE KEY-----\n"#;
        let log = format!(r#"{{"private_key": "{pem}", "kid": "k1"}}"#);
        let sanitized = sanitize_keywords(&log, &[]);
        // The PEM shape goes first, then the named field masks what is left
        // of the value: nothing of the key survives, the neighbour does.
        assert!(!sanitized.contains("MIIE"), "{sanitized}");
        assert!(!sanitized.contains("BEGIN"), "{sanitized}");
        assert!(sanitized.ends_with(r#"", "kid": "k1"}"#), "{sanitized}");
        let value = sanitized
            .strip_prefix(r#"{"private_key": ""#)
            .and_then(|rest| rest.split('"').next())
            .unwrap();
        assert!(
            !value.is_empty() && value.chars().all(|c| c == '*'),
            "{sanitized}"
        );
    }

    #[test]
    fn test_sanitize_keywords_masks_json_escaped_values_holding_escapes() {
        // `{"pin":..,"private_key":"<PEM>","password":"a\\b\"c"}` logged
        // through Debug: every escape inside a value arrives doubled.
        let pem = r#"-----BEGIN KEY-----\\nMIIEsecret\\n-----END KEY-----\\n"#;
        let password = r#"a\\\\b\\\"c"#;
        let log = format!(
            r#"args: ["{{\"pin\":\"123456\",\"private_key\":\"{pem}\",\"password\":\"{password}\"}}"]"#
        );
        assert_eq!(
            sanitize_keywords(&log, &[]),
            format!(
                r#"args: ["{{\"pin\":\"******\",\"private_key\":\"{}\",\"password\":\"{}\"}}"]"#,
                "*".repeat(pem.len()),
                "*".repeat(password.len())
            )
        );
    }

    #[test]
    fn test_sanitize_keywords_keeps_debugging_keys_and_counts() {
        let log = r#"{"finding_key": "vuln:abc", "session_id": "s-1", "input_tokens": 1200} LLM decision: allow (tokens: 1200/80)"#;
        assert_eq!(sanitize_keywords(log, &[]), log);
    }

    #[test]
    fn sentry_events_are_scrubbed_before_they_leave() {
        use sentry::protocol::{Breadcrumb, Context, Event, Exception, LogEntry, Map};
        let mut event = Event::default();
        event.message = Some(
            "LLM error: 401 {\"error\":\"invalid x-api-key sk-ant-api03-AAAAAAAAAAAAAAAAAAAA\"}"
                .into(),
        );
        event.logentry = Some(LogEntry {
            message: "Connected with pin: 123456".into(),
            params: vec![serde_json::json!("Bearer abcdefghijklmnop")],
        });
        event.exception.values.push(Exception {
            ty: "Error".into(),
            value: Some("edamame_api_key=edm_live_0123456789abcdef".into()),
            ..Default::default()
        });
        let mut data = Map::new();
        data.insert("api_key".to_string(), serde_json::json!("plain-secret"));
        event.breadcrumbs.values.push(Breadcrumb {
            message: Some("token=ghp_0123456789abcdefghij0123".into()),
            data,
            ..Default::default()
        });
        event
            .extra
            .insert("oauth_refresh_token".into(), serde_json::json!("rt-secret"));
        event.extra.insert(
            "note".into(),
            serde_json::json!("key xoxb-1234567890-abcdefghij"),
        );
        let mut other = Map::new();
        other.insert("password".to_string(), serde_json::json!("hunter2"));
        event
            .contexts
            .insert("fields".into(), Context::Other(other));

        let scrubbed = scrub_sentry_event(event);
        // The scrubbed surfaces only: event_id / timestamp are random digits.
        let serialized = serde_json::to_string(&(
            &scrubbed.message,
            &scrubbed.logentry,
            &scrubbed.exception,
            &scrubbed.breadcrumbs,
            &scrubbed.extra,
            &scrubbed.contexts,
        ))
        .unwrap();
        for secret in [
            "sk-ant-api03",
            "123456",
            "abcdefghijklmnop",
            "edm_live_0123",
            "plain-secret",
            "ghp_0123",
            "rt-secret",
            "xoxb-",
            "hunter2",
        ] {
            assert!(
                !serialized.contains(secret),
                "{secret} leaked: {serialized}"
            );
        }
        assert!(serialized.contains("LLM error: 401"), "{serialized}");
    }

    #[test]
    fn test_panic_artifact_creation() {
        use std::fs;

        let test_msg = "Test panic message";
        let test_location = "test_file.rs:123:45";
        let test_backtrace = std::backtrace::Backtrace::force_capture();

        // Test the panic artifact creation function directly
        create_panic_artifact("test", test_msg, test_location, &test_backtrace);

        // The panic artifact will be created in the test executable's directory
        let exe_path = current_exe().unwrap();
        let exe_dir = exe_path.parent().unwrap();
        let entries = fs::read_dir(exe_dir).unwrap();

        let mut found_panic_file = false;
        for entry in entries {
            if let Ok(entry) = entry {
                let filename = entry.file_name();
                let filename_str = filename.to_string_lossy();
                if filename_str.starts_with("test_panic_") && filename_str.ends_with(".txt") {
                    found_panic_file = true;

                    // Verify file contents
                    let content = fs::read_to_string(entry.path()).unwrap();
                    assert!(content.contains("PANIC REPORT"));
                    assert!(content.contains("Test panic message"));
                    assert!(content.contains("test_file.rs:123:45"));
                    assert!(content.contains("BACKTRACE"));
                    assert!(content.contains("Type: test"));

                    // Clean up the test file
                    let _ = fs::remove_file(entry.path());
                    break;
                }
            }
        }

        assert!(
            found_panic_file,
            "Panic artifact file was not created in {:?}",
            exe_dir
        );
    }
}
