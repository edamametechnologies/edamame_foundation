use dashmap::iter::{Iter as DashIter, IterMut as DashIterMut};
use dashmap::DashMap;
use once_cell::sync::Lazy;
use std::any::type_name;
use std::backtrace::Backtrace;
use std::borrow::Borrow;
use std::fmt::Debug;
use std::hash::Hash;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Once};
use std::thread::ThreadId;
use std::time::Duration;
use std::time::Instant;
use tokio::sync::RwLock;
use tokio::time;
use tracing::{debug, error, warn};

// Bring in caller location utilities. `Location` is always available, while
// `tracing::Instrument` is only needed when the `tokio-console` feature is
// enabled.
use std::panic::Location;
#[cfg(feature = "tokio-console")]
use tracing::Instrument;

// Define constants for timeouts and warning thresholds
const DEFAULT_RWLOCK_READ_WARNING_SECS: u64 = 10;
const DEFAULT_RWLOCK_WRITE_WARNING_SECS: u64 = 15;
const DEFAULT_DASHMAP_OP_WARNING_SECS: u64 = 1;
const DEFAULT_DASHMAP_WRITE_LOCK_TIMEOUT_SECS: u64 = 10;
const DEFAULT_LOCK_WAIT_SLEEP_MILLIS: u64 = 10;
const RW_WRITE_LOCK_KEY: &str = "__WRITE__";

// Unique counter for iterator tracking keys
static ITER_ID_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Information stored for each active write lock
#[derive(Debug)]
struct LockInfo {
    backtrace: Backtrace,
    started_at: Instant,
    thread_id: ThreadId,
    timeout_logged: AtomicBool,
}

impl Clone for LockInfo {
    fn clone(&self) -> Self {
        Self {
            backtrace: Backtrace::force_capture(),
            started_at: self.started_at,
            thread_id: self.thread_id,
            timeout_logged: AtomicBool::new(self.timeout_logged.load(Ordering::SeqCst)),
        }
    }
}

#[derive(Debug, Default)]
pub struct CustomRwLock<T> {
    name: String,
    lock: RwLock<T>,
    #[cfg(debug_assertions)]
    write_locked: AtomicBool,
    #[cfg(debug_assertions)]
    read_waiting_count: AtomicUsize,
    #[cfg(debug_assertions)]
    write_lock_info: DashMap<String, LockInfo>,
    #[cfg(debug_assertions)]
    waiters: DashMap<ThreadId, String>,
}

impl<T> CustomRwLock<T> {
    pub fn new(data: T) -> Self {
        Self {
            name: type_name::<T>().to_string(),
            lock: RwLock::new(data),
            #[cfg(debug_assertions)]
            write_locked: AtomicBool::new(false),
            #[cfg(debug_assertions)]
            read_waiting_count: AtomicUsize::new(0),
            #[cfg(debug_assertions)]
            write_lock_info: DashMap::new(),
            #[cfg(debug_assertions)]
            waiters: DashMap::new(),
        }
    }

    #[track_caller]
    pub fn read(
        &self,
    ) -> impl std::future::Future<Output = tokio::sync::RwLockReadGuard<'_, T>> + '_ {
        // Capture the caller's location once, outside of the async block. The
        // `#[track_caller]` attribute on this sync wrapper ensures that this
        // location reflects the exterior call-site.
        let _loc = Location::caller();

        async move {
            // Create a tracing span carrying the caller info (only when the
            // `tokio-console` feature is active).
            #[cfg(feature = "tokio-console")]
            let span = tracing::trace_span!(
                "CustomRwLock::read",
                lock_name = %self.name,
                caller_file = _loc.file(),
                caller_line = _loc.line()
            );

            #[cfg(debug_assertions)]
            let start = Instant::now();

            #[cfg(debug_assertions)]
            let current_thread = std::thread::current().id();

            #[cfg(debug_assertions)]
            if self.write_locked.load(Ordering::SeqCst) {
                self.waiters.insert(current_thread, "read".to_string());
            }

            #[cfg(debug_assertions)]
            if self.write_locked.load(Ordering::SeqCst) {
                self.read_waiting_count.fetch_add(1, Ordering::SeqCst);
                debug!(
                    "Read lock '{}' is waiting for a write lock to be released",
                    self.name
                );
            }

            // Await the underlying lock, instrumented with the span when
            // available.
            let guard = {
                #[cfg(debug_assertions)]
                {
                    loop {
                        let fut = {
                            #[cfg(feature = "tokio-console")]
                            {
                                self.lock.read().instrument(span)
                            }
                            #[cfg(not(feature = "tokio-console"))]
                            {
                                self.lock.read()
                            }
                        };
                        match time::timeout(
                            Duration::from_secs(DEFAULT_RWLOCK_READ_WARNING_SECS),
                            fut,
                        )
                        .await
                        {
                            Ok(g) => break g,
                            Err(_) => {
                                self.dump_lock_state();
                                error!("Read lock '{}' could not be acquired within {}s (continuing to wait)", self.name, DEFAULT_RWLOCK_READ_WARNING_SECS);
                            }
                        }
                    }
                }

                #[cfg(not(debug_assertions))]
                {
                    #[cfg(feature = "tokio-console")]
                    {
                        self.lock.read().instrument(span).await
                    }
                    #[cfg(not(feature = "tokio-console"))]
                    {
                        self.lock.read().await
                    }
                }
            };

            #[cfg(debug_assertions)]
            {
                if self.write_locked.load(Ordering::SeqCst) {
                    self.read_waiting_count.fetch_sub(1, Ordering::SeqCst);
                    self.waiters.remove(&current_thread);
                }
                // Check if the read lock took too long
                let duration = start.elapsed();
                if duration.as_secs() > DEFAULT_RWLOCK_READ_WARNING_SECS {
                    error!(
                        "Read lock '{}' took too long to acquire: {:?} seconds",
                        self.name, duration
                    );
                }
            }

            guard
        }
    }

    #[track_caller]
    pub fn write(&self) -> impl std::future::Future<Output = CustomRwLockWriteGuard<'_, T>> + '_ {
        let _loc = Location::caller();

        async move {
            // Build the tracing span when tokio-console is enabled.
            #[cfg(feature = "tokio-console")]
            let span = tracing::trace_span!(
                "CustomRwLock::write",
                lock_name = %self.name,
                caller_file = _loc.file(),
                caller_line = _loc.line()
            );

            #[cfg(debug_assertions)]
            let start = Instant::now();

            #[cfg(debug_assertions)]
            let current_thread = std::thread::current().id();

            #[cfg(debug_assertions)]
            {
                self.waiters.insert(current_thread, "write".to_string());
                if self.write_locked.load(Ordering::SeqCst) {
                    let bt = Backtrace::force_capture();
                    let bt_str = format!("{:?}", bt);

                    // First pass: skip frames from customlock.rs itself
                    let mut frames = extract_useful_frames(&bt_str, true);

                    // Fallback: include customlock.rs if nothing found yet
                    if frames.is_empty() {
                        frames = extract_useful_frames(&bt_str, false);
                    }

                    let frame_msg = if frames.is_empty() {
                        "from unknown source".to_string()
                    } else {
                        format!("from:\n{}", frames.join("\n"))
                    };

                    debug!(
                        "Attempted to acquire write lock for '{}' while another write lock is already active - {}",
                        self.name, frame_msg
                    );
                }

                self.write_locked.store(true, Ordering::SeqCst);
                self.write_lock_info.insert(
                    RW_WRITE_LOCK_KEY.to_string(),
                    LockInfo {
                        backtrace: Backtrace::force_capture(),
                        started_at: Instant::now(),
                        thread_id: current_thread,
                        timeout_logged: AtomicBool::new(false),
                    },
                );
            }

            // Await the underlying write lock, with timeout.
            let guard = {
                #[cfg(debug_assertions)]
                {
                    loop {
                        let fut = {
                            #[cfg(feature = "tokio-console")]
                            {
                                self.lock.write().instrument(span)
                            }
                            #[cfg(not(feature = "tokio-console"))]
                            {
                                self.lock.write()
                            }
                        };
                        match time::timeout(
                            Duration::from_secs(DEFAULT_RWLOCK_WRITE_WARNING_SECS),
                            fut,
                        )
                        .await
                        {
                            Ok(g) => break g,
                            Err(_) => {
                                self.dump_lock_state();
                                error!("Write lock '{}' could not be acquired within {}s (continuing to wait)", self.name, DEFAULT_RWLOCK_WRITE_WARNING_SECS);
                            }
                        }
                    }
                }

                #[cfg(not(debug_assertions))]
                {
                    #[cfg(feature = "tokio-console")]
                    {
                        self.lock.write().instrument(span).await
                    }
                    #[cfg(not(feature = "tokio-console"))]
                    {
                        self.lock.write().await
                    }
                }
            };

            #[cfg(debug_assertions)]
            {
                self.write_locked.store(false, Ordering::SeqCst);
                self.write_lock_info.remove(RW_WRITE_LOCK_KEY);
                self.waiters.remove(&current_thread);
                // Check if the write lock took too long
                let duration = start.elapsed();
                if duration.as_secs() > DEFAULT_RWLOCK_WRITE_WARNING_SECS {
                    error!(
                        "Write lock '{}' took too long to acquire: {:?} seconds",
                        self.name, duration
                    );
                }
            }

            CustomRwLockWriteGuard {
                inner: guard,
                parent: self,
            }
        }
    }

    pub fn read_waiting(&self) -> usize {
        #[cfg(debug_assertions)]
        {
            self.read_waiting_count.load(Ordering::SeqCst)
        }
        #[cfg(not(debug_assertions))]
        {
            0
        }
    }

    /// Dumps current state (write lock info + waiters) for diagnostics
    pub fn dump_lock_state(&self) {
        #[cfg(debug_assertions)]
        {
            warn!("===== Dumping CustomRwLock '{}' state =====", self.name);
            if let Some(info) = self.write_lock_info.get(RW_WRITE_LOCK_KEY) {
                warn!(
                    "WRITE LOCK held for {:?} by {:?}\nbacktrace:\n{:?}",
                    info.started_at.elapsed(),
                    info.thread_id,
                    info.backtrace
                );
            }
            for waiter in self.waiters.iter() {
                let (thread_id, kind) = waiter.pair();
                warn!("WAITER thread={:?} kind={} ", thread_id, kind);
            }
            warn!("===== End CustomRwLock dump =====");
        }
    }
}

/// Wrapper guard that clears write-lock bookkeeping on drop
pub struct CustomRwLockWriteGuard<'a, T> {
    inner: tokio::sync::RwLockWriteGuard<'a, T>,
    parent: &'a CustomRwLock<T>,
}

impl<'a, T> std::ops::Deref for CustomRwLockWriteGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'a, T> std::ops::DerefMut for CustomRwLockWriteGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<'a, T> Drop for CustomRwLockWriteGuard<'a, T> {
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        {
            self.parent.write_locked.store(false, Ordering::SeqCst);
            self.parent.write_lock_info.remove(RW_WRITE_LOCK_KEY);
        }
    }
}

/// Utility: extract up to two relevant frames from a Debug-formatted Backtrace string
fn extract_useful_frames(bt_str: &str, skip_customlock: bool) -> Vec<String> {
    let mut frames = Vec::new();

    // The Debug representation is a single line like:
    // Backtrace [{ fn: "fn_name", file: "path", line: 123 }, { fn: "...", ... }]
    // We split on "}," to iterate each frame regardless of newline placement.
    for seg in bt_str.split("},") {
        // Quick reject if there is no function info
        if let Some(fn_pos) = seg.find("fn: \"") {
            // Extract function name
            let fn_start = fn_pos + 5; // skip "fn: \""
            if let Some(fn_end_rel) = seg[fn_start..].find('\"') {
                let fn_name = &seg[fn_start..fn_start + fn_end_rel];

                // Extract file path if present
                let mut file_path_opt: Option<&str> = None; // Keep track of full path
                let mut file_name_opt: Option<&str> = None;
                let mut line_opt: Option<&str> = None;

                if let Some(file_pos) = seg.find("file: \"") {
                    let file_start = file_pos + 7;
                    if let Some(file_end_rel) = seg[file_start..].find('\"') {
                        let file_path = &seg[file_start..file_start + file_end_rel];
                        file_path_opt = Some(file_path); // Store the full path
                        file_name_opt = Some(file_path.rsplit('/').next().unwrap_or(file_path));

                        // try to get line number after "line: "
                        if let Some(line_pos) = seg[file_end_rel + file_start..].find("line: ") {
                            let line_start_abs = file_start + file_end_rel + line_pos + 6;
                            // read until non-digit
                            let mut line_end_abs = line_start_abs;
                            while line_end_abs < seg.len()
                                && seg.as_bytes()[line_end_abs].is_ascii_digit()
                            {
                                line_end_abs += 1;
                            }
                            line_opt = Some(&seg[line_start_abs..line_end_abs]);
                        }
                    }
                }

                // Filtering: skip obvious system frames
                let mut skip_frame = false;
                if let Some(path) = file_path_opt {
                    // Use the full path
                    if path.contains("rustc")
                        || path.contains(".cargo")
                        // Check path component - more robust than just filename
                        || path.contains("/backtrace/") 
                        || path.contains("\\backtrace\\")
                    // Handle Windows paths too
                    {
                        skip_frame = true;
                    }
                }
                // Check customlock separately using filename
                if !skip_frame && skip_customlock {
                    if let Some(file) = file_name_opt {
                        if file == "customlock.rs" {
                            skip_frame = true;
                        }
                    }
                }

                if skip_frame {
                    continue;
                }

                // Build pretty string
                let formatted = match (file_name_opt, line_opt) {
                    (Some(file), Some(line)) => format!("{}() in {}:{}", fn_name, file, line),
                    (Some(file), None) => format!("{}() in {}", fn_name, file),
                    _ => format!("{}()", fn_name),
                };

                frames.push(formatted);
                if frames.len() >= 2 {
                    break;
                }
            }
        }
    }

    frames
}

/// A wrapper around dashmap::mapref::one::RefMut that releases the write lock on drop.
pub struct CustomRefMut<'a, K, V>
where
    K: Eq + Hash + Debug + Clone,
{
    inner: dashmap::mapref::one::RefMut<'a, K, V>,
    map: &'a CustomDashMap<K, V>,
    key_str: String,
}

impl<'a, K, V> std::ops::Deref for CustomRefMut<'a, K, V>
where
    K: Eq + Hash + Debug + Clone,
{
    type Target = V;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'a, K, V> std::ops::DerefMut for CustomRefMut<'a, K, V>
where
    K: Eq + Hash + Debug + Clone,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<'a, K, V> Drop for CustomRefMut<'a, K, V>
where
    K: Eq + Hash + Debug + Clone,
{
    fn drop(&mut self) {
        self.map.release_write_lock_str(&self.key_str);
    }
}

// Add methods to forward calls to the inner RefMut
impl<'a, K, V> CustomRefMut<'a, K, V>
where
    K: Eq + Hash + Debug + Clone,
{
    #[inline]
    pub fn key(&self) -> &K {
        self.inner.key()
    }

    #[inline]
    pub fn value(&self) -> &V {
        self.inner.value()
    }

    #[inline]
    pub fn value_mut(&mut self) -> &mut V {
        &mut self.inner
    }

    #[inline]
    pub fn pair(&self) -> (&K, &V) {
        self.inner.pair()
    }

    #[inline]
    pub fn pair_mut(&mut self) -> (&K, &mut V) {
        self.inner.pair_mut()
    }
}

// Global registry for all CustomDashMap instances ─────────────────────────────
// Stores (write_locked_keys, timeout_secs) per map-name.
#[cfg(debug_assertions)]
static MONITORED_MAPS: Lazy<DashMap<String, (Arc<DashMap<String, LockInfo>>, u64)>> =
    Lazy::new(|| DashMap::new());
#[cfg(debug_assertions)]
static MONITOR_INIT: Once = Once::new();

#[cfg(debug_assertions)]
fn register_map_for_global_monitor(
    map_name: &str,
    write_locked_keys: Arc<DashMap<String, LockInfo>>,
    timeout_secs: u64,
) {
    MONITORED_MAPS.insert(map_name.to_string(), (write_locked_keys, timeout_secs));

    // Spawn the singleton monitor thread exactly once.
    MONITOR_INIT.call_once(|| {
        std::thread::spawn(|| loop {
            std::thread::sleep(Duration::from_secs(1));
            let now = Instant::now();
            for entry in MONITORED_MAPS.iter() {
                let (map_name, (keys, timeout)) = entry.pair();
                for inner in keys.iter() {
                    let (k, info) = inner.pair();
                    let held = now.duration_since(info.started_at);
                    if held.as_secs() > *timeout {
                        if info
                            .timeout_logged
                            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                            .is_ok()
                        {
                            // Provide actionable context: extract a couple of useful frames
                            let bt_str = format!("{:?}", info.backtrace);
                            let mut frames = extract_useful_frames(&bt_str, true);
                            if frames.is_empty() {
                                frames = extract_useful_frames(&bt_str, false);
                            }
                            let origin = if frames.is_empty() {
                                "unknown".to_string()
                            } else {
                                frames.join(" -> ")
                            };

                            error!(
                                "Write lock for key {} in map '{}' STILL held after {:?} by {:?} originating at: {}",
                                k,
                                map_name,
                                held,
                                info.thread_id,
                                origin,
                            );
                        }
                    }
                }
            }
        });
    });
}

#[cfg(not(debug_assertions))]
fn register_map_for_global_monitor(
    _map_name: &str,
    _write_locked_keys: Arc<DashMap<String, LockInfo>>,
    _timeout_secs: u64,
) {
    // No-op in release mode
}

// CustomDashMap: instrumented wrapper around DashMap operations
pub struct CustomDashMap<K, V> {
    name: String,
    map: DashMap<K, V>,
    #[cfg(debug_assertions)]
    write_locked_keys: Arc<DashMap<String, LockInfo>>,
    #[cfg(debug_assertions)]
    waiters: DashMap<ThreadId, String>,
    #[cfg(debug_assertions)]
    write_lock_timeout_secs: u64, // Timeout in seconds for write lock acquisition
}

impl<K, V> CustomDashMap<K, V>
where
    K: Eq + Hash + Debug + Clone,
{
    /// Create a new instrumented DashMap with the given name.
    pub fn new(name: &str) -> Self {
        #[cfg(debug_assertions)]
        {
            let write_locked_keys = Arc::new(DashMap::new());
            let map_instance = Self {
                name: name.to_string(),
                map: DashMap::new(),
                write_locked_keys: write_locked_keys.clone(),
                waiters: DashMap::new(),
                write_lock_timeout_secs: DEFAULT_DASHMAP_WRITE_LOCK_TIMEOUT_SECS,
            };
            register_map_for_global_monitor(
                &map_instance.name,
                map_instance.write_locked_keys.clone(),
                map_instance.write_lock_timeout_secs,
            );
            map_instance
        }

        #[cfg(not(debug_assertions))]
        {
            Self {
                name: name.to_string(),
                map: DashMap::new(),
            }
        }
    }

    /// Create a new instrumented DashMap with the given name and write lock timeout.
    pub fn new_with_timeout(name: &str, write_lock_timeout_secs: u64) -> Self {
        #[cfg(debug_assertions)]
        {
            let write_locked_keys = Arc::new(DashMap::new());
            let map_instance = Self {
                name: name.to_string(),
                map: DashMap::new(),
                write_locked_keys: write_locked_keys.clone(),
                waiters: DashMap::new(),
                write_lock_timeout_secs,
            };
            register_map_for_global_monitor(
                &map_instance.name,
                map_instance.write_locked_keys.clone(),
                map_instance.write_lock_timeout_secs,
            );
            map_instance
        }

        #[cfg(not(debug_assertions))]
        {
            Self {
                name: name.to_string(),
                map: DashMap::new(),
            }
        }
    }

    /// Creates a key identifier to track locks
    #[cfg(debug_assertions)]
    fn get_key_identifier<Q>(&self, key: &Q) -> String
    where
        K: Borrow<Q>,
        Q: Hash + Eq + Debug + ?Sized,
    {
        format!("{:?}", key)
    }

    /// Checks if a key is currently being written to and logs if it is
    #[cfg(debug_assertions)]
    fn check_write_lock<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Hash + Eq + Debug + ?Sized,
    {
        let key_str = self.get_key_identifier(key);
        if let Some(ref_val) = self.write_locked_keys.get(&key_str) {
            let bt_str = format!("{:?}", ref_val.backtrace);

            // First pass: exclude customlock.rs frames
            let mut frames = extract_useful_frames(&bt_str, true);

            if frames.is_empty() {
                frames = extract_useful_frames(&bt_str, false);
            }

            let frame_msg = if frames.is_empty() {
                "from unknown source".to_string()
            } else {
                format!("from:\n{}", frames.join("\n"))
            };

            debug!(
                "Attempted to write to key {:?} in map '{}' while another write operation is already active - {} (held for {:?} by {:?})",
                key,
                self.name,
                frame_msg,
                ref_val.started_at.elapsed(),
                ref_val.thread_id,
            );
            return true;
        }
        false
    }

    /// Waits for a write lock with timeout, logs error and keeps waiting without panic.
    #[cfg(debug_assertions)]
    fn wait_for_write_lock<Q>(&self, key: &Q)
    where
        K: Borrow<Q>,
        Q: Hash + Eq + Debug + ?Sized,
    {
        let start = Instant::now();
        let current_thread = std::thread::current().id();
        let key_str_wait = self.get_key_identifier(key);
        self.waiters.insert(current_thread, key_str_wait.clone());

        // Capture backtrace of the *writer waiting*, to make the log actionable
        let waiter_bt = Backtrace::force_capture();
        let waiter_bt_frames = extract_useful_frames(&format!("{:?}", waiter_bt), true);
        let waiter_origin = if waiter_bt_frames.is_empty() {
            "unknown".to_string()
        } else {
            waiter_bt_frames.join(" -> ")
        };

        let mut alerted = false;
        while self.check_write_lock(key) {
            let elapsed = start.elapsed();
            if !alerted && elapsed.as_secs() > self.write_lock_timeout_secs {
                alerted = true;
                // include holder info if available
                if let Some(ref_val) = self.write_locked_keys.get(&key_str_wait) {
                    let holder_frames =
                        extract_useful_frames(&format!("{:?}", ref_val.backtrace), false);
                    let holder_msg = if holder_frames.is_empty() {
                        "unknown holder".to_string()
                    } else {
                        holder_frames.join(" -> ")
                    };

                    error!(
                        "Writer WAITING for key {:?} in map '{}' for {:?}. Waiter at: {}. Currently held by {:?} originating at: {}",
                        key,
                        self.name,
                        elapsed,
                        waiter_origin,
                        ref_val.thread_id,
                        holder_msg,
                    );
                } else {
                    error!(
                        "Writer WAITING for key {:?} in map '{}' for {:?}. Waiter at: {}. Holder info not found (lock cleared meanwhile)",
                        key,
                        self.name,
                        elapsed,
                        waiter_origin,
                    );
                }
            }

            std::thread::sleep(std::time::Duration::from_millis(
                DEFAULT_LOCK_WAIT_SLEEP_MILLIS,
            ));
        }

        self.waiters.remove(&current_thread);
    }

    /// Marks a key as being written to
    #[cfg(debug_assertions)]
    fn mark_write_lock<Q>(&self, key: &Q) -> String
    where
        K: Borrow<Q>,
        Q: Hash + Eq + Debug + ?Sized,
    {
        let key_str = self.get_key_identifier(key);

        // Only create entry + background checker if this key is not already tracked
        match self.write_locked_keys.entry(key_str.clone()) {
            dashmap::mapref::entry::Entry::Occupied(_) => {
                // someone else already tracking – no need to spawn another checker
            }
            dashmap::mapref::entry::Entry::Vacant(v) => {
                v.insert(LockInfo {
                    backtrace: Backtrace::force_capture(),
                    started_at: Instant::now(),
                    thread_id: std::thread::current().id(),
                    timeout_logged: AtomicBool::new(false),
                });

                // per-lock checker removed; global monitor thread handles timeouts
            }
        }
        key_str
    }

    /// Releases the write lock on a key string
    #[cfg(debug_assertions)]
    fn release_write_lock_str(&self, key_str: &str) {
        self.write_locked_keys.remove(key_str);
    }

    // No-op versions for release mode
    #[cfg(not(debug_assertions))]
    fn check_write_lock<Q>(&self, _key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Hash + Eq + Debug + ?Sized,
    {
        false
    }

    #[cfg(not(debug_assertions))]
    fn wait_for_write_lock<Q>(&self, _key: &Q)
    where
        K: Borrow<Q>,
        Q: Hash + Eq + Debug + ?Sized,
    {
        // No-op in release mode
    }

    #[cfg(not(debug_assertions))]
    fn mark_write_lock<Q>(&self, _key: &Q) -> String
    where
        K: Borrow<Q>,
        Q: Hash + Eq + Debug + ?Sized,
    {
        String::new()
    }

    #[cfg(not(debug_assertions))]
    fn release_write_lock_str(&self, _key_str: &str) {
        // No-op in release mode
    }

    /// Returns self to mimic CustomRwLock's write() method - for API compatibility.
    /// When CustomDashMap is wrapped in Arc, this allows code to call write() on it.
    pub async fn write(&self) -> &Self {
        self
    }

    /// Get direct access to the underlying DashMap
    pub fn inner(&self) -> &DashMap<K, V> {
        &self.map
    }

    /// Instrumented get; logs if the operation takes longer than 1ms.
    pub fn get<Q>(&self, key: &Q) -> Option<CustomRef<'_, K, V>>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + Debug + ?Sized,
    {
        #[cfg(debug_assertions)]
        let start = Instant::now();

        let res = self.map.get(key);

        #[cfg(debug_assertions)]
        {
            let elapsed = start.elapsed();
            if elapsed.as_secs() > 1 {
                error!(
                    "CustomDashMap '{}' get took {:?} (>1s) for key: {:?}",
                    self.name, elapsed, key
                );
            }

            res.map(|r| {
                let key_str = self.get_key_identifier(key);
                // register read lock
                self.write_locked_keys.insert(
                    key_str.clone(),
                    LockInfo {
                        backtrace: Backtrace::force_capture(),
                        started_at: Instant::now(),
                        thread_id: std::thread::current().id(),
                        timeout_logged: AtomicBool::new(false),
                    },
                );
                CustomRef {
                    inner: r,
                    map: self,
                    key_str,
                }
            })
        }

        #[cfg(not(debug_assertions))]
        {
            res.map(|r| CustomRef {
                inner: r,
                map: self,
                key_str: String::new(),
            })
        }
    }

    /// Instrumented insert; logs if the operation takes longer than the warning threshold.
    pub fn insert(&self, key: K, value: V) {
        #[cfg(debug_assertions)]
        let start = Instant::now();

        #[cfg(debug_assertions)]
        self.wait_for_write_lock(&key);

        #[cfg(debug_assertions)]
        let key_str = self.mark_write_lock(&key);

        self.map.insert(key, value);

        #[cfg(debug_assertions)]
        {
            let elapsed = start.elapsed();
            self.release_write_lock_str(&key_str);
            if elapsed.as_secs() > DEFAULT_DASHMAP_OP_WARNING_SECS {
                error!(
                    "CustomDashMap '{}' insert took {:?} (>{} sec)",
                    self.name, elapsed, DEFAULT_DASHMAP_OP_WARNING_SECS
                );
            }
        }
    }

    /// Instrumented remove; logs if the operation takes longer than the warning threshold.
    pub fn remove<Q>(&self, key: &Q) -> Option<(K, V)>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + Debug + ?Sized,
    {
        #[cfg(debug_assertions)]
        let start = Instant::now();

        #[cfg(debug_assertions)]
        self.wait_for_write_lock(key);

        #[cfg(debug_assertions)]
        let key_str = self.mark_write_lock(key);

        let res = self.map.remove(key);

        #[cfg(debug_assertions)]
        {
            let elapsed = start.elapsed();
            self.release_write_lock_str(&key_str);
            if elapsed.as_secs() > DEFAULT_DASHMAP_OP_WARNING_SECS {
                error!(
                    "CustomDashMap '{}' remove took {:?} (>{} sec) for key: {:?}",
                    self.name, elapsed, DEFAULT_DASHMAP_OP_WARNING_SECS, key
                );
            }
        }

        res
    }

    /// Clears all entries; logs if the operation takes longer than the warning threshold.
    pub fn clear(&self) {
        #[cfg(debug_assertions)]
        let start = Instant::now();

        #[cfg(debug_assertions)]
        {
            // For clear, we lock the entire map
            self.write_locked_keys.insert(
                "__CLEAR_OPERATION__".to_string(),
                LockInfo {
                    backtrace: Backtrace::force_capture(),
                    started_at: Instant::now(),
                    thread_id: std::thread::current().id(),
                    timeout_logged: AtomicBool::new(false),
                },
            );
        }

        self.map.clear();

        #[cfg(debug_assertions)]
        {
            self.write_locked_keys.clear(); // Clear all locks including our own
            let elapsed = start.elapsed();
            if elapsed.as_secs() > DEFAULT_DASHMAP_OP_WARNING_SECS {
                error!(
                    "CustomDashMap '{}' clear took {:?} (>{} sec)",
                    self.name, elapsed, DEFAULT_DASHMAP_OP_WARNING_SECS
                );
            }
        }
    }

    /// Returns the number of entries.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Returns true if the map is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Returns true if the map contains the specified key.
    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.map.contains_key(key)
    }

    /// Returns an iterator over the entries of the map.
    pub fn iter(&self) -> TimedIter<DashIter<'_, K, V>> {
        #[cfg(debug_assertions)]
        let start_acquire = Instant::now();

        let it = self.map.iter();

        #[cfg(debug_assertions)]
        {
            let elapsed = start_acquire.elapsed();
            if elapsed.as_secs() > DEFAULT_DASHMAP_OP_WARNING_SECS {
                error!(
                    "CustomDashMap '{}' iter acquisition took {:?} (>{} sec)",
                    self.name, elapsed, DEFAULT_DASHMAP_OP_WARNING_SECS
                );
            }
            // Register iterator in write_locked_keys so the global monitor can track it
            let iter_id = ITER_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
            let key = format!("__ITER__{}", iter_id);
            self.write_locked_keys.insert(
                key.clone(),
                LockInfo {
                    backtrace: Backtrace::force_capture(),
                    started_at: Instant::now(),
                    thread_id: std::thread::current().id(),
                    timeout_logged: AtomicBool::new(false),
                },
            );

            TimedIter {
                inner: it,
                start: Instant::now(),
                map_name: self.name.clone(),
                lock_key: key,
                lock_map: self.write_locked_keys.clone(),
            }
        }

        #[cfg(not(debug_assertions))]
        {
            TimedIter {
                inner: it,
                start: Instant::now(),
                map_name: self.name.clone(),
                lock_key: String::new(),
                lock_map: Arc::new(DashMap::new()),
            }
        }
    }

    /// Returns a mutable iterator over the entries of the map.
    pub fn iter_mut(&self) -> TimedIter<DashIterMut<'_, K, V>> {
        #[cfg(debug_assertions)]
        let start_acquire = Instant::now();

        let it = self.map.iter_mut();

        #[cfg(debug_assertions)]
        {
            let elapsed = start_acquire.elapsed();
            if elapsed.as_secs() > DEFAULT_DASHMAP_OP_WARNING_SECS {
                error!(
                    "CustomDashMap '{}' iter_mut acquisition took {:?} (>{} sec)",
                    self.name, elapsed, DEFAULT_DASHMAP_OP_WARNING_SECS
                );
            }
            let iter_id = ITER_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
            let key = format!("__ITER__{}", iter_id);
            self.write_locked_keys.insert(
                key.clone(),
                LockInfo {
                    backtrace: Backtrace::force_capture(),
                    started_at: Instant::now(),
                    thread_id: std::thread::current().id(),
                    timeout_logged: AtomicBool::new(false),
                },
            );

            TimedIter {
                inner: it,
                start: Instant::now(),
                map_name: self.name.clone(),
                lock_key: key,
                lock_map: self.write_locked_keys.clone(),
            }
        }

        #[cfg(not(debug_assertions))]
        {
            TimedIter {
                inner: it,
                start: Instant::now(),
                map_name: self.name.clone(),
                lock_key: String::new(),
                lock_map: Arc::new(DashMap::new()),
            }
        }
    }

    /// Instrumented get_mut; logs if the operation takes longer than the warning threshold.
    /// Returns a custom RefMut wrapper that releases the lock on Drop.
    pub fn get_mut<Q>(&self, key: &Q) -> Option<CustomRefMut<'_, K, V>>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + Debug + ?Sized,
    {
        #[cfg(debug_assertions)]
        let start = Instant::now();

        #[cfg(debug_assertions)]
        self.wait_for_write_lock(key);

        #[cfg(debug_assertions)]
        let key_str = self.mark_write_lock(key);

        let res = self.map.get_mut(key);

        #[cfg(debug_assertions)]
        {
            let elapsed = start.elapsed();

            // If we didn't get a reference, release the lock immediately
            if res.is_none() {
                self.release_write_lock_str(&key_str);
            }

            if elapsed.as_secs() > DEFAULT_DASHMAP_OP_WARNING_SECS {
                error!(
                    "CustomDashMap '{}' get_mut took {:?} (>{} sec) for key: {:?}",
                    self.name, elapsed, DEFAULT_DASHMAP_OP_WARNING_SECS, key
                );
            }

            // Wrap the RefMut in our custom type
            res.map(|ref_mut| CustomRefMut {
                inner: ref_mut,
                map: self,
                key_str,
            })
        }

        #[cfg(not(debug_assertions))]
        {
            res.map(|ref_mut| CustomRefMut {
                inner: ref_mut,
                map: self,
                key_str: String::new(),
            })
        }
    }

    /// Returns a reference to the entry for the given key in the map for in-place manipulation.
    pub fn entry(&self, key: K) -> dashmap::mapref::entry::Entry<'_, K, V> {
        #[cfg(debug_assertions)]
        {
            // Fail-fast path identical to get_mut():
            self.wait_for_write_lock(&key); // will log + wait on timeout
            let key_str = self.mark_write_lock(&key);
            let e = self.map.entry(key);
            // We have no way of knowing when the caller is finished with the Entry,
            // so release immediately; this only protects against *double* writers
            // and still keeps the API 100 % unchanged.
            self.release_write_lock_str(&key_str);
            e
        }

        #[cfg(not(debug_assertions))]
        {
            self.map.entry(key)
        }
    }

    /// Retains only the elements specified by the predicate.
    pub fn retain(&self, f: impl FnMut(&K, &mut V) -> bool) {
        #[cfg(debug_assertions)]
        let start = Instant::now();

        #[cfg(debug_assertions)]
        {
            // For retain, we lock the entire map since it can modify any key
            self.write_locked_keys.insert(
                "__RETAIN_OPERATION__".to_string(),
                LockInfo {
                    backtrace: Backtrace::force_capture(),
                    started_at: Instant::now(),
                    thread_id: std::thread::current().id(),
                    timeout_logged: AtomicBool::new(false),
                },
            );
        }

        self.map.retain(f);

        #[cfg(debug_assertions)]
        {
            self.write_locked_keys.remove("__RETAIN_OPERATION__");
            let elapsed = start.elapsed();
            if elapsed.as_secs() > DEFAULT_DASHMAP_OP_WARNING_SECS {
                error!(
                    "CustomDashMap '{}' retain took {:?} (>{} sec)",
                    self.name, elapsed, DEFAULT_DASHMAP_OP_WARNING_SECS
                );
            }
        }
    }

    /// Dumps current lock state (held locks and waiters) to the logs.
    pub fn dump_lock_state(&self) {
        #[cfg(debug_assertions)]
        {
            warn!("===== Dumping lock state for map '{}' =====", self.name);

            let now = Instant::now();
            for item in self.write_locked_keys.iter() {
                let (k, info) = item.pair();
                warn!(
                    "LOCK HELD key={}  held_for={:?}  by={:?}\nbacktrace:\n{:?}",
                    k,
                    now.duration_since(info.started_at),
                    info.thread_id,
                    info.backtrace
                );
            }

            for waiter in self.waiters.iter() {
                let (thread_id, k) = waiter.pair();
                warn!("WAITER thread={:?} waiting_for key={}", thread_id, k);
            }
            warn!("===== End lock state dump =====");
        }
    }

    /// Similar to get_mut but lets the caller specify a custom timeout.
    pub fn get_mut_with_timeout<Q>(
        &self,
        key: &Q,
        timeout: Duration,
    ) -> Result<CustomRefMut<'_, K, V>, ()>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + Debug + ?Sized,
    {
        #[cfg(debug_assertions)]
        {
            let deadline = Instant::now() + timeout;
            let current_thread = std::thread::current().id();
            let key_str_wait = self.get_key_identifier(key);
            self.waiters.insert(current_thread, key_str_wait.clone());

            loop {
                if !self.check_write_lock(key) {
                    // safe to proceed
                    self.waiters.remove(&current_thread);
                    let key_str = self.mark_write_lock(key);
                    let res = self.map.get_mut(key);
                    // If we failed to get the ref, release immediately
                    if res.is_none() {
                        self.release_write_lock_str(&key_str);
                        return Err(());
                    }
                    return Ok(CustomRefMut {
                        inner: res.unwrap(),
                        map: self,
                        key_str,
                    });
                }

                if Instant::now() >= deadline {
                    self.waiters.remove(&current_thread);
                    self.dump_lock_state();
                    return Err(());
                }

                std::thread::sleep(Duration::from_millis(DEFAULT_LOCK_WAIT_SLEEP_MILLIS));
            }
        }

        #[cfg(not(debug_assertions))]
        {
            let res = self.map.get_mut(key);
            match res {
                Some(ref_mut) => Ok(CustomRefMut {
                    inner: ref_mut,
                    map: self,
                    key_str: String::new(),
                }),
                None => Err(()),
            }
        }
    }

    /// Removes all key-value pairs from the map and returns them as an iterator.
    /// The map will be empty after this call.
    /// This operation acquires a conceptual write lock on the entire map for its duration.
    pub fn drain(&self) -> TimedIter<std::vec::IntoIter<(K, V)>>
    where
        V: Clone, // K is already Clone from the impl block
    {
        #[cfg(debug_assertions)]
        let start_overall = Instant::now(); // For overall operation timing

        #[cfg(debug_assertions)]
        {
            // For drain, we acquire a conceptual lock on the entire map
            self.write_locked_keys.insert(
                "__DRAIN_OPERATION__".to_string(),
                LockInfo {
                    backtrace: Backtrace::force_capture(),
                    started_at: Instant::now(), // Lock acquisition time
                    thread_id: std::thread::current().id(),
                    timeout_logged: AtomicBool::new(false),
                },
            );
        }

        // Collect items. This requires K: Clone, V: Clone.
        // DashMap iterators yield references, so we clone.
        let items_to_drain: Vec<(K, V)> = self
            .map
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect();

        // Clear the map after collecting all items.
        self.map.clear();

        let drained_iter = items_to_drain.into_iter();

        #[cfg(debug_assertions)]
        {
            let elapsed_overall = start_overall.elapsed();
            if elapsed_overall.as_secs() > DEFAULT_DASHMAP_OP_WARNING_SECS {
                error!(
                    "CustomDashMap '{}' drain operation (collection + clear) took {:?} (>{} sec)",
                    self.name, elapsed_overall, DEFAULT_DASHMAP_OP_WARNING_SECS
                );
            }

            TimedIter {
                inner: drained_iter,
                start: Instant::now(), // Iteration start time
                map_name: self.name.clone(),
                lock_key: "__DRAIN_OPERATION__".to_string(), // This key will be removed by TimedIter::drop
                lock_map: self.write_locked_keys.clone(),
            }
        }

        #[cfg(not(debug_assertions))]
        {
            TimedIter {
                inner: drained_iter,
                start: Instant::now(),
                map_name: self.name.clone(),
                lock_key: String::new(),
                lock_map: Arc::new(DashMap::new()), // Dummy Arc for release mode
            }
        }
    }
}

impl<K, V> std::fmt::Debug for CustomDashMap<K, V>
where
    K: std::fmt::Debug + Eq + Hash,
    V: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustomDashMap")
            .field("name", &self.name)
            .field("len", &self.map.len())
            .finish()
    }
}

impl<K, V> Default for CustomDashMap<K, V>
where
    K: Eq + Hash + Debug + Clone,
{
    fn default() -> Self {
        Self::new(type_name::<Self>())
    }
}

/// RAII wrapper that measures how long a DashMap iterator lives.
#[derive(Clone)]
pub struct TimedIter<I> {
    inner: I,
    start: Instant,
    map_name: String,
    lock_key: String,
    lock_map: Arc<DashMap<String, LockInfo>>, // reference to the map holding the lock info
}

impl<I> Iterator for TimedIter<I>
where
    I: Iterator,
{
    type Item = I::Item;
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<I> DoubleEndedIterator for TimedIter<I>
where
    I: DoubleEndedIterator,
{
    fn next_back(&mut self) -> Option<Self::Item> {
        self.inner.next_back()
    }
}

impl<I> ExactSizeIterator for TimedIter<I> where I: ExactSizeIterator {}

impl<I> Drop for TimedIter<I> {
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        {
            // Remove tracking entry first
            self.lock_map.remove(&self.lock_key);

            let elapsed = self.start.elapsed();
            if elapsed.as_secs() > DEFAULT_DASHMAP_OP_WARNING_SECS {
                error!(
                    "CustomDashMap '{}' iterator lived {:?} (>{} sec)",
                    self.map_name, elapsed, DEFAULT_DASHMAP_OP_WARNING_SECS
                );
            }
        }
    }
}

// Implement auto traits for cross-thread sending/sharing of our wrappers ─────────────────────────────
// SAFETY: All contained types are `Send + Sync` when their generic parameters are, and all
// interior mutability relies on atomic types or synchronisation primitives from `tokio`/`dashmap`.
// Forwarding the auto-traits therefore upholds the required invariants.
unsafe impl<T: Send + Sync> Send for CustomRwLock<T> {}
unsafe impl<T: Send + Sync> Sync for CustomRwLock<T> {}

unsafe impl<'a, K, V> Send for CustomRefMut<'a, K, V>
where
    K: Send + Sync + Eq + Hash + Debug + Clone,
    V: Send + Sync,
{
}
unsafe impl<'a, K, V> Sync for CustomRefMut<'a, K, V>
where
    K: Send + Sync + Eq + Hash + Debug + Clone,
    V: Send + Sync,
{
}

unsafe impl<K, V> Send for CustomDashMap<K, V>
where
    K: Send + Sync + Eq + Hash + Debug + Clone,
    V: Send + Sync,
{
}
unsafe impl<K, V> Sync for CustomDashMap<K, V>
where
    K: Send + Sync + Eq + Hash + Debug + Clone,
    V: Send + Sync,
{
}

// Propagate auto traits for iterator wrapper as well.
unsafe impl<I> Send for TimedIter<I>
where
    I: Iterator + Send,
    I::Item: Send,
{
}
unsafe impl<I> Sync for TimedIter<I>
where
    I: Iterator + Sync,
    I::Item: Sync,
{
}

impl<K, V> Drop for CustomDashMap<K, V> {
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        {
            // Deregister from global monitor to avoid leaking entries after drop.
            MONITORED_MAPS.remove(&self.name);
        }
    }
}

/// A wrapper around dashmap::mapref::one::Ref that tracks read-access duration just like write locks.
pub struct CustomRef<'a, K, V>
where
    K: Eq + Hash + Debug + Clone,
{
    inner: dashmap::mapref::one::Ref<'a, K, V>,
    map: &'a CustomDashMap<K, V>,
    key_str: String,
}

impl<'a, K, V> std::ops::Deref for CustomRef<'a, K, V>
where
    K: Eq + Hash + Debug + Clone,
{
    type Target = V;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'a, K, V> Drop for CustomRef<'a, K, V>
where
    K: Eq + Hash + Debug + Clone,
{
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        {
            // Remove tracking entry when the read guard is dropped
            self.map.release_write_lock_str(&self.key_str);
        }
    }
}

// Forward commonly used helper methods to match dashmap::Ref API
impl<'a, K, V> CustomRef<'a, K, V>
where
    K: Eq + Hash + Debug + Clone,
{
    #[inline]
    pub fn key(&self) -> &K {
        self.inner.key()
    }

    #[inline]
    pub fn value(&self) -> &V {
        self.inner.value()
    }
    #[inline]
    pub fn pair(&self) -> (&K, &V) {
        self.inner.pair()
    }
}
