use lazy_static::lazy_static;
use std::any::type_name;
use std::backtrace::Backtrace;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{debug, error};

lazy_static! {
    pub static ref DEBUG_PATTERNS: Arc<RwLock<Vec<String>>> = Arc::new(RwLock::new(Vec::new()));
}

#[allow(dead_code)]
pub async fn add_debug_pattern(pattern: &str) {
    let mut patterns = DEBUG_PATTERNS.write().await;
    patterns.push(pattern.to_string());
}

pub async fn match_debug_pattern(message: &str) -> bool {
    let patterns = DEBUG_PATTERNS.read().await;
    for pattern in patterns.iter() {
        if message.contains(pattern) {
            return true;
        }
    }
    false
}

#[derive(Debug, Default)]
pub struct CustomRwLock<T> {
    name: String,
    lock: RwLock<T>,
    write_locked: AtomicBool,
    read_waiting_count: AtomicUsize,
}

impl<T> CustomRwLock<T> {
    pub fn new(data: T) -> Self {
        Self {
            name: type_name::<T>().to_string(),
            lock: RwLock::new(data),
            write_locked: AtomicBool::new(false),
            read_waiting_count: AtomicUsize::new(0),
        }
    }

    pub async fn read(&self) -> tokio::sync::RwLockReadGuard<'_, T> {
        let start = Instant::now();
        if self.write_locked.load(Ordering::SeqCst) {
            self.read_waiting_count.fetch_add(1, Ordering::SeqCst);
            debug!(
                "Read lock '{}' is waiting for a write lock to be released",
                self.name
            );
        } else if match_debug_pattern(&self.name).await {
            debug!("Acquiring read lock for '{}'", self.name);
        }
        let guard = self.lock.read().await;
        if self.write_locked.load(Ordering::SeqCst) {
            self.read_waiting_count.fetch_sub(1, Ordering::SeqCst);
        }
        // Check if the read lock took too long
        let duration = start.elapsed();
        if duration.as_secs() > 5 {
            error!(
                "Read lock '{}' took too long to acquire: {:?} seconds",
                self.name, duration
            );
        }
        guard
    }

    pub async fn write(&self) -> tokio::sync::RwLockWriteGuard<'_, T> {
        let start = Instant::now();
        if self.write_locked.load(Ordering::SeqCst) {
            debug!(
                "Attempted to acquire write lock for '{}' while another write lock is already active  - backtrace:\n{}",
                self.name, Backtrace::force_capture()
            );
        } else if match_debug_pattern(&self.name).await {
            debug!(
                "Acquiring write lock for '{}' - backtrace:\n{}",
                self.name,
                Backtrace::force_capture()
            );
        }
        self.write_locked.store(true, Ordering::SeqCst);
        let guard = self.lock.write().await;
        self.write_locked.store(false, Ordering::SeqCst);
        // Check if the read lock took too long
        let duration = start.elapsed();
        if duration.as_secs() > 5 {
            error!(
                "Write lock '{}' took too long to acquire: {:?} seconds - backtrace:\n{}",
                self.name,
                duration,
                Backtrace::force_capture()
            );
        }
        guard
    }

    pub fn read_waiting(&self) -> usize {
        self.read_waiting_count.load(Ordering::SeqCst)
    }
}
