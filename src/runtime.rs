use once_cell::sync::OnceCell;
use std::future::Future;
use tokio::runtime::Runtime;

// Global runtime instance
static RUNTIME: OnceCell<Runtime> = OnceCell::new();

/// Cap the tokio blocking-pool below the default 512.
///
/// macOS exposes a low `kern.num_taskthreads = 8192` system-wide thread
/// budget. With heavy desktop usage (Chrome, Cursor, Slack, Google Drive,
/// etc.) a single process burning 500+ blocking threads is enough to push
/// the host into `fork: Resource temporarily unavailable` (EAGAIN) and
/// break unrelated tools (`make`, `flutter`, `git`).
///
/// Many EDAMAME hot paths use `tokio::task::spawn_blocking` (flodbadd L7
/// process attribution, port scanner, FIM, vulnerability detector,
/// runner_cli command execution) plus implicit blocking via
/// `tokio::process::Command` / `tokio::fs`. With the default 512 cap the
/// blocking pool ratchets toward 512 long-lived threads over the app's
/// lifetime and never shrinks. 128 is well above the steady-state
/// concurrent need (LAN scan ≈ 32 concurrent connects, FD scans bounded,
/// FIM rare) and gives enough headroom to absorb bursts without
/// dominating the host budget.
const MAX_BLOCKING_THREADS: usize = 128;

/// Initialize the Tokio runtime with edamame-specific settings.
///
/// Call this once at application startup before any async operations.
pub fn init() {
    let _ = RUNTIME.get_or_init(|| {
        let mut builder = tokio::runtime::Builder::new_multi_thread();
        builder
            .enable_all()
            .thread_name("edamame")
            .max_blocking_threads(MAX_BLOCKING_THREADS);

        // Set worker threads based on available parallelism
        if let Ok(parallelism) = std::thread::available_parallelism() {
            builder.worker_threads(parallelism.get());
        }

        builder.build().expect("Failed to build runtime")
    });
}

/// Block on a future using the initialized runtime.
///
/// This is mainly for use in synchronous API functions that need to call async code.
/// In async contexts, use tokio directly.
///
/// # Panics
/// Panics if the runtime hasn't been initialized.
pub fn block_on<F>(future: F) -> F::Output
where
    F: Future,
{
    RUNTIME
        .get()
        .expect("Runtime not initialized. Call runtime::init() first.")
        .block_on(future)
}

/// Get a reference to the runtime.
///
/// Useful when you need to pass the runtime handle explicitly.
pub fn handle() -> &'static Runtime {
    RUNTIME
        .get()
        .expect("Runtime not initialized. Call runtime::init() first.")
}

/// Returns true when the shared runtime has already been initialized.
pub fn is_initialized() -> bool {
    RUNTIME.get().is_some()
}
