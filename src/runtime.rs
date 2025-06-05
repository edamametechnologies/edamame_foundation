use once_cell::sync::OnceCell;
use std::future::Future;
use tokio::runtime::Runtime;

// Global runtime instance
static RUNTIME: OnceCell<Runtime> = OnceCell::new();

/// Initialize the Tokio runtime with edamame-specific settings.
///
/// Call this once at application startup before any async operations.
pub fn init() {
    let _ = RUNTIME.get_or_init(|| {
        let mut builder = tokio::runtime::Builder::new_multi_thread();
        builder.enable_all().thread_name("edamame");

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
