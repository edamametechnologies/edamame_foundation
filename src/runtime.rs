use std::future::Future;
use std::sync::{Arc, Mutex};
use tokio::runtime::{Handle, Runtime};
use tokio::task::JoinHandle;

// Use Arc to wrap the Runtime for safe sharing across threads
static RUNTIME: Mutex<Option<Arc<Runtime>>> = Mutex::new(None);

// Initializes the Tokio runtime and stores it in the global static variable.
// If the runtime is already initialized, it does nothing.
pub fn async_init() {
    // Check if the runtime has already been initialized
    if RUNTIME.lock().expect("Failed to lock runtime").is_some() {
        eprintln!("Runtime already initialized");
        return;
    }

    // Build a new multi-threaded Tokio runtime
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("edamame")
        .build()
        .expect("Failed to build runtime");

    // Store the new runtime in the global static variable
    let rt = Arc::new(rt);
    *RUNTIME.lock().expect("Failed to lock runtime") = Some(rt);
}

// Gets the handle of the initialized runtime.
// If the runtime is not initialized, it returns the current default Tokio runtime handle.
// This is used during unit tests
fn get_runtime_handle() -> Handle {
    match RUNTIME.lock() {
        Ok(rt_lock) => {
            if let Some(rt) = &*rt_lock {
                rt.handle().clone()
            } else {
                Handle::current()
            }
        }
        Err(_) => Handle::current(),
    }
}

// Executes an asynchronous function and blocks until it completes.
// If the custom runtime is not available, it uses the default Tokio runtime.
pub fn async_exec<R, F>(async_fn: F) -> R
where
    R: 'static,
    F: Future<Output = R> + 'static,
{
    let handle = get_runtime_handle();
    handle.block_on(async_fn)
}

// Spawns an asynchronous task on the runtime.
// If the custom runtime is not available, it uses the default Tokio runtime.
pub fn async_spawn<F>(async_fn: F) -> JoinHandle<()>
where
    F: Future<Output = ()> + 'static + Send,
{
    let handle = get_runtime_handle();
    handle.spawn(async_fn)
}

// Spawns a blocking task on the runtime.
// If the custom runtime is not available, it uses the default Tokio runtime.
pub fn async_spawn_blocking<F, R>(blocking_fn: F) -> JoinHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let handle = get_runtime_handle();
    handle.spawn_blocking(blocking_fn)
}
