use log::{trace};

// Standard Mutex
use std;
// For Runtime
use std::future::Future;
use tokio::runtime::Runtime;

// Normal Mutex for the Runtime (no async)
static RUNTIME: std::sync::Mutex<Option<Runtime>> = std::sync::Mutex::new(None);

pub fn async_init() {
    // Initialize a runtime
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("edamame")
        .build();

    // Here we can spawn background tasks to be run on the runtime.

    // Store runtime in a global variable
    *RUNTIME.lock().expect("Set runtime") = Some(rt.unwrap());
}

// Block on a future and return the result
pub fn async_exec<R, F>(async_fn: F) -> R
where
    R: 'static,
    F: Future<Output = R> + 'static,
{
    let res;
    trace!("async_exec for {:?}", std::thread::current().id());
    trace!("Locking RUNTIME - start");
    let mut rt_guard = RUNTIME.lock().expect("Get runtime");
    let rt = rt_guard.as_mut().expect("Runtime present");
    let _guard = rt.enter();
    trace!("block_on - start");
    res = rt.block_on(async_fn);
    trace!("block_on - end");
    drop(rt_guard);
    trace!("Locking RUNTIME - end");
    res
}

// Spawn a thread on the runtime
pub fn async_spawn<F>(async_fn: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    trace!("async_spawn for {:?}", std::thread::current().id());
    trace!("Locking RUNTIME - start");
    let mut rt_guard = RUNTIME.lock().expect("Get runtime");
    let rt = rt_guard.as_mut().expect("Runtime present");
    let _guard = rt.enter();
    trace!("spawn - start");
    rt.spawn(async_fn);
    trace!("spawn - end");
    drop(rt_guard);
    trace!("Locking RUNTIME - end");
}
