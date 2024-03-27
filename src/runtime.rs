use std::future::Future;
use std::sync::{Arc, Mutex};
use tokio::runtime::Runtime;

// Use Arc to wrap the Runtime for safe sharing across threads
static RUNTIME: Mutex<Option<Arc<Runtime>>> = Mutex::new(None);

pub fn async_init() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("edamame")
        .build()
        .expect("Failed to build runtime");

    let rt = Arc::new(rt);
    let mut rt_lock = RUNTIME.lock().expect("Failed to lock runtime");
    *rt_lock = Some(rt);
}

pub fn async_exec<R, F>(async_fn: F) -> R
where
    R: 'static,
    F: Future<Output = R> + 'static,
{
    let rt = {
        let rt_lock = RUNTIME.lock().expect("Failed to lock runtime");
        rt_lock.as_ref().expect("Runtime not initialized").clone()
    };

    rt.block_on(async_fn)
}

pub fn async_spawn<F>(async_fn: F) -> tokio::task::JoinHandle<()>
where
    F: Future<Output = ()> + 'static + Send,
{
    let rt = {
        let rt_lock = RUNTIME.lock().expect("Failed to lock runtime");
        rt_lock.as_ref().expect("Runtime not initialized").clone()
    };

    rt.spawn(async_fn)
}
