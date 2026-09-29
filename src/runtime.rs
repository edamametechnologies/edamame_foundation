use once_cell::sync::OnceCell;
use std::future::Future;
use std::time::Duration;
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

/// The budget of a [`wall_clock_timeout`] ran out before the future completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WallClockElapsed;

impl std::fmt::Display for WallClockElapsed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "wall-clock budget elapsed")
    }
}

impl std::error::Error for WallClockElapsed {}

/// Bound `future` by `budget`, measured by an OS thread instead of the tokio
/// timer.
///
/// `tokio::time::timeout` is a tokio timer: it fires only when a runtime
/// worker parks on the time driver. When every worker is stuck inside a
/// poll (a synchronous lock, a blocking call, a CPU-bound loop), no worker
/// parks, the driver is never serviced and the timeout never fires -- and a
/// caller in [`block_on`] parks forever. That is how `edamame_posture score`
/// sat in `terminate` for two hours with a 20 s `tokio::time::timeout`
/// around it (macOS CI runner, 2026-09-28).
///
/// Here a dedicated thread sleeps for the budget and then completes a
/// `tokio::sync::oneshot`, whose send wakes the waiting task directly,
/// without the time driver. The bound holds as long as the thread polling
/// this future is alive: the main thread inside [`block_on`] always is.
///
/// Costs one short-lived OS thread per call, which lingers until the budget
/// ends: use it for shutdown paths and other rare deadlines, not hot paths.
/// If the thread cannot be spawned, it falls back to `tokio::time::timeout`.
pub async fn wall_clock_timeout<F>(
    budget: Duration,
    future: F,
) -> Result<F::Output, WallClockElapsed>
where
    F: Future,
{
    let (expired_tx, expired_rx) = tokio::sync::oneshot::channel::<()>();
    let spawned = std::thread::Builder::new()
        .name("edamame-deadline".to_string())
        .spawn(move || {
            std::thread::sleep(budget);
            let _ = expired_tx.send(());
        });
    if spawned.is_err() {
        return tokio::time::timeout(budget, future)
            .await
            .map_err(|_| WallClockElapsed);
    }

    tokio::pin!(future);
    tokio::select! {
        biased;
        output = &mut future => Ok(output),
        _ = expired_rx => Err(WallClockElapsed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Instant;

    /// A runtime whose every worker is parked in a synchronous sleep for
    /// `wedge`: nothing services the tokio time driver meanwhile.
    fn wedged_runtime(workers: usize, wedge: Duration) -> Runtime {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(workers)
            .enable_all()
            .build()
            .expect("runtime");
        let (ready_tx, ready_rx) = mpsc::channel();
        for _ in 0..workers {
            let ready_tx = ready_tx.clone();
            rt.spawn(async move {
                let _ = ready_tx.send(());
                std::thread::sleep(wedge);
            });
        }
        for _ in 0..workers {
            ready_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("worker did not start");
        }
        rt
    }

    /// The failure mode: with every worker wedged, a `tokio::time::timeout`
    /// awaited from `block_on` does not fire on time.
    #[test]
    fn tokio_timeout_does_not_fire_while_workers_are_wedged() {
        let wedge = Duration::from_secs(4);
        let rt = wedged_runtime(2, wedge);
        let (done_tx, done_rx) = mpsc::channel();
        let start = Instant::now();
        std::thread::spawn(move || {
            let result = rt.block_on(async {
                tokio::time::timeout(Duration::from_millis(200), std::future::pending::<()>()).await
            });
            let _ = done_tx.send(result.is_err());
        });
        assert!(
            done_rx.recv_timeout(Duration::from_secs(2)).is_err(),
            "tokio timer fired although no worker could service the driver"
        );
        // Once the workers come back the timer fires (late).
        assert_eq!(done_rx.recv_timeout(Duration::from_secs(10)), Ok(true));
        assert!(start.elapsed() >= Duration::from_secs(3));
    }

    /// The fix: the wall-clock budget holds with every worker wedged.
    #[test]
    fn wall_clock_timeout_fires_while_workers_are_wedged() {
        let rt = wedged_runtime(2, Duration::from_secs(4));
        let start = Instant::now();
        let result = rt.block_on(wall_clock_timeout(
            Duration::from_millis(200),
            std::future::pending::<()>(),
        ));
        let elapsed = start.elapsed();
        assert_eq!(result, Err(WallClockElapsed));
        assert!(
            elapsed < Duration::from_secs(2),
            "wall-clock budget took {:?}",
            elapsed
        );
    }

    #[test]
    fn wall_clock_timeout_returns_the_output_when_in_budget() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("runtime");
        let result = rt.block_on(wall_clock_timeout(Duration::from_secs(5), async { 7 }));
        assert_eq!(result, Ok(7));
    }
}
