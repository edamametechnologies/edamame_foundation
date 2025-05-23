/// Conditional dispatch to debug or release implementations of `CustomRwLock` and `CustomDashMap`.

#[cfg(debug_assertions)]
mod debug;

#[cfg(not(debug_assertions))]
mod release;

#[cfg(debug_assertions)]
pub use debug::*;

#[cfg(not(debug_assertions))]
pub use release::*;
