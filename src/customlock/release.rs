use dashmap::DashMap;
use std::hash::Hash;
use std::ops::{Deref, DerefMut};
use tokio::sync::RwLock;

/// In release builds we skip the heavy debugging wrappers and simply
/// re-export the standard Tokio `RwLock`.
/// All APIs (`new`, `read`, `write`, etc.) are therefore identical and zero-cost.
#[allow(dead_code)]
pub type CustomRwLock<T> = RwLock<T>;

/// Thin wrapper around `DashMap` so that we can keep using the existing
/// `CustomDashMap::new` and `CustomDashMap::new_with_timeout` constructors
/// throughout the codebase.  Every other method call is automatically
/// forwarded via `Deref`/`DerefMut`.
pub struct CustomDashMap<K, V>(DashMap<K, V>);

impl<K: Eq + Hash, V> CustomDashMap<K, V> {
    /// Create a new map.  The `name` parameter is ignored in release builds
    /// but preserved so that call-sites compile unchanged.
    pub fn new(_name: &str) -> Self {
        Self(DashMap::new())
    }

    /// Same as `new`; the timeout argument is only relevant for the debug
    /// implementation so it is ignored here.
    pub fn new_with_timeout(_name: &str, _write_lock_timeout_secs: u64) -> Self {
        Self::new(_name)
    }

    /// Dummy async write lock—just returns `&self` so call-sites compile.
    pub async fn write(&self) -> &Self {
        self
    }

    /// Drains the entire map and returns an iterator over owned key-value pairs.
    /// This mimics the debug build signature but without timing logic.
    pub fn drain(&self) -> std::vec::IntoIter<(K, V)>
    where
        K: Clone,
        V: Clone,
    {
        let items: Vec<(K, V)> = self
            .0
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect();
        self.0.clear();
        items.into_iter()
    }
}

impl<K, V> Deref for CustomDashMap<K, V> {
    type Target = DashMap<K, V>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<K, V> DerefMut for CustomDashMap<K, V> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<K, V> Default for CustomDashMap<K, V>
where
    K: Eq + Hash,
{
    fn default() -> Self {
        Self(DashMap::new())
    }
}

impl<K, V> std::fmt::Debug for CustomDashMap<K, V>
where
    K: Eq + Hash + std::fmt::Debug,
    V: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustomDashMap")
            .field("len", &self.0.len())
            .finish()
    }
}
