//! The sensitive-path catalog the helper classifies under from its start.
//!
//! The helper's file monitor and capture classify files and sessions from
//! flodbadd's process-wide catalog snapshots, which start as a compile-time
//! fallback, a small subset of the catalog. `ServerControl::start_server`
//! (the helper's start, shared by every platform's helper binary) puts the
//! model's catalog, the embedded one at start, in force before it builds
//! the server, so before any order can start the file monitor or the
//! capture. Until 2.3.3 nothing did in the helper's process, and it
//! classified under the fallback for its whole life.
//!
//! This file is a test binary of its own, so a process of its own: nothing
//! refreshed the snapshots before the test, as at a real start.
#![cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]

use edamame_foundation::helper_rx::ServerControl;

/// The GitHub CLI's token store: a credential file the catalog lists on
/// every platform (`/.config/gh/hosts.yml`, a common pattern) and the
/// compile-time fallback does not.
const CATALOG_ONLY_CREDENTIAL: &str = "/home/user/.config/gh/hosts.yml";

#[tokio::test]
async fn the_helper_puts_the_catalog_in_force_before_it_serves() {
    assert!(
        flodbadd::sensitive_paths::is_sensitive_path_from_model(CATALOG_ONLY_CREDENTIAL).await,
        "the embedded catalog lists {CATALOG_ONLY_CREDENTIAL}"
    );
    assert!(
        !flodbadd::open_files::is_sensitive_path(CATALOG_ONLY_CREDENTIAL),
        "a fresh process's snapshot is the compile-time fallback, which does not list it"
    );

    // The helper's start, with an address that does not parse: it returns
    // before it binds or serves anything.
    let started = ServerControl::new()
        .start_server("", "", "", "not-an-address", "main")
        .await;
    assert!(started.is_err(), "{started:?}");

    assert!(
        flodbadd::open_files::is_sensitive_path(CATALOG_ONLY_CREDENTIAL),
        "the start puts the embedded catalog in force"
    );
}
