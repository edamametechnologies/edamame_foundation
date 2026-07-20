//! Dogfood harness: exercise `run_agent_cli_fix_interactive` on a real
//! Windows desktop session (Path of Enlightenment fix-runner launch path).
//!
//! Usage:
//!   interactive_fix_launch.exe <agent_type> <workspace_path> [prompt]
//!
//! Place a resolvable agent CLI (`claude` / `codex` / `cursor-agent`) on PATH
//! or under the user's home candidate dirs. For a launch-only smoke test, a
//! stub `.cmd` that prints and `pause`s is enough.

use std::env;
use std::path::PathBuf;
use std::process;

fn main() {
    let mut args = env::args().skip(1);
    let agent_type = args.next().unwrap_or_else(|| {
        eprintln!("usage: interactive_fix_launch <agent_type> <workspace_path> [prompt]");
        process::exit(2);
    });
    let workspace = args.next().unwrap_or_else(|| {
        eprintln!("usage: interactive_fix_launch <agent_type> <workspace_path> [prompt]");
        process::exit(2);
    });
    let prompt = args
        .next()
        .unwrap_or_else(|| "EDAMAME dogfood interactive fix-run smoke test".to_string());

    let home = dirs::home_dir().or_else(|| {
        env::var_os("USERPROFILE")
            .map(PathBuf::from)
            .or_else(|| env::var_os("HOME").map(PathBuf::from))
    });

    println!("agent_type={agent_type}");
    println!("workspace={workspace}");
    println!(
        "home={}",
        home.as_ref()
            .map(|h| h.display().to_string())
            .unwrap_or_default()
    );

    match edamame_foundation::agent_cli_insight::run_agent_cli_fix_interactive(
        &agent_type,
        &workspace,
        &prompt,
        home.as_deref(),
    ) {
        Ok(spawn) => {
            println!("spawn_ok=true");
            println!("pid={}", spawn.pid);
            println!("binary={}", spawn.binary);
            println!("command={}", spawn.command.join(" "));
            process::exit(0);
        }
        Err(e) => {
            eprintln!("spawn_ok=false");
            eprintln!("error={e}");
            process::exit(1);
        }
    }
}
