use std::env;
use std::path::PathBuf;

fn main() {
    #[cfg(target_os = "windows")]
    flodbadd::windows_npcap::configure_build_linking_from_metadata();

    // Tonic/proto.
    //
    // Redirect prost-build's intermediate descriptor set out of the system
    // `%TEMP%` directory and into Cargo's `$OUT_DIR`. The default behavior is
    // to create a fresh temp dir under `%TEMP%\prost-buildXXX\` (or
    // `/tmp/prost-buildXXX/` on Unix), write `prost-descriptor-set` there
    // synchronously, then read it back. On github-hosted `windows-latest`
    // runners Defender's real-time scanner opens that file the instant it is
    // created and the read-back races with the scan, producing
    // `os error 32: process cannot access the file because it is being used
    // by another process` halfway through `cargo build`. Defender path /
    // process exclusions on `%TEMP%` are racy on Tamper-Protected hosts and
    // the prost-build retry ladder just creates a fresh temp dir on each
    // attempt, so all three retries fail the same way.
    //
    // `$OUT_DIR` lives under `target/` which is already excluded from
    // Defender on EDAMAME runners AND is project-scoped, so this eliminates
    // the race deterministically. This is the pattern documented in
    // `prost_build::Config::file_descriptor_set_path`.
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set by Cargo"));
    let descriptor_path = out_dir.join("edamame-descriptor.bin");
    match tonic_prost_build::configure()
        .file_descriptor_set_path(&descriptor_path)
        .compile_protos(&["./proto/edamame.proto"], &["./proto"])
    {
        Ok(_) => println!("Tonic/proto compiled successfully."),
        Err(e) => {
            panic!("Failed to compile Tonic/proto: {}", e);
        }
    }
}
