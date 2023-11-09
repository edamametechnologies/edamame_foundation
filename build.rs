use vergen::EmitBuilder;
use std::env;

// To debug cfg, in particular target_os
fn dump_cfg() {
    for (key, value) in env::vars() {
        if key.starts_with("CARGO_CFG_") {
            eprintln!("{}: {:?}", key, value);
        }
        if key.starts_with("TARGET") {
            eprintln!("{}: {:?}", key, value);
        }
        if key.starts_with("SDK") {
            eprintln!("{}: {:?}", key, value);
        }
        if key.starts_with("ARCH") {
            eprintln!("{}: {:?}", key, value);
        }
    }
}

fn main() {
    // Debug cfg
    dump_cfg();

    // Tonic/proto
    tonic_build::compile_protos("./proto/edamame.proto").unwrap();

    // Emit the instructions
    let _ = EmitBuilder::builder().
        all_build().
        git_branch().
        emit();
}
