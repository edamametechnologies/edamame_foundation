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

    // Dotenv build with a specific env path
    let config = dotenv_build::Config {
        filename: std::path::Path::new("../edamame/secrets/foundation.env"),
        recursive_search: false,
        fail_if_missing_dotenv: false,
        ..Default::default()
    };
    dotenv_build::output(config).unwrap();

    // Tonic/proto
    tonic_build::compile_protos("./proto/edamame.proto").unwrap();

    // Emit the instructions
    let _ = EmitBuilder::builder().
        all_build().
        git_branch().
        emit();
}
