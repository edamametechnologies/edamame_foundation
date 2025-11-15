fn main() {
    configure_npcap_linking();
    // Tonic/proto
    match tonic_prost_build::compile_protos("./proto/edamame.proto") {
        Ok(_) => println!("Tonic/proto compiled successfully."),
        Err(e) => {
            panic!("Failed to compile Tonic/proto: {}", e);
        }
    }
}

#[cfg(target_os = "windows")]
fn configure_npcap_linking() {
    use std::env;
    const LIB_ENV: &str = "DEP_FLODBADD_NPCAP_NPCAP_LIB_DIR";
    const RUNTIME_ENV: &str = "DEP_FLODBADD_NPCAP_NPCAP_RUNTIME_DIR";

    if let Ok(lib_dir) = env::var(LIB_ENV) {
        println!("cargo:rustc-link-search=native={lib_dir}");
    } else {
        println!(
            "cargo:warning=Npcap SDK library path missing ({}). wpcap.lib may be unresolved.",
            LIB_ENV
        );
    }

    if let Ok(runtime_dir) = env::var(RUNTIME_ENV) {
        println!("cargo:rustc-link-search=native={runtime_dir}");
    }
}

#[cfg(not(target_os = "windows"))]
fn configure_npcap_linking() {}
