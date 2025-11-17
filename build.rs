fn main() {
    #[cfg(target_os = "windows")]
    flodbadd::windows_npcap::configure_build_linking_from_metadata();
    // Tonic/proto
    match tonic_prost_build::compile_protos("./proto/edamame.proto") {
        Ok(_) => println!("Tonic/proto compiled successfully."),
        Err(e) => {
            panic!("Failed to compile Tonic/proto: {}", e);
        }
    }
}
