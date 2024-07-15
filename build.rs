fn main() {
    // Tonic/proto
    #[cfg(not(feature = "nohelper"))]
    tonic_build::compile_protos("./proto/edamame.proto").unwrap();
}
