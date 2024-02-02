fn main() {

    // Tonic/proto
    #[cfg(not(feature = "disable-helper"))]
    tonic_build::compile_protos("./proto/edamame.proto").unwrap();
}
