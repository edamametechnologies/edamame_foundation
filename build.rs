fn main() {

    // Tonic/proto
    #[cfg(not(feature = "disable_grpc"))]
    tonic_build::compile_protos("./proto/edamame.proto").unwrap();
}
