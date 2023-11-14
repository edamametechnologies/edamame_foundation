fn main() {

    // Tonic/proto
    tonic_build::compile_protos("./proto/edamame.proto").unwrap();
}
