fn main() {
    // Tonic/proto
    match tonic_build::compile_protos("./proto/edamame.proto") {
        Ok(_) => println!("Tonic/proto compiled successfully."),
        Err(e) => {
            panic!("Failed to compile Tonic/proto: {}", e);
        }
    }
}
