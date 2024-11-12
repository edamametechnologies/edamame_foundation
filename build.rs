#[cfg(all(target_os = "windows", feature = "packetcapture"))]
use reqwest;
#[cfg(all(target_os = "windows", feature = "packetcapture"))]
use std::env;
#[cfg(all(target_os = "windows", feature = "packetcapture"))]
use std::fs;
#[cfg(all(target_os = "windows", feature = "packetcapture"))]
use std::path::PathBuf;
#[cfg(all(target_os = "windows", feature = "packetcapture"))]
use zip;

fn main() {
    // Tonic/proto
    tonic_build::compile_protos("./proto/edamame.proto").unwrap();

    // For Windows, download and extract the Npcap SDK
    #[cfg(all(target_os = "windows", feature = "packetcapture"))]
    {
        // Define the SDK URL and paths
        let sdk_url = "https://nmap.org/npcap/dist/npcap-sdk-1.13.zip";
        let sdk_zip_path = PathBuf::from("npcap-sdk-1.13.zip");
        let sdk_extract_path = PathBuf::from("npcap-sdk-1.13");

        // Get the absolute path to the project's root directory
        let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

        // Define absolute paths
        let sdk_zip_abs_path = manifest_dir.join(&sdk_zip_path);
        let sdk_extract_abs_path = manifest_dir.join(&sdk_extract_path);

        // Download the SDK zip file if it doesn't exist
        if !sdk_zip_abs_path.exists() {
            println!("Downloading Npcap SDK from {}...", sdk_url);
            let response = reqwest::blocking::get(sdk_url).expect("Failed to download Npcap SDK");
            let content = response.bytes().expect("Failed to read SDK zip content");
            fs::write(&sdk_zip_abs_path, &content).expect("Failed to write SDK zip file");
            println!("Npcap SDK downloaded successfully.");
        } else {
            println!("Npcap SDK zip already exists at {:?}", sdk_zip_abs_path);
        }

        // Extract the SDK zip file if it hasn't been extracted yet
        if !sdk_extract_abs_path.exists() {
            println!("Extracting Npcap SDK to {:?}...", sdk_extract_abs_path);
            let file = fs::File::open(&sdk_zip_abs_path).expect("Failed to open SDK zip file");
            let mut archive = zip::ZipArchive::new(file).expect("Failed to read SDK zip file");

            for i in 0..archive.len() {
                let mut file = archive
                    .by_index(i)
                    .expect("Failed to access SDK zip content");
                let outpath = sdk_extract_abs_path.join(file.name());

                if file.is_dir() {
                    fs::create_dir_all(&outpath).expect("Failed to create SDK directory");
                } else {
                    if let Some(parent) = outpath.parent() {
                        if !parent.exists() {
                            fs::create_dir_all(parent)
                                .expect("Failed to create SDK file directory");
                        }
                    }
                    let mut outfile =
                        fs::File::create(&outpath).expect("Failed to create SDK file");
                    std::io::copy(&mut file, &mut outfile).expect("Failed to copy SDK file");
                }
            }
            println!("Npcap SDK extracted successfully.");
        } else {
            println!("Npcap SDK already extracted at {:?}", sdk_extract_abs_path);
        }

        // Determine the target architecture
        let target = env::var("TARGET").expect("TARGET environment variable not set");
        let arch = if target.contains("x86_64") {
            "x64"
        } else if target.contains("aarch64") || target.contains("arm64") {
            "arm64"
        } else {
            panic!("Unsupported target architecture: {}", target);
        };

        // Construct the absolute library path based on architecture
        let sdk_lib_path = sdk_extract_abs_path.join("Lib").join(arch);

        // Verify that the library path exists
        if !sdk_lib_path.exists() {
            panic!(
                "Expected SDK library path does not exist: {:?}",
                sdk_lib_path
            );
        }

        // Verify that 'wpcap.lib' exists in the library path
        let wpcap_lib = sdk_lib_path.join("wpcap.lib");
        if !wpcap_lib.exists() {
            panic!("wpcap.lib not found in SDK library path: {:?}", wpcap_lib);
        }

        // Specify library paths for the SDK based on architecture
        println!("Using SDK library path: {:?}", sdk_lib_path);

        // Add the SDK library path to the linker search path
        println!("cargo:rustc-link-search=native={}", sdk_lib_path.display());

        // Link the Packet.lib and wpcap.lib libraries
        println!("cargo:rustc-link-lib=dylib=Packet"); // Link Packet.lib
        println!("cargo:rustc-link-lib=dylib=wpcap"); // Link wpcap.lib
    }
}
