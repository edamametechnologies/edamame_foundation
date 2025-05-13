#[cfg(all(target_os = "windows", feature = "packetcapture"))]
use reqwest;
#[cfg(all(target_os = "windows", feature = "packetcapture"))]
use std::env;
#[cfg(all(target_os = "windows", feature = "packetcapture"))]
use std::fs;
#[cfg(all(target_os = "windows", feature = "packetcapture"))]
use zip;
#[cfg(all(feature = "ebpf", target_os = "linux"))]
use std::env;
#[cfg(all(feature = "ebpf", target_os = "linux"))]
use std::path::{Path, PathBuf};
#[cfg(all(feature = "ebpf", target_os = "linux"))]
use std::process::Command;

fn main() {
    // Tonic/proto
    match tonic_build::compile_protos("./proto/edamame.proto") {
        Ok(_) => println!("Tonic/proto compiled successfully."),
        Err(e) => {
            panic!("Failed to compile Tonic/proto: {}", e);
        }
    }

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

    // Only attempt to build the eBPF object when we are compiling the userspace
    // crate for Linux with the ebpf feature enabled.  On other platforms the helper will run in stub mode, so
    // a missing object file is not an error.
    #[cfg(all(feature = "ebpf", target_os = "linux"))]
    {
        // Location of the eBPF program crate (sibling directory `ebpf/l7_ebpf_program`)
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        let manifest_dir = Path::new(&manifest_dir);
        let ebpf_crate_dir = manifest_dir.join("ebpf/l7_ebpf_program");
        let cargo_toml = ebpf_crate_dir.join("Cargo.toml");

        if !cargo_toml.exists() {
            eprintln!(
                "warning: ebpf crate not found at {} – skipping eBPF build",
                cargo_toml.display()
            );
            return;
        }

        // Build the eBPF crate with the nightly toolchain and build the core
        // library from source for the BPF target.  We only need `core` (and
        // `alloc`) so this keeps the build reasonably fast while avoiding the
        // need for a pre-compiled rust-std for `bpfel-unknown-none`.
        let status = Command::new("cargo")
            .args([
                "+nightly",
                "build",
                "--release",
                "-Z",
                "build-std=core,alloc",
                "--target",
                "bpfel-unknown-none",
                "--manifest-path",
            ])
            .arg(cargo_toml.as_os_str())
            .env("RUSTFLAGS", "-C embed-bitcode=no")
            .status()
            .expect("failed to spawn cargo to build ebpf");

        if !status.success() {
            panic!("eBPF build failed (status: {status})");
        }

        // Path to the generated object file
        let obj_path = ebpf_crate_dir.join("target/bpfel-unknown-none/release/l7_ebpf_program.o");

        let final_obj_path = if obj_path.exists() {
            obj_path
        } else {
            // Newer Rust nightly versions emit a static archive instead of a single
            // object.  Extract the first object from the archive so that Aya can
            // load a plain ELF file.
            let archive_path =
                ebpf_crate_dir.join("target/bpfel-unknown-none/release/libl7_ebpf_program.a");
            if !archive_path.exists() {
                panic!(
                    "eBPF build succeeded but neither .o nor .a artefact found at {}",
                    ebpf_crate_dir.display()
                );
            }

            // Use the `ar` tool to list members then extract the first one.
            let list_output = Command::new("ar")
                .args(["t", archive_path.to_str().unwrap()])
                .output()
                .expect("failed to invoke ar to list archive members");
            if !list_output.status.success() {
                panic!("ar t failed on {:?}", archive_path);
            }
            let members = String::from_utf8_lossy(&list_output.stdout);
            let obj_member = members
                .lines()
                .find(|m| m.ends_with(".o"))
                .expect("no .o member found in staticlib");

            let extracted_path = archive_path.with_extension("extracted.o");

            let extract_status = Command::new("ar")
                .args(["x", archive_path.to_str().unwrap(), obj_member])
                .current_dir(archive_path.parent().unwrap())
                .status()
                .expect("failed to extract object from archive");
            if !extract_status.success() {
                panic!(
                    "ar x failed extracting {} from {:?}",
                    obj_member, archive_path
                );
            }

            let extracted_full = archive_path.parent().unwrap().join(obj_member);
            if extracted_path.exists() {
                std::fs::remove_file(&extracted_path).ok();
            }
            std::fs::rename(&extracted_full, &extracted_path)
                .expect("failed to rename extracted object");

            // Check if extracted object is already an ELF eBPF object
            let is_elf = Command::new("file")
                .arg(&extracted_path)
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).contains("ELF"))
                .unwrap_or(false);

            if is_elf {
                extracted_path
            } else {
                // ---------------------------------------------------------
                // Convert LLVM bitcode into a real eBPF ELF object using llc
                // ---------------------------------------------------------
                let elf_path = extracted_path.with_extension("elf.o");

                // Prefer the LLVM tools that ship with the nightly toolchain to avoid
                // version mismatch with system LLVM (Rust 1.89 uses LLVM 20).
                let rustc_sysroot = Command::new("rustc")
                    .args(["+nightly", "--print", "sysroot"])
                    .output()
                    .ok()
                    .and_then(|o| {
                        if o.status.success() {
                            Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
                        } else {
                            None
                        }
                    });

                let llc_path = if let Some(sysroot) = rustc_sysroot {
                    let direct = Path::new(&sysroot).join("bin/llc");
                    if direct.exists() {
                        direct
                    } else {
                        // rustup installs llvm-tools under lib/rustlib/<host>/bin
                        let pattern = Path::new(&sysroot).join("lib/rustlib");
                        if let Ok(entries) = std::fs::read_dir(pattern) {
                            let mut found = None;
                            for e in entries.flatten() {
                                let p = e.path().join("bin/llc");
                                if p.exists() {
                                    found = Some(p);
                                    break;
                                }
                            }
                            found.unwrap_or_else(|| PathBuf::from("llc"))
                        } else {
                            PathBuf::from("llc")
                        }
                    }
                } else {
                    PathBuf::from("llc")
                };

                let llc_status = Command::new(llc_path)
                    .args([
                        "-march=bpf",
                        "-filetype=obj",
                        extracted_path.to_str().unwrap(),
                        "-o",
                        elf_path.to_str().unwrap(),
                    ])
                    .status()
                    .expect("failed to invoke llc");

                if !llc_status.success() {
                    panic!("llc failed to compile bitcode into eBPF ELF (status: {llc_status})");
                }

                let _ = std::fs::remove_file(&extracted_path);
                elf_path
            }
        };

        // Make the userspace crate aware of the location via env-var so runtime code
        // can load it.  We store the *absolute* path to avoid cwd issues.
        println!(
            "cargo:rustc-env=L7_EBPF_OBJECT={}",
            final_obj_path.display()
        );

        // Re-run the build script if either the eBPF source or build script itself changes.
        println!("cargo:rerun-if-changed=build.rs");
        println!("cargo:rerun-if-changed={}", ebpf_crate_dir.display());
    }
}
