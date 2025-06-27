use sgx_build::SgxBuilder;
use std::env;

fn main() {
    let builder = SgxBuilder::new();

    // Set library search path for SGX SDK
    println!(
        "cargo:rustc-link-search=native={}",
        builder.get_sdk_lib_path().display()
    );

    // Enable simulation feature based on SGX_MODE environment variable
    let sgx_mode = env::var("SGX_MODE").unwrap_or_default().to_uppercase();
    if sgx_mode == "SW" || sgx_mode == "SIM" {
        println!("cargo:rustc-cfg=feature=\"simulation\"");
    }
    println!("cargo:rustc-env=SGX_MODE={sgx_mode}");
}
