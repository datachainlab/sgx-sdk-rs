fn main() {
    // Check SGX_MODE environment variable at compile time
    let sgx_mode = std::env::var("SGX_MODE").unwrap_or_else(|_| "HW".to_string());

    // Set configuration based on SGX_MODE
    println!("cargo:rustc-check-cfg=cfg(sgx_sim)");
    if sgx_mode == "SW" {
        println!("cargo:rustc-cfg=sgx_sim");
    }

    println!("cargo:rerun-if-env-changed=SGX_MODE");

    sgx_build::SgxBuilder::new()
        .build_enclave("Enclave.edl")
        .expect("Failed to build SGX enclave");
}
