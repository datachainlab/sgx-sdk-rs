fn main() {
    sgx_build::SgxBuilder::new()
        .build_app("../enclave/Enclave.edl")
        .expect("Failed to build SGX app");
}
