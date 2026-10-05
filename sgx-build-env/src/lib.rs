//! Locates the Intel SGX SDK from the environment.
//!
//! Split out of `sgx-build` so that `sgx-types` can read the SDK layout from
//! its build script without taking a build dependency on `cc`.

use std::env;
use std::path::PathBuf;

/// Install prefix of the SGX SDK, from `SGX_SDK`.
pub fn sgx_sdk() -> PathBuf {
    PathBuf::from(env::var("SGX_SDK").unwrap_or_else(|_| "/opt/intel/sgxsdk".to_string()))
}

/// Target architecture, from `SGX_ARCH`. Defaults to the host width.
pub fn sgx_arch() -> String {
    env::var("SGX_ARCH").unwrap_or_else(|_| {
        if cfg!(target_pointer_width = "32") {
            "x86".to_string()
        } else {
            "x64".to_string()
        }
    })
}

/// Directory holding the SDK libraries for the selected architecture.
pub fn sdk_lib_path() -> PathBuf {
    match sgx_arch().as_str() {
        "x86" => sgx_sdk().join("lib"),
        _ => sgx_sdk().join("lib64"),
    }
}
