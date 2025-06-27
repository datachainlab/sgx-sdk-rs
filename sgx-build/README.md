# sgx-build

A Rust build helper crate for Intel SGX enclaves. This crate provides a programmatic interface to compile C/C++ code for SGX enclaves, based on Intel's official [buildenv.mk](https://github.com/intel/linux-sgx/blob/main/buildenv.mk) and [Makefile](https://github.com/intel/linux-sgx/blob/main/SampleCode/SampleEnclave/Makefile).

## Overview

`sgx-build` is a Rust alternative to the Makefile-based SGX build system. It leverages the `cc` crate to provide a familiar Rust API while maintaining compatibility with Intel's SGX SDK build requirements. The main struct `SgxBuilder` handles both enclave and application build configurations.

## Usage

Add `sgx-build` to your `build-dependencies` in `Cargo.toml`:

```toml
[build-dependencies]
sgx-build = { path = "../sgx-build" }
```

### For Enclave Build

Create a `build.rs` file in your enclave project:

```rust
fn main() {
    sgx_build::SgxBuilder::new()
        .build_enclave("Enclave.edl")
        .expect("Failed to build SGX enclave");
}
```

This simple function `build_enclave` handles all the necessary steps:
- Processes the EDL file for the trusted side
- Compiles the generated C code
- Sets up enclave linker flags
- Links with the generated EDL object
- Automatically reruns if the EDL file changes

The generated EDL bindings (`Enclave_t.c`, `Enclave_t.h`) and compiled library (`libEnclave_t.a`) will be placed in the same directory as the EDL file.

If you need more control over the build process, you can use the lower-level APIs:

```rust
fn main() {
    let builder = sgx_build::SgxBuilder::new();

    // Process EDL file
    let edl_output = builder
        .edl_generate(std::path::Path::new("Enclave.edl"), true)
        .expect("Failed to process EDL");

    // Compile generated C file with EDL-based library name
    builder.compile_edl(&edl_output.c_file, true, &edl_output.lib_name);

    // Set up linker flags
    builder.setup_enclave_linker();

    // Link with the generated EDL object (lib_name will be "Enclave_t" for "Enclave.edl")
    let edl_dir = std::path::Path::new("Enclave.edl")
        .parent()
        .expect("EDL file should have a parent directory");
    println!("cargo:rustc-link-search=native={}", edl_dir.display());
    println!("cargo:rustc-link-lib=static={}", edl_output.lib_name);
}
```

### For App Build

Create a `build.rs` file in your app project:

```rust
fn main() {
    sgx_build::SgxBuilder::new()
        .build_app("../enclave/Enclave.edl")
        .expect("Failed to build SGX app");
}
```

This simple function `build_app` handles all the necessary steps:
- Processes the EDL file for the untrusted side
- Compiles the generated C code
- Links with the generated EDL object
- Runs if the EDL file changes

The generated EDL bindings (`Enclave_u.c`, `Enclave_u.h`) and compiled library (`libEnclave_u.a`) will be placed in the same directory as the EDL file.

## CVE-2020-0551 Mitigation

LVI (Load Value Injection) mitigations should only be enabled for systems affected by [INTEL-SA-00334](https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00334.html). Please check if your processor is listed in the advisory before enabling these mitigations, as they may impact performance.

To enable LVI mitigations in your enclave build:

```rust
fn main() {
    std::env::set_var("MITIGATION_CVE_2020_0551", "LOAD");
    sgx_build::SgxBuilder::new()
        .build_enclave("Enclave.edl")
        .expect("Failed to build SGX enclave");
}
```

## Environment Variables

- `SGX_SDK`: Path to Intel SGX SDK (default: `/opt/intel/sgxsdk`)
- `SGX_MODE`: SGX execution mode (default: `HW`)
  - `HW`: Hardware mode (requires SGX-enabled CPU)
  - `SW` or `SIM`: Simulation mode (for development without SGX hardware)
- `DEBUG` or `SGX_DEBUG`: Enable debug build with `-O0 -g` flags
- `MITIGATION_CVE_2020_0551`: Set to `LOAD` or `CF` to enable LVI mitigations
