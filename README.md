# sgx-sdk-rs

Rust SDK for [Intel SGX (Software Guard Extensions)](https://github.com/intel/linux-sgx) - A collection of tools and libraries for building secure enclaves in Rust.

## Features

- **Rust SGX Libraries**: Core libraries for developing SGX enclaves
- **cargo-sgx**: A Cargo subcommand that streamlines SGX enclave development by providing:
  - Project initialization with templates (`cargo sgx new`)
  - Automated enclave building command (`cargo sgx build`)
  - Seamless integration with the Rust toolchain using custom target `x86_64-unknown-unknown-sgx`

## Getting Started

### Install cargo-sgx

```bash
cargo install --git https://github.com/datachainlab/sgx-sdk-rs --branch main cargo-sgx
```

Or install from local directory:

```bash
cargo install --path ./cargo-sgx
```

### Create Your First Enclave

```bash
cargo sgx new my-enclave
cd my-enclave
cargo sgx build
```

## Project Structure

- `sgx-*` - Core SGX libraries (types, ert, trts, tseal, urts, etc.)
- [`cargo-sgx/`](cargo-sgx/) - Cargo subcommand for SGX development
- [`sgx-build/`](sgx-build/) - Build utilities for SGX enclaves
- [`unit-test/`](unit-test/) - Unit tests for core SGX libraries
- [`samples/hello-rust/`](samples/hello-rust/) - Basic SGX enclave example

## Documentation

- [cargo-sgx README](cargo-sgx/README.md) - Learn about the cargo-sgx tool
- [sgx-build README](sgx-build/README.md) - Learn about the sgx-build crate

## Requirements

- Rust nightly toolchain
- Intel SGX SDK
- Intel SGX Driver(only for Hardware Mode)

## Acknowledgements

This project is based on the excellent work done by the [Apache Teaclave SGX SDK](https://github.com/apache/incubator-teaclave-sgx-sdk/tree/1b1d03376056321441ef99716aa0888bd5ef19f7) project. We are grateful for their foundational contributions to the Rust SGX ecosystem.

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.
