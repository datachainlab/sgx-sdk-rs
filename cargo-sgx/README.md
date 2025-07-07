# cargo-sgx

A Cargo subcommand for building Intel SGX enclaves with Rust. This tool simplifies the development workflow for SGX applications by integrating SGX-specific build steps into the familiar Cargo ecosystem.

## Installation

```sh
# From the repository
$ cargo install --path .

# From GitHub
$ cargo install --git https://github.com/datachainlab/sgx-sdk-rs --branch main cargo-sgx
```

## Commands

- `cargo sgx new` - Create a new SGX enclave project with template files
- `cargo sgx build` - Build an SGX enclave and generate the signed shared object

## Usage

### Create a new SGX enclave project

```sh
# Create an enclave in the default directory (./enclave)
$ cargo sgx new

# Create an enclave in a specific directory
$ cargo sgx new my-enclave

# Create an enclave with a custom name in a specific directory
$ cargo sgx new my-project --name my-enclave
```

### Build an SGX enclave

```sh
# Build in debug mode
$ cargo sgx build

# Build in release mode
$ cargo sgx build --release

# Build with verbose output
$ cargo sgx build --verbose
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](../LICENSE) for details.
