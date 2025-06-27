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

- `cargo sgx init` - Initialize a new SGX enclave project with template files
- `cargo sgx build` - Build an SGX enclave and generate the signed shared object

## Usage

### Initialize a new SGX enclave project

```sh
# Create an enclave in the default directory (./enclave)
$ cargo sgx init

# Create an enclave with a custom name
$ cargo sgx init --name my-enclave

# Create an enclave in a custom directory
$ cargo sgx init --path my-project --name my-enclave
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
