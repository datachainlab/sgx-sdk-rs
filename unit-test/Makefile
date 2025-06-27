# Paths
SGX_SDK ?= /opt/sgxsdk
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
Enclave_SO := enclave/target/x86_64-unknown-unknown-sgx/release/enclave.so
Signed_Enclave := bin/enclave.signed.so
Enclave_Config := enclave/Enclave.config.xml
Enclave_Key := enclave/Enclave_private.pem
App_Binary := app/target/release/app

.PHONY: all build build-enclave build-app sign clean

all: build sign

build: build-enclave build-app

build-enclave:
	@echo "Building enclave (including .so generation)..."
	cd enclave && cargo sgx build --release

build-app:
	@echo "Building app..."
	cd app && cargo build --release
	@echo "Copying app binary to bin/..."
	@cp $(App_Binary) bin/

sign: $(Signed_Enclave)

$(Signed_Enclave): build
	@mkdir -p bin
	@$(SGX_ENCLAVE_SIGNER) sign -key $(Enclave_Key) -enclave $(Enclave_SO) -out $@ -config $(Enclave_Config)
	@echo "SIGN => $@"

clean:
	@rm -rf bin/*
	@cd enclave && cargo clean
	@cd app && cargo clean
