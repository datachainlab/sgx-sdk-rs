.PHONY: fmt
fmt:
	@find . -name Cargo.toml -not -path "./target/*" -exec dirname {} \; | while read dir; do \
		echo "Formatting $$dir..."; \
		(cd "$$dir" && cargo fmt) || exit 1; \
	done

.PHONY: fmt-check
fmt-check:
	@find . -name Cargo.toml -not -path "./target/*" -exec dirname {} \; | while read dir; do \
		echo "Checking $$dir..."; \
		(cd "$$dir" && cargo fmt -- --check) || exit 1; \
	done

.PHONY: clippy
clippy:
	@find . -name Cargo.toml -not -path "./target/*" -exec dirname {} \; | while read dir; do \
		if echo "$$dir" | grep -E -q "(enclave$$)"; then \
			echo "Running clippy on $$dir with SGX target..."; \
			TARGET_SPEC="$$(pwd)/unit-test/enclave/x86_64-unknown-unknown-sgx.json"; \
			(cd "$$dir" && cargo clippy -Z build-std=core,alloc --target="$$TARGET_SPEC" --all-features -- -D warnings) || exit 1; \
		else \
			echo "Running clippy on $$dir..."; \
			(cd "$$dir" && cargo clippy --all-targets --all-features -- -D warnings) || exit 1; \
		fi; \
	done

.PHONY: check
check: fmt-check clippy

.PHONY: test
test: enclave-test untrusted-test
	@echo "All tests completed successfully!"

.PHONY: enclave-test
enclave-test:
	@echo "Building and running enclave unit tests..."
	@cd unit-test && make clean all
	@cd unit-test/bin && ./app

.PHONY: untrusted-test
untrusted-test:
	@echo "Running untrusted crate tests..."
	@echo "Testing sgx-types..."
	@cargo +stable test --manifest-path sgx-types/Cargo.toml --features urts
	@echo "Testing sgx-urts..."
	@cargo +stable test --manifest-path sgx-urts/Cargo.toml --no-default-features --features simulate_utils
	@echo "Testing sgx-build..."
	@cargo +stable test --manifest-path sgx-build/Cargo.toml
	@echo "Testing cargo-sgx..."
	@cargo +stable test --manifest-path cargo-sgx/Cargo.toml

.PHONY: toml-fmt
toml-fmt:
	@echo "Formatting TOML files..."
	@taplo fmt --config ./taplo.toml ./**/Cargo.toml

.PHONY: toml-check
toml-check:
	@echo "Verifying TOML syntax..."
	@taplo check --config ./taplo.toml ./**/Cargo.toml
