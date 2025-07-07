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
		if echo "$$dir" | grep -E -q "(enclave$$|sgx-ert|sgx-trts|sgx-tcrypto|sgx-tse|sgx-tseal)"; then \
			echo "Running clippy on $$dir with SGX target..."; \
			TARGET_SPEC="$$(pwd)/unit-test/enclave/x86_64-unknown-unknown-sgx.json"; \
			(cd "$$dir" && cargo clippy -Z build-std=core,alloc --target="$$TARGET_SPEC" --all-features -- -D warnings) || exit 1; \
		else \
			echo "Running clippy on $$dir..."; \
			(cd "$$dir" && cargo clippy --all-targets --all-features -- -D warnings) || exit 1; \
		fi; \
	done

.PHONY: check
check: fmt clippy

.PHONY: test
test:
	@echo "Building and running unit tests..."
	@cd unit-test && make clean all
	@cd unit-test/bin && ./app

.PHONY: toml-fmt
toml-fmt:
	@echo "Formatting TOML files..."
	@taplo fmt --config ./taplo.toml ./**/Cargo.toml

.PHONY: toml-check
toml-check:
	@echo "Verifying TOML syntax..."
	@taplo check --config ./taplo.toml ./**/Cargo.toml
