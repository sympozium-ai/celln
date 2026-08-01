# Nouscell POC — build orchestration.
# Rust for code, make for orchestration, shell for glue. No Python.

CARGO ?= cargo
.DEFAULT_GOAL := help

.PHONY: help
help: ## show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## build the whole workspace (mock backend)
	$(CARGO) build

.PHONY: release
release: ## optimised build
	$(CARGO) build --release

.PHONY: test
test: ## run all unit tests
	$(CARGO) test

.PHONY: demo
demo: ## run the five-beat proof loop (mock mode, no KVM)
	@$(CARGO) run --quiet --bin nous-demo

.PHONY: test-kvm
test-kvm: ## run warden tests against REAL KVM (needs /dev/kvm)
	$(CARGO) test -p warden --features kvm

.PHONY: demo-kvm
demo-kvm: ## run the five-beat proof on REAL KVM (needs /dev/kvm)
	@$(CARGO) run --quiet -p pilot --features kvm --bin nous-demo-kvm

.PHONY: bench-kvm
bench-kvm: ## measure the M1/M2 exit criteria on REAL KVM -> bench/results/
	@$(CARGO) run --quiet --release -p pilot --features kvm --bin nous-bench-kvm

.PHONY: fmt
fmt: ## format all crates
	$(CARGO) fmt

.PHONY: fmt-check
fmt-check: ## check formatting without writing (skips if rustfmt absent)
	@command -v rustfmt >/dev/null 2>&1 && $(CARGO) fmt --check || echo "  (rustfmt not installed — skipping fmt-check)"

.PHONY: clippy
clippy: ## lint (warnings as errors; skips if clippy absent)
	@command -v cargo-clippy >/dev/null 2>&1 && $(CARGO) clippy --all-targets -- -D warnings || echo "  (clippy not installed — skipping)"

.PHONY: doctor
doctor: ## check host readiness for the real (KVM) path
	@./scripts/doctor.sh

.PHONY: ci
ci: fmt-check build test ## what CI runs

.PHONY: clean
clean: ## remove build artifacts and demo state
	$(CARGO) clean
	rm -rf .nous
