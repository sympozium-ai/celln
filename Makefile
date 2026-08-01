# Development tasks for working ON nouscell.
#
# This is NOT the user interface. Users install `nous` and run `nous <verb>` —
# nothing here is required to use the tool, and nothing here does anything a
# user needs. If you find yourself documenting a make target for users, it
# belongs in the CLI instead.
#
#   make install    build and install `nous` into ~/.cargo/bin
#   make ci         what CI runs
#
# Rust for code, make for orchestration, shell for glue. No Python.

CARGO ?= cargo
.DEFAULT_GOAL := help

.PHONY: help
help: ## show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

.PHONY: install
install: ## build and install the `nous` CLI into ~/.cargo/bin
	$(CARGO) install --path crates/nous-cli --locked
	@echo "installed. try: nous doctor"

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

.PHONY: initramfs
initramfs: ## build the guest initramfs (freestanding init, needs gcc + cpio)
	@./scripts/mkinitramfs.sh

.PHONY: toolfs
toolfs: ## build the sealed tool filesystem image (needs e2fsprogs)
	@./scripts/mktoolfs.sh

.PHONY: guest
guest: initramfs toolfs ## build everything the guest side needs

.PHONY: boot-kvm
boot-kvm: guest ## boot a STOCK kernel and prove the VFS<->memslot join (needs /dev/kvm)
	@$(CARGO) run --quiet -p pilot --features kvm --bin nous-boot-kvm

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
