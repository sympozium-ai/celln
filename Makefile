# Development tasks for working on Celln.
#
# This is NOT the user interface. Users install `celln` and run `celln <verb>` —
# nothing here is required to use the tool, and nothing here does anything a
# user needs. If you find yourself documenting a make target for users, it
# belongs in the CLI instead.
#
#   make install    build and install `celln` into ~/.cargo/bin
#   make ci         what CI runs
#
# Rust for code, make for orchestration, shell for glue. No Python.

CARGO ?= cargo
FETCH_URL ?= https://example.com/
.DEFAULT_GOAL := help

.PHONY: help
help: ## show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

.PHONY: install
install: ## build and install the `celln` CLI into ~/.cargo/bin
	$(CARGO) install --path crates/celln-cli --locked
	@echo "installed. try: celln doctor"

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
	@$(CARGO) run --quiet --bin celln-demo

.PHONY: test-kvm
test-kvm: ## run warden tests against REAL KVM (needs /dev/kvm)
	$(CARGO) test -p celln-warden --features kvm

.PHONY: demo-kvm
demo-kvm: ## run the five-beat proof on REAL KVM (needs /dev/kvm)
	@$(CARGO) run --quiet -p celln-pilot --features kvm --bin celln-demo-kvm

.PHONY: bench-kvm
bench-kvm: ## measure the M1/M2 exit criteria on REAL KVM -> target/celln-bench/
	@$(CARGO) run --quiet --release -p celln-pilot --features kvm --bin celln-bench-kvm

.PHONY: initramfs
initramfs: ## build the guest initramfs (freestanding init, needs gcc + cpio)
	@./scripts/mkinitramfs.sh

.PHONY: toolfs
toolfs: ## build the sealed tool filesystem image (needs e2fsprogs)
	@./scripts/mktoolfs.sh

.PHONY: diagram
diagram: ## regenerate the README stack diagram (needs rsvg-convert + ffmpeg)
	@./scripts/mkdiagram.sh

.PHONY: guest
guest: initramfs toolfs ## build everything the guest side needs

.PHONY: boot-kvm
boot-kvm: guest ## boot a STOCK kernel and prove the VFS<->memslot join (needs /dev/kvm)
	@$(CARGO) run --quiet -p celln-pilot --features kvm --bin celln-boot-kvm

.PHONY: fetch-proof
fetch-proof: ## prove a real cell fetches HTTPS through pilot (needs /dev/kvm + egress)
	@$(CARGO) run --quiet -p celln-pilot --features kvm --bin celln-fetch-proof -- $(FETCH_URL)

.PHONY: acceptance-kvm
acceptance-kvm: ## prove setup, agent cell, output, and ps on real KVM
	@$(CARGO) build --quiet -p celln-cli
	@./scripts/acceptance-agent-cell.sh

.PHONY: fmt
fmt: ## format all crates
	$(CARGO) fmt

.PHONY: fmt-check
fmt-check: ## check formatting without writing
	$(CARGO) fmt --check

.PHONY: clippy
clippy: ## lint (warnings as errors)
	$(CARGO) clippy --all-targets --all-features -- -D warnings

.PHONY: doctor
doctor: ## check host readiness for the real (KVM) path
	@./scripts/doctor.sh

.PHONY: ci
ci: fmt-check clippy build test ## what CI runs

.PHONY: clean
clean: ## remove build artifacts and demo state
	$(CARGO) clean
	rm -rf .celln
