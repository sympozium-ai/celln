# Scoped artifact native evidence — 2026-09-24

- Implementation source: `460b371650a726c218a9ea666711d6cbe6d377e9`.
- Base: `4a71178c266d0a36fa8a7bfe3b821c48d570af19`.
- Contract: `docs/tenancy-scoped-artifacts.md`.
- Shared fixture: `tests/fixtures/scoped-artifacts/v1.json`, SHA-256
  `d8d8dc6a3505d517d515bc492d86996cd5e3f907e8c9718d3195ecf20c14c800`.
- Raw native proof: `scoped-artifacts-kvm-2026-09-24.log`, SHA-256
  `44f973f31314601f644f4a514e8f8d7b9316ab2d0bb9082344f35783e67a06a0`.
- `installedAcceptance: false`. No shared cluster, host Celln installation,
  primary worktree, real provider, or production credential was used or modified.

## Actual native result

The scoped receiver admitted an enduring parent with a composed, signed runtime
and explicitly lent `workspace-read` / `workspace-write` executables. Actual
guest tool replies proved one write and two reads of `artifact-violet` at
revision 1. The scripted assistant reply was merely `tool completed`; the test
asserted the independent guest tool response, not that assistant text.

Stable parent/incarnation:
`blake3:a8e1d2b323bdc5fbcb115167794c91d956ceb4be006d13c38d1011e13989dacc`.

| Turn | Actual cell ID | Native phase |
| --- | --- | --- |
| Initial | `84be72114921` | Running, retained parent |
| Follow-up 2 | `77433f818314` | Succeeded, child cleanup confirmed |
| Follow-up 3 | `e25f9d87723f` | Succeeded, child cleanup confirmed |

The raw log includes three distinct derived child IDs, execution grants with
`workspace: none`, exact executable/closure/kernel/initrd/toolfs identities and
receipts. Six requests reached only the local TLS fixture gateway. Root cleanup
reported `Cancelled` and `cleanupConfirmed: true`; the live parent registry
reported `Stopped`. Scanning every state-root file found no execution/model
permit bytes. No provider credential file or model profile was installed.

## Commands and outcomes

Builds used `CARGO_BUILD_JOBS=2`. All commands ran from the dedicated worktree.

| Check | Actual result |
| --- | --- |
| `cargo fmt --all --check` | Exit 0 |
| `cargo build --locked` | Exit 0 |
| `cargo build --release --locked --target x86_64-unknown-linux-musl -p celln-pilot --bins` | Exit 0; rebuilt static guest tools |
| `cargo test --locked --workspace --exclude celln-warden -- --test-threads=2` | Exit 0; 430 passed, 19 ignored across test binaries/doctests |
| Warden's built workspace test binary, KVM-accessible execution, `--test-threads=2` | Exit 0; 131 passed, none ignored |
| `cargo clippy --locked -p celln-cli -p celln-warden --all-targets --no-deps -- -D warnings` | Exit 0 |
| Exact `scoped_brokered_artifacts_three_turns_on_real_kvm`, `--ignored --nocapture --test-threads=1` | Exit 0; 1 passed, none skipped |
| Exact pre-existing `scoped_mediated_lifecycles_on_real_kvm`, same flags | Exit 0; regression passed |
| `git diff --check` | Exit 0 |

The ordinary user lacks `/dev/kvm` access. The first unsplit workspace test run
therefore failed five existing warden boot cases with `Permission denied`.
No permissions/groups were changed: only the already-built test executables
were run with `sudo -n`, explicit private scratch `HOME`/`TMPDIR`, and explicit
`CELLN_PILOT_DIR` pointing into this worktree. No privileged Cargo installation
or host configuration changes occurred. The split suite above then passed.

During fixture development, the first native attempt refused missing schema
string minimum bounds (fixed in the fixture), and another attempt hit an
admission-journal `503 AUTH_CONTEXT_LOST` during read polling. Journal locking
uses `LOCK_NB`; the read-only polling helper now tolerates transient unavailable
observations within its fixed deadline and logs them. Start/model operations
are never automatically retried. Subsequent native attempts passed, including
the final recorded artifact proof and the existing scoped lifecycle regression.

Local retained diagnostics (not portable acceptance dependencies):

- Final KVM logs/state:
  `/home/axjns/.hermes/cache/scratch/celln-scoped-final-kvm-Pc3AAS/`.
- Final workspace and warden logs:
  `/home/axjns/.hermes/cache/scratch/celln-scoped-validation-6xQhNM/`.

The strict `scripts/conformance-kvm.sh` list now includes the new artifact case
and rejects skipped/missing cases. The entire strict hardware matrix was not
rerun here; only the two named scoped cases and warden suite were executed.
Cross-namespace installed Sympozium evidence and paired Go fixture consumption
remain downstream integration work, not native-test claims.
