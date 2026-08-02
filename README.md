# Cellulose

**Cellulose** — run agents in hardware-isolated **cells**, where
every tool is attested memory the host lends in and can revoke in microseconds.

> *Software is a service the host provides to the process, not property the
> machine owns.*

<p align="center">
  <img src="docs/assets/stack.gif" width="820"
       alt="A tool is lent from the host store into a hardware-isolated cell, sealed read-only, moved to the agent lane when an interpreter is fed agent-authored input, its write refused by the hardware, and finally revoked out of the running cell.">
</p>

## Install

```sh
brew tap sympozium-ai/tap
brew install sympozium-ai/tap/cellulose
```

The tap and source repository are private: this uses the SSH Git key you
already use for GitHub. On Linux, enable the one static target that the local
build plane uses for generated programs:

```sh
rustup target add x86_64-unknown-linux-musl
```

<details>
<summary>or from source</summary>

```sh
git clone git@github.com:sympozium-ai/cellulose.git
cd cellulose
cargo build --release -p cell-cli
./target/release/cell doctor
```
</details>

Sealing cells needs Linux with `/dev/kvm`; generated-program cells additionally
need `gcc`, `cpio`, and `e2fsprogs`. Everywhere else `cell` still validates
specs and runs `cell demo`, and `cell doctor` says which you have.

## Use it

**1. Write a spec** — what your agent may be lent, and what it intends to run.

```sh
cell spec init > agent.toml
```

```toml
name = "code-reviewer"

[cell]
memory = "256MiB"
require_tier = "verified"

[[tool]]
alias = "/usr/bin/python"     # the name your agent uses
path = "/usr/bin/python3"     # where the bytes come from
interpreter = true            # see below

[run]
exec = "/usr/bin/python"
args = ["review.py"]
input = "data"                # the agent wrote it
```

**2. Check it** — validation, plus what the trust model will decide.

```sh
$ cell spec check agent.toml
✔ code-reviewer  1 tool(s), 256MiB memory, require_tier=verified

tools
  /usr/bin/python          interpreter  /usr/bin/python3

run
  /usr/bin/python review.py
  runs in the agent lane — demoted: an interpreter fed agent-authored input
```

That demotion is the point. `python` is fully attested, but the moment it is
fed something the agent wrote, *that invocation* moves to the agent lane — including the
`python -c "…"` form that file-level taint tracking misses.

**3. Run it.**

```sh
$ cell run agent.toml
● sealing cell code-reviewer
  + /usr/bin/python        tier=verified cold — verified now, forged queued
  · microVM sealed, phase=Materialise
  · /usr/bin/python sealed read-only into the cell
  · authority ratcheted to Work — no further tools can be lent
  ✔ /usr/bin/python permitted in the agent lane
● cell dissolved
```

**4. Prove it.** Not a claim in a README — run it on your machine.

```sh
$ cell verify
proving isolation on this machine
  ✔ a ring-0 guest with its own page tables cannot write lent tool code
  ✔ revoking a tool stops it in an already-running cell
```

## Experimental: a model writes code, a cell runs it

This is for **computations, not questions**. A cell exists to contain code you
would rather not run unsealed — if nothing executes, it has nothing to protect
you from, and asking the model directly is the right tool. `--show-source`
prints what it wrote.

```sh
$ cell agent "print the first 100 primes, space separated"
● asking anthropic (claude-opus-5) to build: print the first 100 primes, space separated
  · waiting for claude (up to 90s; --timeout changes it)
  · replied in 5s
  · selected sealed runtime: Rust 2021 (static musl); 23 source lines  /tmp/nous-agent-1844068/program.rs
  + rebuilt, reproduced  blake3:c0d7ceb8247d62bee808d6dc84b1ea57abeb7c16c95e46b5dc126f9abacd40b7  436 KiB  tier=forged author=agent
  · cell sealed, tools lent read-only
  ✔ pilot: /agent/program permitted:agent

2 3 5 7 11 13 17 19 23 29 31 ...
```

The program ran in the **agent lane**. The
program was graded `forged` — we compiled it ourselves from source we hold. It
is still `author=agent`, and agent-authored code never carries tool-lane
authority at any tier. Pilot gives it only its own executable plus a writable
workspace; Landlock rejects other filesystem access and seccomp rejects network
and privileged syscalls.

Compiling is not a way around that. `rustc` fed model-written source is
`python` fed model-written source with the interpretation moved earlier; if the
laundering ban stops one it has to stop both.

`--trust-agent-code` remains only as an explicitly unsafe debugging override;
it is not part of the normal example.

## The model, in three lines

- **Tool lane**: host-provided, attested tools use only the authority the cell loans them.
- **Agent lane**: agent-authored code gets only explicitly loaned capabilities: its executable and workspace by default, with no network.
- **Data**: bytes the agent produced or fetched. Data never gains authority by being handed to an attested tool.

That last rule is the point: `python` is trusted tooling, but `python` fed an
agent-written script is an **agent-lane** execution, not a way to inherit the
tool lane.

The model writes the program **on the host**; `forge` compiles it **twice, in
different directories**, and compares the bytes; `assay` grades on what that
rebuild reported and records who wrote it; the binary is sealed into the cell as
read-only memory; and pilot re-hashes it in the guest and decides for itself.
Under DAX there is no page-cache copy, so the instructions the guest executes
*are* the host's pages.

> **`forged` is earned here, not asserted.** A rebuild that reproduces earns the
> tier and records the recipe it reproduced from; one that does not is graded
> `verified` instead — we still hold the bytes, we just cannot claim they were
> reproduced. `assay` checks the proof is about the bytes in hand before
> recording anything, so a good proof cannot be carried alongside a different
> binary. Scope: this proves reproducibility *on this machine with this
> toolchain*, not that anyone anywhere gets the same bytes
> ([ADR-0008](docs/decisions/0008-the-forged-tier-is-earned.md)).

Pick who writes it — `cell agents` shows what this host can use:

```sh
$ cell setup                         # discovers codex, claude, or ollama
✔ default agent: openai (~/.config/cell/config.toml)

$ cell agents
  ✔ anthropic  claude-opus-5          claude
  ✔ openai     (cli default)          codex  default
  ✔ local      qwen2.5-coder          ollama

$ cell agents --set-default anthropic # change the saved default
$ cell agent --agent openai "…"       # override it for one invocation
$ CELL_AGENT=local cell agent "…"     # override it for one shell command
```

The saved setting is deliberately small and credential-free:

```toml
# ~/.config/cell/config.toml (or $XDG_CONFIG_HOME/cell/config.toml)
[agent]
default = "openai"
```

Use `cell ask "…"` for a question: it asks the selected agent directly on the
host because no program runs and there is nothing to contain. Use `cell agent
"…"` for work that generates code to run; that path is where Cellulose seals
and governs the resulting program. The agent selects a runtime from the cell's
sealed capability set; today that set contains one static Rust runtime. Adding
a runtime is a capability change—not a prompt convention—because its bytes
must be attested, sealed, and revocable too.

Network-shaped work must declare exactly where it may reach before a model is
called:

```sh
cell agent --allow-host example.com "crawl https://example.com/ …"
```

Without `--allow-host`, Cellulose returns `Unsupported`; it does not generate a
crawler that can never connect.

Backends are subprocess adapters over CLIs you have already authenticated, not
linked SDKs — `cell` never reads, stores, or forwards a key. That is not just
convenience: under ADR-0006 the credential belongs to the host and must never
approach the cell.

Two things this is careful about. **The cell has no network** — not a
firewalled one, none — so the API credential never goes near it; only bytes
cross. **Grading is provenance, not intent**: a tier says where these bytes came
from, not that the program is correct or benign. Nobody read it. The cell is
what makes running it acceptable anyway.

Getting the *model itself* into a cell is the same problem as any other egress,
and gets the same answer — an attested network stack behind a broker, never an
ambient NIC ([ADR-0006](docs/decisions/0006-hermetic-cells-network-as-a-tool.md)).

## It pipes

Human-readable on a terminal, NDJSON the moment it is not. No flag needed,
though `--json` and `--no-json` force it either way.

```sh
cell run agent.toml | jq -r 'select(.event=="tool_resolved") | "\(.alias) \(.tier)"'
cell ps -a --json | jq -r "select(.status==\"failed\") | .id"
cell doctor --json | jq -e '.can_seal_cells // empty' >/dev/null && echo "can seal"
```

Diagnostics go to stderr, so they never land in the data. Exit codes mean
something: `0` ok · `1` error · `2` spec invalid · `3` host cannot seal cells ·
`4` refused by the trust model · `5` unsupported.

## What is real

`cell run` seals a **real** hardware-isolated microVM and lends it your tools as
read-only memory that the guest cannot modify — proven against a guest that
enters protected mode and maps the page writable in page tables it wrote itself.
Revocation reaches a cell that is already running.

**In-cell execution works in the agent lane** — `cell agent` runs agent-authored
programs behind a Landlock filesystem boundary and a seccomp syscall filter.
The guest may execute `/tools/program` and write only to `/nous/work`; network,
mounting, tracing, and privilege gain are refused. `cell run` remains the
spec-driven sealing path.

Honest numbers, including a gate we miss: [docs/findings/](docs/findings/).

## Reading

| | |
|---|---|
| The five-minute tour | [docs/TRY_IT.md](docs/TRY_IT.md) |
| What is proven, and what is not | [docs/findings/](docs/findings/) |
| Why each choice was made | [docs/decisions/](docs/decisions/) — ADRs 0001–0008 |
| Vocabulary — mote, cell, lane, tier | [docs/NAMES_AND_CONVENTIONS.md](docs/NAMES_AND_CONVENTIONS.md) |
| Working on Cellulose itself | [AGENTS.md](AGENTS.md), then `make help` |

## Vocabulary

- **mote** — the substrate at rest. The seed.
- **cell** — a live, sealed, tool-loaned mote. *Every cell is a sealed mote.*
- **tool lane / agent lane / data** — attested host tools use loaned authority;
  agent-authored execution is bounded in the agent lane; data never gains
  authority by crossing into a tool.

Pre-alpha, single-host. Name pending formal trademark/domain clearance.
