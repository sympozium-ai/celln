# nouscell

**Nouscell** ( _NOWSS-cell_ ) — run agents in hardware-isolated **cells**, where
every tool is attested memory the host lends in and can revoke in microseconds.

> *Software is a service the host provides to the process, not property the
> machine owns.*

<p align="center">
  <img src="docs/assets/stack.gif" width="820"
       alt="A tool is lent from the host store into a hardware-isolated cell, sealed read-only, demoted to the data lane when an interpreter is fed agent-authored input, its write refused by the hardware, and finally revoked out of the running cell.">
</p>

## Install

```sh
brew install sympozium-ai/tap/nouscell
```

<details>
<summary>or from source</summary>

```sh
cargo install --git https://github.com/sympozium-ai/nouscell nous-cli
```
</details>

Sealing cells needs Linux with `/dev/kvm`. Everywhere else `nous` still
validates specs and runs `nous demo`, and `nous doctor` says which you have.

## Use it

**1. Write a spec** — what your agent may be lent, and what it intends to run.

```sh
nous spec init > agent.toml
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
$ nous spec check agent.toml
✔ code-reviewer  1 tool(s), 256MiB memory, require_tier=verified

tools
  /usr/bin/python          interpreter  /usr/bin/python3

run
  /usr/bin/python review.py
  runs in the data lane — demoted: an interpreter fed agent-authored input
```

That demotion is the point. `python` is fully attested, but the moment it is
fed something the agent wrote, *that invocation* runs collared — including the
`python -c "…"` form that file-level taint tracking misses.

**3. Run it.**

```sh
$ nous run agent.toml
● sealing cell code-reviewer
  + /usr/bin/python        tier=verified cold — verified now, forged queued
  · microVM sealed, phase=Materialise
  · /usr/bin/python sealed read-only into the cell
  · authority ratcheted to Work — no further tools can be lent
  ✔ /usr/bin/python permitted in the data lane
● cell dissolved
```

**4. Prove it.** Not a claim in a README — run it on your machine.

```sh
$ nous verify
proving isolation on this machine
  ✔ a ring-0 guest with its own page tables cannot write lent tool code
  ✔ revoking a tool stops it in an already-running cell
```

## End to end: a model writes code, a cell runs it

```sh
$ nous agent "print the first 100 primes, space separated"
● asking claude for a program
  · 16 lines of rust
  + forged  blake3:c76fdc66321d6990def93a9e130d7b273acc1bcca5a9716973eb01ce336cdaa4  436 KiB
  · cell sealed, tools lent read-only
  ✔ pilot: /agent/program permitted:tool

2 3 5 7 11 13 17 19 23 29 31 37 41 43 47 53 59 61 67 71 73 79 83 89 97 ...
```

Claude writes the program **on the host**; `rustc` builds it static; forgectl
attests the bytes it actually built; the binary is sealed into the cell as
read-only memory; and pilot re-hashes it in the guest and execs it by hash out
of the sealed mapping. Under DAX there is no page-cache copy, so the
instructions the guest executes *are* the host's pages.

Two things this is careful about. **The cell has no network** — not a
firewalled one, none — so the API credential never goes near it; only bytes
cross. **Attestation is provenance, not intent**: forging says these bytes are
what we built, not that the program is correct or benign. Nobody read it. The
cell is what makes running it acceptable anyway.

Getting the *model itself* into a cell is the same problem as any other egress,
and gets the same answer — an attested network stack behind a broker, never an
ambient NIC ([ADR-0006](docs/decisions/0006-hermetic-cells-network-as-a-tool.md)).

## It pipes

Human-readable on a terminal, NDJSON the moment it is not. No flag needed,
though `--json` and `--no-json` force it either way.

```sh
nous run agent.toml | jq -r 'select(.event=="tool_resolved") | "\(.alias) \(.tier)"'
nous ps -a --json | jq -r "select(.status==\"failed\") | .id"
nous doctor --json | jq -e '.can_seal_cells // empty' >/dev/null && echo "can seal"
```

Diagnostics go to stderr, so they never land in the data. Exit codes mean
something: `0` ok · `1` error · `2` spec invalid · `3` host cannot seal cells.

## What is real

`nous run` seals a **real** hardware-isolated microVM and lends it your tools as
read-only memory that the guest cannot modify — proven against a guest that
enters protected mode and maps the page writable in page tables it wrote itself.
Revocation reaches a cell that is already running.

**In-cell execution works for the tool lane** — that is what `nous agent` does
above. **Data-lane exec is still refused**, deliberately: it needs the per-exec
collar (Landlock + seccomp), and running collared code before the collar exists
would be exactly backwards. `nous run` still stops at sealing; `nous agent` is
the path that reaches execution.

Honest numbers, including a gate we miss: [docs/findings/](docs/findings/).

## Reading

| | |
|---|---|
| The five-minute tour | [docs/TRY_IT.md](docs/TRY_IT.md) |
| What is proven, and what is not | [docs/findings/](docs/findings/) |
| Why each choice was made | [docs/decisions/](docs/decisions/) — ADRs 0001–0005 |
| Vocabulary — mote, cell, lane, tier | [docs/NAMES_AND_CONVENTIONS.md](docs/NAMES_AND_CONVENTIONS.md) |
| Working on nouscell itself | [AGENTS.md](AGENTS.md), then `make help` |

## Vocabulary

- **mote** — the substrate at rest. The seed.
- **cell** — a live, sealed, tool-loaned mote. *Every cell is a sealed mote.*
- **tool lane / data lane** — attested code has authority; code the agent wrote
  runs collared. An interpreter fed agent-authored input is demoted to the data
  lane for that invocation.

Pre-alpha, single-host. Working name pending trademark/domain clearance.
