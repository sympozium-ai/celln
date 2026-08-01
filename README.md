# nouscell

**Nouscell** ( _NOWSS-cell_ ) — run agents in hardware-isolated **cells**, where
every tool is attested memory the host lends in and can revoke in microseconds.

> *Software is a service the host provides to the process, not property the
> machine owns.*

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

**In-cell execution of your command is not wired yet** (build plan M5: stripped
mote kernel + `pilot`). Today `nous run` provisions the cell, attests and seals
the tools, and applies every trust decision — the isolation substrate, not yet a
place to run arbitrary work.

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
