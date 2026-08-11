<p>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/celln-lockup-dark.svg">
    <img src="docs/assets/celln-lockup.svg" width="360" alt="Celln">
  </picture>
</p>

**Celln** runs agents in isolated **cells** that borrow verified tools instead
of rebuilding Linux environments.

```console
$ celln agent --tool python "decode this base64 and name the file type: R0lGODlhAQABAAAAACw="
  ✔ /usr/bin/python permitted in the agent lane
GIF image
```

A model wrote that code. An attested python ran it, on input you have no reason
to trust, in a cell with no network and nothing writable but `/tmp` — then the
cell dissolved.

Read the second line again. It says **agent** lane, and you never had to ask
for it. python is fully attested and keeps its hash, but code a model wrote is
agent-authored input, and handing that to a tool marked `interpreter = true`
demotes the invocation. Authority is decided per call, not per binary.

<p align="center">
  <img src="docs/assets/stack.gif" width="940"
       alt="Two digest-pinned tool images are lent into a hardware-isolated cell, each sealed read-only at its own mount. A model writes a program, an attested python is asked to run it and that call is demoted to the agent lane, it runs and returns its answer, and the lend is finally taken back as the cell dissolves.">
</p>

## How is this different?

Most agent runtimes give an agent a machine. Celln gives it a temporary,
read-only lease on the tools it needs.

[Read the documentation →](https://sympozium-ai.github.io/celln/) ·
[Guided tutorial →](https://sympozium-ai.github.io/celln/tutorial.html)

> *Software is a service the host provides to the process, not property the
> machine owns.*

## Install

```sh
brew install sympozium-ai/celln/celln
```

Homebrew names the `sympozium-ai/homebrew-celln` repository as the
`sympozium-ai/celln` tap. The tap and source repository are public. On Linux,
the formula downloads the static release archive; it does not build Celln with
Rust locally. Building from source needs the one static target that the local
build plane uses for generated programs:

```sh
rustup target add x86_64-unknown-linux-musl
```

Release archives target Linux x86_64; Celln does not publish an ARM64 archive
while its KVM backend is x86-specific.

<details>
<summary>or from source</summary>

```sh
git clone https://github.com/sympozium-ai/celln.git
cd celln
cargo build --release -p celln-cli
./target/release/celln doctor
```
</details>

Sealing cells needs Linux with `/dev/kvm`; generated-program cells additionally
need `gcc`, `cpio`, and `e2fsprogs`. Everywhere else `celln` still validates
specs and runs `celln demo`, and `celln doctor` says which you have.

## Declaring it instead

The one-liner at the top is the short path. For anything you'd repeat, a spec is
the durable artifact — reviewable, checked in, and the thing that says what a
cell may ever be lent. Two tools, from two separate images, in one cell:

```toml
# cell.toml
name = "two-tools"

[cell]
memory = "512MiB"

[[tool]]
alias = "/usr/bin/python"
image = "python"                    # digest-pinned; a tag is refused
exec  = "/usr/local/bin/python3.12"
interpreter = true

[[tool]]
alias = "/usr/bin/curl"
image = "curl"                      # a second, independent image
exec  = "/usr/bin/curl"

[[run]]
exec = "/usr/bin/python"
args = ["-c", "import ssl; print('python  ', ssl.OPENSSL_VERSION)"]

[[run]]
exec = "/usr/bin/curl"
args = ["--version"]
```

```console
$ celln setup                       # once: agent CLI + default tool images
$ celln run cell.toml
● sealing cell two-tools
  · cell sealed, 2 tool(s) lent read-only
  · image mounted at /tools1
  ✔ pilot: /usr/bin/python permitted:tool   exit=0
  ✔ pilot: /usr/bin/curl   permitted:tool   exit=0

python   OpenSSL 3.5.6 7 Apr 2026
curl 8.21.0 (x86_64-pc-linux-musl) libcurl/8.21.0 OpenSSL/3.5.7 …
● cell dissolved
```

Look at the two OpenSSL versions. python came from a glibc image, curl from
a musl one — two libcs and two TLS stacks in the same cell, each its own sealed
namespace, neither aware of the other. Nothing was installed, and nothing
persists: the tools are read-only memory the host lent and can revoke.

Need a tool that isn't shipped? One command — give it a tag, celln pins the
digest:

```console
$ celln image add node:22-slim
● node:22-slim → node@sha256:0f1cd7…
  + added node to ~/.celln/tools.toml
      /usr/bin/node → /usr/local/bin/node
```

## Use it

**1. Get a tool.** Most real tools are a *closure* — a binary, its loader and
the shared objects it resolves by absolute path — so celln lends them as a
sealed filesystem built from a digest-pinned OCI image. `celln setup`
materialises the defaults; pulling is its own step so starting a cell never
waits on a registry.

```sh
$ celln image catalogue
  ✔ python     /usr/bin/python /bin/sh      materialised
  ✔ curl       /usr/bin/curl                materialised
```

**2. Write a spec** — what your agent may be lent, and what it intends to run.

```sh
celln image spec python > agent.toml     # or: celln spec init
```

```toml
name = "code-reviewer"

[cell]
memory = "512MiB"
require_tier = "verified"

[[tool]]
alias = "/usr/bin/python"     # the name your agent uses
image = "python"              # a catalogue name; a tag is refused
exec  = "/usr/local/bin/python3.12"
interpreter = true            # see below

[run]
exec = "/usr/bin/python"
args = ["-c", "print(1 + 1)"]
input = "data"                # the agent wrote it
```

A tool comes from exactly one of three places: `image` + `exec` for a closure,
`path` for a single static binary already on this host, or `builtin = "fetch"`
for the brokered HTTPS capability. A cell can declare several `[[run]]`
invocations and mount several images at once.

**3. Check it** — validation, plus what the trust model will decide.

```sh
$ celln spec check agent.toml
✔ code-reviewer  1 tool(s), 512MiB memory, require_tier=verified

tools
  /usr/bin/python          interpreter  python → /usr/local/bin/python3.12

run
  /usr/bin/python -c print(1 + 1)
  runs in the agent lane — demoted: an interpreter fed agent-authored input
```

`python` is fully attested, but an invocation fed agent-written input moves to
the agent lane — including the `python -c "…"` form that file-level taint
tracking misses.

**4. Run it.**

```sh
$ celln run agent.toml
● sealing cell code-reviewer
  + /usr/bin/python        tier=verified cold — verified now, forged queued
  ✔ /usr/bin/python permitted in the agent lane
  · cell sealed, 1 tool(s) lent read-only
  ✔ pilot: /usr/bin/python permitted:agent
  · /usr/bin/python exit=0

2
● cell dissolved
```

The verdict appears twice on purpose: once on the host before the cell exists,
and once from pilot inside it, after re-hashing the bytes it actually found.

A [guided tutorial](https://sympozium-ai.github.io/celln/tutorial.html) works
through three worked examples — an agent using python, a cell reaching a named
host with no network stack of its own, and two independent toolchains in one
cell.

**5. Verify the isolation.**

```sh
$ celln verify
proving isolation on this machine
  ✔ a ring-0 guest with its own page tables cannot write lent tool code
  ✔ revoking a tool stops it in an already-running cell
```

## A model writes code, a cell runs it

A cell exists to contain code you would rather not run unsealed.
`--show-source` prints what the model wrote.

**With a lent interpreter.** The shortest path: name a catalogue tool, and the
model writes that tool's language.

```sh
$ celln agent --tool python "decode this base64 and name the file type: R0lGODlhAQABAAAAACw="
● asking openai for Python to run as /usr/bin/python
  · replied in 6s, 8 lines
  ≡ /usr/bin/python        tier=verified warm — page map, no build
  ✔ /usr/bin/python permitted in the agent lane
  · cell sealed, 1 tool(s) lent read-only
  ✔ pilot: /usr/bin/python permitted:agent
  · /usr/bin/python exit=0

GIF image
```

You never had to ask for the **agent** lane there. The model's code is
agent-authored input handed to a tool marked `interpreter = true`, so it is
demoted for that invocation — python keeps its hash and loses its authority.

**Or forged from source.** Without `--tool`, the model writes Rust and Celln
compiles it, which is where the more interesting claim lives:

```sh
$ celln agent "print the first 100 primes, space separated"
● asking anthropic (claude-opus-5) to build: print the first 100 primes, space separated
  · waiting for claude (up to 90s; --timeout changes it)
  · replied in 5s
  · selected sealed runtime: Rust 2021 (static musl); 23 source lines  /tmp/celln-agent-1844068/program.rs
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

## Execution lanes

- **Tool lane**: host-provided, attested tools use only the authority the cell loans them.
- **Agent lane**: agent-authored code gets only explicitly loaned capabilities: its executable and workspace by default, with no network.
- **Data**: bytes the agent produced or fetched. Data never gains authority by being handed to an attested tool.

An attested interpreter fed an agent-written script runs in the **agent lane**;
it does not inherit tool-lane authority.

The model writes the program **on the host**; `forge` compiles it **twice, in
different directories**, and compares the bytes; `assay` grades on what that
rebuild reported and records who wrote it; the binary is sealed into the cell as
read-only memory; and pilot re-hashes it in the guest and decides for itself.
Under DAX there is no page-cache copy, so the instructions the guest executes
*are* the host's pages.

A `forged` tier requires a matching rebuild and records the reproduced recipe.
Otherwise the artifact is `verified`. `assay` checks that a proof names the
bytes being admitted. This establishes reproducibility on this machine and
toolchain, not across every environment.

Pick who writes it — `celln agents` shows what this host can use:

```sh
$ celln setup                         # finds an agent CLI and materialises the default tool images
✔ default agent: openai (~/.config/celln/config.toml)

$ celln agents
  ✔ anthropic  claude-opus-5          claude
  ✔ openai     (cli default)          codex  default
  ✔ local      qwen2.5-coder          ollama

$ celln agents --set-default anthropic # change the saved default
$ celln agent --agent openai "…"       # override it for one invocation
$ CELLN_AGENT=local celln agent "…"    # override it for one shell command
```

The saved setting is credential-free:

```toml
# ~/.config/celln/config.toml (or $XDG_CONFIG_HOME/celln/config.toml)
[agent]
default = "openai"
```

`celln agent "…"` is for work that generates code to run; that path is where
Celln seals and governs the resulting program. Without `--tool` the model
writes Rust, which is forged into a static binary and attested. With
`--tool python` it writes that tool's language instead, and the program is
interpreted by a lent, attested interpreter — which makes it agent-authored
input, and so agent-lane, automatically.

Network-shaped work must declare exactly where it may reach before a model is
called:

```sh
celln agent --allow-host example.com "crawl https://example.com/ …"
```

Without `--allow-host`, Celln returns `Unsupported`; it does not generate a
crawler that can never connect.

Backends are subprocess adapters over CLIs you have already authenticated, not
linked SDKs. `celln` never reads, stores, or forwards a key; credentials remain
on the host.

Cells have no ambient network, so API credentials never enter the guest; only
brokered bytes cross the boundary. Grading records provenance, not program
correctness or safety.

Getting the *model itself* into a cell is the same problem as any other egress,
and gets the same answer — an attested network stack behind a broker, never an
ambient NIC.

## Output

Human-readable on a terminal, NDJSON the moment it is not. No flag needed,
though `--json` and `--no-json` force it either way.

```sh
celln run agent.toml | jq -r 'select(.event=="tool_resolved") | "\(.alias) \(.tier)"'
celln ps -a --json | jq -r "select(.status==\"failed\") | .id"
celln doctor --json | jq -e '.can_seal_cells // empty' >/dev/null && echo "can seal"
```

Diagnostics go to stderr, so they never land in the data. Exit codes mean
something: `0` ok · `1` error · `2` spec invalid · `3` host cannot seal cells ·
`4` refused by the trust model · `5` unsupported.

## Isolation and limits

Based on our hardware tests, `celln run` seals a microVM and lends tools as
read-only memory that the guest cannot modify. `celln verify` runs a guest that
enters protected mode and maps a sealed page writable in page tables it wrote.
The test also checks revocation in an already-running cell.

`celln agent` runs agent-authored programs behind a Landlock filesystem boundary
and a seccomp syscall filter.
The guest may execute `/tools/program` and write only to `/celln/work`; network,
mounting, tracing, and privilege gain are refused. `celln run` remains the
spec-driven sealing path.

Run `celln verify` and `make bench-kvm` on a KVM host to reproduce the hardware
checks and measurements.

## Reading

The full set is published at [sympozium-ai.github.io/celln](https://sympozium-ai.github.io/celln/).

| Topic | Where | Covers |
|---|---|---|
| Start here | [Start here](https://sympozium-ai.github.io/celln/start.html) | Five commands, about five minutes: install, connect an agent, then `doctor` / `spec` / `run` / `verify` / `agent` in order. |
| Command reference | [CLI](https://sympozium-ai.github.io/celln/cli.html) | The commands most people need, grouped: daily use, asking an agent, running declared tools, inspecting a run. |
| Tutorial | [Tutorial](https://sympozium-ai.github.io/celln/tutorial.html) | Three worked cells, each teaching one idea; plus adding your own tool. |
| Concepts hub | [Concepts](https://sympozium-ai.github.io/celln/concepts.html) | The four-page series below, as one entry point. |
| The model | [Model](https://sympozium-ai.github.io/celln/model.html) | Mote, cell, assay, warden, pilot — the vocabulary and one cell's lifecycle. |
| Tool lane | [Tool lane](https://sympozium-ai.github.io/celln/tool-lane.html) | `celln spec` / `celln run`: declaring a tool, closures and images, tiers, the interpreter flag. |
| Agent lane | [Agent lane](https://sympozium-ai.github.io/celln/agent-lane.html) | `celln agent` walkthrough: forging, attestation, choosing a backend, brokered egress. |
| Security boundary | [Security](https://sympozium-ai.github.io/celln/security.html) | What's hardware-enforced, what's brokered, and what Celln does not claim. |
| Vocabulary reference | [docs/NAMES_AND_CONVENTIONS.md](docs/NAMES_AND_CONVENTIONS.md) | Every term (mote, cell, lane, tier, …) in one place. |
| Run the hardware checks | `celln verify` and `make bench-kvm` | Reproduce the isolation proofs and spawn-latency measurements on your own KVM host. |
| Working on Celln itself | [AGENTS.md](AGENTS.md), then `make help` | Contributor setup, the Makefile targets, what CI runs. |

## Vocabulary

- **mote** — the substrate at rest. The seed.
- **cell** — a live, sealed, tool-loaned mote. *Every cell is a sealed mote.*
- **tool lane / agent lane / data** — attested host tools use loaned authority;
  agent-authored execution is bounded in the agent lane; data never gains
  authority by crossing into a tool.

Pre-alpha, single-host. Name pending formal trademark/domain clearance.
