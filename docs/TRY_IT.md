# Try it

Five commands, about five minutes. Each proves something specific, and this page
says what to look for so you can read it without running anything.

> **The honest part first.** `nous run` does not yet execute your command inside
> the cell. There is no toolplane, no vsock, no in-cell shell — that is build
> plan M5. What exists today is the **isolation substrate**: a real
> hardware-isolated microVM, your tools sealed into it as memory the guest
> cannot modify, and every trust decision applied. If you are evaluating whether
> the idea holds up, this is the evidence.

---

## 1. What can this machine do?

```sh
nous doctor
```

```
host
  ✔ kvm            /dev/kvm available
  ✔ cpu-virt       vmx/svm present
  ✔ guest-kernel   /boot/vmlinuz-7.1.4-200.fc44.x86_64
  ✔ cargo          /home/you/.cargo/bin/cargo

✔ this machine can seal real, hardware-isolated cells.
```

Every failed check prints what to do about it. Exit code `3` means "cannot seal
cells", so a script can branch without parsing text:

```sh
nous doctor -q || echo "no hardware isolation here"
```

---

## 2. Write a spec

```sh
nous spec init > agent.toml
```

The template is commented in place — it is meant to be read, not just filled
in. The field worth understanding is `interpreter`:

```toml
[[tool]]
alias = "/usr/bin/python"
path = "/usr/bin/python3"
interpreter = true
```

`interpreter = true` is the most consequential line in the file. An interpreter
fed something the agent wrote is moved to the agent lane *for that
invocation*, so an agent cannot launder its own code into full authority by
handing it to `python`. Mark interpreters as interpreters; `nous spec check`
warns if you forget on a name it recognises.

---

## 3. Check it before running it

```sh
nous spec check agent.toml
```

```
✔ code-reviewer  1 tool(s), 256MiB memory, require_tier=verified

tools
  /usr/bin/python          interpreter  /usr/bin/python3

run
  /usr/bin/python review.py
  runs in the data lane — demoted: an interpreter fed agent-authored input
```

**What to notice.** It tells you the *lane your run will land in* before
anything is sealed. That last line is the laundering ban applied to your file.

Mistakes read like a compiler, and every one carries a fix:

```
invalid spec in agent.toml
  ✘ tool[0].path
    /nope/missing does not exist
    fix: point at a real file on this host; a tool is bytes, and they have to come from somewhere
  ✘ run.exec
    "/usr/bin/ghost" is not one of the tools
    fix: add a [[tool]] with alias = "/usr/bin/ghost", or point run.exec at one of: /usr/bin/python
```

A typo is an error, not a shrug — `teir = "forged"` is rejected rather than
ignored, because a silently-dropped tier means a cell quietly running at the
wrong trust level.

---

## 4. Seal a cell

```sh
nous run agent.toml
```

```
● sealing cell code-reviewer
  + /usr/bin/python        tier=verified cold — verified now, forged queued
  · microVM sealed, phase=Materialise
  · /usr/bin/python sealed read-only into the cell
  · authority ratcheted to Work — no further tools can be lent
  ✔ /usr/bin/python permitted in the data lane
● cell dissolved
```

**What to notice.**

- `cold — verified now, forged queued`: an unseen tool is admitted at Verified
  in seconds and a hermetic rebuild is queued *behind* the traffic. Launch is
  never slow; trust upgrades asynchronously. Run it again and it is `warm — page
  map, no build`.
- `authority ratcheted to Work`: once any agent-authored code has run, the cell
  can never be lent another tool. Authority only shrinks, and the host enforces
  it, so a compromised cell cannot roll it back.
- Your 24 MB Python binary really was sealed into a microVM's physical address
  space as read-only memory.

`--dry-run` stops after resolving tools, if you only want to see what a spec
would pull in.

---

## 5. Prove the isolation, on your machine

```sh
nous verify
```

```
proving isolation on this machine
  ✔ a ring-0 guest with its own page tables cannot write lent tool code
  ✔ revoking a tool stops it in an already-running cell

✔ isolation holds on this machine.
```

**What to notice.** The first proof is the one the design rests on. It builds a
guest that enters 32-bit protected mode, installs page tables **it wrote
itself**, maps the sealed tool page writable in them, and writes. Guest-side
that write is entirely legal — ring 0, PTE says writable, no fault. It still
does not land, because stage-2 sits below the guest's own translation.

Nothing in the guest is enforcing this. The guest is root.

---

## 6. Have a model write the code, and run it sealed

Steps 2–4 stop at sealing. This is the path that actually executes something.

First, choose the already-authenticated agent CLI `nous` should use:

```sh
nous setup
```

Then ask it to build a computation. The current build plane emits static musl
artifacts, so a source install needs `rustup target add x86_64-unknown-linux-musl`.

```sh
nous agent "print the first 100 primes, space separated"
```

```
● asking anthropic (cli default) to build: print the first 100 primes, space separated
  · waiting for claude (up to 90s; --timeout changes it)
  · replied in 5s
  · selected sealed runtime: Rust 2021 (static musl); 23 source lines
  + rebuilt, reproduced  blake3:c0d7ceb8…  436 KiB  tier=forged author=agent
  · cell sealed, tools lent read-only
  ✔ pilot: /agent/program permitted:data
  ✔ pilot: /agent/program refused:agent-lane-unavailable
warning: pilot refused to run it: refused:agent-lane-unavailable
```

**The refusal is the correct answer, and it is the interesting part.** The
program was graded `forged` — `forge` rebuilt it twice and the bytes matched,
so the tier was earned rather than asserted. It is still `author=agent`, and
agent-authored code never carries tool-lane authority at any tier. Running it
needs the agent-lane capability boundary, which does not exist yet.

Compiling is not a way around that. `rustc` fed model-written source is
`python` fed model-written source with the interpretation moved earlier.

To watch it actually run while the agent lane is being built:

```sh
nous agent --trust-agent-code "print the first 100 primes, space separated"
```

```
2 3 5 7 11 13 17 19 23 29 31 37 41 43 47 53 59 61 67 71 73 79 83 89 97 ...
```

**This is for computations, not questions.** A cell exists to contain code you
would rather not run unsealed; if nothing executes, it has nothing to protect
you from. It also has **no network at all**, so anything needing one will build
and then do nothing — `nous agent` warns up front when a task looks like that.

Pick who writes it, and see what this host can use:

```sh
nous agents
nous agent --agent openai "…"        # or --agent local
nous agent --show-source "…"         # print the program it wrote
```

Backends are subprocess adapters over CLIs you have already authenticated —
`nous` never reads, stores, or forwards a key.

---

## Piping

Human on a terminal, NDJSON when not. No flag required:

```sh
# which tools went cold?
nous run agent.toml | jq -r 'select(.event=="tool_resolved" and .warm==false) | .alias'

# fail a build if a spec would run something in the tool lane
nous spec check agent.toml | jq -e 'select(.event=="run_plan") | .lane=="data"'

# just the proofs
nous verify | jq -c 'select(.event=="proof")'
```

Diagnostics and warnings go to **stderr**, so `| jq` never chokes on prose.
`--json` and `--no-json` force the mode when you want it explicit.

---

## Also

```sh
nous demo     # the five-beat proof loop; works without KVM
nous tools    # what this host has attested so far
nous agents   # which model backends this host can use
```

`nous demo` is the fastest way to see the whole idea, and it runs anywhere —
laptop, container, CI runner with no virtualization at all.

---

## When something says it cannot

| | |
|---|---|
| `/dev/kvm not present` | Virtualization off in firmware, or a VM without nested virt |
| `/dev/kvm present but not readable` | `sudo usermod -aG kvm $USER`, then log out and in |
| `no readable /boot/vmlinuz-*` | Only affects the boot-path demos, not `nous run` |
| `anthropic needs \`claude\` on PATH` | `nous agent` drives a CLI you have already logged into — see `nous agents` |
| `reported error_during_execution` | The model CLI failed, not nous. Some prompts trigger it every time; rewording helps more than retrying |

---

## Where to go next

| | |
|---|---|
| What is proven, and what is not | [findings/m2.md](findings/m2.md) |
| A gate we miss, and why | [findings/m1-spawn.md](findings/m1-spawn.md) |
| Why each design choice was made | [decisions/](decisions/) |
| Working on nouscell itself | [../AGENTS.md](../AGENTS.md), then `make help` |
