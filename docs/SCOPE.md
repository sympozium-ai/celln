# Scope freeze (from 2026-10-30)

Celln is now one optional execution backend for Sympozium, chosen per run
(`AgentRun.spec.backend: celln`), not the default
([sympozium#692](https://github.com/sympozium-ai/sympozium/issues/692),
[sympozium#693](https://github.com/sympozium-ai/sympozium/issues/693)). It
stays open source, Apache-2.0 and maintained. Its scope is frozen to:

## In scope

- The `celln.json-tools/v1` contract: correctness, bounds, refusals.
- Isolation correctness: anything a cell can do that it should not.
- Security fixes, at any time.
- The KVM CI lane with an enforcing CNI, published as evidence with each
  release ([sympozium#685](https://github.com/sympozium-ai/sympozium/issues/685)).

## Paused

- New runtime features, new lanes or data paths into a cell.
- Expanding enduring/persistent parents, suspend/resume
  ([#9](https://github.com/sympozium-ai/celln/issues/9)).

## Moved

- A per-namespace spend ceiling belongs in Sympozium, enforced at the model
  gateway for every backend, not in Celln
  ([sympozium#688](https://github.com/sympozium-ai/sympozium/issues/688)).

## Pull requests

Pull requests in paused areas are welcome but will be held, not closed: they
will be reviewed if the freeze lifts. If you are unsure whether a change is in
scope, open an issue first.
