# Bounded router refusal delivery

Issue #96 was observed in the Sympozium MLP journey: a router refusal surfaced
through its TLS reverse proxy as 502/unexpected EOF rather than 401. The previous
raw TCP helper tolerated ConnectionReset after receiving any nonempty response,
which did not establish complete HTTP delivery.

`unauthorized_buffered_body_receives_complete_response_without_reset` queues
32 KiB before the router processes an unauthenticated request. It failed on the
old implementation with Linux ConnectionReset (104), and passes with the fix.
The handler now shuts down its response direction before bounded disposal of
unread input: at most 64 KiB and a 100 ms **total** deadline. It neither parses
nor forwards that tail. Excess or stalled input still loses its connection;
complete delivery is not promised for an unlimited malicious upload. A slow-byte
test checks that incremental arrivals cannot continually renew the timeout.

Authentication, request limits, durable ownership and dispatch decisions are
unchanged. Existing raw TCP tests now require clean complete reads rather than
tolerating a partial response followed by reset. This change does not qualify
unbounded connection concurrency or the dispatcher HTTP server's separate paths.

Validation on 2026-09-08:

- `CARGO_TARGET_DIR=target/validation make ci` passed, including all-feature
  Clippy, build and workspace tests. All 19 router tests passed separately.
- Sympozium `TestActualRouterRefusalsThroughTLSProxy` passed: 96 actual-router
  requests over a real TLS reverse proxy, missing or backend-only credentials,
  bodies of 0, 2 and 32768 bytes, exact complete 401 JSON, zero backend requests.
  No retry, Kubernetes, KVM or model is involved in that protocol test.
- Separate deployed API/controller-Pod/browser → host TLS issuer/router → actual
  KVM/DeepSeek run passed in isolated `kind-celln-deployed`: two lent tools, fresh
  result `CELLN has length 5`, nine credential refusals, two foreign-CA refusals,
  withdrawal/refusal, retained receipt and registered cleanup. Controller image
  `35b45cd`, API image `a3ba456`. Run UID
  `168c5220-5754-4db8-84db-4b9f3edb27bb`, action
  `celln-921a0d68af0794c307863bbf64b2c9e04f14565f1d9d6b2ca10e0114a46df1c8`.
  Local Sympozium evidence: `target/celln-live-proof/catalogue-live-1389851853`.
  Final `test-outcome.json` passed; the original test controller was restored.

The tested Celln executable SHA-256 is
`6f9a6a73c83b165bf931a971c7de7bca797eca4d713369ca77c84b874ebbbcd6`.
Its source tree is the router fix in `93acb52` (rebased onto main without a tree
change after compilation). This is targeted transport and integration evidence,
not full production installation, fleet failure or guest adversarial acceptance.
