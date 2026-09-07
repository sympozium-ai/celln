# Deployed dispatcher Secret rotation — 2026-09-07

Scope: backend authentication through the isolated `kind-celln-deployed`
cluster, with two dispatcher Pods and two router replicas. Framework is not
involved. This proof uses public dummy tokens and makes no provider requests.

## Revision and setup

- Dispatcher source: `a0a4938`, image
  `localhost/celln-dispatcher-rotation:a0a4938`.
- Image configuration SHA256:
  `80b54a84b6940ceec64ea3e3868d7bc678e63d94a70dee2ef03c425b4640d2f1`.
- Static dispatcher binary SHA256:
  `0c5158d5d3c09fa64c30f79730378521941b0b66581d1de62f456a5b78bb6775`.
- Router: `bb1e718`, the previously deployed chart topology, with separate
  projected client and backend credentials.
- Both dispatchers reported zero live cells before image rollout. Rotation
  begins only after both upgraded Pods are Ready.
- The protected target is the already completed execution
  `journal-terminal-proof-647487df-40a5-49c8-8683-a2b82baf07b5`.
  Its owner is dispatcher-0; dispatcher-1 has no record for that ID.

## Procedure

1. Read the terminal record directly on its owner (200), confirm authenticated
   non-owner lookup (404), and retrieve the audit through the router Service
   from the allowed controller-labelled client Pod (200).
2. Replace `celln-system/celln-dispatcher-backend` with a different valid dummy
   token. Wait for Secret projection; require the new token to reach each
   dispatcher's protected lookup and the old token to receive 401 on both.
   Require the router Service audit request to recover to 200.
3. Replace that Secret with the invalid value `short`. Require protected
   requests to both dispatchers and the router Service to return 503.
4. Restore the original dummy token. Require owner 200, non-owner 404,
   rotated-token 401 on both dispatchers, and router Service audit 200.
5. Compare all four service Pod UIDs and restart counts before/after the
   rotation sequence; changes fail the proof.

The local script has an EXIT trap restoring the original dummy Secret even
on failure. Each projection wait has a 180-second deadline. Persistent raw
output is under `target/deployed-kind.JcI9Gg/evidence/rotation-proof.log`.

## Result: passed

All times UTC on 2026-09-07:

| Observation | Time | Result |
| --- | --- | --- |
| Baseline owner / non-owner / router Service | 11:33:56–57 | 200 / 404 / 200 |
| New token accepted on both dispatchers | 11:34:47 | 200 / 404 |
| Old token rejected on both dispatchers | 11:34:47 | 401 / 401 |
| Router Service with rotated backend token | 11:34:50 | 200 |
| Invalid Secret on both dispatchers and router | 11:35:59 | 503 / 503 / 503 |
| Original token restored on both dispatchers | 11:37:04–20 | 200 / 404 |
| Rotated token rejected after restoration | 11:37:20 | 401 / 401 |
| Router Service recovered | 11:37:20 | 200 |

All four Pod UIDs and restart counts were unchanged during rotation:

| Pod | UID | Restarts before and after |
| --- | --- | --- |
| celln-router-7766b9c46b-72nv9 | caf3f0b9-5049-4527-af7c-2ee8c5a10214 | 0 |
| celln-router-7766b9c46b-fshxf | ce5c96da-b3b9-41a7-a418-b54a419acea6 | 1 |
| dispatcher-0 | cb1ca244-5846-4dca-bc50-0d93af4272e6 | 0 |
| dispatcher-1 | 5b904fcb-e45c-49e5-a883-ccec46f5df85 | 0 |

The router's existing restart count of one predates this test (the prior
owner-node restart proof). No provider Secret was present. The original dummy
backend credential was restored and verified through protected requests.

## Limits

This does not prove simultaneous or zero-downtime rotation: independent
projected volumes can disagree temporarily. It does not revoke an already
authorized in-flight request, rotate provider credentials, test TLS, or certify
production installation/upgrade. No new execution or model call is submitted.
The authenticated non-owner 404 is expected, not a missing-owner recovery test.
