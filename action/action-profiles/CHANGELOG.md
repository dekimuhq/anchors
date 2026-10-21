# @dekimuhq/action-profiles

## 0.6.4

### Patch Changes

- First release from the public `dekimuhq/anchors` repository: package metadata now points at it (`repository`, `homepage`, `bugs`), `publishConfig.access` is `public`, `engines.node` is declared as `>=24.6.0`, and every tarball ships a README and the Apache-2.0 LICENSE. No API changes.
- Updated dependencies
  - @dekimuhq/anchors-envelope@0.26.2

## 0.6.2

### Patch Changes

- 28c64ff: Re-sync internal dependency ranges so npm links the workspace instead of fetching stale published copies.

  Five internal 0.x carets could not admit their own workspace version (`^0.6.6` cannot match `0.7.0`), so npm resolved those packages from the registry, and those older tarballs pinned `@dekimuhq/anchors-envelope@^0.18.1` — materialising envelope 0.18.x in nested `node_modules` where `cli` then compiled against it. Every `anchors-envelope` range is now `^0.26.1` (the published version, matching the workspace source), and the five broken internal pins admit their workspace versions.

  This removes the root cause of the nesting, so the root `postinstall` rm -rf and the explicit `npm run postinstall` step in `anchors-ci.yml` are both deleted — the workaround was masking the drift that created it.

## 0.5.0

### Minor Changes

- Add the `aiact.art12` profile to AActR (`ar.action.v1`) — EU AI Act Article 12 record-keeping (a second exclusive profile + optional nested `aiact_art12` overlay). Relax the verb-allowlist on BOTH profiles (`hub.automation` + `aiact.art12`) to accept kebab-case op segments (the real verb `operator.draft-reminder` was rejected → would verify INVALID). Envelope dep `^0.19.0`→`^0.22.0`.

## 0.4.0

### Minor Changes

- 370249b: AActR — add an OPTIONAL `delegation_chain` field to the `ar.action.v1` body (spec §4.5), recording the delegation path when the authorizing mandate is a CHAIN (a sub-agent acting under an attenuated sub-mandate) rather than the root principal's own mandate. Shape: `{ depth, leaf_key, root_credential_id }` — a verifier sees "this action was taken by a sub-agent at chain depth N, rooted at credential X", beyond the single root `credential_id`.

  Plaintext, non-PII metadata; the chain already lives, signed, in the capability token, so this introduces NO new cryptographic primitive and the verify-time caveat-intersection boundary is unchanged. It is issuer-asserted descriptive metadata — a stateless single-receipt verifier cannot re-check that the delegation chain actually existed (same honesty bound as `credential_id`, spec §4.5/§6). Binding-integrity rules (reference verifier): `delegation_chain` present without `credential_id` → `delegation_chain.orphan`; `root_credential_id !== credential_id` → `delegation_chain.root_mismatch`; present without `caveats_consumed` → `delegation_chain.no_caveats`; `depth` must be an integer `>= 1`. Additive and backward-compatible: receipts minted before this verify byte-equal, and root-only / policy-authorized actions omit the field entirely. `mintActionV2` accepts an optional `delegation_chain` input. New `delegation-chain.test.ts` (10 tests; family floor 107 → 117). Bet B Unit 3 — receipt chain-binding.

## 0.3.0

### Minor Changes

- fea8824: AActR `ar.action.v1` — optional `agent_id` per-agent principal (spec §4.6).

  Threads the verified per-agent principal onto the action receipt: a new optional
  `AActRBody.agent_id` field carrying the stable agent id (`@dekimuhq/agent-capability`'s
  root-bound `agentId`, surfaced by `@dekimuhq/mandate-verify` as `verdict.verifiedAgentId`).
  Distinct from `credential_id` (per-MANDATE) and the envelope `iss` (per-TENANT) — it
  answers "WHICH agent took this action", stable across that agent's many mandates. Closes
  the AIUC-1 A003.3 identity-granularity gap on the receipt side.

  `@dekimuhq/action-profiles`:

  - `AActRBody.agent_id?: string` — optional, plaintext, non-PII opaque principal id.

  `@dekimuhq/action`:

  - `MintActionV2Input.agent_id?` + `buildBody` passthrough (omitted when absent — no
    undefined key).
  - `verifyActionBody` validates it: `agent_id.invalid` (present but not a non-empty
    string) and `agent_id.orphan` (present without `credential_id` — a verified principal
    only exists under a mandate). Same issuer-asserted boundary as `credential_id`: a
    stateless single-receipt verifier cannot re-derive it (it lives in the mandate chain).

  Additive + backward-compatible: existing AActRs carry none of the new field and verify
  byte-equal. action-profiles 32/32, action 117/117 (incl. 6 new agent_id cases with real
  mint→verifyReceipt round-trips) on Node v24.16.0; tsc clean.

## 0.2.0

### Minor Changes

- feab80c: AActR `ar.action.v1`: add optional `credential_id` + `caveats_consumed` to the
  body (mandate binding). Additive — existing receipts verify byte-equal; fields
  absent for policy-authorized actions. The verifier rejects an empty
  `credential_id`, malformed caveats, and orphan caveats (caveats without a
  `credential_id`); `mintActionV2` carries the fields through under
  `exactOptionalPropertyTypes` (keys absent, never `undefined`, when not provided).

## 0.1.0

Initial release — body types + profile validators for Anchored Action Receipts (AActR) v1.

- `AActRBody` canonical body shape, `AActRProfile`, `AActROutcome`, `AActRClaimType`.
- `hub.automation` profile validator (`validateHubAutomationProfile`).
