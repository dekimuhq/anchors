# Changelog

## 0.4.1

### Patch Changes

- `family.meta.spec_path` now points at the public spec (https://github.com/dekimuhq/anchors-spec/tree/main/adr) instead of an unpublished internal path.

## 0.4.0

### Minor Changes

- 83ef364: AP2 interop — optional `authorizing_credential` reference on ADR grant bodies.

  Adds an OPTIONAL, grant-only `authorizing_credential { scheme, id, type }` field to
  `AdrGrantBody` that references — by identifier — the external credential that
  authorized a delegation (canonically an AP2 mandate, `payment_mandate_id` / SD-JWT
  `jti`). This is a _pointer_ inside the envelope-signed body: receipt-_of_, never
  is-a. AP2 mandates are SD-JWT-VC (not W3C-VC) and sign ES256 while our envelopes
  sign Ed25519/ML-DSA-65 — the algorithms do not meet, so we reference rather than
  embed. See `meta/STANDARDS-BRIDGE.md` §2d.

  - `@dekimuhq/adr-profiles`: new `AdrAuthorizingCredential` type + optional
    `authorizing_credential?: AdrAuthorizingCredential | null` on `AdrGrantBody`.
  - `@dekimuhq/adr`: runtime validator accepts a well-formed `authorizing_credential`
    on `grant` (shape-check when present; absent or explicit `null` both graceful),
    and PROHIBITS it on every non-grant event (revoke/narrow/renew/suspend/resume);
    `mintGrant`/`mintAdrV2` thread the field through, emitting the key only when
    supplied.

  Additive + optional: envelope untouched, no envelope dep bump; every pre-existing
  ADR receipt verifies byte-equal (the key is absent, not `null`). Pure `node:crypto`.

- 0b54548: New ADR profile `gdpr.dsr.authorised-agent` — additive 6th v1 profile.

  Models a legal/natural person acting as a data subject's **authorised representative**
  to exercise GDPR data-subject rights against one named controller. Grounded on the
  general authorised-agent route (national civil-law mandate / power of attorney + GDPR
  Art. 12(2)/(6) + Recital 59) — deliberately NOT `gdpr.art80.*` (that route is
  not-for-profit-only and does not apply to a commercial representative), and distinct
  from `gdpr.art28.processor` (acts for the subject, not as the controller's processor)
  and the AI-agent profiles (a representative is a legal person, not an autonomous agent).

  - `@dekimuhq/adr-profiles`: new `gdpr.dsr.authorised-agent` id on the `AdrProfile`
    union + `validateGdprDsrAuthorisedAgent` / `validateGdprDsrAuthorisedAgentProfile`.
  - `@dekimuhq/adr`: id registered in `ADR_PROFILES` + the family `profiles` map, so
    `isAdrProfile` accepts it.

  Grant-only invariants: `delegable === false`; `agent.agent_descriptor === null` +
  non-empty `agent.agent_pubkey`; `scope.actions` non-empty ⊆ {gdpr-art-15,-16,-17,-18,-20,-21};
  `scope.resources` exactly one named controller; `constraints.letter_hash`
  (`sha256:<64-hex>`, binds the Layer-1 Letter of Authority), `constraints.representative`,
  `constraints.mandate_basis` all present. Additive + optional: every pre-existing ADR
  receipt verifies byte-equal. Pure `node:crypto`. Spec §5.6 + decision
  `2026-07-05-adr-gdpr-dsr-authorised-agent-profile.md`.

### Patch Changes

- Updated dependencies [83ef364]
- Updated dependencies [0b54548]
- Updated dependencies [d700da7]
- Updated dependencies [82541e7]
  - @dekimuhq/adr-profiles@0.4.0
  - @dekimuhq/anchors-envelope@0.26.1

## 0.3.1

### Patch Changes

- ADR — adopt `ar.continuity.v1` issuer-key-rotation attestations, closing the last
  family gap (12/13 already wired). The issuer kit re-exports the family-shared
  `issueContinuityAttestation`/`verifyContinuityAttestation` from
  `@dekimuhq/anchors-envelope/continuity` (callers pin `family: "adr"`). Repairs
  `keys.ts` (a prior mid-family merge had dropped the `generateIssuerKey`/
  `encodePublicKey` KeyObject helpers — restored). New `continuity.test.ts` (family
  floor 131 → 135). Additive; existing receipts verify byte-equal. Depends only on
  the already-published `@dekimuhq/anchors-envelope@^0.18.1` (`/continuity` present
  since 0.18.1) — independent of the gated v1.3 ml-dsa envelope bump.

## 0.2.4

### Patch Changes

- e365570: Ship built `dist` (`*.js` + `*.d.ts`) instead of raw `src/*.ts`.

  Every publishable anchors package now publishes a compiled `dist` tree with declaration
  files, built via `tsc -p tsconfig.build.json` (`rewriteRelativeImportExtensions` rewrites
  `.ts` import specifiers to `.js`). `main`/`types`/`exports` point at `dist`; `files` drops
  `src`. The public type and runtime API is byte-identical — no source change, patch bump only.

  Fixes the `dekimu-packages` Release-CI block: consumers previously resolved these packages'
  types to raw `.ts` source, which forced `tsc` to descend into them and raised TS5097
  (`.ts` import extension) plus TS2305 (cross-version source skew). Shipping `dist`+`.d.ts`
  eliminates both — proven 2026-06-03: `dekimu-packages` workspaces typecheck goes from
  412×TS5097 + 19×TS2305 to 0 of each.

  `aar-tsl` is intentionally excluded (pre-existing `fast-xml-parser` declaration debt; nothing
  depends on it). Consumer apps keep their `transpilePackages` entries — they become harmless
  no-ops, and removing them is a separate, individually-verified pass.

- Updated dependencies [e365570]
  - @dekimuhq/adr-profiles@0.2.4
  - @dekimuhq/anchors-envelope@0.18.1

## 0.2.3

### Patch Changes

- Updated dependencies [7c4329d]
  - @dekimuhq/anchors-envelope@0.18.0
  - @dekimuhq/adr-profiles@0.2.3

## 0.2.2

### Patch Changes

- Updated dependencies [a054911]
- Updated dependencies [a4aee8f]
  - @dekimuhq/anchors-envelope@0.17.0
  - @dekimuhq/adr-profiles@0.2.2

## 0.2.1

### Patch Changes

- Align `@dekimuhq/anchors-envelope` dependency range to `^0.16.0` across all remaining families. These packages pinned `^0.13.0`, which cannot resolve the published envelope `0.16.0` (caret on a 0.x minor) — leaving the dependency range unsatisfiable for downstream consumers. Envelope 0.16.0 is additive (adds the mandate-aware `TsaState` type), so this is a metadata-only alignment with no behavior change.
- Updated dependencies
  - @dekimuhq/adr-profiles@0.2.1

## 0.2.0

### Minor Changes

- c2f423e: feat: add qts_attestation_hash cross-sibling QTS upgrade field

### Patch Changes

- @dekimuhq/adr-profiles@0.2.0

## 0.1.0

Initial release of `@dekimuhq/adr-verifier`.

- ADR v1 receipt verification via `verifyReceipt()`.
- 6-event state machine: `delegation.granted`, `delegation.revoked`, `delegation.suspended`, `delegation.reinstated`, `delegation.expired`, `delegation.transferred`.
- 5 profile validators via `@dekimuhq/adr-profiles`.
- Scope subset validation and sub-delegation tree walk.
- Status List 2021 consumer.
