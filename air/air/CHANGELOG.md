# @dekimuhq/air-verifier

## 0.7.2

### Patch Changes

- `family.meta.spec_path` now points at the public spec (https://github.com/dekimuhq/anchors-spec/tree/main/air) instead of an unpublished internal path.

## 0.7.1

### Patch Changes

- 28c64ff: Re-sync internal dependency ranges so npm links the workspace instead of fetching stale published copies.

  Five internal 0.x carets could not admit their own workspace version (`^0.6.6` cannot match `0.7.0`), so npm resolved those packages from the registry, and those older tarballs pinned `@dekimuhq/anchors-envelope@^0.18.1` — materialising envelope 0.18.x in nested `node_modules` where `cli` then compiled against it. Every `anchors-envelope` range is now `^0.26.1` (the published version, matching the workspace source), and the five broken internal pins admit their workspace versions.

  This removes the root cause of the nesting, so the root `postinstall` rm -rf and the explicit `npm run postinstall` step in `anchors-ci.yml` are both deleted — the workaround was masking the drift that created it.

- Updated dependencies [dd49239]
- Updated dependencies [28c64ff]
  - @dekimuhq/anchors-disclosure@0.3.0
  - @dekimuhq/air-profiles@0.7.1

## 0.6.1

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
  - @dekimuhq/air-profiles@0.6.1
  - @dekimuhq/anchors-envelope@0.18.1

## 0.6.0

### Patch Changes

- Updated dependencies [7c4329d]
  - @dekimuhq/anchors-envelope@0.18.0
  - @dekimuhq/air-profiles@0.6.0

## 0.5.3

### Patch Changes

- Updated dependencies [a054911]
- Updated dependencies [a4aee8f]
  - @dekimuhq/anchors-envelope@0.17.0
  - @dekimuhq/air-profiles@0.5.3

## 0.5.1

### Patch Changes

- db75e89: Fix AIR `status_list_slot` collision: AIR shipped slot 6, colliding with ASR (slot 6) and contradicting FAMILY-CONSISTENCY §4 which assigns AIR slot 7. Two families sharing a Status List 2021 slot corrupts revocation state for both. Corrected to slot 7. Consumers reading the AIR family manifest must republish to pick up the fix.
- Updated dependencies [db75e89]
  - @dekimuhq/anchors-envelope@0.16.0

## 0.5.0

### Minor Changes

- c2f423e: feat: add qts_attestation_hash cross-sibling QTS upgrade field

### Patch Changes

- @dekimuhq/air-profiles@0.5.0

## 0.4.0 — 2026-05-20

Phase 4B-2: chain-walk compose warnings wired through `composeAir`.

### Added

`composeAir` is now async and walks the envelope-`prev` chain via the new
`FamilyVerifyOptions.resolveReceiptById` resolver (envelope 0.11.0+) to
surface six chain-walk warnings:

- **`dpia_review_overdue`** — spec §6.2 rule 6. Most recent `dpia.completed`
  has `review_due_at < now` and no `dpia.reviewed` followed it.
- **`art36_consultation_overdue`** — spec §4.8. Art. 36
  `prior_consultation_resolved.iat > prior_consultation_initiated.iat
  - 14 weeks`.
- **`dpo_commit_drift`** — spec §4.3. Two or more `dpia.dpo_advised` events
  carry different `dpo_did_or_email_commit`.
- **`dpia_post_hoc_warning`** — D10-AIR. A `dpia.completed` landed strictly
  later than the chain head's `processing_start_at`.
- **`re_dpia_predecessor_missing`** — spec §6.2 rule 7. Chain head is a
  re-DPIA (`prev !== null`) but the referenced predecessor is absent from
  the resolver's corpus.
- **`voluntary_high_risk_no_consultation`** — NEW, spec §5.5. Fires only
  when `opts.profile === "impact.voluntary"` AND the most recent
  unsuperseded `dpia.completed` carried `residual_risk_level === "high"`
  AND no `dpia.prior_consultation_initiated` followed it. Informational
  only — the `processing_authorised` path is still hard-invalidated by
  §6.2 rule 5 via `art36_prior_consultation_skipped`.

Closes the four warnings deferred in 0.3.0's "Deferred to Phase 4B-2" note
plus picks up two more (`art36_consultation_overdue`,
`re_dpia_predecessor_missing`) that already existed in `walkAirChain`.

### Walker change

`walkAirChain` gains an optional `opts.profile` slot. When supplied, the
walker dispatches the new §5.5 `voluntary_high_risk_no_consultation`
evaluator. Other rules are unaffected — they remain profile-agnostic.

### Bumped

- envelope dep range `^0.10.0` → `^0.11.0` (requires
  `resolveReceiptById` + extended `ComposeInput.envelope` shape).

### Walk semantics

The compose callback walks `prev` up to `AIR_DEFAULT_DEPTH_LIMIT` hops,
calling `resolveReceiptById` once per hop. Stops at the chain head
(`dpia.threshold_triggered` or `prev === null`), at a dangling reference
(resolver returns null/undefined), or at the depth limit. When the
resolver isn't supplied, chain-walk warnings are silently skipped — the
four single-receipt warnings from 0.3.0 still fire as before.
Hard-invalid chain-walk reasons from `walkAirChain` (e.g.
`processing_activity_drift`, `art36_prior_consultation_skipped`) are
intentionally dropped by compose — chain-conformance hard-fail stays the
responsibility of callers that invoke `walkAirChain` directly. Compose
only surfaces _informational_ diagnostics, never poisons
`signature_valid`.

### Tests

12 new tests in `test/compose.test.ts` covering each chain-walk warning,
the no-resolver short-circuit, the dangling-prev abort path, and the
resolver-throw propagation. Total: 232 tests (was 220).

regression check: `grep -n "resolveReceiptById\|voluntary_high_risk_no_consultation" src/compose.ts src/chain.ts` reports ≥3 hits.

## 0.3.0 — 2026-05-20

Phase 4B compose-warnings channel. Two-part land:

- **Task 1+2 (commits `bb89aff` + `1c63afa`):** AIR migrated onto `defineFamily()` factory. New `src/family.ts` declares `airFamily` (chip 13, status_list_slot 6, `ar.impact.v1`, continuity: true, per-event subject-presence callback wrapping `checkAirSubjectPresence` with reason mapping to envelope-level codes, 5 v1 profile validators adapted from AIR-shape to envelope-shape inline). New `src/body-validator.ts` is a pass-through adapter (mirrors `anr-verifier/src/body-validator.ts`). `src/envelope-v2.ts` collapsed onto `airFamily.verifyReceipt` (440 → 110 LOC, -330): wrapper preserves event-keyed `applyAirTsaMandate` RECOMMENDED downgrade + multi-validator profile dispatch + strips factory's `signature_invalid` reason for legacy compat. Subject-presence now runs INSIDE the factory pipeline (Step 10) via the manifest callback; the legacy `applyAirSubjectPresence` post-processor stays exported but is no longer invoked from envelope-v2. No public API changes — `verifyV2` / `EnvelopeVerifyResult` / `EnvelopeVerifyOptions` byte-equal.
- **Task 3 (this commit):** New `src/compose.ts` registers `composeAir` on the family manifest. Surfaces four single-receipt informational warnings on `dpia.completed`:
  - `art35_3a_aer_link_missing` — spec §5.1 + §8.1: profile `impact.art35_3_a_automated_decisions` SHOULD carry non-empty `body.aer_receipt_ids`.
  - `art35_3b_alr_link_missing` — spec §5.2 + §8.3: profile `impact.art35_3_b_large_scale_special_categories` SHOULD carry non-empty `body.alr_receipt_ids`.
  - `review_window_long` — spec §5.1-§5.4: the four strict Art. 35(3-4) profiles SHOULD have `body.review_due_at - envelope.iat ≤ 12 months`.
  - `review_window_long_voluntary` — spec §5.5: `impact.voluntary` SHOULD have `body.review_due_at - envelope.iat ≤ 36 months`.

Warnings flow onto `FamilyVerifyResult.warnings` without poisoning `signature_valid` — advisory only. The duplicate-with-profile-validator overlap is intentional for the post-Phase-4B-1 window: the four warnings are also emitted by `@dekimuhq/air-profiles` validators but dropped by `ProfileStateEntry` (no warnings field). Compose is now the only top-level surface. A future Phase 4B-2 may unify the two paths.

### Profile dispatch — caller-supplied via opts.profile

Critical AIR-specific discovery surfaced during Phase 4B Task 3: **AIR receipts do NOT carry `profile` anywhere on the envelope or body.** `AirBody` has no `profile` field, the shared `Envelope` type has no `profile` field, and `mint-v2` accepts `input.profile` but silently drops it (likely an issuer-kit bug — tracked separately, out of scope for this release). AIR's `validateAirProfile(profile, input)` dispatcher takes profile as a caller-supplied separate argument — there's no on-receipt way to recover it.

Phase 4B Task 3 adds `EnvelopeVerifyOptions.profile?: string` to AIR's verifier surface. The wrapper forwards it to the factory's `FamilyVerifyOptions.profile` slot, and `composeAir` reads `input.opts.profile` to dispatch the four warning codes above. When undefined (the default), every profile-keyed warning skips silently — receipts still verify byte-equal to pre-0.3.0 behaviour.

Earlier exploratory work in this session tried plumbing profile via `ComposeInput.envelope.profile` (envelope 0.10.0 → 0.11.0 bump). That approach was reverted when the on-receipt absence surfaced — `envelope.profile` was always going to be undefined for AIR. The chosen path uses the existing `FamilyVerifyOptions.profile` slot already exposed on envelope 0.10.0, no envelope MINOR bump needed.

### Deferred to Phase 4B-2

Chain-walk warnings (`dpia_review_overdue`, `dpo_commit_drift`, `voluntary_high_risk_no_consultation`, `dpia_post_hoc_warning`) require either a new AIR-specific resolver option on `FamilyVerifyOptions` (envelope MINOR bump) or the existing `walkAirChain` API hoisted into the compose surface. `dpia_post_hoc_warning` specifically needs `processing_start_at` from a prior `dpia.scope_locked` receipt — pinned-null on `dpia.completed` itself.

A separate cleanup track: fix `mint-v2`'s drop of `input.profile` (either write to envelope-level `profile` field once the shared Envelope type allows it, or write to a new `AirBodyBase.profile` field). Until that lands, all AIR profile-keyed verifier behaviour is opt-in caller metadata.

### Surface changes

- `@dekimuhq/anchors-envelope` dep range `^0.9.0` → `^0.10.0` (needed for the `ComposeResult.warnings` channel per ASR Phase 4 precedent `68ba5f7`). NO envelope MINOR bump this round — earlier 0.11.0 exploration was reverted.
- `@dekimuhq/air-profiles` added as a runtime dep (was implicit via test fixtures only) at `^0.2.0` — needed for the family-manifest profile registry.
- `EnvelopeVerifyOptions.profile?: string` added — caller-supplied profile metadata. Optional. Default undefined → compose-warnings silently skip.
- New exports: `airFamily`, `airBodyValidator`, `composeAir`.

### Tests

- `test/family.test.ts` — 14 tests on manifest identity + subject-presence + tsa-mandate matrix + profile registration + pass-through body validator + continuity helpers + compose wired.
- `test/compose.test.ts` — 13 tests (each warning: positive + negative + boundary; non-`dpia.completed` short-circuit; malformed body / iat tolerance; opts.profile-undefined silently skips).
- Verifier total: 192 → 219. Workspace-wide `npm test --workspaces`: ≥2828 / 0 fail.

### Migration

- Callers that pass `opts.profileValidators` see no change — multi-validator dispatch unaffected.
- Callers that want compose-warnings MUST opt in by passing `opts.profile` to `verifyV2`. Until they do, warnings stay quiet.
- Callers that read `result.warnings` may now see one or more of the four new codes on `dpia.completed` receipts that previously surfaced no warnings — only when `opts.profile` is supplied.

regression check: `grep -nE 'art35_3a_aer_link_missing|art35_3b_alr_link_missing|review_window_long|composeAir' anchors/air/air-verifier/src/*.ts | wc -l` reports >= 7 hits.

## 0.2.0 — 2026-05-19

### Changed

- Envelope dep range `^0.7.1` → `^0.9.0`. No source changes — pulls in the cross-issuer interop Phase A Slice 2 surface (trust dispatch + cross-family resolvers) shipped via shared `family-verify-pipeline.ts`. AIR is factory-based, so `FamilyVerifyOptions.verifyIssuerTrust` + `resolveArr` / `resolveAlr` / `resolveAtr` / `resolveApur` are now passthrough-available to AIR consumers without any verifier-side code change. Default-undefined preserves byte-equal verification — the new options are opt-in only.

### Migration

- Existing 0.1.x callers see byte-equal results when not supplying the new options. No code changes required.

regression check: `grep -n '\^0.9.0' anchors/air/air-verifier/package.json` reports 1 hit.

## 0.1.4 — 2026-05-19

§E per-event subject-presence rule (spec §4.4 + D10-AIR-6 + FAMILY-CONSISTENCY.md §3).

- New module `src/subject-presence.ts` — AIR is processing-activity-scoped, not subject-scoped. Envelope-level `subject` MUST be `null` on every event EXCEPT OPTIONALLY on `dpia.stakeholders_consulted`, where it MAY carry a `"sha256:<hex>"` salted-commit (v1.1 envelope §5.4) of the consulted representative organisation AND ONLY when `body.consultation_method ∈ {"representative_org","ngo_review"}` (D10-AIR-6). Survey / focus_group / public_consultation / internal_advisory_panel / other consultation methods MUST keep `subject: null`.
- `checkAirSubjectPresence({subject, body})` returns one of three internal reasons: `subject_must_be_null` (non-stakeholders_consulted event carrying a non-null subject), `subject_must_be_sha256` (stakeholders_consulted with subject present but not `sha256:<hex>` — form check ahead of method), `method_disallows_subject` (stakeholders_consulted with valid `sha256:<hex>` but a non-bearing method). Unknown event_type and malformed body fall through to the strict (must-be-null) branch — the §C body verifier separately rejects unknown discriminators.
- `applyAirSubjectPresence(target, envelope)` mutates the verify result with bare envelope reason codes: `subject_present` ← `subject_must_be_null`, `subject_invalid_form` ← `subject_must_be_sha256`, `representative_subject_method_mismatch` ← `method_disallows_subject`. No-op when `signature_valid` is already false (first failure wins).
- `envelope-v2.ts` wires `applyAirSubjectPresence(out, e)` immediately after the §D TSA mandate block, guarded on `out.signature_valid`. Early-return on rejection so downstream status / profile-validator dispatch doesn't run against a poisoned result. Mirrors the ABR `989dfa4` / ANR sibling integration pattern.
- Tests (`test/subject-presence.test.ts`, +62 tests). U1–U5 stakeholders_consulted accepted shapes (representative_org / ngo_review × sha256/null; survey + null = 5) · U6–U10 each non-bearing method × sha256 → method_disallows_subject (5 methods) · U11–U15 bad-subject-form rejections (5: empty / raw / form-check-ahead-of-method / uppercase hex / short hex) · U16 missing consultation_method → method_disallows_subject (1) · U17–U19 every non-stakeholders_consulted event (10) × {null OK, sha256 must-be-null, raw-string must-be-null} = 30 cases · U20 unknown event_type (2) · U21 missing/null/sha256-with-no-body body (3) · A1–A5 apply semantics (5) · I1–I6 end-to-end verifyReceipt integration through the live envelope-v2.ts wire-in (6). 62/62 pass. Verifier total moves to 192 (130 from §D + 62 from §E). Plan §3 Phase 5 floor (≥100) cleared with wide margin.

## 0.1.3 — 2026-05-19

§D per-event TSA mandate matrix + envelope POLICY_BOUND wire-in (spec §4.5/§4.7/§4.8 + FAMILY-CONSISTENCY.md §2).

- New module `src/tsa-mandate.ts` — `AIR_TSA_MANDATE` keyed on `body.event_type` (eleven rows). `dpia.completed`, `dpia.prior_consultation_initiated`, `dpia.prior_consultation_resolved` declared RECOMMENDED (regulatory-clock-bearing events per spec §4.5/§4.7/§4.8); the other eight events declared OPTIONAL. AIR v1 has NO MANDATORY-TSA event — the MANDATORY branch is retained in `applyAirTsaMandate` for forward-compatibility with the family-uniform mandate shape (audit-fix H7 principled rule: regulatory-clock-START ⇒ MANDATORY, deadline-checks ⇒ RECOMMENDED, else OPTIONAL).
- `applyAirTsaMandate(target, body)` mutates the verify result: RECOMMENDED + `tsa_state === "tsa_absent"` → `tsa_state: "tsa_recommended"` (warning only; signature stays valid); OPTIONAL + absent → no-op; any real TSA reason already in `tsa_state` short-circuits the matrix (no-op). Defensive on unknown event_type — short-circuits to no-op rather than mis-flagging the receipt (the §C body verifier is the authoritative gate for event-type validity).
- `envelope-v2.ts` wires `applyAirTsaMandate(out, e.body as AirBody)` immediately after the TSA dispatch block; guarded on `out.signature_valid` so an earlier failure isn't overwritten. Mirrors the ABR `989dfa4` / ALR `267214a` / ANR `d846fc9` integration pattern.
- `@dekimuhq/anchors-envelope ^0.7.1` adds `ar.impact.v1` to its `POLICY_BOUND` set (additive — no API change). `validatePolicyFields` now returns the expected `policy_fields_required:*` reasons on a malformed AIR envelope instead of the placeholder `unknown_claim_type` returned during §B/§C.
- Dep range bumped from `^0.6.2` to `^0.7.1` (the new POLICY_BOUND entry is the load-bearing change). Publish hold from envelope 0.7.0 carries forward to 0.7.1 — both versions stay unpublished on GitHub Packages until A.2-full Phase 2 + a downstream family release validate the new envelope surface end-to-end.
- Tests (`test/tsa-integration.test.ts` + `test/_helpers/v2-receipt.ts`, +31 tests). 3 RECOMMENDED-event integration paths (sig valid, `tsa_state: tsa_recommended`) + 8 OPTIONAL-event integration paths (sig valid, `tsa_state: tsa_absent` untouched) + 2 injected-imprint-mismatch paths (real-reason precedence on both RECOMMENDED and OPTIONAL bodies) + matrix-shape assertion (0 MANDATORY, 3 RECOMMENDED, 8 OPTIONAL) + 11 per-event lookup tests + 6 unit tests on `applyAirTsaMandate` (RECOMMENDED+absent, OPTIONAL+absent, real-reason precedence on RECOMMENDED + OPTIONAL, undefined `tsa_state`, defensive unknown event_type). Verifier total moves to 130 (99 from §C + 31 from §D). Plan §3 Phase 5 floor (≥100) cleared.

## 0.1.2 — 2026-05-19

§C body verifier + chain walker (spec §3.1 + §4 + §6.1 + §6.2 + D10-AIR-1/-2/-3/-4/-7).

- `verifyAirBody(body)` (`src/verify-single.ts`) — per-event-type body verifier dispatching on `body.event_type` across the 11 wire-level discriminator values. Enforces per-event required fields (spec §4.1–§4.9), cross-event pinned-null invariants (the discriminated union enforces these at compile time; the verifier catches mis-built runtime bodies), and the `consultation_output_empty` HARD-invalid (§4.4 — `consultation_output_hash` MUST NOT equal `sha256("")` in either bare-hex or `sha256:<hex>` prefixed form). `dpa_jurisdiction` (§4.7) accepted as ISO 3166-1 alpha-2 or the literal `"EU-EDPB"`. Exports `isAirProfile()` for callers that want to confirm a profile string is one of the 5 v1 set without importing the full body verifier.
- `walkAirChain(startId, index, opts)` (`src/chain.ts`) — envelope-`prev` chain walker. Unlike ABR (where the chain head is always `prev: null`), an AIR `dpia.threshold_triggered` MAY have a non-null `prev` referencing a predecessor chain's `dpia.reviewed` (re-DPIA inheritance, §6.2 rule 7); the walker stops at the first `dpia.threshold_triggered` and surfaces the head's `prev` separately for the re-DPIA check.
- Per-hop linear-walk invariants surfaced as result flags: `cycle`, `truncated`, `dangling`, `iss_inconsistent`, `air_receipt_id_inconsistent` (D10-AIR-2), `chain_head_not_threshold_triggered`, `predecessor_id`.
- Cross-event invariants applied AFTER the walk (oldest→newest), surfaced as `hard_invalid_reasons[]`: `processing_activity_drift` (§6.2 rule 3 / D10-AIR-3 id half), `ropa_snapshot_drift` (§6.2 rule 3 hash half), `dpia_artifact_hash_drift` (§6.2 rule 4 / D10-AIR-7), `art36_prior_consultation_skipped` (§6.2 rule 5 / D10-AIR-4 — high-risk completed MUST pass through `prior_consultation_resolved` before `processing_authorised`; material-change reviews reset the gate), `scope_rewrite_without_review` (spec §4.2 — re-scope-after-finding), `re_dpia_invalid_predecessor` (§6.2 rule 7 — predecessor MUST be `dpia.reviewed` with `review_outcome ∈ {material_change, superseded}` AND match `iss`).
- Informational warnings surfaced as `warnings[]`: `dpia_review_overdue` (§6.2 rule 6 — now > `review_due_at` AND no review since), `art36_consultation_overdue` (§4.8 — resolved.iat > initiated.iat + 14 weeks), `dpo_commit_drift` (§4.3 — differing `dpo_did_or_email_commit` across two `dpia.dpo_advised` events), `dpia_post_hoc_warning` (D10-AIR informational — `dpia.completed.iat > threshold_triggered.processing_start_at`), `re_dpia_predecessor_missing` (re-DPIA predecessor absent from index).
- `buildAirChainIndex(receipts)` helper; depth-limit clamping into `[AIR_DEPTH_LIMIT_MIN=32, AIR_DEPTH_LIMIT_MAX=1024]` with default `AIR_DEFAULT_DEPTH_LIMIT=256`.
- Tests (`test/verify-single.test.ts` + `test/chain.test.ts` + `test/_helpers/bodies.ts`, +99 tests across 2 files). 62 verify-single tests (11 happy paths + per-event required-field rejection + consultation_output_empty in both surface forms + dpa_jurisdiction format + cross-event pinning regression sweep + isAirProfile guard) and 37 chain-walker tests (depth-limit constants + per-hop flags + each cross-event hard-invalid + each informational warning + end-to-end high-risk-authorise lifecycle). 99/99 pass.

No envelope-v2.ts edits — single-receipt body verification stays caller-side (same pattern as `@dekimuhq/abr-verifier/verify-single`). §D TSA-mandate matrix + envelope POLICY_BOUND wire-in lands next.

## 0.1.1 — 2026-05-19

§B types + v=2 dispatch.

- `AirClaimType` = `"ar.impact.v1"` (single entry, no batch variant — multi-DPIA-per-activity history is reconstructed by joining chains on `body.processing_activity_id` per D10-AIR-3, §6.4).
- `AirEventType` — 11 wire-level discriminator values per spec §4 + D10-AIR-1 (audit fix H9): `dpia.threshold_triggered`, `dpia.scope_locked`, `dpia.dpo_advised`, `dpia.stakeholders_consulted`, `dpia.completed`, `dpia.reviewed`, `dpia.prior_consultation_initiated`, `dpia.prior_consultation_resolved`, and the wire-disjoint terminal trio `dpia.processing_authorised | dpia.processing_blocked | dpia.terminated`. 9 logical events → 11 wire discriminators.
- `AirProfile` — 5 v1 profiles (`impact.art35_3_a_automated_decisions`, `impact.art35_3_b_large_scale_special_categories`, `impact.art35_3_c_public_monitoring`, `impact.art35_4_dpa_list`, `impact.voluntary`).
- Closed enums: `AirResidualRiskLevel`, `AirConsultationMethod` (7 values incl. `representative_org`/`ngo_review` — the only methods that may anchor a representative-org `sub_commit` in envelope `subject`), `AirReviewOutcome`, `AirTerminalDisposition`, `AirStatusState` (4-state per spec §6.3 — `active | closed | withdrawn | revoked`; one wider than ABR/ANR's 3-state set).
- `AirBody` discriminated union of 11 variants keyed on `event_type` with cross-event-pinned `null` fields in the ALR/ANR/ABR style. Composition fields (audit fix C5, spec §3.1):
  - `dpia.completed`: `aer_receipt_ids`, `atr_receipt_ids`, `alr_receipt_ids`, `apur_receipt_ids` (all `readonly string[] | null`).
  - `dpia.reviewed`: `abr_receipt_id` (`string | null`).
  - all other events: composition fields pinned null.
- `envelope-v2.ts` mirrors ABR/ANR dispatch with AIR deltas:
  - single claim_type allowlist (`ar.impact.v1`); `POLICY_BOUND` matrix entry deferred to §D (identical pattern to ABR `989dfa4` / ALR `267214a` / ANR `d846fc9` — until §D lands, `validatePolicyFields` returns `unknown_claim_type` for AIR receipts; §B ships the dispatch surface so §C/§D land additively).
  - TSA dispatch independent of §D mandate matrix (next commits upgrade `tsa_state` to `tsa_recommended` on `dpia.completed` / `dpia.prior_consultation_initiated` / `dpia.prior_consultation_resolved` per spec §4.5/§4.7/§4.8 + FAMILY-CONSISTENCY §2; AIR has no MANDATORY-TSA event in v1).
  - Status List 2021 reconciliation via `verifyCredentialStatus` (consumer #6 per FAMILY-CONSISTENCY §4 — after ALR/ACR/ARR/ANR/ABR).
  - predicates not blocked at envelope level (spec §3.2 names one rare use: `dpia.completed` MAY commit a predicate binding `residual_risk_level === "high"` to a mandatory `prior_consultation_resolved` traversal).
- `verifyReceipt` top-level entry — `v === 2` dispatches to `verifyV2`, anything else fail-closed.

No tests in this section — §B is types + dispatch surface only. Test floor (≥100 per plan §3 Phase 5 header) opens in §C onward.

## 0.1.0 — 2026-05-19

- Initial skeleton.
