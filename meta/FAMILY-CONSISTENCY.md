<!-- Canonical source: https://github.com/dekimuhq/anchors-spec/blob/main/family-consistency.md -->
<!-- This is a working copy for development convenience. The spec repo version is authoritative. -->

# Anchored Receipts — Family-wide Consistency Tables

**Authority:** This document is the **single source of truth** for cross-family invariants that would otherwise drift across member specs: chip positions on `verify.dekimu.com/check`, TSA mandate matrix, subject-presence matrix, Status List 2021 consumer ordering, and shared package references.

**Companion to:** [`REGISTRY.md`](REGISTRY.md) (claim_type registry) + [`CROSS-REFERENCES.md`](CROSS-REFERENCES.md) (composition relationships).

**Created:** 2026-05-17 (closure consistency-audit fix-pass, addressing audit findings H4/H5/H7/H10/H11/H12 per an internal design record (not published)).

**Maintenance rule:** Adding a new family member requires updating every table below. The tables ship to the spec template at [`anchors/templates/spec-template.md`](../templates/spec-template.md) as a "consistency-checklist" snippet that new spec drafts MUST fill in.

---

## 1. `verify.dekimu.com/check` chip-position matrix

Canonical chip ordering. Each chip represents one family member's filter on the `/check` UI; ordering is locked to avoid mid-roadmap reshuffles. Pre-canonical chips 1–3 are shipped; 4–13 are reserved for the order below.

| Chip # | Family | `claim_type` | Status | Notes |
|---|---|---|---|---|
| 1 | APR | `ar.provenance.v1` | shipped | First shipped family member |
| 2 | ACR | `ar.consent.v1` (+ `ar.modification.v1`, `ar.withdrawal.v1`) | shipped | Single chip covers ACR's 3 claim_types |
| 3 | ARR | `ar.erasure.v1` (+ `ar.expiry.v1`, `ar.hold.v1`, `ar.anonymization.v1`, `ar.archive.v1`, `ar.batch.v1`) | shipped | Single chip covers ARR's 6 claim_types |
| 4 | ADR | `ar.delegation.v1` | shipped | adr 0.4.0 + adr-profiles 0.4.0 (2026-07-31 re-sync); 6 event types + 6 regulatory profiles (GDPR Art. 28, GDPR DSR authorised-agent (§5.6, additive 2026-07-05, publish maintainer-gated), AI Act Arts. 14/26, corporate, agentops); OPTIONAL grant-only `authorizing_credential {scheme,id,type}` — reference (by id) to an external authorizing artifact, canonically an AP2 mandate (SD-JWT-VC), receipt-*of* never is-a; additive 2026-07-01, prohibited on non-grant events, mirrors AActR `credential_id` (chip 15). See STANDARDS-BRIDGE §2d + decision 2026-06-30-mandate-naming-posture-vs-ap2 (internal design record, not published) |
| 5 | ATR | `ar.transfer.v1` | shipped | 4 event types (arrangement, transfer, tia, suspension); 8 profiles; per-event subject split; transfer validity computation §7.2 |
| 6 | APuR | `ar.purpose.v1` | shipped | 3 event types (binding, repurpose, unbinding); 4 regulatory profiles |
| 7 | AER | `ar.evaluation.v1` | shipped | 2 event types (conformity + transparency), 9 profiles |
| 8 | AAR | `ar.attestation.v1` | shipped | aar 0.4.0 + aar-profiles 0.3.3 + aar-tsl 0.2.6 (2026-07-31 re-sync) |
| 9 | ALR | `ar.lineage.v1` | shipped | alr 0.5.0 + alr-profiles 0.4.2 (2026-07-31 re-sync) |
| 10 | ANR | `ar.notice.v1` | shipped | anr 0.7.0 + anr-profiles 0.6.2 (2026-07-31 re-sync) |
| 11 | ABR | `ar.breach.v1` | shipped | 8 event types under 5 regulatory profiles (GDPR Art. 33/34, NIS2 Art. 23, DORA Art. 19, US-AG) |
| 12 | ASR | `ar.subject_rights.v1` | shipped | 9 event types under 6 regulatory profiles (GDPR Arts. 15/16/17/18/20/21); first family minted via factory-from-day-1 through `defineFamily()` |
| 13 | AIR | `ar.impact.v1` | shipped | 11 wire event types (9 logical + terminal trio) under 5 regulatory profiles (GDPR Art. 35(3)(a-c), Art. 35(4) DPA-list, voluntary); RECOMMENDED-TSA matrix on 3 deadline-bearing events (completed, prior_consultation_initiated, prior_consultation_resolved) — no MANDATORY-TSA event in v1; per-event subject carve-out on `dpia.stakeholders_consulted` (D10-AIR-6) |
| 14 | ATokR | `ar.tokenization.v1` | shipped | `@dekimuhq/atokr` 0.3.0 (consolidated verifier + issuer-kit, `.` + `./issue` subpaths, commit `5d09dec2`) + `atokr-profiles` 0.2.4; 4 event types (`token.issued`, `token.redeemed`, `token.revoked`, `token.rotated`); PII-free — salted commit only; scope-binding (audience + purpose + validity); format_class discriminator (`pan`, `email`, `iban`, `phone`, `national_id`, `freeform`). Decision: 2026-05-20-atokr-anchored-tokenization-receipts.md (internal design record, not published) |
| 15 | AActR | `ar.action.v1` | shipped | Autonomous Hub-automation action receipt. Single-shape, null-subject (workspace-level); 1 profile (`hub.automation`); plaintext `verb`/`rule_id`/`recipe_id`/`outcome`/`executed_at` + 3 salted target commits (`decision`/`params`/`request_id`); OPTIONAL mandate binding (`credential_id` + `caveats_consumed`, + `delegation_chain` `{depth,leaf_key,root_credential_id}` for sub-agent delegation paths — Bet B Unit 3, 2026-06-18, additive; + `agent_id` per-agent principal — 2026-06-19, additive); Status-List non-consumer; TSA OPTIONAL. Spec: [2026-06-07-ar-action-v1-anchored-action-receipts-design.md](https://github.com/dekimuhq/anchors-spec/tree/main/action) |
| 16 | AQR | `ar.quality.v1` | shipped | Anchored Quality Receipts — output/version quality-eval provenance (provenance not truth). `@dekimuhq/quality` 0.1.0 + `quality-profiles` 0.1.0; null-subject (must-be-null); 2 profiles (`quality.output`, `quality.release`); Status-List non-consumer; TSA OPTIONAL (upgrade path `free`). DISTINCT from AER (`ar.evaluation.v1`, AI Act conformity). Spec: [2026-06-19-ar-quality-v1-anchored-quality-receipts-design.md](https://github.com/dekimuhq/anchors-spec/tree/main/quality) |
| 17 | AGR | `ar.guard.v1` | shipped | Anchored Guard Verdicts — deterministic prompt-injection / input-screening verdict receipt (provenance of screening, NOT a safety guarantee). `@dekimuhq/guard` 0.1.0 + `guard-profiles` 0.1.0 + `guard-detect` 0.1.0; null-subject (must-be-null); Status-List non-consumer; TSA OPTIONAL (upgrade path `free`). DISTINCT from AER (`ar.evaluation.v1`) and AQR (`ar.quality.v1`). |
| 18 | AGrR | `ar.grounding.v1` | shipped | Anchored Grounding Receipts — citation-binding + grounding-support provenance for RAG answers (binding-authoritative, score-advisory; provenance not truth). `@dekimuhq/grounding` 0.1.0 + `grounding-profiles` 0.1.0 + `grounding-check` 0.1.0; null-subject (must-be-null); Status-List non-consumer; TSA OPTIONAL (upgrade path `free`). DISTINCT from AER/AQR/AGR. Spec: [2026-06-20-ar-grounding-v1-anchored-grounding-receipts-design.md](https://github.com/dekimuhq/anchors-spec/tree/main/grounding) |
| 19 | AgTR | `ar.trace.v1` | shipped | Anchored Agent-Trace Receipts — per-run execution provenance (provenance not behavior). `@dekimuhq/trace` 0.1.0 + `trace-profiles` 0.1.0; null-subject (must-be-null); 1 profile (`agent.trace`); Status-List non-consumer; TSA OPTIONAL (upgrade path `free`). DISTINCT from AActR/AQR/AGR. Spec: [2026-06-20-ar-trace-v1-anchored-agent-trace-receipts-design.md](https://github.com/dekimuhq/anchors-spec/tree/main/trace) |
| 19 | AgTR | `ar.trace.v2` | shipped | signed OTel-compatible span tree; spans[] + parent_span_id + Merkle spans_root (per-span selective disclosure); coexists with v1-flat. `@dekimuhq/trace` 0.2.0 + `trace-profiles` 0.2.0 + `@dekimuhq/trace-otel` 0.1.0. null-subject (must-be-null); Status-List non-consumer; TSA OPTIONAL (upgrade path `free`); single profile `agent.trace`. DISTINCT from AActR/AQR/AGR. |
| 20 | APIIR | `ar.redaction.v1` | shipped (published 2026-06-21) | Anchored PII-Redaction Receipts — proves which PII-redaction pass ran over content before model send (provenance of redaction, NOT a PII-free guarantee). `@dekimuhq/redaction` 0.1.0 + `redaction-profiles` 0.1.0; null-subject (must-be-null); 1 profile (`redaction.prompt`); per-category counts + dual salted commits (input/output) + `ruleset_hash`; reversible map + salt are controller-only, NEVER anchored; reuses the `@dekimuhq/ai` `redactPII` detector (no own detection engine). Status-List non-consumer; TSA OPTIONAL (upgrade path `free`). DISTINCT from ATokR (`ar.tokenization.v1`, reversible vault token) and `ar.anonymization.v1` (irreversible). Spec: [2026-06-20-ar-redaction-v1-pii-redaction-receipt-design.md](https://github.com/dekimuhq/anchors-spec/tree/main/redaction) |
| 21 | ACBR | `ar.compliance.v1` | shipped (published 2026-06-21) | Anchored Compliance Bundle Receipts — workspace-level Proof-of-Compliance bundle (RoPA + DPIA + obligation-satisfaction references). `@dekimuhq/compliance` 0.1.0; null-subject (must-be-null); single profile (`compliance.bundle`); Status-List non-consumer; TSA OPTIONAL (upgrade path `free`); continuity false. References constituents; does not re-derive compliance. Spec: [2026-06-20-b2-verifiable-proof-of-compliance-design.md](https://github.com/dekimuhq/anchors-spec/tree/main/compliance) |

> **Audit fix H4 (2026-05-17):** ANR/ABR/ASR/AIR specs had previously claimed chip positions 6/7/8/9, which collided with AER (positions 4–9 unassigned). This table replaces all per-spec chip-position claims. Member specs SHOULD NOT redeclare chip position; they reference this table instead.
>
> **Version re-sync (2026-06-04):** ALR + ANR Notes synced to the post-publish package versions after the verifier↔profiles cycle-break patch bump (acr/alr/anr/asr/arr) + ATR merge. §6 test counts were already re-measured the same day (see §6 note); ACR/ARR/ASR rows carry no version string here.

---

## 2. TSA mandate matrix

Per-event TSA (eIDAS RFC 3161 trusted timestamp) requirement. The v1.1 envelope §6 carries `tsa` as a top-level signed-out block. The mandate level is per-event-type, not per-claim-type, because deadline-clock-start events warrant stricter time anchoring than informational events.

**Mandate levels:**

| Level | Meaning | Verifier surface when absent |
|---|---|---|
| **MANDATORY** | Receipt is invalid without `tsa`. | HARD-invalid (`tsa_required`) |
| **RECOMMENDED** | Receipt valid without `tsa`, but verifier surfaces a warning that downgrades verifier confidence for deadline-sensitive queries. | `tsa_recommended` (warning) |
| **OPTIONAL** | No verifier surface. | none |

**Family-wide rule (derived from audit-finding H7 review):** events whose `iat` starts a regulatory clock are **MANDATORY**. Events whose `iat` is the basis for a verifier-side deadline check but where the clock-start is anchored elsewhere are **RECOMMENDED**. All other events are **OPTIONAL**.

| Family | Event | Mandate | Rationale |
|---|---|---|---|
| APR | (any) | OPTIONAL | Provenance receipts; no regulatory clock |
| ACR | `ar.consent.v1` issuance (default profiles) | OPTIONAL | Consent collection; clock is the policy-version anchor |
| ACR | `acr.esig.accept@qes` profile | MANDATORY (incl. `requires_tsa_listed`, `requires_tsa_policy_oid`) | Per v1.1 §6.8 profile-mandate; QES acceptance is legally-defining |
| ARR | `ar.erasure.v1` under `arr.gdpr.art17.erasure-finalized` profile | MANDATORY | Per v1.1 §6.8; erasure execution is legally-defining |
| ARR | other events | RECOMMENDED | Retention decisions cross-checked but not regulatory-clock-start |
| ADR | (any) | OPTIONAL | Delegation; no regulatory clock |
| ATR | `body.event_type: arrangement` | RECOMMENDED | Arrangement clock relevant for transfer-validity checks |
| ATR | `body.event_type: suspension` | RECOMMENDED | Suspension clock relevant for post-suspension transfer invalidation |
| ATR | other events | OPTIONAL | |
| APuR | (any) | OPTIONAL | Purpose binding; no regulatory clock |
| AER | `body.event_type: conformity` | RECOMMENDED | Conformity has `valid_until` clock |
| AER | `body.event_type: transparency` | OPTIONAL | |
| AAR | `body.event_type: issuance` with `service_type: qts` | MANDATORY | QTS issuance is the timestamp itself |
| AAR | `body.event_type: issuance` other service types | RECOMMENDED | |
| AAR | `body.event_type: revocation` | RECOMMENDED | |
| ALR | (any) | OPTIONAL | Lineage; no regulatory clock |
| ANR | `notice.aiact.art50_transparency` profile | MANDATORY + QTS OID `0.4.0.2023.1.1` | AI Act evidence; profile-side eIDAS QTS pinning (EUTL-listed + BTSP OID) |
| ANR | other profiles | RECOMMENDED | Notice presentation deadlines |
| ABR | `body.event_type: breach.detected` | **MANDATORY** (per spec D10-ABR-2) | The 72-hour clock starts here; no exception |
| ABR | other events | RECOMMENDED | All breach-lifecycle events are deadline-sensitive |
| ASR | `body.event_type: request.received` | RECOMMENDED | 30-day clock starts here; raise to MANDATORY in v1.1 if EUDI Wallet pilots demand stronger anchoring. **Verifier enforcement (the `tsa_recommended` warning) DEFERRED to Phase 4 Task 4.5a** — the event-keyed mandate callback shape that also resolves ABR's matrix is not yet wired, so `asr-verifier` surfaces no warning for this event in the current release. |
| ASR | other events | OPTIONAL | |
| AIR | `body.event_type: dpia.completed` | RECOMMENDED | DPIA completion sequence vs processing-start |
| AIR | `body.event_type: dpia.prior_consultation_initiated` | RECOMMENDED | Art. 36 clock |
| AIR | `body.event_type: dpia.prior_consultation_resolved` | RECOMMENDED | DPA-advice receipt clock |
| AIR | other events | OPTIONAL | |
| ATokR | (any) | OPTIONAL | No regulatory clock starts on a tokenization event in current EU regimes. Re-evaluate if EUDI Wallet ARF or NIS2 sectoral acts impose tokenization deadlines. |
| AActR | (any) | OPTIONAL | No regulatory clock starts on an autonomous action; trusted timestamp is opt-in. |
| AQR | (any) | OPTIONAL | No regulatory clock starts on a quality eval; trusted timestamp is opt-in (upgrade path `free`). |
| AGR | (any) | OPTIONAL | No regulatory clock starts on a guard verdict; trusted timestamp is opt-in (upgrade path `free`). |
| AGrR | (any) | OPTIONAL | No regulatory clock starts on a grounding receipt; trusted timestamp is opt-in (upgrade path `free`). |
| AgTR | (any) | OPTIONAL | No regulatory clock starts on an agent-trace event; trusted timestamp is opt-in (upgrade path `free`). |
| AgTR (`ar.trace.v2`) | (any) | OPTIONAL | Span-tree trace; no regulatory clock; trusted timestamp is opt-in (upgrade path `free`). |
| APIIR | (any) | OPTIONAL | No regulatory clock starts on a redaction pass; trusted timestamp is opt-in (upgrade path `free`). |
| ACBR | (any) | OPTIONAL | No regulatory clock starts on a compliance bundle receipt; trusted timestamp is opt-in (upgrade path `free`). |

> **Audit fix H7 (2026-05-17):** prior to this table, TSA mandate language varied across closure specs (ABR mandated on `breach.detected`, ASR recommended on `request.received`, AIR recommended on `dpia.completed` — without a principled rule). This table applies a single rule (regulatory-clock-start ⇒ MANDATORY; deadline-checks ⇒ RECOMMENDED; else OPTIONAL). Member specs reference this table; per-spec mandate language MUST match.

---

## 3. Subject-presence matrix

Each family member declares whether the `subject` envelope field is `null`, populated as a salted commit (`"sha256:<hex>"` per v1.1 §5.4), or carries a free-form provenance subject. This table consolidates the per-spec rules so cross-spec invariants (e.g. "ASR↔ARR subject parity") can be enforced uniformly.

| Family | Event | `subject` value | Rationale |
|---|---|---|---|
| APR | (any) | free-form (artifact URL/id); `"sha256:<hex>"` is accepted and is the typical/recommended form (asset hash) | Provenance; v1.1 §5.4. Verifier requires subject present, no prefix exclusion (`apr-verifier` `checkSubjectPresence` accepts `sha256:<hex>`) |
| ACR | (any) | `"sha256:<hex>"` (HMAC-salted subject commit) | Required per v1.1 §5.4 |
| ARR | (any) | `"sha256:<hex>"` | Required per v1.1 §5.4. Body carries `target_kind` + `target_commit` for finer-grain target discrimination (subject vs system vs object) |
| ADR | (any) | `"sha256:<hex>"` of delegator commit; processor/deployer references in body | |
| ATR | `body.event_type: arrangement` | `null` (arrangement is data-flow-level, not subject-level) | |
| ATR | `body.event_type: transfer` | `"sha256:<hex>"` batch root or per-subject commit | Per-transfer subjects identified via batch leaves |
| ATR | other events | `null` | |
| APuR | (any) | `null` (purpose is processing-activity-level, not subject-level) | |
| AER | `body.event_type: conformity` | `null` (system-level) | |
| AER | `body.event_type: transparency` | `"sha256:<hex>"` (end-user subject) | |
| AAR | `body.event_type: issuance` | `"sha256:<hex>"` of signatory commit | |
| AAR | `body.event_type: revocation` | `"sha256:<hex>"` matching the revoked issuance's subject | |
| ALR | (any) | `null` (lineage is dataset-level) | Body carries source/derivation refs |
| ANR | `body.event_type: notice.acknowledged` | `"sha256:<hex>"` | Acknowledgement is per-subject |
| ANR | other events | `"sha256:<hex>"` (default) OR `null` for jurisdiction-level notice events that have no subject context | |
| ABR | incident-level events (detected, assessed, dpa_notified, dpa_delayed, contained, closed) | `null` | Incident-level, not subject-level |
| ABR | `body.event_type: subject_notified` | `"sha256:<hex>"` batch root | Batch over affected subjects |
| ABR | `body.event_type: subject_notification_exempted` | `null` (the exemption is incident-level, not per-subject) | |
| ASR | (every event) | `"sha256:<hex>"` (MANDATORY per D10-ASR-5) | Every event is subject-scoped |
| AIR | (every event) | `null` (DPIA is processing-activity-level) | EXCEPT `body.event_type: stakeholders_consulted` where representative-org commit MAY appear |
| ATokR | (every event) | `"sha256:<hex>"` (salted commit of the tokenized plaintext) | Every tokenization event is subject-scoped — the receipt anchors the surrogate↔plaintext mapping proof |
| AActR | (every receipt) | `null` | Workspace/activity-level; the action's target is a body commit (`decision_commit`/`params_commit`), never the envelope subject |
| AQR | (every receipt) | `null` (must-be-null) | Quality eval is about a model/output, not a data subject |
| AGR | (every receipt) | `null` (must-be-null) | Guard verdict is about a prompt/input, not a data subject |
| AGrR | (every receipt) | `null` (must-be-null) | Grounding receipt is about a RAG answer + sources, not a data subject |
| AgTR | (every receipt) | `null` (must-be-null) | Agent-trace is about an execution run, not a data subject |
| AgTR (`ar.trace.v2`) | (every receipt) | `null` (must-be-null) | Span-tree trace is about an execution run, not a data subject; per-span detail is bound via the Merkle `spans_root`, never the envelope subject |
| APIIR | (every receipt) | `null` (must-be-null) | Redaction is about a prompt/content blob, not a data subject; the redacted content is bound via salted body commits, never the envelope subject |
| ACBR | (every receipt) | `null` (must-be-null) | Compliance bundle is workspace-level; constituents reference data subjects by hash in their own receipts |

> **Audit fix H10 (2026-05-17):** consolidates subject-presence rules. Member-spec D10 deltas SHOULD reference this table rather than re-declaring rules. Subject-parity invariants between specs (e.g. ASR↔ARR Art. 17) cross-check this table's salted-commit form (`"sha256:<hex>"`).

---

## 4. Status List 2021 consumer ordering

W3C Status List 2021 was introduced in v1.1 hardening (§8). Each family member that consumes Status List 2021 declares an ordering position. The order is anchored to **first-consumer date**, not "Nth family member" (the latter drifts as new members are added).

| Order | Family | Consumer-of-status-list-since | Notes |
|---|---|---|---|
| 1 | ALR | v1.0 (designed-in) | Reference implementation; spec-source for the family-wide consumer pattern |
| 2 | ACR | v1.1 retrofit | First retrofit on shipped code |
| 3 | ARR | v1.1 retrofit | Second retrofit on shipped code |
| 4 | ANR | v1.0 of ANR (= post-v1.1 envelope) | First spec authored with status-list-consumer at design time |
| 5 | ABR | v1.0 of ABR | |
| 6 | ASR | v1.0 of ASR | |
| 7 | AIR | v1.0 of AIR | |
| 8 | ADR | v1.0 of ADR | |
| 9 | ATR | v1.0 of ATR | |
| 10 | APuR | v1.0 of APuR | |
| 11 | AER | v1.0 of AER | |
| 12 | AAR | v1.0 of AAR | |
| 13 | ATokR | v1.0 of ATokR | `token.revoked` flips bit; `token.rotated` flips predecessor bit |

APR currently does NOT consume Status List 2021 (provenance receipts are typically not revocable; immutability is part of their value). Adding APR to Status List 2021 would require a v1.1 APR amendment.

AActR also does NOT consume Status List 2021 (`status_list_slot: null`) — an autonomous action is a non-revocable event that *happened*; there is no suspension/revocation surface in v1 (spec §3, decision 3).

AQR also does NOT consume Status List 2021 (`status_list_slot: null`) — an eval is a point-in-time fact; supersede with a newer receipt, never revoke.

AGR also does NOT consume Status List 2021 (`status_list_slot: null`) — a guard verdict is a point-in-time screening decision; supersede with a newer receipt, never revoke.

AGrR also does NOT consume Status List 2021 (`status_list_slot: null`) — a grounding receipt is a point-in-time binding+scoring fact about one answer; supersede with a newer receipt, never revoke.

AgTR also does NOT consume Status List 2021 (`status_list_slot: null`) — an agent-trace is a point-in-time execution record; supersede with a newer receipt, never revoke. This holds for both claim types (`ar.trace.v1` flat + `ar.trace.v2` span-tree).

APIIR also does NOT consume Status List 2021 (`status_list_slot: null`) — a redaction receipt is a point-in-time provenance fact; supersede with a newer receipt, never revoke.

ACBR also does NOT consume Status List 2021 (`status_list_slot: null`) — a compliance bundle receipt is a point-in-time provenance snapshot; supersede with a newer receipt to reflect updated compliance state, never revoke.

> **Audit fix H5 (2026-05-17):** consolidates per-spec ordering claims that conflicted (multiple specs claimed "Nth"). This table is the canonical sequence; member specs reference it instead of declaring their own ordinal.

### 4.1 Suspension List support

Wave 3 (envelope 0.14.0) added `suspensionStatus` — a second Status List 2021 pointer with `statusPurpose: "suspension"` (two-way, unlike revocation which is permanent). Issuer-kits expose `suspensionList?: SuspensionListConfig` on their mint input.

All 13 families that consume revocation also support suspension. APR does not (non-revocable by design). The `family-mint-pipeline` (`buildMintV2`) supports suspension for any family routed through `defineFamily()` (currently ASR).

---

## 5. Shared-package references (mandatory imports)

Every member spec's anchor flow §7 and verifier package SHOULD reference these shared packages by name. Failing to import implies the spec re-defines envelope fields, leading to drift on next envelope version.

| Package | Purpose | Required for |
|---|---|---|
| `@dekimuhq/anchors-envelope` (subpaths: `/continuity`, `/issuer`, `/suspension`, `/merkle`, `/commit`, `/field-commit`) | v1.1+ shared envelope, canonical-JSON helpers, signing primitives, `JSON_LOGIC_ALLOWLIST_V1_2` constant. Phase 2 Tier A added `/merkle` (Merkle tree helpers, lifted from acr-verifier), `/commit` (salted-field commit primitive), and `/field-commit` (`ar.field_commit.v1` attestation shape + issue/verify helpers). | Every member's verifier + issuer-kit |
| `@dekimuhq/did-web-resolver` (v0.1.0, shipped 2026-05-17; 0.2.0 adds `verifyIssuerKey` + trust-tier hooks under Phase A of the cross-issuer interop plan) | did:web resolution + InMemoryKeyCache + `trustedLogs` allowlist option (cross-issuer interop) | Every member's verifier that accepts non-Dekimu issuers; closure-set members SHOULD declare cross-issuer interop support in v1 |
| `@dekimuhq/anchors-trusted-issuers` (Phase B of the cross-issuer interop plan, 2026-05-19 (internal design record, not published)) | Default `TrustedIssuersSource` implementation: signed allowlist + revocation surface, mirrored at `verify.dekimu.com/.well-known/dekimu-trusted-issuers.json` and hash-chained at `dekimuhq/anchors-trusted-issuers-chain` | Every member's verifier whose default trust dispatch matches Dekimu's policy; OPTIONAL for verifiers that ship their own `TrustedIssuersSource` |
| `@dekimuhq/anchors-federation` 0.1.0 (Phase C of the cross-issuer interop plan, shipped 2026-05-22) | Federated discovery: `fetchIssuerManifest` + `verifyIssuerManifest` + `runHandshake` + `ManifestCache`; parses, verifies, and caches `ar.issuer_manifest.v1` documents; CLI handshake report via `scripts/run.ts` | OPTIONAL — only verifiers and tools that surface cross-issuer discovery (e.g. `verify.dekimu.com`, audit pipelines). Member specs SHOULD list the family memberships and profiles they expect to advertise in their own `dekimu-issuer.json` |
| `@dekimuhq/anchors-disclosure` (private, Phase 2 Tier A, shipped 2026-06-01) | Tier A selective disclosure: `buildPresentation`/`assemblePresentation` (assemble reveal set + Merkle paths into an `ar.disclosure.v1` presentation) + `verifyPresentation` (verifies field reveals against the issuer-signed `ar.field_commit.v1` out of body). The `ar.field_commit.v1` attestation is issued/verified by `@dekimuhq/anchors-envelope` (`issueFieldCommit`/`verifyFieldCommit`, `./field-commit`). | OPTIONAL — disclosure tooling only; not required by any member verifier in v1. **Exception: `ar.trace.v2` (AgTR)** imports `@dekimuhq/anchors-disclosure` directly — its issuer-kit (`mintTraceV2`, `issue/mint-v2.ts`) computes the per-span Merkle `spans_root` for selective disclosure; the verifier NEVER recomputes `spans_root` (format check only — `verify-tree.ts` holds only the skeleton). This is a REQUIRED import for the trace v2 package (beyond the baseline `@dekimuhq/anchors-envelope`). |

> **Audit fix H11 + H12 (2026-05-17):** consolidates package-reference rule. Pre-canonical specs (ATR/APuR/AER/AAR/ALR) had no envelope-package mention; closure specs (ANR/ABR/ASR/AIR) had no did-web-resolver mention. This table establishes both as family-wide mandatory imports.
>
> **Cross-issuer interop additions (2026-05-19, plan-approved):** `@dekimuhq/anchors-trusted-issuers` and `@dekimuhq/anchors-federation` added as opt-in shared infrastructure for the trust surface. They do NOT touch wire format. Member specs that integrate `verifyIssuerKey` (mandatory once 0.2.0 lands in Phase A) SHOULD reference the default `TrustedIssuersSource` shipped by `@dekimuhq/anchors-trusted-issuers` unless the deployment overrides it.
>
> **`did-web-resolver` conditionality (behavioral rule — clarified 2026-05-30, generalized 2026-06-04):** the row's "Required for" is conditional on a verifier performing its **own** in-verifier issuer-trust dispatch. **Every current family verifier (all 14) delegates issuer-key resolution entirely to the caller's `resolveKey`** — the default returns `undefined` and no member bundles a did:web / cross-issuer trust step (verified across the family 2026-06-04, ASR carve-out corrected 2026-09-02: APR/ACR/ARR/ALR/ANR/ABR/AIR/ATR/APuR/AER/AAR/ADR/ATokR use the wrapper `resolveKey: opts?.resolveKey ?? (() => undefined)`; **ASR is the one exception** — factory-from-day-1 through `defineFamily()`, no legacy wrapper: `resolveKey` is a **required** `FamilyVerifyOptions` field with no fallback, so caller-delegation holds there by construction). So `@dekimuhq/did-web-resolver` is **OPTIONAL for every family verifier today**; it becomes REQUIRED only for a member that adopts in-verifier `verifyIssuerKey` in a future minor. Cross-issuer trust is the integrator's responsibility until then. _(Supersedes the earlier "pre-canonical APR/ACR/ARR only" wording — that named three examples of what is in fact the universal pattern; the invariant audit 2026-06-04 flagged the gap as 5 separate false discrepancies.)_

---

## 6. Engineering budget table (canonical)

| Family | Status | Tests promised | Engineering budget (1-eng-eq) | Closeable by |
|---|---|---|---|---|
| APR | shipped | 89 (apr 89; no profiles package) | shipped | shipped |
| ACR | shipped | 183 (acr 141 + acr-profiles 42) | shipped | shipped |
| ARR | shipped | 217 (arr 171 + arr-profiles 46) | shipped | shipped |
| ADR | shipped | 196 (adr 151 + adr-profiles 45) | shipped | — |
| ATR | shipped | 175 (verifier 75 + profiles 77 + issuer-kit 23) | shipped | — |
| APuR | shipped | 171 (verifier 99 + profiles 49 + issuer-kit 23) | shipped | — |
| AER | shipped | 118 (aer 71 + aer-profiles 47; verifier + issuer-kit consolidated into `@dekimuhq/aer` — re-measured 2026-09-02) | ~3.5 weeks | shipped |
| AAR | shipped | 217 (aar 90 + aar-profiles 76 + aar-tsl 51) | shipped | shipped |
| ALR | shipped | 160 (alr 119 + alr-profiles 41) | shipped | shipped |
| ANR | shipped | 268 (verifier 154 + issuer-kit 45 + profiles 69) | shipped | shipped |
| ABR | shipped | 453 (verifier 197 + issuer-kit 113 + profiles 143) | shipped | shipped |
| ASR | shipped | 409 (asr 292 + asr-profiles 117) | shipped | shipped |
| AIR | shipped | 465 (verifier 242 + issuer-kit 112 + profiles 111) | shipped | shipped |
| ATokR | shipped | 109 (atokr 77 + atokr-profiles 32; verifier + issuer-kit consolidated into `@dekimuhq/atokr` — re-measured 2026-09-02) | shipped | shipped |
| AActR | shipped | 223 (action 142 + action-profiles 81) | ~0.5 eng-eq | shipped (2026-06-08) |
| AQR | shipped | 156 (quality 109 + quality-profiles 47) | ~0.5 eng-eq | shipped (2026-06-19) |
| AGR | shipped | 99 (guard 47 + guard-profiles 7 + guard-detect 45) | ~0.5 eng-eq | shipped (2026-06-20) |
| AGrR | shipped | 125 (grounding 57 + grounding-profiles 59 + grounding-check 9) | ~0.5 eng-eq | shipped (2026-06-20) |
| AgTR | shipped | 148 (trace 134 + trace-otel 4 + trace-profiles 10) | ~0.5 eng-eq | shipped (2026-06-20) |
| AgTR (`ar.trace.v2`) | shipped | see `trace`/`trace-profiles` 0.2.0 + `trace-otel` 0.1.0 test suites (v2 span-tree + OTel exporter) | ~0.5 eng-eq | built-to-ready on `feat/ar-trace-v2` |
| APIIR | shipped | 91 (redaction 58 [verify-single 36 + mint-v1 22] + redaction-profiles 33) | ~0.5 eng-eq | published 2026-06-21 |
| ACBR | shipped | 196 (compliance 196; no profiles pkg) | ~0.5 eng-eq | published 2026-06-21; floor re-applied 2026-09-07 (was 9, exemption lifted) |

**Total unimplemented: 0 — all 21 members built AND published (AActR added 2026-06-08; AQR added 2026-06-19; AGR + AGrR + AgTR added 2026-06-20; APIIR + ACBR added 2026-06-21 and published the same day).**

> **APIIR test-floor note (RESOLVED — 2026-06-21):** the suite was expanded 12 → **91 genuine tests** (maintainer chose "expand"). Coverage spans every validator error path (both `verifyRedactionBody` and the `redaction.prompt` profile), all 6 categories + empty/zero/boundary counts, the `Array.isArray` counts guard, `buildRedactionBody` shape/passthrough, all five `mintRedactionV1` guards, verify-before-sign, round-trip Ed25519 verification, tamper rejection, salt/PII absence, and commit-reveal (`verifyCommitment`). At 91 it sits 8 short of the ≥99 floor; the remaining gap is **accepted as the genuine ceiling for this surface** (APIIR has no own detection engine — it reuses `@dekimuhq/ai` `redactPII`; unlike AGR's 45-test `guard-detect` corpus), padding to 99 would be test-theater. Documented mini-exemption, parallel to APR's grandfathering rationale.

> **ACBR test-floor note (EXEMPTION LIFTED — 2026-09-07):** the floor now applies to ACBR and it clears it: the `compliance` suite was expanded **9 → 196 genuine tests** (`test/validator-paths.test.ts` · `test/mint-guards.test.ts` · `test/keys-family-exports.test.ts`). **The 2026-07-06 exemption should never have been granted on the reason it gave.** It rested on ACBR being "build-to-ready, publish maintainer-gated" with publish "not yet scheduled", and bound itself to re-apply the floor at publish time — but `@dekimuhq/compliance@0.1.0` had **already published on 2026-06-21** (GitHub Packages `created_at` 2026-06-21T01:32:41Z, read from the registry rather than from a document), **sixteen days before the exemption was written**. So a published package ran on 9 tests against a ≥99 floor for 78 days, and the condition that was supposed to catch it had already passed unnoticed. This is NOT the APIIR case: APIIR stopped at 91 because it has no detection engine of its own and padding would have been test-theater, whereas ACBR's surface genuinely supports the coverage — ~30 distinct validator error codes over a nested body, plus five mint guards, verify-before-sign, envelope-field derivation and tamper rejection on the only surface in the package that emits a SIGNED artefact. The mint guards had **zero** coverage before this pass. Lesson recorded rather than the exemption re-justified: a gate whose release condition is a future event needs the event checked, not assumed.

**Family-wide test gate:** ≥99 tests per family member — **except APR** (exempt: 84 tests, pre-canonical reference family with no profiles package; the ≥99 floor was set 2026-05-27 *after* APR shipped, and APR's verifier+issuer-kit coverage is the verified-acceptable baseline, not a regression). **ACBR's exemption was LIFTED 2026-09-07** (9 → 196 tests — see the ACBR test-floor note above), so APR is now the only exemption. All other members clear the floor. Baseline 4,164 across all packages (2026-05-27) — **STALE, re-verify via `npm run validate`.**

> **Test-count re-verification (2026-07-06):** all 21 rows re-measured via `npm run validate` (which now actually runs each family's `npm test` and sums the TAP summary — see §7 automation-coverage note). 9 rows had drifted from their actual counts and were corrected here: AActR 131→223, AAR 166→217, ACR 168→183, ADR 161→196, ARR 210→217, ALR 155→160, APR 84→89, ASR 391→409, AgTR 110→148. All corrections are pure count growth (more tests added since the promised figure was last written) — none regressed below the floor.

> **Test-count re-verification (2026-06-04):** **all 14 rows re-measured directly** via `npm test` on a development branch and synced — replacing the prior vague placeholders (ACR/ARR "subset of 579", ADR "99+", AER "90+") and stale counts (ANR 260→268, ABR 373→453, ASR 213→391, and the earlier ATR 175 / APuR 171 / ALR 155 / AIR 465 updates; ATR includes the new countersig_key V17 test). APR/AAR/ATokR were already correct. §6 counts remain NOT machine-gated — re-verify on audit.

> **Audit fix H2 (2026-05-17):** pre-canonical specs (ATR/APuR/AER/AAR/ADR) had no budget or test-count promise. Consolidated here. ALR weeks added.

---

## 7. Consistency-checklist for new family members

When proposing a new claim_type (any time post-2026-05-17), the spec MUST update this file's tables before merging:

1. Add chip-position row (§1).
2. Add TSA mandate row(s) per event (§2).
3. Add subject-presence row(s) per event (§3).
4. Add status-list consumer position (§4) — or declare APR-style "not consumed".
5. Add shared-package import declarations (§5).
6. Add engineering budget row (§6).

Spec authors: copy the consistency-checklist into your draft's §3.0 ("family integration") section and fill in. Auditor pre-merge: confirm all six tables updated.

> **Automation coverage (updated 2026-07-06 — corrects the 2026-05-30 note, which had gone stale):** `npm run validate` (`schema/validate.ts`) now cross-checks every family against **§1 (chip)**, **§2 (TSA mandate — manifest-level OPTIONAL/non-OPTIONAL split, PLUS a `src/family.ts` source-level drift check)**, **§3 (subject-presence — manifest-level must-be-null/must-be-present/either, PLUS the same `src/family.ts` source-level drift check)**, **§4 (status-list slot)**, **§5 (shared-package import rules — the mandatory `@dekimuhq/anchors-envelope` dependency for every member, and the documented `@dekimuhq/anchors-disclosure` REQUIRED exception for AgTR/trace)**, and **§6 (test-count floor — actually runs each family's `npm test` and sums the `node --test` TAP summary, gated on the ≥99 floor with the APR/APIIR documented exemptions (ACBR's was lifted 2026-09-07))** — plus a **manifest-roster coverage check**: every acronym in the §1 chip table MUST have a `schema/families/*.anchor.json` manifest, hard error otherwise. §2/§3/§5/§6 checks are intentionally conservative (assert only where the table gives an unambiguous signal; hedged/prose-only rows fall back to a warn) — see `schema/validate.ts`'s doc comment for the full per-section design. **Resolved 2026-07-06:** the 2026-07-06 live finding below (APIIR/ACBR missing manifests + ACBR below the §6 floor) is now closed — `schema/families/ar.redaction.v1.anchor.json` and `schema/families/ar.compliance.v1.anchor.json` were authored (closing the manifest-roster gap for chips 20/21) and the ACBR test-floor note above now records that its exemption was LIFTED on 2026-09-07 rather than re-justified — the 9→196 expansion means `npm run validate` exits 0 with ACBR measured against the real floor, not excused from it. **Trap for anyone re-running this:** §6 executes each family's `npm test`, so an unbuilt workspace `dist/` makes sibling suites fail to LOAD and the counts silently undercount — a first run here reported 7 families below the floor and APIIR at 35-vs-91, all of which vanished after `npm run build-all`. Build before believing a count. CI wiring: `npm run validate` runs on every `pull_request` and push to `main` via `.github/workflows/ci.yml`. §7, §8.2, §8.3 and APR's positive Status-List exclusion are not machine-checked by `schema/validate.ts`; they are covered by maintainer review.

---

## 8. Standalone attestations (non-receipt signed artifacts)

Standalone attestations are signed artifacts that share the canonical `ar.<noun>.v<N>` discriminator family with member receipts but carry **no `claim_type`, no body-derived `field_root` of their own, no `subject`, and no v=2 envelope wrapper**. They certify operational state (key continuity, trust scope, issuer self-description, or receipt-binding metadata) rather than a per-subject event. Note: `ar.field_commit.v1` is the first standalone attestation that *references* (does not compute) a receipt's `field_root` and additionally carries a signed `leaf_count`; it does not define its own field tree. All standalone attestations:

- Sign the JCS-canonicalised attestation body with `sig: null` (RFC 8785 canonical JSON; ed25519 over the canonical bytes).
- Are owned by an `@dekimuhq/anchors-envelope/<subpath>` export so issuer-kits across the family share one primitive surface.
- Use a `kind` discriminator (or shape-named field) keyed to the `ar.<noun>.v<N>` taxonomy — mutating any field (including the discriminator) invalidates the signature.
- Are registered in [`REGISTRY.md`](REGISTRY.md) under the "standalone-attestation" subsection (separate from the `claim_type` registry).

Two scopes are distinguished:

| Scope | Meaning | Members |
|---|---|---|
| **Per-family** | One attestation per family member, owned by that family's issuer-kit (pins a `family` slug at issue time). | `ar.continuity.v1` (§8.1) |
| **Family-wide** | One attestation surface shared across all 14 members; not pinned to any one family. Carries no `family` slug. | `ar.trusted_issuers.v1` (§8.2), `ar.issuer_manifest.v1` (§8.3), `ar.field_commit.v1` (§8.4) |

### §8.1 — `ar.continuity.v1` (per-family issuer key-rotation attestation)

Promoted from per-family `<family>.continuity.v1` (ALR / ARR / ANR) to the canonical `ar.<noun>.v<N>` wire form in envelope 0.7.0. Owned by `@dekimuhq/anchors-envelope/continuity` subpath export; each family's issuer-kit re-exports the helpers and pins its own `family` slug at issue time. Spec: [`2026-05-18-anchors-continuity-v1-unification.md`](https://github.com/dekimuhq/anchors-spec/tree/main/envelope).

| Family | Slug (body `family` field) | Continuity flow | Issuer-kit re-export | Notes |
|---|---|---|---|---|
| APR | `apr` | **shipped** | `@dekimuhq/apr` (`./issue` subpath) | Re-exports from envelope/continuity. |
| ACR | `acr` | **shipped** | `@dekimuhq/acr` (`./issue` subpath) | Re-exports from envelope/continuity. |
| ARR | `arr` | **shipped** | `@dekimuhq/arr` (`./issue` subpath) | Re-exports `issueContinuityAttestation` + `verifyContinuityAttestation` from envelope subpath. |
| ALR | `alr` | **shipped** | `@dekimuhq/alr` (`./issue` subpath) | Re-exports. |
| ANR | `anr` | **shipped** | `@dekimuhq/anr` (`./issue` subpath) | Re-exports. |
| ASR | `asr` | **shipped** | `@dekimuhq/asr` (`./issue` subpath) | Re-exports from envelope/continuity. |
| ABR | `abr` | **shipped** | `@dekimuhq/abr` (`./issue` subpath) | Re-exports. |
| AIR | `air` | **shipped** | `@dekimuhq/air` (`./issue` subpath) | Re-exports. |
| ATokR | `atokr` | **shipped** | `@dekimuhq/atokr` (`./issue` subpath) | Re-exports. |
| APuR | `apur` | **shipped** | `@dekimuhq/apur` (`./issue` subpath) | Re-exports from envelope/continuity. |
| ATR | `atr` | **shipped** | `@dekimuhq/atr` (`./issue` subpath) | Re-exports from envelope/continuity. |
| AER | `aer` | **shipped** | `@dekimuhq/aer` (`./issue` subpath) | Re-exports from envelope/continuity. |
| AAR | `aar` | **shipped** | `@dekimuhq/aar` (`./issue` subpath) | Re-exports `issueContinuityAttestation` + `verifyContinuityAttestation` from envelope/continuity. |
| ADR | `adr` | **shipped** | `@dekimuhq/adr` (`./issue` subpath) | Re-exports from envelope/continuity. |

> **Issuer-kit column re-synced 2026-09-02:** the per-family `@dekimuhq/<family>-issuer-kit` packages were consolidated into each family package's `./issue` subpath (commit `5d09dec2`, 2026-06-05, verified fleet-wide 2026-06-18); the standalone issuer-kit packages no longer exist. The old version floors (arr ≥0.5.0, alr ≥0.2.0, anr ≥0.2.0, adr ≥0.3.1) referenced the retired packages and are superseded by the consolidated package versions in each package's `package.json` (the version authority).

**Wire-format notes:**

- The closed `FamilySlug` union (`apr | acr | arr | alr | atr | apur | aer | aar | adr | anr | asr | abr | air | atokr`) is exported from `@dekimuhq/anchors-envelope/continuity` and matches the 14 continuity-participating families (the 7 later members — AActR/AQR/AGR/AGrR/AgTR/APIIR/ACBR — opt out via `continuity: false` in their `family.ts`).
- Hard-cut migration applied 2026-05-19 (pre-launch): no legacy `<family>.continuity.v1` parser shipped. The verifier rejects any non-`ar.continuity.v1` `kind` with `kind.invalid`.

### §8.2 — `ar.trusted_issuers.v1` (family-wide signed allowlist manifest)

**Status:** shipped — `@dekimuhq/anchors-trusted-issuers` (0.1.0 Phase B; 1.0.0 pins the B6 genesis `BOOTSTRAP_PUBLISHER_KEY`, 2026-07-17) (Phase B of the cross-issuer interop plan, `2026-05-19-anchors-cross-issuer-interop.md` (internal design record, not published) §2). 123 tests. Verifier `verifyTrustedIssuersList()` (JCS + ed25519 over `{ ...doc, sig: null }`); append-only chain fixtures at `trusted-issuers/data/chain/v0{1,2,3}.json`.

Family-wide. No `family` slug — one signed list governs trust dispatch for every family member's verifier. Published at `verify.dekimu.com/.well-known/dekimu-trusted-issuers.json`; append-only chain at `dekimuhq/anchors-trusted-issuers-chain`. **Byte flow (2026-10-19):** the chain repo is where docs are signed (the publisher seed is its `SIGNING_KEY_BASE64` Actions secret, no escrow) and where `chain/head.json` names the current head; verify fetches `head.json` (1 h revalidate), serves it only if it verifies under the pinned key, else a vendored floor copy. Verifiers still fetch the verify URL, never the repo.

| Surface | Value |
|---|---|
| Discriminator | `kind: "ar.trusted_issuers.v1"` |
| Body shape | `{ kind, version, issued_at, valid_until, publisher, publisher_key, previous_sha256 \| null, issuers: TrustedIssuerRecord[], sig }` (`version` + `previous_sha256` form the append-only hash chain; `issued_at`/`valid_until` bound the validity window) — `TrustedIssuerListV1` in `trusted-issuers/src/types.ts` |
| Signing key | Pinned `BOOTSTRAP_PUBLISHER_KEY` (Dekimu family key in v1); 1-year rotation with 90-day overlap (Q5 decision) |
| Cadence | Each doc is valid 30 days. `monthly-republish.yml` in `dekimuhq/anchors-trusted-issuers-chain` checks weekly (Mon 03:17 UTC) and re-signs when < 14 days remain; output is a `republish/vNN` PR (merge = publish). Reds when a renewal is due but cannot be produced. That repo's Actions may not open PRs (deliberate, 2026-10-16), so the run pushes the branch and a separate maintainer workflow (Mon + Thu 04:30 UTC + dispatch) opens the PR and, since 2026-10-20, squash-merges it automatically when it is a PURE renewal (same `issuers` as main, `version` + 1, same `publisher_key`, one commit over the two chain paths, every check on the head sha green); a `sign-proposal` PR (issuer-set change) always waits for the maintainer. By hand: `gh pr create -R dekimuhq/anchors-trusted-issuers-chain --head republish/vNN --base main`. Until 2026-10-19 it ran monthly with a 30-day skip and was dry-run — v01 expired 2026-08-16 |
| Consumed by | `verifyIssuerKey` (§5 row 2) via the default `TrustedIssuersSource` implementation |

**Wire-format notes:**

- Standalone attestation per §8 invariants (no envelope; JCS + sig: null; ed25519).
- The `BOOTSTRAP_PUBLISHER_KEY` SPKI is baked into `@dekimuhq/anchors-trusted-issuers` and `@dekimuhq/did-web-resolver`. Rotating it requires a package version bump on every consumer.
- The federation governance Q4 (rotating chair / multi-sig 2-of-3) is deferred. v1 ships unilateral Dekimu signing; the manifest README links the federation roadmap.
- **Issuer PQC-migration trust state (2026-06-19, R3 — decision `2026-06-19-anchors-v1-3-r3-issuer-pqc-migration-trust-state.md` (internal design record, not published)):** `TrustedIssuerRecord` gains an **optional** `pqc_mandatory?: { min_sig_alg, mandatory_from } | null` (`PqcMandate`, defined in `did-web-resolver`). Additive — absent ⇒ Ed25519 accepted; existing records/manifests unchanged, no wire change to the list shape. The issuer-level half of the HNDL defense (per-receipt half = envelope `sig_min_alg`): pure policy `issuerPqcRequirement` / `satisfiesIssuerPqc` in `@dekimuhq/anchors-trusted-issuers` (fail-closed on unrecognised `min_sig_alg`). **Enforcement is Phase-2-wired (commit `800f5c1c`):** the shared `family-verify-pipeline.ts` Step 5.6 calls an injected `verifyIssuerPqc` hook after issuer-trust resolves to a matched record, deriving the floor-alg from the *verified* `hybrid.validAlgs` (never the self-described `sig_alg`); the hook is composed by `makeVerifyIssuerPqc` in `@dekimuhq/anchors-trusted-issuers`. This reaches **all `defineFamily` families including the 4 "legacy" ones (apr/acr/arr/alr)** — their public `verifyReceipt` forwards `Partial<FamilyVerifyOptions>` (now incl. `verifyIssuerPqc?`) into the shared pipeline via spread, so the "legacy-verifier backport" needed **no source change**; per-family regression tests (`<family>/test/issuer-pqc-enforcement-v1-3-r3.test.ts`) guard the forwarding. **Phase 2b still deferred:** a quantum-trustworthy `effectiveTime` source (inclusion-proof time; until then `now` = fail-toward-rejection) + PQC list-signing (deferred R2 `SUPPORTED_LIST_SIG_ALGS`).

### §8.3 — `ar.issuer_manifest.v1` (per-issuer self-published manifest)

**Status:** shipped — `@dekimuhq/anchors-federation@0.1.0` (Phase C, 2026-05-22). 118 tests.

Family-wide. One manifest per issuer (not per family member): each `did:web` issuer publishes ONE `dekimu-issuer.json` at their own `/.well-known/` path advertising which family memberships they emit, which `claim_type`s they support, which profiles they implement, and a pointer to their `dekimu-keys.json`. Consumed by `verify.dekimu.com` and by cross-issuer handshake tooling.

| Surface | Value |
|---|---|
| Discriminator | `kind: "ar.issuer_manifest.v1"` |
| Body shape | `{ kind, version, issued_at, valid_until, iss, operator: { name, jurisdiction, contact_uri }, key_doc_uri, memberships: [{ family, claim_types, profiles, spec_versions }], trust_anchors: { endorses, endorsed_by }, sig }` |
| Signing key | The issuer's own family key (the one referenced by `key_doc_uri`). Self-attestation; cross-verified via did:web resolution. |
| Consumed by | `@dekimuhq/anchors-federation`'s `fetchIssuerManifest` + `verifyIssuerManifest` + `runHandshake`; `verify.dekimu.com` discovery surface |
| Drift surface | `profile_scope_mismatch` warning when receipts in the wild advertise profiles not declared in this manifest (verifier surfaces; does not auto-reject) |

**Wire-format notes:**

- Standalone attestation per §8 invariants. Same JCS + ed25519 signing primitive as §8.1 / §8.2.
- The `FamilySlug` union is reused verbatim from `@dekimuhq/did-web-resolver` (loose-typed `string`, narrowed by schema validator against the locked 14-member set).
- `valid_until` is verifier-side advisory (≤90 days from `issued_at`); the trusted-issuers allowlist (§8.2) is the authoritative revocation surface. A manifest past `valid_until` triggers `issuer_manifest_stale` warning; a revoked issuer is never trusted regardless of manifest freshness.
- `operator` block identifies the legal entity behind the issuer DID (name, jurisdiction, contact URI).
- `trust_anchors.endorses` / `endorsed_by` are observational metadata for cross-issuer trust discovery; they do NOT confer trust on their own.

### §8.4 — `ar.field_commit.v1` (family-wide receipt-to-field-tree binding attestation)

**Status:** shipped — `@dekimuhq/anchors-envelope/field-commit` (Phase 2 Tier A, 2026-06-01). Spec: [`anchors-spec/tree/main/envelope`](https://github.com/dekimuhq/anchors-spec/tree/main/envelope).

Family-wide. No `family` slug. Issued by the same key that signed the parent v=2 receipt; binds the receipt `id` to its `field_root` (the Merkle root of all field leaves) and signed `leaf_count` so that a holder can prove selective field disclosure **without presenting the full receipt body**.

| Surface | Value |
|---|---|
| Discriminator | `kind: "ar.field_commit.v1"` |
| Body shape | `{ kind, family, id, field_root, leaf_count, iss_key, issued_at, sig }` — `id` is the parent receipt's `id`; `field_root` is the root hash of the field Merkle tree; `leaf_count` is the total leaf count (required for Merkle position verification) |
| Signing key | The issuer's own family key (same key as the parent receipt's `iss_key`). Ed25519 over JCS-canonicalised body with `sig: null`. |
| `field_root` semantics | References the receipt's computed field_root — does NOT define its own field tree. The attestation certifies the binding `id → (field_root, leaf_count)` after the receipt is sealed. |
| Owned by | `@dekimuhq/anchors-envelope/field-commit` — `issueFieldCommit` + `verifyFieldCommit` helpers |
| Consumed by | `@dekimuhq/anchors-disclosure` (`buildPresentation`/`assemblePresentation` + `verifyPresentation`) |

**Wire-format notes:**

- Standalone attestation per §8 invariants (no envelope; JCS + `sig: null`; ed25519).
- `family` field carries the FamilySlug of the parent receipt (same closed union as `ar.continuity.v1`).
- Leaf preimage convention (shared with `ar.disclosure.v1` presentations): `commit(salt, canonicalize({path, value}))` where `path` is the JSON-pointer field path (e.g. `/purposes/0`) and `value` is the field value. This binds the path into the leaf so disclosure cannot re-order or re-label field values.

**Disclosable adopters:** ACR is native (per-field salted-commitment tree built at mint). Flat-`field_root` families (ANR/ABR/AIR/ALR/ARR) opt in via a `mintXxxV2Disclosable` sibling that builds the per-field tree from the family `DisclosureSchema` (declared in `@dekimuhq/anchors-disclosure/schemas`) + emits `ar.field_commit.v1` + returns the holder seed — additive, shipped flat receipts unaffected and their `mintXxxV2` unchanged. **ANR migrated 2026-06-02** (`ANR_DISCLOSURE_SCHEMA`, leaves `/profile /lang_tag /event_type /jurisdiction`; TSA + disclosable rejected in v0 — re-signing would void the timestamp). **ABR/AIR/ALR migrated 2026-06-02** (identical pattern): `ABR_DISCLOSURE_SCHEMA` (`/profile /incident_correlation_id /event_type /jurisdiction`), `AIR_DISCLOSURE_SCHEMA` (`/air_receipt_id /processing_activity_id /event_type` — AIR has no `profile` in body), `ALR_DISCLOSURE_SCHEMA` (`/profile /artifact_hash /event_at /event_type`); all reject TSA in v0. Note ABR `breach.detected` mandates TSA at the verifier, so a disclosable detected receipt cannot also be fully verified — use a non-mandatory event or the flat path. **ARR migrated 2026-06-02** (the special case): two sibling mints `mintArrV2SingleDisclosable` + `mintArrV2BatchDisclosable`, each pairing with `ARR_SINGLE_DISCLOSURE_SCHEMA` (`/profile /target_kind /trigger /event_at`) or `ARR_BATCH_DISCLOSURE_SCHEMA` (`/profile /batch_event_kind /target_kind /event_at`). The disclosable mints discard ARR's subset-hash `field_root` and rebuild a per-field Merkle tree, so the single/batch body split is the only divergence. One seed per mint call — a batch is a single receipt with one field tree over its body (not per-target), so per-call seeds already give cross-receipt unlinkability (L20). `DisclosureSchema.claim_type` is documentary (unenforced by `verifyPresentation`), so the single schema spans all 5 single kinds. **Flat-family migration COMPLETE — all of ANR/ABR/AIR/ALR/ARR adopted.**

> **Phase 2 Tier A addition (2026-06-01):** §8 extended to seat `ar.field_commit.v1` as the first standalone attestation that *references* (does not compute) a receipt's `field_root`. The `field_root` invariant in the §8 intro was generalised from "carry no `field_root`" to "carry no *body-derived* `field_root` of their own" — `ar.field_commit.v1` references the parent receipt's field_root without defining one independently.

> **Cross-issuer interop addition (2026-05-19, plan-approved):** §8 generalised from "`ar.continuity.v1` — family-shared issuer key-rotation attestation" to "Standalone attestations (non-receipt signed artifacts)" to seat `ar.trusted_issuers.v1` (Phase B) and `ar.issuer_manifest.v1` (Phase C) alongside the existing continuity attestation. No wire-format changes; this is the doc-only prerequisite gate cleared before Phase A of the cross-issuer interop plan touches code.

---

## 9. Standards-vocabulary mapping — PCI/EMVCo tokenization ↔ envelope payload modes

The anchors family's `public_full` vs `committed` payload modes (envelope v1.1 §5.4) map cleanly onto the **High-Value Token (HVT) / Low-Value Token (LVT)** distinction codified in the PCI tokenization literature and EMVCo Payment Tokenisation (March 2014). This section is non-normative — it surfaces the lineage so security reviewers fluent in tokenization vocabulary can locate our design without re-deriving it.

| Anchors term | PCI/EMVCo equivalent | Property |
|---|---|---|
| `public_full` payload | High-Value Token (HVT) | Surrogate carries enough structure to act on without round-tripping to the issuer (e.g. a fully-published consent receipt that downstream systems can verify standalone). |
| `committed` payload (`withheld_fields` + salted SHA-256 commits per v1.1 §5.4) | Low-Value Token (LVT) | Surrogate is proof-only; useless without the issuer's mapping (the salt + plaintext). Verifier confirms a commit matches a known plaintext only when the issuer reveals it. |
| Issuer's HMAC/SHA-256 salt (per-receipt or per-issuer) | Tokenization vault secret | Single irreversibility root. Compromise yields offline bruteforce over the receipt's withheld-field space. |
| `scope` envelope block (audience + purpose + validity) | EMV scope-binding cryptogram (device + merchant + transaction context) | Replay/scope-creep mitigation. Verifiers enforce mismatch as a HARD invalidation. |

**Implication for reviewers:** the family is structurally a stateless, format-flexible tokenization system in the PCI sense — vaultless (no central token table), irreversibility via cryptographic commit rather than mapping-table lookup, with scope-binding enforced verifier-side rather than vault-side. The 14-member family extends the pattern from "PAN ↔ token" to "GDPR/EU-AI-Act/eIDAS event ↔ verifiable receipt."

**Not a new normative rule.** No member spec is required to update behaviour because of this section. The mapping is documentation only — added 2026-05-20 after a literature-review pass mapped the anchors design space onto PCI tokenization vocabulary (see an internal design record (not published)). **ATokR (14th member, LOCKED 2026-05-21)** is the family member that directly instantiates this vocabulary mapping — its 4 event types (`token.issued/redeemed/revoked/rotated`) are the receipt-level counterparts of the HVT/LVT lifecycle described here.

---

## 10. Countersignature key field (`countersig_key`)

Added in envelope 0.13.0 (2026-05-21). Decision: an internal design record (not published).

**Cross-family invariants:**

- `countersig_key` is **signed-in**. The issuer commits to the countersigner identity at issuance time. Mutating it post-sign invalidates the issuer's Ed25519 signature.
- `countersig` remains **signed-out**. The countersigner signs the same `preSigCanonical` bytes as the issuer (signed-out fields `anchor`, `sig`, `countersig`, `tsa` zeroed to `null`).
- The field follows the same `<alg>:<base64url>` prefix convention as `iss_key` (the `IssuerKeyRef` union). Algorithm agility is provided by the v1.3 `sig_alg` discriminator (signed-in, closed enum) + the `SIG_VERIFIERS` dispatch registry. **Phase 2 (2026-06-04):** `SIG_ALGS = ["ed25519", "ml-dsa-65"]` — `ml-dsa-65` (FIPS 204) registered via native `node:crypto` on Node ≥24.6 (no third-party crypto; `liboqs` withdrawn). `ml-dsa-65` keys are the raw 1952 B public key, `ml-dsa-65:<b64url>`. `slh-dsa-sha2-128s` + hybrid `sig2` remain spec-only/deferred. See [`anchors-spec/blob/main/rfcs/RFC-001-sig-alg-discriminator.md`](https://github.com/dekimuhq/anchors-spec/blob/main/rfcs/RFC-001-sig-alg-discriminator.md) + decision `2026-06-04-anchors-v1-3-ml-dsa-65-ratification.md` (internal design record, not published).
- Optional on every family member — absent on all pre-0.13.0 receipts. No family member mandates countersignatures in v1.

| State | `countersig_key` | `countersig` | Verifier outcome |
|---|---|---|---|
| No countersig expected | absent | absent | — |
| Legacy/pre-delta receipt | absent | present | Format check only (64-byte Ed25519 length) |
| Awaiting countersig | present | absent | "Awaiting countersignature from identified key" |
| Full verification | present | present | Ed25519 cryptographic verification of countersig against `countersig_key` |

**Planned consumer:** EUDI Wallet integration (subject countersigns consent/notice receipts). No family member ships EUDI support in v1; the field is the forward-compatible prerequisite.

---

## 11. Cross-sibling QTS upgrade (`qts_attestation_hash`)

Every body variant across all 14 families carries an optional nullable field:

```
qts_attestation_hash: string | null
```

**Semantics:** SHA-256 hash of an `ar.attestation.v1` receipt with `body.service_type = qts` (Qualified Timestamp Service). When present, the receipt's timestamp is considered *qualified* under eIDAS rather than merely RFC 3161.

**Wire rules:**
- Nullable: `null` when no QTS attestation is referenced.
- Additive: existing receipts without this field are valid (field is `undefined` at runtime on pre-upgrade wire data; validators accept this).
- No structural validation at verification time. Format validation happens at compose time when resolving the referenced AAR receipt (separate concern).

**Mint default:** `null` when not provided by the caller.

**Reference implementation:** ATR `transfer` event body (shipped in v1.0).

**Verification-time resolution:** Out of scope for the field addition. Resolution follows the same `resolveReceiptById` compose pattern used by AIR→AER cross-family composition.

| Family | Placement |
|--------|-----------|
| APR | `APRBody` (single interface) |
| ACR | `ACRReceipt` (single interface) |
| ARR | `ARRReceipt` + `ARRBatchReceipt` |
| ALR | `AlrBodyBase` (inherited by 4 variants) |
| ANR | `AnrBodyBase` (inherited by 6 variants) |
| ASR | `AsrBodyBase` (inherited by 9 variants) |
| ABR | `AbrBodyBase` (inherited by 8 variants) |
| AIR | `AirBodyBase` (inherited by 11 variants) |
| ATokR | 4 standalone variant interfaces |
| AER | 2 standalone variant interfaces |
| AAR | 2 standalone variant interfaces |
| ADR | 6 standalone variant interfaces |
| APuR | 3 standalone variant interfaces |
| ATR | 4 standalone variant interfaces (`transfer` had it already) |

The 7 post-14 families do NOT carry `qts_attestation_hash` — excluded by design, not a table-update gap (verified in source 2026-09-02; mirrors §4's per-family exclusion pattern):

AActR does NOT carry `qts_attestation_hash` — an autonomous action receipt has no eIDAS qualified-timestamp upgrade surface in v1.

AQR does NOT carry `qts_attestation_hash` — a quality-eval receipt is point-in-time provenance with no qualified-timestamp requirement.

AGR does NOT carry `qts_attestation_hash` — a guard verdict has no qualified-timestamp requirement.

AGrR does NOT carry `qts_attestation_hash` — a grounding receipt has no qualified-timestamp requirement.

AgTR does NOT carry `qts_attestation_hash` (both `ar.trace.v1` and `ar.trace.v2`) — an agent-trace has no qualified-timestamp requirement.

APIIR does NOT carry `qts_attestation_hash` — a redaction receipt has no qualified-timestamp requirement.

ACBR does NOT carry `qts_attestation_hash` — a compliance bundle references constituent receipts; any QTS anchoring lives on the constituents, never on the bundle.

---

**This document is normative for cross-family invariants. When a member spec contradicts this file, this file wins until the spec is updated to match.**
