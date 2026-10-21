# Anchored Receipts — Cross-References Matrix

**Authority:** This matrix is the single source of truth for receipt-to-receipt relationships across the Anchored Receipts family. Two kinds of relationship exist:

1. **Chain `prev`** — an envelope-level `prev: sha256:<hex>` field linking same-claim_type receipts into a cryptographic chain. Verifier walks forward from a chain head; tampering with any link invalidates the rest.
2. **Cross-family ref** — a body-level field carrying another receipt's `id`. Not a cryptographic chain — a verifier composition pointer. Reference resolution is verifier-coordinated, not signature-mandated.

**Plan source:** an internal design record (not published) — Delta E (Phase 0, Task H2).

**Companion file:** [REGISTRY.md](REGISTRY.md) — claim_type discriminator authority. Update both files together.

---

## 1. Chain `prev` relationships (cryptographic — same claim_type, linear chain)

| From (successor) | To (predecessor via `prev`) | Semantics | Spec section |
|---|---|---|---|
| `ar.withdrawal.v1` | `ar.consent.v1` *(or another `acr.*.v1` on same subject chain)* | Withdraws a prior consent receipt. Verifier MUST resolve `prev` to confirm the withdrawn receipt exists, is signed by an accepted issuer for the same subject, and has not already been withdrawn. | ACR spec §7 chain semantics |
| `ar.modification.v1` | `ar.consent.v1` *(or another `acr.*.v1` on same subject chain)* | Modifies scope/purpose of a prior consent. `body.modified_fields` declares what changed; verifier MUST resolve `prev`. | ACR spec §7 chain semantics |
| `ar.erasure.v1` | Prior `arr.*.v1` on same `target_commit` *(or `prev: null` if first link)* | Per-target chain link. Carries full `state_snapshot`; no delta receipts. Terminal: chain closed. | ARR spec §7.2 per-target chains |
| `ar.expiry.v1` | Prior `arr.*.v1` on same `target_commit` | Scheduled-deletion link. Non-terminal — chain continues if e.g. anonymisation follows. | ARR spec §7.2 |
| `ar.anonymization.v1` | Prior `arr.*.v1` on same `target_commit` | Terminal: chain closed for personal-data purposes. | ARR spec §7.2 |
| `ar.hold.v1` | Prior `arr.*.v1` on same `target_commit` | Annotation: flips `hold_active`. Chain remains open. | ARR spec §7.2 |
| `ar.archive.v1` | Prior `arr.*.v1` on same `target_commit` | Transition to long-term archive; chain remains open if archive lifecycle persists. | ARR spec §7.2 |
| `ar.batch.v1` | **n/a — standalone, no chain** | Bulk-emission receipt. Carries `state_snapshot_root` Merkle root, not a single `prev`. | ARR spec §7.4 |
| `ar.delegation.v1` *(events: revoke, narrow, renew, suspend, resume)* | Prior `ar.delegation.v1` on same authority chain *(or sub-delegation parent grant)* | Lifecycle event continuation OR sub-delegation tree link (child Grant's `prev` points at parent Grant when `delegable: true`). Ancestor revoke cascades to subtree. | ADR spec §7 chain walk + §4 sub-delegation |
| `ar.lineage.v1` *(event: `superseded_by`)* | Prior `ar.lineage.v1` on same artifact | Linear supersession chain per artifact. | ALR spec §6 prev semantics |
| `ar.lineage.v1` *(event: `derived_from`)* | `prev: null` (chain-head) | Derivation lineage uses `body.parents[].artifact_hash` refs, not `prev`. Allowed to have `prev` only if extending an existing supersession chain. | ALR spec §6 |
| `ar.lineage.v1` *(event: `forked_from`)* | `prev: null` (chain-head) | New fork starts its own chain. | ALR spec §6 |
| `ar.lineage.v1` *(event: `disclosed`)* | Prior `ar.lineage.v1` on same artifact | Continues per-artifact chain when disclosure is logged after creation/supersession. | ALR spec §6 |
| `ar.provenance.v1` | **n/a — standalone, no chain in v1** | Origin receipt. v1 mints emit a single APR per artifact; supersession is handled by ALR. | APR v1.0 (code-only) |
| `ar.notice.v1` *(event: `notice.presented`)* | `prev: null` (chain-head) | First notice in a chain. Linear `prev` chain extends via `re_presented` / `acknowledged` / `withdrawn`. | ANR spec §6.2 chain walker |
| `ar.notice.v1` *(event: `notice.re_presented`)* | Prior `ar.notice.v1` on same `policy_uri` host (presented / re_presented) | Material-change re-surface. Body `supersedes_anr_id` MUST also point at the prior receipt. | ANR spec §4.2, §6.2 |
| `ar.notice.v1` *(event: `notice.acknowledged`)* | Prior `ar.notice.v1` (presented / re_presented) being acknowledged | Per-subject ack. Subject MUST be `"sha256:<hex>"`; verifier confirms `prev` resolves to a presented receipt on the same chain. | ANR spec §4.3 + FAMILY-CONSISTENCY §3 |
| `ar.notice.v1` *(event: `notice.withdrawn`)* | Prior `ar.notice.v1` on the same chain | Controller deprecation. Body XOR — exactly one of `supersedes_anr_id` / `cessation_reason`. | ANR spec §4.4 |
| `ar.notice.v1` *(event: `notice.translated`)* | `prev: null` (branches from `base_anr_id`, not linear chain) | D10-ANR-5: translation branches from the base receipt; envelope `prev` is forced `null` at mint time. Walker handles via a single translation-branch sidecar against `body.base_anr_id`. | ANR spec §4.5, §6.2 step 3 |
| `ar.notice.v1` *(event: `notice.joint_controller_essence`)* | `prev: null` (standalone or attached to a presented chain) | Art. 26(2) essence — body `joint_controllers[]` carries the controller list. | ANR spec §4.6 |
| `ar.tokenization.v1` *(event: `token.issued`)* | `prev: null` (chain-head) | First token issuance for a given subject. | ATokR decision doc §1 |
| `ar.tokenization.v1` *(event: `token.redeemed`)* | Prior `ar.tokenization.v1` on same `token_id` | Detokenization event; verifier confirms predecessor is an `issued` or `rotated` event on the same token. | ATokR decision doc §1 |
| `ar.tokenization.v1` *(event: `token.revoked`)* | Prior `ar.tokenization.v1` on same `token_id` | Terminal: chain closed for this token. | ATokR decision doc §1 |
| `ar.tokenization.v1` *(event: `token.rotated`)* | Prior `ar.tokenization.v1` on same `token_id` | Non-terminal: `body.rotation_of` carries the prior `token_id`; new token starts a fresh chain-head with `prev` pointing at the rotated-from receipt. | ATokR decision doc §1 |

**Verifier invariants for `prev`:**

- Same `claim_type` *(or claim_type family — e.g. ARR chain links can mix `ar.erasure.v1`, `ar.expiry.v1`, etc. against the same `target_commit`)*.
- Same `iss` and `iss_key` allowed; key rotation handled by countersig from prior key (out of scope here).
- `prev` resolution failure (predecessor not in anchor log, signature mismatch, subject mismatch) → verifier returns `errors: ["chain.prev_unresolved"]`.
- W3C Status List 2021 revocation (v1.1) flips the bit at the predecessor's `statusListIndex` when a successor is detected by the `verify.dekimu.com` worker. Chain truth is canonical; Status List is a fast O(1) cache.

---

## 2. Cross-family composition refs (body-level pointers, verifier-coordinated)

| Source field | From claim_type | To claim_type | Purpose | Spec section |
|---|---|---|---|---|
| `body.trigger_receipt` | `ar.erasure.v1` (subject-triggered) | `ar.withdrawal.v1` *(or `ar.subject_rights.v1` once shipped)* | Anchors GDPR Art. 12(3) 30-day window: ARR verifier MUST resolve `trigger_receipt` and confirm time delta ≤ 30d. Failure → `errors: ["gdpr.art12.timeout"]`. | ARR spec §4.2 |
| `body.parents[].parent_apr_id` | `ar.lineage.v1` *(event: derived_from, forked_from)* | `ar.provenance.v1` | Lineage rooted at an APR-anchored origin. Verifier resolves to confirm parent existence; not a `prev` chain. Composition surface lives in `@dekimuhq/alr`'s `composition.ts` (`extractAprComposition`, `buildAprReverseIndex`, `buildAprCoverageReport`). | ALR spec §4.1, §6.2 step 3 |
| `body.parents[].artifact_hash` | `ar.lineage.v1` *(event: derived_from, forked_from)* | Hash of parent artifact (out of family) | When parent is not APR-anchored (`parent_apr_id: null`), the `artifact_hash` content-addresses the parent directly. | ALR spec §4.1 |
| `body.parents[].parent_alr_id` | `ar.lineage.v1` *(event: derived_from, forked_from)* | Upstream `ar.lineage.v1` | Cites an upstream ALR receipt (e.g. an earlier fork) — extends the lineage DAG backward across multiple ALR generations. | ALR spec §4.1 |
| `body.successor.parent_apr_id` *(or `successor.parent_alr_id`)* | `ar.lineage.v1` *(event: superseded_by)* | `ar.provenance.v1` *(or upstream `ar.lineage.v1`)* | Forward-time supersession pointer. The receipt's artifact is the OLD one; `successor` points at the new artifact (and optionally its APR or ALR coverage). | ALR spec §4.3 |
| `body.scope.processor_authority_hash` | `ar.transfer.v1` *(specced)* | `ar.delegation.v1` | ATR receipts for processor-to-sub-processor transfers MAY reference an ADR grant for the upstream authority. | ADR spec §6 (specced) |
| `body.request_ref` | `ar.erasure.v1` | `ar.subject_rights.v1` *(parked — confirmed planned)* | ASR anchors the Art. 17 erasure-request lifecycle; ARR anchors the execution. Verifier composes the pair for the "honoured-within-30-days" proof bundle. | Closure brainstorm §4 ASR |
| `body.execution_ref` | `ar.subject_rights.v1` *(parked)* | `ar.erasure.v1` | Reverse direction of the ASR ↔ ARR composition above. ASR MUST reference an ARR execution receipt for any `art17.erasure_request` profile receipt. | Closure brainstorm §4 ASR |
| `body.anr_id` | `ar.consent.v1` *(consent.collect@\* profile, v1.2+)* | `ar.notice.v1` | ACR proves *informed* consent by referencing the ANR receipt for the notice the subject saw. v1.1 of ACR has the field as OPTIONAL; v1.2 upgrades to MANDATORY for `gdpr.art7` profile. Composition surface lives in `@dekimuhq/anr`'s `composition.ts` (`extractAcrAnrLink`, `buildAcrReverseIndex`, `buildNoticeCoverageReport`). | ANR spec §8.1 |
| `body.translation_provenance_alr_id` | `ar.notice.v1` *(event: `notice.translated`)* | `ar.lineage.v1` *(event: `derived_from`)* | Optional. When set, the verifier cross-checks that the ALR receipt's `artifact_hash` matches the ANR's `policy_hash`. Surface: `@dekimuhq/anr`'s `extractAlrTranslationProvenance` / `buildAlrTranslationProvenanceIndex`. | ANR spec §8.3 |
| `body.aer_id` | `ar.notice.v1` *(profile `notice.aiact.art50_transparency`)* | `ar.evaluation.v1` *(specced)* | Optional. AI Act Art. 50 transparency — cross-checks the provider DID against the AER receipt. | ANR spec §8.4 |
| `body.joint_controllers[].adr_id` | `ar.notice.v1` *(event: `notice.joint_controller_essence`)* | `ar.delegation.v1` *(specced)* | Optional (SHOULD, not MUST). ANR verifier cross-references each ADR `iss`; does not fail-hard on mismatch (joint controllers may not all participate in the anchor family). | ANR spec §8.5 |
| `body.dpa_attestation_ref` | `ar.breach.v1` *(parked)* | `ar.attestation.v1` *(specced)* | If a DPA submission requires a qualified e-signature, ABR references the AAR receipt for the QTSP issuance. | Closure brainstorm §5 ABR |
| `body.aer_receipt_ids` | `ar.impact.v1` *(dpia.completed, profile art35_3_a)* | `ar.evaluation.v1` *(conformity)* | AIR ↔ AER ADM composition (§8.1). DPIA cites AER conformity receipts for algorithmic-impact evidence. Verifier compose surfaces `art35_3a_aer_unresolvable`, `art35_3a_aer_not_conformity`, `art35_3a_aer_expired` warnings. STRONGLY RECOMMENDED, not HARD-invalid. | AIR spec §8.1 |
| `body.atr_receipt_ids` | `ar.impact.v1` *(dpia.completed)* | `ar.transfer.v1` | AIR ↔ ATR composition (§8.2). DPIA cites ATR receipts for cross-border transfer mechanisms in scope. Advisory — no verifier compose check in v1. | AIR spec §8.2 |
| `body.alr_receipt_ids` | `ar.impact.v1` *(dpia.completed)* | `ar.lineage.v1` | AIR ↔ ALR composition (§8.3). DPIA cites ALR receipts for data-flow lineage in scope. `art35_3b_alr_link_missing` warning on art35_3_b profile. | AIR spec §8.3 |
| `body.apur_receipt_ids` | `ar.impact.v1` *(dpia.completed)* | `ar.purpose.v1` | AIR ↔ APuR composition (§8.4). DPIA cites purpose-binding receipts being assessed. Advisory — no verifier compose check in v1. | AIR spec §8.4 |
| `body.abr_receipt_id` | `ar.impact.v1` *(dpia.reviewed, cause=breach)* | `ar.breach.v1` | AIR ↔ ABR composition (§8.5). DPIA review cites breach receipt that triggered the re-assessment. Advisory — no verifier compose check in v1. | AIR spec §8.5 |
| `body.recipient_notification_ref` | `ar.subject_rights.v1` *(parked)* | `ar.lineage.v1` *(disclosed event)* | Art. 19 recipient-notification leans on ALR's `disclosed` history to compute the recipient set. | Closure brainstorm §4 ASR |
| `body.objection_target` | `ar.subject_rights.v1` *(parked, profile `art21.objection`)* | `ar.purpose.v1` | Art. 21 objection terminates a purpose binding; ASR `art21.objection` MAY emit an `ar.purpose.v1` `closed` event in the same anchor batch. | Closure brainstorm §4 ASR |
| `body.asr_ref` | `ar.tokenization.v1` *(event: `token.redeemed`, `token.revoked`)* | `ar.subject_rights.v1` | Optional. When detokenization or revocation is triggered by a subject-rights request, ATokR references the ASR receipt. | ATokR decision doc §1 |
| `body.arr_ref` | `ar.tokenization.v1` *(event: `token.revoked`)* | `ar.erasure.v1` | Optional. When token revocation co-occurs with Art. 17 erasure of the underlying plaintext, ATokR references the ARR receipt. | ATokR decision doc §1 |
| `body.alr_ref` | `ar.tokenization.v1` *(event: `token.issued`, `token.rotated`)* | `ar.lineage.v1` | Optional. When the tokenized value flows through a pipeline, ATokR references the ALR receipt anchoring the lineage. | ATokR decision doc §1 |
| `body.apur_ref` | `ar.tokenization.v1` *(any event)* | `ar.purpose.v1` | Optional. Purpose declared in ATokR scope; APuR purpose binding is the durable record. | ATokR decision doc §1 |

**Verifier invariants for cross-family refs:**

- Composition refs are NOT cryptographic chains. Tampering does not invalidate the source receipt's signature.
- Verifiers MAY refuse a receipt whose composition ref fails to resolve, but this is a profile-level mandate, not an envelope-level rule.
- Each ref is documented in the source receipt's spec §4 body schema. Cross-family verifier coordination is `arr-verifier` / `acr-verifier` / `adr-verifier` (etc.) calling a shared resolver in `@dekimuhq/anchors-envelope`.

---

## 3. Status List 2021 cross-family flips (v1.1)

Status List bit-flipping is published by `verify.dekimu.com` worker (outside this plan — see worker contract in v1.1 hardening plan). Trigger conditions:

| Successor receipt | Predecessor whose Status List bit flips | Status semantic |
|---|---|---|
| `ar.withdrawal.v1` | `ar.consent.v1` referenced by `prev` | `revoked` |
| `ar.modification.v1` | `ar.consent.v1` referenced by `prev` | `revoked` *(modification supersedes original scope)* |
| `ar.erasure.v1`, `ar.anonymization.v1` (terminal events on a chain) | Prior `arr.*.v1` on same target | `revoked` *(chain closed)* |
| `ar.expiry.v1`, `ar.archive.v1` (non-terminal) | Prior `arr.*.v1` on same target | **No flip** — chain remains open. |
| `ar.hold.v1` (annotation) | Prior `arr.*.v1` on same target | **No flip** — chain remains open. |
| `ar.delegation.v1` event `revoke` | Prior `ar.delegation.v1` Grant + every descendant in subtree | `revoked` *(cascading per §4 sub-delegation rules)* |
| `ar.delegation.v1` event `narrow` | Prior `ar.delegation.v1` Grant whose scope is now narrowed | `revoked` *(superseded by narrowed grant)* |
| `ar.delegation.v1` event `suspend` | Prior `ar.delegation.v1` Grant | **No flip** — suspend is reversible; verifier honours `suspended_until` from receipt body. |
| `ar.delegation.v1` event `resume` | Prior suspended Grant | **No flip** — resume restores active state. |
| `ar.lineage.v1` event `superseded_by` | Prior `ar.lineage.v1` on same artifact | `revoked` *(linear supersession)* |
| `ar.notice.v1` event `notice.withdrawn` (with `supersedes_anr_id` set) | Prior `ar.notice.v1` referenced by `body.supersedes_anr_id` | `superseded` *(successor notice exists)* |
| `ar.notice.v1` event `notice.withdrawn` (with `cessation_reason` set, no successor) | Prior `ar.notice.v1` chain head | `withdrawn` *(processing ceased; no successor)* |
| `ar.notice.v1` event `notice.re_presented` | Prior `ar.notice.v1` referenced by `body.supersedes_anr_id` | `superseded` *(material change rolled forward)* |
| `ar.notice.v1` controller-side revocation (fraud / error / compromise) | Target `ar.notice.v1` | `revoked` *(out-of-band issuer revocation)* |
| Future closure members (not yet specced) | TBD | TBD per spec — flip rules documented when each spec opens. |
| `ar.tokenization.v1` event `token.revoked` | Prior `ar.tokenization.v1` on same `token_id` | `revoked` *(chain closed)* |
| `ar.tokenization.v1` event `token.rotated` | Prior `ar.tokenization.v1` on same `token_id` (the rotated-from token) | `revoked` *(superseded by rotated token)* |

**APR exception:** APR receipts do NOT carry `credentialStatus` in v1.1 — provenance receipts have no revocation semantics. Supersession of an APR-anchored artifact is recorded by `ar.lineage.v1 superseded_by`, which flips the predecessor ALR's Status List bit (not the APR's).

---

## 4. Verifier dispatch order (when a receipt chains AND composes)

Verifiers resolve in this order (fail-fast):

1. **Envelope signature** — Ed25519 over canonical JCS bytes (RFC 8785).
2. **Anchor proof** — RFC 6962 Merkle inclusion in the published log.
3. **TSA timestamp** (if profile mandates) — RFC 3161 signature + trust-anchor chain.
4. **`prev` chain walk** (if present) — predecessor in anchor log, same `iss`, subject continuity.
5. **`policy_uri` + `policy_hash` + `policy_version`** — per-claim-type policy matrix (v1.1 hardening plan §C).
6. **`credentialStatus`** — fetch + decode Status List 2021; reconcile with chain (chain wins per v1.1 spec §6.4 reconciliation rules).
7. **Cross-family composition refs** — profile-mandated only; resolver in `@dekimuhq/anchors-envelope` calls into sibling verifier packages.

A v=2 receipt that fails any step returns the canonical error code (see v1.1 hardening spec §8 error taxonomy).

---

## 5. Maintenance

When adding a new claim_type or shipping a closure-brainstorm member:

1. Add a row to [REGISTRY.md](REGISTRY.md) first.
2. Determine `prev` chain semantics — same claim_type chain? Mixed-claim_type chain (like ARR)? Standalone (like APR + `ar.batch.v1`)?
3. List cross-family refs in the spec §4 body schema, then add a row to §2 of this matrix.
4. Document Status List 2021 flip rules in the spec §6 verifier semantics, then add a row to §3.
5. Cross-check verifier dispatch order — does any new step need to land before existing steps? If yes, escalate to maintainer (potential envelope schema change).
