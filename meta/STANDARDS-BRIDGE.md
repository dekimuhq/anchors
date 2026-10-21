# Anchored Receipts — Standards Bridge (IETF / W3C-VC)

**Status:** DRAFT skeleton (2026-06-17). Mappings below are placeholders pending field-level work — do NOT cite as authoritative until each table is filled and verified against the named external draft revision.

**Authority:** Non-normative. `ar.<noun>.v<N>` + the anchors envelope remain the **canonical, signed, anchored** wire format ([`FAMILY-CONSISTENCY.md`](FAMILY-CONSISTENCY.md) is the SSOT for the families). This document defines a **one-way export mapping** (canonical anchors claim → external standard shape) so anchors receipts are *both* anchored AND standards-readable. It does NOT make external shapes canonical and does NOT bind our versioning to external drafts.

**Decision:** an internal design record (not published) — Hybrid bridge (Option C).

**Direction:** canonical anchors claim ──export──▶ { IETF delegation-receipt JSON · W3C-VC mandate }. One-way only. No ingest of external receipts as canonical.

**Add (2026-06-18 autoimprove scan):** `draft-farley-acta-signed-receipts` (IETF) is an Ed25519 + deterministic-JSON-canon signed-action-receipt for MCP **with a reference proxy** — an IETF draft of our exact AActR primitive. Add to §0 and build the `ar.action.v1 → ACTA` export alongside the IETF delegation-receipt target. `draft-marques-asqav-compliance-receipts` = ACTA's compliance profile. `draft-singla-agent-identity-protocol` (DID delegation) + arXiv 2603.24775 (macaroons/UCAN caveats) ≈ our Mandate — track but no export owed.

---

## 0. External draft revisions tracked

Pin the exact revision each mapping was verified against. Re-verify on every external draft bump; the canonical format does NOT move with it.

| External shape | Source | Revision verified | Date | Stability |
|---|---|---|---|---|
| **ACTA signed action receipts** (AActR target — §1) | `draft-farley-acta-signed-receipts` | **-01** | 25 Apr 2026 (exp 27 Oct 2026) | individual I-D, Informational, no IETF standing |
| **ACTA compliance profile** (AActR overlay — §1) | `draft-marques-asqav-compliance-receipts` | **-05** | 31 May 2026 | profile of ACTA; Informational |
| **niyikiza AAT** (Mandate target — §2) | `draft-niyikiza-oauth-attenuating-agent-tokens` | **-01** | 15 Jun 2026 (exp 17 Dec 2026) | OAuth WG individual submission, Std-Track intended (not adopted) |
| **IETF Agent Delegation Receipts (DRP)** | `draft-nelson-agent-delegation-receipts` | **-10** | 13 Jun 2026 (exp 15 Dec 2026) | **PRE-AUTH object** — analogue of our Mandate, NOT the action receipt (see §1 note). Individual I-D, Informational |
| **AP2 mandate** (SD-JWT-VC, **NOT W3C-VC** — §2b) | `google-agentic-commerce/AP2` | **v0.2** @ main | verified 2026-06-30 | DRAFT pre-1.0; repo churning (SDK/spec term drift). Pin to commit SHA before shipping |
| **A2A Signed Agent Card** (identity-only — §2c) | `a2aproject/A2A` | **v1.0.0** | Mar 2026 | stable (Linux Foundation, Apache-2.0). Signs identity, NOT authority |
| IETF SCITT transparency receipts | SCITT WG | _TBD_ | — | pre-production — transparency-log slot, future |
| Sello (Notarized Agents) | arXiv 2606.04193 / sello.build (CC BY 4.0) | v1 (2606.04193v1) | 2026-06-18 | research + reference impl |
| **Pipelock action receipt** (AActR peer — interop note, NOT an export target) | `luckyPipewrench/pipelock` · pipelab.org/learn/action-receipt-spec | envelope **v1** (`version`, `action_record`, `signature`, `signer_key`); v2 EvidenceReceipt alongside | verified 2026-10-02 | Apache-2.0 OSS agent egress firewall, ~0.9k★; self-described "implementation spec, not a design document". **Mediator-signed** (the proxy, outside the agent trust boundary): Ed25519 over the SHA-256 digest of canonical JSON in Go-struct field order (JCS/RFC 8785 only in v2); per-session hash chain (`chain_seq`, `chain_prev_hash`, genesis); `verdict` ∈ allow/block/warn/ask/strip/forward/redirect; UUIDv7 `action_id`; readers MUST reject unknown versions. No JWS/COSE/VC, no status list, no transparency slot — a bespoke envelope, so nothing to map to. Watch for a COSE/VC profile or an I-D; verifiers shipped in Go/TS/Rust/Python |

> **Verified 2026-06-30 (field-level research, A2 lane).** All four IETF/industry drafts found with published shapes — full field tables in §1/§2; raw research in the A2-lane handoff. **Two corrections to this doc's original assumptions:** (1) `draft-nelson-...delegation-receipts` (DRP) is a *pre-authorization* object signed before the action → it is the analogue of our **Mandate**, not our AActR; the true action-receipt target is **ACTA** (`farley` + `marques` profile). §1 retargeted accordingly. (2) **AP2 mandates are SD-JWT-VC, not the W3C VC Data Model** — there is no `@context`/`credentialSubject`/`proof`/`credentialStatus`; the "W3C Verifiable Credential" framing in vendor blogs is marketing. §2 retargeted to the real SD-JWT shape. All drafts expire Oct–Dec 2026 — **re-pin revisions before shipping the adapter.**

**SCITT is the gravity well for the transparency-log half.** Our anchoring + the in-flight witness-cosign (`anchors v1.5`) target the same problem SCITT/CT standardize. The export mapping for the transparency-receipt slot (§1 "anchoring/transparency-log slot") should target SCITT shape, not just the delegation-receipt draft.

**Sello (receiver-attested) — interop note, NOT an export target (yet).** Sello inverts the signer: the **receiving service** signs (COSE_Sign1 + HPKE-to-owner + public Merkle log + witness cosign), positioning itself as a neutral witness. This is architecturally *different* from our issuer/operator-minted `ar.action.v1`, so it is not a one-way export of our claim — it is a separate attestation model. Two consequences: (a) it validates our witness-cosign direction; (b) it raises a positioning question our model must answer — see an internal design record (not published). If receiver-attestation proves to be a required interop mode, add a §5 covering an `ar.action.v1` ⇄ Sello bridge then.

---

## 0.1 Agent-identity standards layer (tracked — NO export owed yet)

The §0 table tracks **receipt/credential wire shapes** we one-way export to. A distinct and **currently un-tracked** front is the **agent-identity standards layer** — who/what an agent *is* and how that identity is issued, as opposed to the receipt it produces. The 2026-06-19 tech-world deep-research (an internal design record (not published)) flagged this as the live **fragmentation** front: multiple active initiatives, no convergence winner. These are **substrate**, not a receipt shape we emit, so **no export adapter is owed** — but the leader determines what `iss` / `credential_id` / `agent_id` (the per-agent principal, added 2026-06-19) should be interoperable *with*, so we watch.

| Identity-layer effort | Source | What it is | Relevance to us | Action |
|---|---|---|---|---|
| NIST AI Agent Standards Initiative | nist.gov (CAISI, launched 17 Feb 2026) | US-gov standards push; pillar = agent authentication/identity infra; concept paper on agent identity/authorization (comment closed 2 Apr 2026) + 9 Mar RFI on agent security | Government gravity well for agent identity (US). Could set the de-facto `iss`/credential identity model | Watch concept-paper outcome; map `iss` (per-tenant key) + `credential_id` (Mandate) onto its identity model when it stabilises |
| W3C Agent Identity Registry | W3C Community Group | Registry-protocol CG for agent identities | W3C-VC adjacency — feeds the §2 W3C-VC/AP2 export target | Track alongside §2; if it ships a v1 registry shape, decide whether `iss` resolves through it |
| SPIFFE / SPIRE | CNCF (community-governed) | Workload-identity issuance (SVIDs); cited by AIUC-1 as fitting the verifiable-agent-identity control | Issuance substrate our per-tenant signing keys could align to; community-governed | No action; note as a candidate identity-issuance backend if a customer needs SPIFFE interop |
| AIUC-1 A003.3 / A003.4 | aiuc-1.com (Q2-2026) | Security-controls standard requiring verifiable agent identity + JIT permissions | Controls-conformance wedge (not a wire shape) | **Mapped** → an internal design record (not published). **A003.3 identity-granularity gap CLOSED (capability + receipt layer, 2026-06-19):** the per-agent principal now exists as Mandate `agentId` (root-bound, immutable, `verifiedAgentId`) and threads onto `ar.action.v1` as `agent_id` |

**Watch-log:**
- **2026-06-19 re-check (deep-research-driven).** Fragmentation confirmed real and unresolved (NIST · W3C Agent Identity Registry · SPIFFE/SPIRE · MCP/A2A · AIUC-1 all active; no default). **Hedge holds:** our Hybrid bridge is one-way export with zero binding to external drafts (decision 2026-06-17 (internal design record, not published)), so fragmentation costs us nothing until a leader emerges — at which point we add/adjust *one export adapter*, not re-architect. **Recommendation: no build action now.** The identity layer is substrate (no receipt to export); the receipt-shape targets in §0 remain the only export work. Re-check when any identity effort ships a v1 OR the NIST concept paper publishes a recommended identity model. Killed claim guard: do **not** adopt the refuted "capability-identity gap no framework can detect" framing (deep-research 0-3).

## 1. `ar.action.v1` (AActR) ──▶ ACTA signed action receipt (`protectmcp:decision`)

> **Retargeted 2026-06-30.** Originally aimed at `draft-nelson-...delegation-receipts`; field-level research showed nelson DRP is a **pre-authorization** object (analogue of our Mandate — see §2 note), not an action record. The true post-action target is **ACTA** (`draft-farley-acta-signed-receipts-01`), with the **compliance profile** (`draft-marques-asqav-compliance-receipts-05`) as an EU-AI-Act/DORA overlay. Canonical AActR fields from the [AActR spec](https://github.com/dekimuhq/anchors-spec/tree/main/action).

ACTA wire envelope = `{ payload, signature{alg,kid,sig} }`; the action payload uses `type:"protectmcp:decision"`. ACTA signs Ed25519/ES256 over JCS-canonicalised payload (RFC 8785) — compatible with our envelope canon, but **the export is unsigned** (the ACTA `signature` would be over different bytes than our envelope sig; we do NOT re-sign — see §3). Authoritative signature + anchor stay on the canonical claim at verify.dekimu.com.

| anchors (`ar.action.v1`) | ACTA `protectmcp:decision` (`-01`) | Fidelity |
|---|---|---|
| `verb` (`<ns>.<op>`) | `tool_name` | clean (one tool per decision receipt) |
| `executed_at` (ISO8601 UTC) | `issued_at` (ISO8601) | clean — receipt creation at action time |
| `policy_hash` | `policy_digest` (`"sha256:<hex>"`) | clean |
| `outcome` (`executed`/`failed-gave-up`) | `decision` (`allow`/`deny`/`rate_limit`) | **semantic mismatch** — ACTA `decision` is authorize-time gate, our `outcome` is post-execution. Export `outcome` to a custom payload field; map to `decision` only when modelling the gate |
| `decision_commit` / `params_commit` / `request_id_commit` (salted `sha256:`) | `payload_digest` / `action_ref` (generic digests) | **anchored superset** — salted privacy-preserving commits have no precise ACTA equiv; emit as custom fields, keep salts off-wire |
| `rule_id` / `recipe_id` / `policy_version` / `policy_uri` | — | **anchored superset** — no ACTA equiv (emit as namespaced custom fields) |
| `credential_id` + `caveats_consumed` (mandate binding) | `action_ref` (loose correlation) | **anchored superset** — mandate-authority lives in §2 (AAT), not the receipt shape |
| `delegation_chain` `{depth, leaf_key, root_credential_id}` | `parent_session_id` (DAG only, no depth/attenuation) | **anchored superset** — ACTA has no attenuation model; export depth/root as custom fields |
| `agent_id` (per-AGENT principal) | `agent_tier` (tier, not id) / `issuer_id` | **anchored superset** — no stable agent-principal slot; emit as custom field |
| envelope `signature` | `signature{alg,kid,sig}` | **shape-compatible but NOT copied** — export emits the ACTA payload only; canonical sig stays on the anchored claim (§3) |
| envelope `anchor` | (external Rekor/DSSE in ACTA; RFC3161+OTS mandated by `marques`) | **anchored superset** — our embedded `anchor` is a documented superset; ACTA anchors out-of-band |

**Compliance overlay (`marques-...-05`):** promotes `payload_digest`/`action_ref`/`policy_digest`/`previousReceiptHash` to REQUIRED + adds `risk_class` / `incident_class`; binds to EU AI Act Arts 12 & 26 + DORA Art 17 (≥6mo / 1827-day retention). Our `toACTA(..., {compliance:true})` should populate these.

---

## 2. Mandate capability credential ──▶ niyikiza AAT (attenuating-token, RAR profile)

> **Retargeted 2026-06-30.** The clean field-level target for our attenuating capability chain is **niyikiza AAT** (`draft-niyikiza-oauth-attenuating-agent-tokens-01`, JWT + RFC 9396 RAR) — monotonic narrowing across capability/depth/lifetime, offline chain-verify from a root key (= our Bet B). AP2 (§2b) and A2A (§2c) are **interop notes, not built adapters** (low fidelity). Mandate = `@dekimuhq/agent-capability` `CapabilityToken { rootKey, blocks[]{alg,nextKey,caveats{expiry,spendBudget,dataScope,credentialId,agentId}} }`.

| anchors / Mandate | niyikiza AAT (`-01`) | Fidelity |
|---|---|---|
| `rootKey` | root token `iss` (URI) + trust-anchor key | clean — our root key ≈ AAT root trust anchor |
| `blocks[].nextKey` | derived token `cnf.jwk` (+ `iss` = JWK-thumbprint URI) | clean — block next-key ≈ next token's bound holder key |
| `caveats.capability` (tool/op) | `authorization_details.tools.<tool>` map key | clean |
| `caveats.dataScope[]` | `authorization_details.tools.<tool>.<arg>` `subset`/`one_of` constraint | clean (constraint vocab: exact/range/one_of/subset/…) |
| `caveats.expiry` | `exp` (+ `iat` floor) | clean — monotonic (child `exp` ≤ parent) |
| `caveats.credentialId` | `jti` (token id, rec. UUIDv7) | clean |
| (block chain order) | `del_depth` / `del_max_depth` | clean — block index ≈ `del_depth`; synthesize `del_max_depth` ceiling on export |
| (block → parent link) | `par_hash` (SHA-256 of parent JWS signing input) | synthesize on export (we chain by `nextKey`) |
| `caveats.spendBudget{currency,max,total?}` | `range`/`exact` arg constraint | **lossy** — no first-class spend type; `total` (cumulative) not modelled (AAT is stateless, no consumption ledger) |
| `caveats.agentId` (per-AGENT principal) | — (AAT omits `sub` by design) | **superset** — emit via Appendix-B.6 custom claim |
| `blocks[].alg` `ML-DSA-65` (PQC) | — (AAT has Ed25519/ES256 only) | **superset** — no PQC `alg` in AAT; Ed25519 blocks export, PQC blocks documented-loss |

### 2b. Mandate ──▶ AP2 mandate (SD-JWT-VC) — **interop note, deferred adapter**

AP2 v0.2 secures mandates as **SD-JWT-VC** (NOT W3C-VC). Only a **narrowing payment-shaped projection** fits: `issuer→iss`+`kid` (clean), `caveats.expiry→exp` (clean), capability scope → `constraints[]` **custom types** (AP2 ships only `checkout.allowed_merchants`/`checkout.line_items`), `agentId→cnf.jwk` (lossy — AP2 binds by key, no stable id slot), `credentialId→jti`/`payment_mandate_id` (lossy). **No `credentialStatus`/revocation** (AP2 relies on short `exp`). **Ed25519 is DISALLOWED on the payment-bound Checkout JWT** (must be non-deterministic, e.g. ES256) and **ML-DSA-65 has no AP2 `alg`** — so our default mandate keys can't ride into AP2 unchanged. Build only when a real payment use-case lands, and only for the payment subset — **do not force payment semantics onto the general mandate.**

### 2c. Agent identity ──▶ A2A Signed Agent Card — **interop note, deferred adapter**

A2A v1.0 Signed Agent Card signs **identity + capability declaration, NOT per-action authority**. Only `iss → AgentCardSignature.protected.kid` (JWS, JCS-canon) maps cleanly. `agent_id` is lossy (no stable-id slot — carry in `provider`/extension), and `credential_id` + mandate caveats **have no home** in a card. Useful for *who the agent is*, irrelevant to *what authorized an action* — that stays in AActR/AAT.

### 2d. AP2 mandate ◀── ADR (`ar.delegation.v1`) receipt-of map — **anchors REFERENCE an AP2 mandate, never embed one**

The §2b/§2c adapters above export *our* shapes outward. This subsection is the inverse and the actual interop story: an anchored receipt that **records the compliance obligations around an action an AP2 mandate authorized**. The relationship is *receipt-of*, never *is-a* (posture C — decision `2026-06-30-mandate-naming-posture-vs-ap2.md` (internal design record, not published)).

**Why reference, not embed.** AP2 v0.2 mandates are **SD-JWT-VC** (NOT the W3C VC Data Model — see §0 table + §2b; there is no `@context`/`credentialSubject`/`proof`/`credentialStatus`, so the "AP2 Mandate = W3C Verifiable Credential" framing in vendor blogs is marketing). More decisively, the **signature algorithms do not meet**: the payment-bound AP2 Checkout JWT **disallows Ed25519** (it must be non-deterministic, e.g. **ES256**), while our default anchored envelopes sign Ed25519 and our PQC path is **ML-DSA-65, which has no AP2 `alg` at all**. There is no single canonical byte-string both ecosystems could verify — so embedding an AP2 mandate inside an anchored receipt (or vice versa) would produce a credential neither side can validate. The honest, verifiable move is to **name the AP2 mandate by its identifier** (`payment_mandate_id` / SD-JWT `jti`) inside the envelope-signed ADR body, and let each side verify its own artifact. That identifier lives in the OPTIONAL, grant-only `authorizing_credential { scheme, id, type }` field on ADR (`ar.delegation.v1`), added additively — pre-existing receipts verify byte-equal.

**Receipt-of map.** AP2's Intent/Cart/Payment Mandates *authorize* the payment; the anchored receipts *record what happened around it* — the EU-compliance evidence square AP2 leaves open:

| AP2 layer (Google AP2 — authorizes) | anchors receipt (records the obligation around it) | Obligation captured |
|---|---|---|
| **AP2 Intent / Cart / Payment Mandate** (SD-JWT-VC) | **ADR** — `ar.delegation.v1` | the delegated authority the agent acted under, **referencing** the AP2 mandate by id (`authorizing_credential`) — receipt-*of* the mandate, never a copy of it |
| the authorized action | **ACR** — `ar.consent.v1` | GDPR consent captured for the action |
| — | **ARR** — `ar.erasure.v1` (retention) | retention / erasure obligation on the resulting data |
| — | **AGR** — `ar.guard.v1` | prompt-injection input screening ran before the action |
| — | **ACBR** — `ar.compliance.v1` | workspace-level Proof-of-Compliance bundle around the whole flow |

In one line for copy: **AP2 Mandates prove the payment was authorized; the attached ADR (+ ACR/ARR/AGR/ACBR) proves the GDPR / consent / retention / screening obligations around it — which AP2 does not cover.** We don't issue Mandates — we anchor the receipt for whatever mandate authorized the action, AP2's included.

**Field.** `authorizing_credential?: { scheme, id, type }` on `AdrGrantBody` (`@dekimuhq/adr-profiles`), validated grant-only by `@dekimuhq/adr` (prohibited on revoke/narrow/renew/suspend/resume), mirroring AActR's optional `credential_id` (FAMILY-CONSISTENCY §1 chip 15). `scheme` names the external system (`"ap2"`), `type` the artifact (`"payment-mandate"`), `id` the opaque identifier the AP2 mandate travels under. No shape, no crypto — a pointer resolved out-of-band against AP2. Additive + optional: absent on receipts that record no external authorization; **not** an adapter and **not** an export (contrast §2b, which stays a deferred outward-export adapter).

---

## 3. Export adapter (implementation note)

Package: **`@dekimuhq/anchors-bridge`** (dekimu-packages — pure/isomorphic so verify.dekimu.com can call it; NOT `server-only` like `anchors-emit`).

- Pure functions: `toACTA(verifiedActionClaim, opts?) → ACTAEnvelope` (§1) and `toAAT(verifiedMandate, opts?) → AATChain` (§2). **No new crypto.**
- **Unsigned projection.** The export emits the external *shape* only; it does NOT copy or re-mint a signature (the external sig would be over different canonical bytes). The authoritative signature + anchor stay on the canonical claim — verification stays on `verify.dekimu.com`. Each export carries a `canonical_ref` back to the anchored claim.
- Inputs are plain typed objects (the verified claim / verified mandate), not the heavy `@dekimuhq/action` or full `CapabilityToken` runtime — keeps the bridge dependency-light and cross-workspace-clean.
- Reuse `@dekimuhq/compass-obligations` canonicalize (RFC 8785 JCS) for any digest/serialization (never roll own receipt shape).
- One-way: export only. No ingest of external receipts as canonical.
- Cross-reference the `agents.txt` action-policy primitive — it and this bridge should reference each other.

## 4. Build sequence

1. ✅ Pin external draft revisions (§0) — done 2026-06-30 (A2 lane). Re-pin before shipping (all expire Oct–Dec 2026).
2. ✅ Fill §1 + §2 field tables — done 2026-06-30.
3. 🟡 Implement `@dekimuhq/anchors-bridge` `toACTA` + `toAAT` + conformance tests against the pinned revisions (A2 lane, branch `feat/a2-standards-bridge-exporter`). AP2 (§2b) + A2A (§2c) stay interop-notes (deferred adapters).
4. ⬜ AEO surface: "anchored AND standards-readable" on the anchors public surface (folds into Bet A AEO scope).
