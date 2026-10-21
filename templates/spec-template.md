# <MEMBER> — Anchored <Noun> Receipts (Design Spec)

**Date:** YYYY-MM-DD
**Status:** Draft | In review | Locked
**Version target:** v1
**Inherits from:** [envelope spec](https://github.com/dekimuhq/anchors-spec/tree/main/envelope) shared envelope
**Family registry row:** see [REGISTRY.md](https://github.com/dekimuhq/anchors/blob/main/meta/REGISTRY.md)
**License (this doc):** CC0

---

## 0. Frontmatter

| Field | Value |
|---|---|
| Family member | <MEMBER> — Anchored <Noun> Receipts |
| Wire format `claim_type` | `ar.<noun>.v1` (plus any sibling discriminators — all `ar.*.v1`) |
| Verifier package | `@dekimuhq/<member>-verifier` |
| Issuer-kit package | `@dekimuhq/<member>-issuer-kit` |
| Profile-pack package | `@dekimuhq/<member>-profiles` *(omit if no profiles)* |
| Inherits envelope | v1.1 §5.2 — fields verbatim |
| Introduces | *(one-paragraph summary of what this member adds — schema, lifecycle, profiles, cross-family refs)* |
| Out of scope | *(short bullet list of what this member explicitly does NOT cover)* |

---

## 1. Why this member exists

*(2–4 paragraphs. Regulator / law / standard that creates the need. What audit / regulator query is unanswerable today without this receipt. Why no existing family member covers it.)*

---

## 2. What's already on the market — and why it falls short

*(Competitor / status-quo paragraph. Compliance platforms, GRC tools, sector-specific SaaS. Identify why none produce verifiable cryptographic evidence the way this member will.)*

---

## 3. Locked design decisions (D1–D9 family-inherited; D10+ member-specific)

| # | Decision | Rationale |
|---|---|---|
| D1 | Path C OSS posture | Inherited from family — see APR D1 |
| D2 | eIDAS RFC 3161 timestamps optional (mandated by profile) | Inherited |
| D3 | W3C Status List 2021 for fast revocation | Inherited |
| D4 | Versioned policy hash (`policy_uri` + `policy_hash` + `policy_version`) | Inherited |
| D5 | RFC 8785 JCS canonicalisation | Inherited |
| D6 | Ed25519 / SHA-256 / RFC 6962 Merkle anchor log | Inherited |
| D7 | `claim_type` discriminator at envelope level | Inherited |
| D8 | ULID receipt `id`; ISO 8601 `iat`; `iss_key: "ed25519:<base64url>"` | Inherited |
| D9 | Shared envelope hosted in `@dekimuhq/anchors-envelope` | Inherited |
| D10-<MEMBER> | *(first member-specific decision — e.g. lifecycle event count, chain semantics)* | *(rationale)* |
| D11-<MEMBER> | *(second member-specific decision)* | *(rationale)* |
| … | … | … |

---

## 4. Receipt shape

### 4.1 Canonical receipt example

```jsonc
{
  "v": 2,
  "id": "01HXXXXXXXXXXXXXXXXXXXXXXX",
  "iat": "2026-MM-DDTHH:mm:ssZ",
  "exp": null,
  "claim_type": "ar.<noun>.v1",
  "iss": "did:web:example.com:<member>:issuer",
  "iss_key": "ed25519:<base64url>",
  "subject": "sha256:<hex>",
  "prev": null,
  "policy_uri": "https://policies.example.com/<member>/v1/<profile>.json",
  "policy_hash": "sha256:<hex>",
  "policy_version": "<semver>",
  "tsa": null,
  "credentialStatus": {
    "type": "StatusList2021Entry",
    "statusListCredential": "https://verify.dekimu.com/<member>/v1/status/YYYY/MM",
    "statusListIndex": "<int>",
    "statusPurpose": "revocation"
  },
  "anchor": {
    "log": "did:web:verify.dekimu.com",
    "tree_size": <int>,
    "leaf_index": <int>,
    "inclusion_proof": ["sha256:<hex>", "..."],
    "root_hash": "sha256:<hex>",
    "signed_at": "2026-MM-DDTHH:mm:ssZ",
    "anchor_sig": "<base64url>"
  },
  "body": {
    // member-specific schema — define in 4.2
  },
  "sig": "<base64url>"
}
```

### 4.2 `body` schema

*(Field-by-field table. Required / optional, type, semantic, profile interaction.)*

| Field | When required | Type | Semantic |
|---|---|---|---|
| `event` | … | … | … |
| `profile` | always | string | Profile name from `@dekimuhq/<member>-profiles` |
| … | … | … | … |

### 4.3 Chain semantics (`prev`)

*(Same claim_type? Mixed-claim_type chain (like ARR)? Standalone (no chain)? See [CROSS-REFERENCES.md](https://github.com/dekimuhq/anchors/blob/main/meta/CROSS-REFERENCES.md) §1.)*

### 4.4 Cross-family composition refs

*(List any body-level pointers to other claim_types. Update CROSS-REFERENCES.md §2 alongside.)*

---

## 5. Profiles (if applicable)

*(Per-profile spec — name, regulator anchor, required body fields, mandate matrix for `requires_tsa`, `requires_tsa_listed`, `requires_tsa_policy_oid`, Status List 2021 flip rules.)*

---

## 6. Verifier semantics

### 6.1 Dispatch order

Inherits the 7-step order from [CROSS-REFERENCES.md](https://github.com/dekimuhq/anchors/blob/main/meta/CROSS-REFERENCES.md) §4. Document any member-specific additions / order tweaks here.

### 6.2 Error taxonomy

*(Canonical error codes — `<member>.<error>.<detail>`. Document each.)*

### 6.3 Status List flip rules

*(When does a successor receipt cause a predecessor's Status List bit to flip? Update CROSS-REFERENCES.md §3 alongside.)*

---

## 7. Issuer-kit semantics

*(Mint, key handling, profile selection, opt-in TSA, Status List index allocation callback. Reference the v1.1 hardening design §6.)*

---

## 8. Test plan

*(Minimum test count target. Coverage areas: schema validation, chain walks, profile-mandate enforcement, TSA opt-in, Status List integration, cross-family composition resolution.)*

---

## 9. Open questions (OQ-N)

*(List unresolved design questions with proposed defaults. Reference back here from implementation plan.)*

---

## 10. Glossary additions

*(Only terms not already in the v1.1 hardening spec glossary.)*

---

## 11. Decision linkage

- Spec drafted: https://github.com/dekimuhq/anchors-spec
- Implementation plan: an internal design record (not published)
- Decision docs: an internal design record (not published) for any non-obvious tradeoff.
