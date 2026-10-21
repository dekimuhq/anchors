# Anchored Receipts → W3C Verifiable Credential Binding (v1)

> **CC0 1.0 Universal.** To the extent possible under law, the authors have
> dedicated this specification to the public domain. Brand marks (e.g. "Dekimu")
> are excluded from the dedication. This is a DRAFT staged for the public
> `dekimuhq/anchors-spec` repository; the reference implementation is
> `@dekimuhq/anchors-vc`.

## 1. Purpose

This binding lets a W3C Verifiable Credential Data Model (VCDM 2.0) consumer —
including agent protocols that interoperate on DID + VC (A2A, AP2, MCP) — ingest
an anchored `ar.*` receipt and verify it, **without modifying the receipt or any
family package**. It is additive and byte-equal: every existing receipt continues
to verify unchanged through its existing verifier.

The binding is a **representation**, not a new receipt family. It defines no new
`claim_type`.

## 2. Model — carrier, not transform

An Anchored Receipt Verifiable Credential (ARVC) is a **carrier**: the full
Anchored Receipts `Envelope` rides verbatim inside the credential's `evidence`
array. A minimal, lossless set of envelope fields is *lifted* to VC top-level so
standard VC tooling functions.

A conforming producer MUST NOT re-canonicalise or re-sign the envelope. The
cryptographic truth is the embedded envelope, verified by the family's existing
verifier over `extractEnvelope(vc)`.

### 2.1 Field lift

| VC field | Source (`Envelope`) | Rule |
|---|---|---|
| `issuer` | `iss` | verbatim (a DID or self-describing key id) |
| `validFrom` | `iat` | verbatim |
| `validUntil` | `exp` | present iff `exp !== null` |
| `credentialSubject.id` | `subject` | present iff `subject !== null` (§4) |
| `credentialStatus` | `credentialStatus` / `suspensionStatus` | 1:1 (§5) |
| `evidence[0].envelope` | the entire `Envelope` | verbatim, untouched |
| `evidence[0].anchorLog` | `anchor.log` | descriptor only, NOT a proof (§3) |
| `evidence[0].treeHeadRoot` | `anchor.tree_head_root` | descriptor only, NOT a proof |
| `type` | — | `["VerifiableCredential", "AnchoredReceiptCredential"]` |
| `@context` | — | `["https://www.w3.org/ns/credentials/v2", "https://anchors.dekimu.com/ns/vc/v1", …]` |

`extractEnvelope(toVerifiableCredential(e))` MUST deep-equal `e`.

## 3. Two trust layers

1. **Root of trust — the embedded envelope `sig`.** Ed25519 or `ml-dsa-65` over
   `preSigCanonical(envelope)`. Verified by the existing anchors verifier. A
   conforming consumer that understands anchors MUST verify this layer.
2. **Optional wrapper proof — `DataIntegrityProof`.** Cryptosuite
   `eddsa-jcs-2022`, signed by the **same issuer key** over the RFC 8785 (JCS)
   canonical form of the credential with its `proof` member removed. `proofValue`
   is base64url. This layer proves wrapper **integrity** under whatever key the
   verifier supplies. It is NOT, by itself, an issuer-authenticity check: the
   `verificationMethod` and the lifted `issuer` are writable by whoever builds the
   credential, so a wrapper proof only means "*some* key signed these bytes."
   Issuer authenticity derives solely from layer 1, whose key is resolved from the
   trust anchor. A verifier MUST NOT treat a valid wrapper proof as issuer
   authentication in isolation.

The envelope `sig` MUST NOT be reused as the VC `proof`: it covers the envelope
canonical bytes, not the wrapper fields. Reusing it would falsely assert the
wrapper is signed. A credential MAY carry no wrapper proof, in which case trust
derives solely from layer 1. A verifier MUST reject a wrapper proof whose
`cryptosuite` is not `eddsa-jcs-2022` (v1) rather than attempt to evaluate it.

The RFC 6962 Merkle inclusion proof (`anchor`) and any transparency-log block
(`incl`) are **anchoring**, not **signing** — they remain inside the embedded
envelope and MUST NOT be expressed as a VC `proof`.

## 4. Subject framing

The binding is subject-presence-agnostic: it frames purely on `subject === null`.
It does NOT enforce the per-family subject-presence rules — that remains the
family verifier's responsibility (`FAMILY-CONSISTENCY §3`).

- `subject` is a string → `credentialSubject = { id: <subject> }`.
- `subject` is `null` (null-subject / agent families such as AActR, AQR, AGR,
  AGrR, AgTR, APIIR, ACBR, and the event-conditional null cases of ATR, AER, ABR,
  AIR, APuR, ALR) → `credentialSubject` carries **no `id`**; it describes the act:
  `{ receipt: <envelope.id>, claimType: <claim_type> }`.

## 5. Status parity

The envelope's `credentialStatus` is already a W3C `StatusList2021Entry`; it maps
1:1 to the VC `credentialStatus`. When both a revocation pointer and a
`suspensionStatus` (`statusPurpose: "suspension"`) are present, both are carried
as an array (revocation first). A status-list non-consumer receipt carries no
`credentialStatus`.

`credentialStatus` is a **pointer**, not a checked state. Determining whether a
receipt is revoked requires dereferencing `statusListCredential` and reading the
bit at `statusListIndex`; this binding (and `verifyCredential`) does not fetch it.
A consumer MUST NOT infer non-revocation from a passing signature check alone.

## 6. Issuer key resolution (DID scope)

`did:web` is primary and resolves via `@dekimuhq/did-web-resolver` (no new
resolver). A `did:key`-equivalent fallback reads the self-describing envelope
`iss_key` (`<sig_alg>:<base64url-raw-key>`). Other DID methods are out of scope
for v1 (additive later). Wrapper-proof verification consumes the raw key; the
resolver's SPKI-DER output for ed25519 is stripped to the raw 32 bytes.

## 7. Relationship to AP2 mandates (naming)

An ARVC carries the **receipt of** what a mandate authorized. It is not an AP2
mandate and does not issue one; "mandate" is used only as the lowercase concept.
The artifact that travels is the ADR (Anchored Delegation Receipt) where a
delegation is involved. Anchors is the registered evidence/receipt layer beneath
the protocols, not a competitor to them, and settles no payment.

## 8. Worked example

See [`vectors/anchors-vc-example.json`](vectors/anchors-vc-example.json) — a real
`ar.consent.v1` receipt (deterministic Ed25519 key, seed = 32 × `0x07`) wrapped as
an ARVC with a `eddsa-jcs-2022` wrapper proof and a revocation `credentialStatus`.
Reproducible; both the embedded envelope signature and the wrapper proof verify,
and `extractEnvelope` is byte-equal to the input.

## 9. Conformance

A conforming **producer** MUST: carry the envelope verbatim in `evidence[0]`;
lift fields per §2.1; frame the subject per §4; map status per §5; never re-sign
the envelope; never emit the envelope `sig` as the VC `proof`.

A conforming **consumer** MUST verify layer 1 as the mandatory root of trust:
recover the envelope from `evidence[0].envelope`, resolve the issuer key from the
trust anchor (§6) using the **envelope's** `iss` / `iss_key`, verify the envelope
signature against it, and assert `vc.issuer === envelope.iss`. A consumer MUST NOT
rely on the wrapper `proof` in isolation for issuer authenticity, MUST NOT treat
`anchorLog` / `treeHeadRoot` descriptors as cryptographic proofs, and MUST NOT
infer non-revocation without dereferencing `credentialStatus` (§5). The reference
implementation's `verifyCredential` performs this combined check.
