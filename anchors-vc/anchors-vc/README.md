# @dekimuhq/anchors-vc

W3C Verifiable Credential binding for the **Anchored Receipts** family.

It lets a VC-native consumer (A2A / AP2 / MCP, or any VCDM 2.0 verifier) ingest an
anchored `ar.*` receipt — by carrying the receipt **verbatim** inside a Verifiable
Credential. The embedded envelope stays the cryptographic root of trust.

- **Carrier, not transform.** The full `Envelope` rides in `evidence[0].envelope`,
  untouched. `extractEnvelope(toVerifiableCredential(e))` is byte-equal to `e`, so
  the envelope's RFC 8785 / Merkle signature still verifies through the family's
  existing verifier. No re-canonicalisation, no re-signing.
- **Honest trust layers.** Issuer authenticity comes **only** from the embedded
  envelope `sig`, verified against a key resolved from the trust anchor (`did:web`).
  The optional wrapper `DataIntegrityProof` (`eddsa-jcs-2022`) proves wrapper
  *integrity* under that key — it is **not** an issuer check on its own (the
  `verificationMethod` and `issuer` are writable by whoever builds the credential).
  Use `verifyCredential` (below) for the correct combined check; the envelope `sig`
  is never reused as the VC `proof`.
- **`credentialStatus` parity.** The envelope's `StatusList2021Entry` lifts 1:1.
  Note it is a *pointer*, not a checked state — revocation requires dereferencing
  the StatusList separately; `verifyCredential` does not fetch it.
- **`did:web` reuse.** Issuer-key resolution reuses `@dekimuhq/did-web-resolver`;
  a `did:key`-equivalent fallback reads the self-describing `iss_key`.
- **Pure `node:crypto`.** No third-party crypto. Node ≥ 24.6.

## Usage

```ts
import { toVerifiableCredential, extractEnvelope } from "@dekimuhq/anchors-vc";

const vc = toVerifiableCredential(receiptEnvelope);   // carry as a VC
// ... hand `vc` to an A2A task result / AP2 evidence slot / MCP tool result ...

const envelope = extractEnvelope(vc);                 // recover, byte-equal
// verify with the family's existing verifier (e.g. @dekimuhq/acr)
```

Verify — the safe, combined path (roots trust in the did:web-resolved envelope
signature, asserts `issuer` consistency, then checks the wrapper proof if present):

```ts
import { verifyCredential } from "@dekimuhq/anchors-vc";

const r = await verifyCredential(vc); // did:web issuer resolved via the shared resolver
// r.ok, r.checks = { issuerMatch, envelopeSignature, wrapperProof: "valid"|"absent"|"invalid" }
```

Attaching an optional wrapper proof (for pure-VC verifiers) — signed by the issuer key:

```ts
import { attachWrapperProof, verificationMethodFor } from "@dekimuhq/anchors-vc";

const signed = attachWrapperProof(vc, issuerKeypair, {
  verificationMethod: verificationMethodFor(envelope.iss, envelope.iss_key),
});
```

`verifyWrapperProof(vc, key)` and `resolveWrapperKey(iss, iss_key)` are exposed as
lower-level primitives, but prefer `verifyCredential` — the wrapper proof alone does
not establish issuer authenticity.

For subjectless agent receipts (AActR/AQR/AGR/AGrR/AgTR/APIIR/ACBR, and the
event-conditional null cases of ATR/AER/ABR/AIR/APuR/ALR) the credential is framed
around the act, not a data subject (no `credentialSubject.id`) — detected purely
from `subject === null`.

## Status

Carrier wrap/unwrap + field-lift + `credentialStatus` parity, the optional
`eddsa-jcs-2022` wrapper proof, and `did:web`/`did:key` resolution are implemented
and tested (103 tests; `ml-dsa-65` hybrid *carriage* covered, hybrid *signing*
awaits a Node ≥ 24.6 runtime). Remaining before publish: the CC0 binding spec +
worked vector in `dekimuhq/anchors-spec` (maintainer-gated).

Design: an internal design record (not published).

## Naming (vs AP2)

This binding carries the **receipt of** what a mandate authorized — it is not an
AP2 mandate and does not issue one. ADR (Anchored Delegation Receipt) is the
artifact that travels. See the naming-posture decision (2026-06-30).

## License

Apache-2.0.
