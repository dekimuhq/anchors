# Design note: committing AActR to its capability token (F6)

Status: DESIGN ONLY. No schema or code change. `ar.action.v1` is a published, locked wire format.

## Problem

An `ar.action.v1` (AActR) body carries `credential_id`, `agent_id`, `caveats_consumed` and `delegation_chain`
as plain issuer-asserted fields. Nothing in the signed receipt commits to the capability token (mandate) they
claim to describe. A stateless verifier therefore cannot tell whether:

- the named `credential_id` / `delegation_chain` / `agent_id` ever existed together,
- `caveats_consumed.spend_step` stayed inside the mandate's caveats,
- the chain depth / `leaf_key` / `root_credential_id` belong to that token.

An issuer (or an attacker holding the issuer key) can mint a receipt claiming any mandate. The only check
today is internal consistency (`delegation_chain.root_credential_id == credential_id`), which proves nothing
about the token. The `body.ts` docs already name this as "the same issuer-asserted boundary".

## Proposal

Add one signed-body field, `mandate_commit`: `sha256:<hex>` of the RFC 8785-canonical capability token
(root block + all delegation blocks, signatures included), optionally salted like the existing `*_commit`
fields (`commit(salt, canonicalize(token))`) so a public receipt does not let anyone confirm a guessed token.

Verification then becomes: given the token (supplied out of band by the party disputing/auditing the action),

1. recompute `mandate_commit` and compare to the receipt body;
2. run the existing `@dekimuhq/mandate-verify` over the token and check that `credentialId`, `verifiedAgentId`,
   chain depth, `leaf_key` and root id equal the body's `credential_id`, `agent_id`, `delegation_chain.*`;
3. check `caveats_consumed` against the verified caveat intersection.

With the commitment, the plain fields become checkable claims rather than assertions; a receipt that names a
mandate the issuer cannot produce, or whose token contradicts the fields, fails.

Limit: this binds the receipt to a token, not the token to reality. A rogue issuer can still mint a token it
controls; the commitment makes that visible and non-repudiable, and lets the revocation proof
(`non_revocation_proof`) be tied to the same token.

## Why a new version

Adding `mandate_commit` to the `ar.action.v1` body changes a locked, published schema: v1 verifiers reject
unknown body keys (body schema is closed), and the field would be absent from every existing receipt, so
"required when `credential_id` is present" cannot be enforced on v1 without breaking already-minted receipts.
Options:

- **(A) `ar.action.v2` (recommended).** New claim type; body = v1 + `mandate_commit`, REQUIRED whenever
  `credential_id` is present. v1 stays valid forever and is verified by the unchanged v1 path.
- **(B) Envelope amendment.** A generic signed envelope slot (e.g. a `commits` map) usable by any family.
  Broader, touches every family and the envelope version (v1.3/v1.4 amendment process); heavier than the
  finding warrants.

## Compatibility plan

1. Register `ar.action.v2` (REGISTRY.md, FAMILY-CONSISTENCY.md, claim-type union); publish spec text first.
2. Verifier accepts both; v2 rule: `credential_id` present => `mandate_commit` present, else
   `mandate_commit_missing`. v1 receipts verify unchanged and surface a non-blocking warning
   `mandate_uncommitted` so consumers can see the weaker assurance.
3. Issuers (Hub gateway) dual-mint v2 once `mandate-verify` exposes the canonical token bytes to hash; v1 minting
   stops after one release window. Public claims about mandate binding stay off until v2 verifiers ship
   (public-claims policy).
4. Optional later: `mandate-verify` gains `verifyReceiptAgainstToken(receipt, token)` implementing steps 1-3.

## Open questions

- Salted vs unsalted commit (token entropy is high; salt only needed if tokens are guessable).
- Whether `non_revocation_proof` should also move under the commitment in v2.
