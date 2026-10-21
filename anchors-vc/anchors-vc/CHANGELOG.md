# @dekimuhq/anchors-vc

## 0.1.2

### Patch Changes

- First release from the public `dekimuhq/anchors` repository: package metadata now points at it (`repository`, `homepage`, `bugs`), `publishConfig.access` is `public`, `engines.node` is declared as `>=24.6.0`, and every tarball ships a README and the Apache-2.0 LICENSE. No API changes.
- Updated dependencies
  - @dekimuhq/anchors-envelope@0.26.2
  - @dekimuhq/did-web-resolver@0.5.1

## 0.1.1

### Patch Changes

- 28c64ff: Re-sync internal dependency ranges so npm links the workspace instead of fetching stale published copies.

  Five internal 0.x carets could not admit their own workspace version (`^0.6.6` cannot match `0.7.0`), so npm resolved those packages from the registry, and those older tarballs pinned `@dekimuhq/anchors-envelope@^0.18.1` — materialising envelope 0.18.x in nested `node_modules` where `cli` then compiled against it. Every `anchors-envelope` range is now `^0.26.1` (the published version, matching the workspace source), and the five broken internal pins admit their workspace versions.

  This removes the root cause of the nesting, so the root `postinstall` rm -rf and the explicit `npm run postinstall` step in `anchors-ci.yml` are both deleted — the workaround was masking the drift that created it.

## 0.1.0

W3C Verifiable Credential carrier binding for the Anchored Receipts family — first release.

- **Carrier** — `toVerifiableCredential` / `extractEnvelope`: an anchored `ar.*` receipt rides verbatim in `evidence[0].envelope`; round-trip is byte-equal, so the envelope's signature still verifies through the family's existing verifier. Additive; zero edits to the envelope or any family package.
- **`verifyCredential`** — recommended combined verifier: roots trust in the did:web-resolved envelope signature (keyed on the embedded issuer), asserts `vc.issuer === envelope.iss`, then checks the optional wrapper proof. The wrapper proof alone does not establish issuer authenticity.
- **Wrapper proof** — optional `eddsa-jcs-2022` `DataIntegrityProof` over the wrapper (`attachWrapperProof` / `verifyWrapperProof`), signed by the issuer key; the envelope `sig` is never reused as the VC proof; non-`eddsa-jcs-2022` cryptosuites are rejected.
- **`credentialStatus` parity** (1:1 `StatusList2021Entry` lift; a pointer, not a checked state), **`did:web`** resolution via `@dekimuhq/did-web-resolver` with a `did:key`-equivalent fallback (`resolveWrapperKey` / `verificationMethodFor` / `publicKeyFromIssKey`).
- **Subjectless framing** on `subject === null` (agent families frame around the act, no `credentialSubject.id`).
- Algorithm-agnostic at layer 1: ed25519 and post-quantum `ml-dsa-65` primary signatures both verify (ml-dsa needs Node ≥ 24.6). Pure `node:crypto`, no third-party crypto. 116 tests; security-reviewed. CC0 binding spec + worked vector published to `dekimuhq/anchors-spec`.
