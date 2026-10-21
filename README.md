# Anchored Receipts

TypeScript reference implementation of the **Anchored Receipts** family: signed receipts for agent actions, provenance, consent, retention, lineage, notices, subject rights, breaches, impact assessments, delegation, attestation and more.

A receipt is signed by its issuer over a canonical (RFC 8785) serialization. It can be anchored to a Merkle root and an RFC 3161 timestamp, and revoked through a W3C status list. Receipts are tamper-evident by construction, and a third party can check a receipt's signature offline, with no account.

- **Specs (CC0):** [`dekimuhq/anchors-spec`](https://github.com/dekimuhq/anchors-spec)
- **Code (Apache-2.0):** this repository: 53 packages under the `@dekimuhq` npm scope.
- **Wire format:** every receipt carries a `claim_type` of the form `ar.<noun>.v<N>`. New fields are optional and additive. A breaking change gets a new `v<N+1>` discriminator.
- **Cross-family invariants:** [`meta/FAMILY-CONSISTENCY.md`](meta/FAMILY-CONSISTENCY.md) · **Registry:** [`meta/REGISTRY.md`](meta/REGISTRY.md)

## Requirements

Node **≥24.6**. Every package declares `"engines": { "node": ">=24.6.0" }`.

> **Node 22:** installs print an npm engine warning, which becomes a hard failure under `engine-strict`. The ML-DSA (post-quantum) signing and verification path needs the native ML-DSA support that ships in Node ≥24.6, so it does not work on Node 22.

Runtime crypto is `node:crypto` only. No third-party crypto dependency.

## Install

```bash
npm install @dekimuhq/anchors-envelope @dekimuhq/apr
```

Each family package exposes its verifier on the package root (`.`) and its issuer helpers on the `./issue` subpath. Profile validators live in the matching `-profiles` package. `@dekimuhq/anchors` re-exports every family under one namespace, and `@dekimuhq/anchors-cli` verifies receipt files from the command line.

## Packages

| Package | Path | Version |
|---|---|---|
| `@dekimuhq/anchors-envelope` | [`envelope`](envelope) | 0.26.2 |
| `@dekimuhq/anchors-transparency` | [`transparency/anchors-transparency`](transparency/anchors-transparency) | 0.3.2 |
| `@dekimuhq/anchors-disclosure` | [`disclosure/anchors-disclosure`](disclosure/anchors-disclosure) | 0.3.1 |
| `@dekimuhq/anchors-vc` | [`anchors-vc/anchors-vc`](anchors-vc/anchors-vc) | 0.1.2 |
| `@dekimuhq/apr` | [`apr/apr`](apr/apr) | 0.7.3 |
| `@dekimuhq/acr` | [`acr/acr`](acr/acr) | 0.7.2 |
| `@dekimuhq/acr-profiles` | [`acr/acr-profiles`](acr/acr-profiles) | 0.7.3 |
| `@dekimuhq/alr` | [`alr/alr`](alr/alr) | 0.5.2 |
| `@dekimuhq/alr-profiles` | [`alr/alr-profiles`](alr/alr-profiles) | 0.5.3 |
| `@dekimuhq/anr` | [`anr/anr`](anr/anr) | 0.7.2 |
| `@dekimuhq/anr-profiles` | [`anr/anr-profiles`](anr/anr-profiles) | 0.7.3 |
| `@dekimuhq/abr` | [`abr/abr`](abr/abr) | 0.6.2 |
| `@dekimuhq/abr-profiles` | [`abr/abr-profiles`](abr/abr-profiles) | 0.6.3 |
| `@dekimuhq/asr` | [`asr/asr`](asr/asr) | 0.6.2 |
| `@dekimuhq/asr-profiles` | [`asr/asr-profiles`](asr/asr-profiles) | 0.6.3 |
| `@dekimuhq/air` | [`air/air`](air/air) | 0.7.2 |
| `@dekimuhq/air-profiles` | [`air/air-profiles`](air/air-profiles) | 0.7.3 |
| `@dekimuhq/arr` | [`arr/arr`](arr/arr) | 0.9.2 |
| `@dekimuhq/arr-profiles` | [`arr/arr-profiles`](arr/arr-profiles) | 0.9.3 |
| `@dekimuhq/atokr` | [`atokr/atokr`](atokr/atokr) | 0.3.2 |
| `@dekimuhq/atokr-profiles` | [`atokr/atokr-profiles`](atokr/atokr-profiles) | 0.3.3 |
| `@dekimuhq/adr` | [`adr/adr`](adr/adr) | 0.4.1 |
| `@dekimuhq/adr-profiles` | [`adr/adr-profiles`](adr/adr-profiles) | 0.4.2 |
| `@dekimuhq/aar` | [`aar/aar`](aar/aar) | 0.4.2 |
| `@dekimuhq/aar-profiles` | [`aar/aar-profiles`](aar/aar-profiles) | 0.4.3 |
| `@dekimuhq/aar-tsl` | [`aar/aar-tsl`](aar/aar-tsl) | 0.2.8 |
| `@dekimuhq/atr` | [`atr/atr`](atr/atr) | 0.3.2 |
| `@dekimuhq/atr-profiles` | [`atr/atr-profiles`](atr/atr-profiles) | 0.3.3 |
| `@dekimuhq/apur` | [`apur/apur`](apur/apur) | 0.3.2 |
| `@dekimuhq/apur-profiles` | [`apur/apur-profiles`](apur/apur-profiles) | 0.3.3 |
| `@dekimuhq/aer` | [`aer/aer`](aer/aer) | 0.3.2 |
| `@dekimuhq/aer-profiles` | [`aer/aer-profiles`](aer/aer-profiles) | 0.3.3 |
| `@dekimuhq/action` | [`action/action`](action/action) | 0.6.3 |
| `@dekimuhq/action-profiles` | [`action/action-profiles`](action/action-profiles) | 0.6.4 |
| `@dekimuhq/quality` | [`quality/quality`](quality/quality) | 0.1.2 |
| `@dekimuhq/quality-profiles` | [`quality/quality-profiles`](quality/quality-profiles) | 0.1.2 |
| `@dekimuhq/trace-profiles` | [`trace/trace-profiles`](trace/trace-profiles) | 0.2.2 |
| `@dekimuhq/trace` | [`trace/trace`](trace/trace) | 0.2.2 |
| `@dekimuhq/trace-otel` | [`trace/trace-otel`](trace/trace-otel) | 0.1.1 |
| `@dekimuhq/guard` | [`guard/guard`](guard/guard) | 0.1.2 |
| `@dekimuhq/guard-detect` | [`guard/guard-detect`](guard/guard-detect) | 0.1.1 |
| `@dekimuhq/guard-profiles` | [`guard/guard-profiles`](guard/guard-profiles) | 0.1.1 |
| `@dekimuhq/grounding` | [`grounding/grounding`](grounding/grounding) | 0.1.2 |
| `@dekimuhq/grounding-check` | [`grounding/grounding-check`](grounding/grounding-check) | 0.1.1 |
| `@dekimuhq/grounding-profiles` | [`grounding/grounding-profiles`](grounding/grounding-profiles) | 0.1.2 |
| `@dekimuhq/compliance` | [`compliance/compliance`](compliance/compliance) | 0.1.2 |
| `@dekimuhq/redaction` | [`redaction/redaction`](redaction/redaction) | 0.1.2 |
| `@dekimuhq/redaction-profiles` | [`redaction/redaction-profiles`](redaction/redaction-profiles) | 0.1.2 |
| `@dekimuhq/did-web-resolver` | [`did-web-resolver`](did-web-resolver) | 0.5.1 |
| `@dekimuhq/anchors-trusted-issuers` | [`trusted-issuers`](trusted-issuers) | 1.0.1 |
| `@dekimuhq/anchors-federation` | [`federation`](federation) | 0.1.6 |
| `@dekimuhq/anchors` | [`meta`](meta) | 0.12.3 |
| `@dekimuhq/anchors-cli` | [`cli`](cli) | 0.1.2 |

`anchor-contracts` and `e2e` are private workspaces and are not published. `templates/` holds scaffolds for new family members and sits outside the workspace list.

## Development

The cross-family conformance suite in `e2e/` reads test vectors from a sibling checkout of the spec repository, so clone both side by side:

```bash
git clone https://github.com/dekimuhq/anchors.git
git clone --depth 1 https://github.com/dekimuhq/anchors-spec.git   # read by e2e as ../anchors-spec
cd anchors
npm ci
npm run build-all     # builds every package's dist/ in dependency order
npm run typecheck
npm test
npm run validate      # manifest + FAMILY-CONSISTENCY cross-checks (runs every family's tests)
```

Build before typecheck, test or validate: packages import each other through their built `dist/`.

TypeScript runs in strict mode with `exactOptionalPropertyTypes`. Tests use the built-in `node:test` runner.

## Envelope versions

- **v=1** — legacy shape. Existing v=1 receipts still verify byte-equal.
- **v=2** — the shared `@dekimuhq/anchors-envelope`, discriminated by `claim_type`. It carries `tsa`, `credentialStatus` and `policy`. `mint*()` emits v=2 by default.

Verifiers dispatch on the `v` field.

## Contributing, security, license

- [CONTRIBUTING.md](CONTRIBUTING.md): changesets, versioning, DCO sign-off.
- [SECURITY.md](SECURITY.md): report vulnerabilities to **security@dekimu.com**, not in a public issue.
- Code: [Apache-2.0](LICENSE). Specs: CC0, in `dekimuhq/anchors-spec`.
