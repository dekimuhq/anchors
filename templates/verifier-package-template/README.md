# @dekimuhq/<member>-verifier

Verifier for **Anchored <Noun> Receipts** (<MEMBER>) v1. Stateless. Edge-runtime compatible.

Part of the [Anchored Receipts](https://github.com/dekimuhq/anchors) family. See the [v1 design spec](TODO: link to spec file) for protocol details.

## Install

```bash
npm install @dekimuhq/<member>-verifier
```

## Usage

```ts
import { verify<MEMBER> } from "@dekimuhq/<member>-verifier";

const result = await verify<MEMBER>(receipt, {
  trustedIssuers: [/* did:web identifiers */],
  resolveStatusList: async (url) => { /* fetcher */ },
  resolveAnchor: async (logId) => { /* anchor-log fetcher */ },
});

if (result.ok) {
  // result.claims is fully resolved
} else {
  // result.errors lists canonical codes (see spec §6.2)
}
```

## What this verifier does

1. Validates envelope v=2 (shape, JCS canonical, Ed25519 sig).
2. Walks `prev` chain if present.
3. Resolves `policy_uri` / `policy_hash` / `policy_version` per claim_type matrix.
4. Validates RFC 3161 timestamp if profile mandates.
5. Resolves W3C Status List 2021 `credentialStatus`.
6. Resolves cross-family composition refs per profile.
7. Returns canonical `{ ok, claims, errors, warnings }`.

## What this verifier does NOT do

- Mint receipts (use `@dekimuhq/<member>-issuer-kit`).
- Publish anchor logs (the `verify.dekimu.com` worker does that).
- Validate the underlying business event — only that the cryptographic shape, chain, timestamps, status, and policy bindings are correct.

## License

Apache-2.0
