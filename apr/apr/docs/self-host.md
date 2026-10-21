# Self-host verifier guide

The reference hosted verifier at `verify.dekimu.com` is convenient but optional. APR is designed so a third party can verify a receipt end-to-end with no network access, using only:

- This library (`@dekimuhq/apr`).
- The receipt itself.
- The daily-root envelope for the receipt's anchor date.
- The id list the daily root was built over.
- A claim-key catalog (`kid → {publicKey, issuer}`).
- A root-key catalog (`kid → {publicKey}`).

If you have those five inputs, you can prove a receipt is verified, tampered, or unverified without talking to anyone.

## Why you might self-host

- **CI gates.** Verify an APR is `verified` before letting a deploy proceed.
- **Audit / forensics.** Inspect receipts pulled from cold storage years after issuance.
- **Air-gapped environments.** Verify receipts in environments that cannot reach the public internet.
- **Cross-checking the hosted verifier.** Belt-and-braces: verify locally that what `verify.dekimu.com` shows is what your local library agrees with.

## Minimal example

```ts
import * as fs from "node:fs";
import {
  verify,
  base64UrlDecode,
  type ClaimKeyResolver,
  type RootKeyResolver,
  type ClaimVerifyingKey,
  type RootVerifyingKey,
  type DailyRoot,
} from "@dekimuhq/apr";

const claim       = JSON.parse(fs.readFileSync("claim.json",       "utf8"));
const anchor      = JSON.parse(fs.readFileSync("anchor.json",      "utf8")) as DailyRoot;
const anchorIds   = JSON.parse(fs.readFileSync("anchor-ids.json",  "utf8")) as string[];
const claimKeys   = JSON.parse(fs.readFileSync("verify-keys.json", "utf8"));
const rootKeys    = JSON.parse(fs.readFileSync("root-keys.json",   "utf8"));

const claimKeyMap = new Map<string, ClaimVerifyingKey>();
for (const [kid, entry] of Object.entries<{ issuer: string; publicKey: string }>(claimKeys)) {
  claimKeyMap.set(kid, {
    kid,
    publicKey: base64UrlDecode(entry.publicKey),
    issuer: entry.issuer,
  });
}
const claimKeyResolver: ClaimKeyResolver = (kid) => claimKeyMap.get(kid);

const rootKeyMap = new Map<string, RootVerifyingKey>();
for (const [kid, entry] of Object.entries<{ publicKey: string }>(rootKeys)) {
  rootKeyMap.set(kid, { kid, publicKey: base64UrlDecode(entry.publicKey) });
}
const rootKeyResolver: RootKeyResolver = (kid) => rootKeyMap.get(kid);

const result = verify({
  claim,
  anchor,
  anchorIds,
  claimKeyResolver,
  rootKeyResolver,
});

console.log(result);
```

Run on a fresh machine with only Node ≥22 installed:

```bash
node --experimental-strip-types verify-local.ts
```

No network. No Dekimu credentials. The result is a `{status, reasons}` object whose decision rules are documented in [`apr-spec/v1.md`](https://github.com/dekimuhq/anchors-spec/blob/main/apr/v1.md) §8.

## Where the inputs come from

| Input | Source |
|---|---|
| `claim.json` | The receipt itself. Issuers publish these; consumers fetch them and store them. |
| `anchor.json` | The daily-root envelope for the receipt's UTC date. Published by whoever runs the anchor service (e.g. `verify.dekimu.com/api/anchor/<date>`). |
| `anchor-ids.json` | The id list the root was built over. Published alongside the daily root by the anchor service. |
| `verify-keys.json` | The claim-key catalog. The issuer publishes their public keys; verifiers source them from a channel they trust independently of the receipts being verified (env var, signed catalog, `/.well-known` endpoint, etc.). |
| `root-keys.json` | The root-key catalog. Published by whoever runs the anchor service. Independent of any one issuer. |

For the reference hosted setup, all five are served as plain JSON under `verify.dekimu.com`'s public surface; the env-var-driven setup uses `CLAIMS_VERIFY_KEYS_JSON` for the claim-key catalog and an analogous env for root keys.

## Validation against the published vectors

The fastest way to confirm a self-hosted instance is wired correctly:

```bash
git clone https://github.com/dekimuhq/anchors.git
cd anchors && npm ci && npm run build-all
npm test -w @dekimuhq/apr
```

All five published v1 vectors must pass with their declared `status` and `reasons`. If any vector fails, the local setup has a bug — fix that before trusting the verifier on production receipts.

## What self-host does NOT give you

- **Anchor freshness.** This library verifies whatever anchor envelope you hand it. If the anchor for your receipt's date has not yet been published, the verifier returns `unverified` with reason `unanchored`. Build a retry loop on top of that — don't pretend the anchor exists.
- **Catalog freshness.** If an issuer rotates `kid`s and you cached the old catalog, you'll fail verification on the new receipts with `unknown_kid`. Re-fetch the catalog on rotation events; don't cache forever.
- **Network-level revocation.** APR v1 has no push-revocation; the closest analogue is `notAfter` on a `kid`. If your verifier needs faster-than-`notAfter` revocation, layer it on top.

## See also

- [`apr-spec/v1.md`](https://github.com/dekimuhq/anchors-spec/blob/main/apr/v1.md) — the protocol.
- [`apr-spec/conformance/test-vectors/SCHEME.md`](https://github.com/dekimuhq/anchors-spec/blob/main/apr/conformance/test-vectors/SCHEME.md) — the reference Merkle scheme.
- [`apr-spec/THREAT-MODEL.md`](https://github.com/dekimuhq/anchors-spec/blob/main/apr/THREAT-MODEL.md) — what verification actually proves.
