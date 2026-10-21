# @dekimuhq/anchors-cli

Offline / third-party verifier CLI for the **Anchored Receipts** family.

```
anchors verify <file...> [--json] [--trusted-keys <file>]
```

Routes any receipt to its family verifier by `claim_type` — no network, no
trust in the Dekimu SaaS. The signing key travels inside the receipt as the
`iss_key` fingerprint, so a third party can verify a receipt entirely offline.

## Install

```bash
npm i -g @dekimuhq/anchors-cli
```

## Usage

```bash
# Self-certifying: verify the signature against the receipt's embedded key.
anchors verify receipt.json

# Require a known issuer: only pass if iss_key is in the allowlist.
anchors verify receipt.json --trusted-keys trusted.json

# Machine-readable output.
anchors verify *.json --json
```

Each file is a single receipt envelope **or** a JSON array of envelopes.

`--trusted-keys` takes a JSON array of `ed25519:<base64url>` fingerprints:

```json
["ed25519:0pQ…", "ed25519:Xy9…"]
```

### Verification modes

| Mode | Flag | What a PASS proves |
|------|------|--------------------|
| Self-certifying | _(default)_ | The receipt is internally consistent and signed by the key it **claims** — not who owns that key. |
| Trusted-keys | `--trusted-keys` | The above **and** the signing key is one you listed as trusted. |

> Offline verification checks the signature, envelope structure, and body
> schema. It does **not** check Merkle inclusion against the transparency log
> (that needs the log) — use `verify.dekimu.com` for full log-anchored
> verification.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Every receipt valid |
| `1` | At least one receipt invalid or undispatched |
| `2` | Usage error, or an unreadable / malformed input file |

## Programmatic use

```ts
import { verifyAnchor, selfCertifyingResolveKey } from "@dekimuhq/anchors-cli";

const outcome = await verifyAnchor(receipt, { resolveKey: selfCertifyingResolveKey });
// { ok, claim_type, family, result }
```

`supportedClaimTypes()` lists every discriminator the CLI can route.

## License

Apache-2.0.
