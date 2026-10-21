# @dekimuhq/did-web-resolver

`did:web` key resolver for the Anchored Receipts protocol family. Fetches
`/.well-known/dekimu-keys.json` from an issuer's domain and returns the
public key bytes matching an `iss_key` fingerprint.

## Install

```
npm install @dekimuhq/did-web-resolver
```

## Usage

```ts
import { resolveDidWebKey } from "@dekimuhq/did-web-resolver";

const pub = await resolveDidWebKey({
  iss: "did:web:competitor.com",
  iss_key: "ed25519:abc123...",
});
```

Returns `Uint8Array` (SPKI DER). Throws `DidWebResolveError` on fetch,
parse, no-matching-key, or out-of-validity-window failures.

## Convention

Issuers publish at `https://<domain>/.well-known/dekimu-keys.json`:

```json
{
  "version": 1,
  "keys": [{
    "iss_key": "ed25519:<base64url-fingerprint>",
    "public_key_der_base64": "<base64-of-SPKI-DER>",
    "valid_from": "2026-05-17T00:00:00Z",
    "valid_until": null
  }]
}
```

Multiple keys per issuer (rotation). `valid_until: null` = no expiry yet.

## License

Apache-2.0.
