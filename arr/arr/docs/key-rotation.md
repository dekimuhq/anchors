# Key rotation

ARR signing keys SHOULD rotate on a fixed cadence (annually is a reasonable default) and MUST rotate immediately on any compromise suspicion.

Like ACR — and unlike APR — **ARR receipts are self-contained**: each receipt embeds the issuer's public key in its `iss_key` field. There is no central verifier catalog. Rotation is a local operation in your issuer; the verifier-side surface is unchanged.

## TL;DR

1. Generate a new keypair via `generateIssuerKey()`.
2. Encode the matching public key with `encodePublicKey()` and pass it as `iss_key` on every new mint.
3. Flip your issuer's "active key" pointer to the new private key.
4. Keep the old private seed alive only as long as you might need to sign chained retention events for targets already in flight.

The runnable example: [`../quickstart/rotate-key.ts`](../quickstart/rotate-key.ts). Run with `node --experimental-strip-types quickstart/rotate-key.ts`.

## Why the catalog story is different

In APR, verification looks like:

```
APR claim → kid → CATALOG → public key → verify signature
```

The catalog is shared infrastructure. Rotating keys means updating it without breaking past receipts — hence APR's `notBefore` / `notAfter` semantics and overlap-window discipline.

In ARR, verification looks like:

```
ARR receipt → iss_key (embedded) → verify signature
```

There is no shared catalog. Every receipt carries everything a verifier needs. Rotating keys is local to your issuer; verifiers and chain walkers don't notice. Old receipts keep verifying because their pubkey is part of the receipt itself.

The tradeoff: receipts are larger (32 extra bytes of pubkey per receipt, plus the `ed25519:` prefix and base64url encoding overhead). For retention-grade receipts — typically one per lifecycle event, not one per write — this is negligible. Batch receipts amortise the overhead further: one `iss_key` per `ar.batch.v1` envelope, not one per target.

## Step-by-step

### 1. Generate the new keypair

Use `generateIssuerKey()` from `@dekimuhq/arr/issue`. It returns Node `KeyObject` references for both halves of an Ed25519 keypair — you do not need to copy raw bytes around.

Store the private key in a secrets vault (Vercel envs, HashiCorp Vault, 1Password Connect, HSM). Use `loadPrivateKey(pkcs8Pem)` at issuance time to rehydrate it from PKCS8 PEM. **Never commit the seed.**

### 2. Pre-compute the encoded public key

Every `mint*` call needs `iss_key: encodePublicKey(publicKey)`. Cache the encoded string at issuer-startup — `encodePublicKey()` is cheap but called per mint it shows up in profiles for high-throughput issuers.

### 3. Flip the issuer's active key

Whatever your issuer code reads as "the current signing key pair," update it to point at the new pair. From this point onward all `mintErasure` / `mintExpiry` / `mintHoldExtension` / `mintHoldRelease` / `mintAnonymization` / `mintPseudonymization` / `mintArchive` / `mintBatchReceipt` calls will embed the new pubkey in `iss_key`.

There is no protocol-level handshake; this is a configuration flip in your issuer. There is nothing to deploy to a verifier.

### 4. Keep the old key around as long as you need it

If a retention chain for a target is still active — for example, a `hold_extension` issued under the old key that may yet receive a matching `hold_release` — keep the old private key available so you can mint that follow-up. Once the target reaches a terminal state (`ar.erasure.v1` or `ar.anonymization.v1`) or you've decided no more chained operations will occur, the old private key can be destroyed.

Destroying the old key does NOT break verification of receipts signed under it. The pubkey stays embedded in those receipts. Only future mints are affected.

## Chain integrity across rotations

A multi-event retention chain for the same `target_commit` CAN span multiple signing keys. `resolveTargetChain` in `@dekimuhq/arr` walks the chain, validates each link's `prev` against its predecessor's full canonical hash (including the predecessor's `iss_key`), and checks signatures using each receipt's embedded pubkey.

If you reorder, replace, or post-hoc-edit any link, `resolveTargetChain` returns a `chain.prev.mismatch[i]` error pointing at the broken link.

### `prev` hash helper

`@dekimuhq/arr` v0.1.x does NOT export the receipt-hash primitive directly — it is internal to `resolveTargetChain`. If you need to compute the `prev` value yourself when minting a chained follow-up, you have two options:

1. **Use `resolveTargetChain` end-to-end** for chain validation, and inline the hash algorithm in your issuer (canonicalise the receipt with `anchor: null` + `sig: null`, SHA-256 the canonical bytes, prefix with `sha256:`). This matches the implementation in `arr-verifier/src/chain.ts`.
2. **Wait for `hashArrReceipt`** — a future minor release will expose it as a public symbol for parity with `@dekimuhq/acr`'s `hashReceipt`.

If chain semantics are central to your use case, option 2 is preferred. Open an issue on the repo if this gate is blocking you.

## Compromised-key emergency rotation

If the old private key leaks, the playbook is shorter than APR's:

1. Generate a new keypair (step 1 above).
2. Flip the issuer's active key (step 3 above).
3. **There is nothing to publish to a verifier.** No catalog snippet, no env var redeploy.
4. Audit every receipt signed under the old key against your internal records. Any receipt verifying under the leaked key that your system did not produce is a forgery and SHOULD be invalidated downstream via your application logic (ARR has no protocol-level revocation in v1).
5. Publish a short disclosure noting the issuer DID, the rotation date, and how downstream consumers should respond.

The defence against a leaked key is destroying the key and rotating; the protocol does not provide a revocation primitive in v1.

## Audit trail

Issuers SHOULD keep an internal record of:

- Which signing key was active during which time range.
- Which receipts were signed under each key (operators already have this — every receipt carries `iss_key`, so grepping the receipt store by pubkey gives you the answer).
- Why each rotation happened (scheduled / compromise / re-keying for an HSM swap / etc.).

This is forensic insurance; the protocol does not require it.
