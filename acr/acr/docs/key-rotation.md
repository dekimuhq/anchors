# Key rotation

ACR signing keys SHOULD rotate on a fixed cadence (annually is a reasonable default) and MUST rotate immediately on any compromise suspicion.

Unlike APR — which routes verification through a `kid → public key` catalog — **ACR receipts are self-contained**: each receipt carries the issuer's public key in its `iss_key` field. That single design choice removes most of the operational surface APR ships with. There is no catalog to flip, no `notBefore` / `notAfter` window to manage, no overlap period to schedule.

## TL;DR

1. Generate a new keypair.
2. Flip your issuer's "active key" pointer to the new one.
3. Keep the old private seed alive only as long as you might need to mint chained operations on receipts already in flight.

The runnable example: [`../quickstart/rotate-key.ts`](../quickstart/rotate-key.ts). Run with `node --experimental-strip-types quickstart/rotate-key.ts`.

## Why the catalog story is different

In APR, verification looks like:

```
APR receipt → kid → CATALOG → public key → verify signature
```

The catalog is shared infrastructure. Rotating keys means updating it without breaking past receipts — hence APR's `notBefore` / `notAfter` semantics and overlap-window discipline.

In ACR, verification looks like:

```
ACR receipt → iss_key (embedded) → verify signature
```

There is no shared catalog. Every receipt carries everything a verifier needs. Rotating keys is a local operation in your issuer; the verifier-side surface is unchanged. Old receipts keep verifying because their pubkey is part of the receipt itself.

The tradeoff: receipts are larger (32 extra bytes of pubkey per receipt, plus the `ed25519:` prefix and base64url encoding overhead). For a consent-grade use case this is negligible.

## Step-by-step

### 1. Generate the new keypair

Use `generateKeypair(kid)` from `@dekimuhq/acr/issue`. Naming convention: `<issuer>-<year>`, e.g. `bank-2027`. The `kid` is a label your operator sees in audit logs — it is NOT used by verifiers for key resolution (ACR has no catalog lookup).

Store the private seed in a secrets vault (Vercel envs, HashiCorp Vault, 1Password Connect, HSM). **Never commit the seed.**

### 2. Flip the issuer's active key

Whatever your issuer code reads as "the current signing key," update it to point at the new keypair. From this point onward all new `mintConsent` / `mintModification` / `mintWithdrawal` calls will embed the new pubkey in `iss_key`.

There is no protocol-level handshake; this is a configuration flip in your issuer. There is nothing to deploy to a verifier.

### 3. Keep the old seed for as long as you need it

If a chain of receipts is still in flight — for example, a consent issued under the old key that may yet receive a modification or withdrawal — keep the old private seed available so you can mint those follow-ups. Once the chain has reached a terminal state (`ar.withdrawal.v1`) or you've decided no more chained operations will occur, the old seed can be destroyed.

Destroying the old seed does NOT break verification of receipts signed under it. The pubkey stays embedded in those receipts. Only future mints are affected.

## Chain integrity across rotations

A consent → modification → withdrawal chain CAN span multiple signing keys. Each receipt's `iss_key` is read independently by `verifyReceiptSignature` and `resolveChainState`. The chain's `prev` field hashes the previous receipt's full canonical view (including its `iss_key`), so any post-hoc tampering with an earlier link is detectable.

The runnable example demonstrates this: a consent signed under the 2026 key, followed by a modification and withdrawal both signed under the 2027 key. All three verify; the chain resolves cleanly.

## Compromised-key emergency rotation

If the old private seed leaks, the playbook is shorter than APR's:

1. Generate a new keypair (step 1 above).
2. Flip the issuer's active key (step 2 above).
3. **There is nothing to publish to a verifier.** No catalog snippet, no env var redeploy.
4. Audit every receipt signed under the old key against your internal records. Any receipt verifying under the leaked seed that your system did not produce is a forgery and SHOULD be invalidated downstream via your application logic (ACR has no protocol-level revocation in v1).
5. Publish a short disclosure noting the issuer DID, the rotation date, and how downstream consumers should respond.

The defence against a leaked seed is destroying the seed and rotating; the protocol does not provide a revocation primitive in v1.

## Audit trail

Issuers SHOULD keep an internal record of:

- Which signing key was active during which time range.
- Which receipts were signed under each key (operators already have this — every receipt carries `iss_key`, so grepping the receipt store by pubkey gives you the answer).
- Why each rotation happened (scheduled / compromise / re-keying for an HSM swap / etc.).

This is forensic insurance; the protocol does not require it.
