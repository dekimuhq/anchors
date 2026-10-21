# Key rotation

APR signing keys SHOULD rotate on a fixed cadence (annually is a reasonable default) and MUST rotate immediately on any compromise suspicion.

A clean rotation preserves the verifiability of receipts signed under the old `kid` while moving new traffic to a new `kid`. Done wrong, you invalidate every receipt you've ever issued.

## TL;DR

1. Keep the old kid in the verifier catalog.
2. Add a new kid alongside it.
3. Flip your issuer's "active" kid pointer to the new one.
4. Retire the old kid (remove from catalog) only when no live consumer needs to verify receipts signed under it.

The runnable example: [`../quickstart/rotate-key.ts`](../quickstart/rotate-key.ts). Run with `node --experimental-strip-types quickstart/rotate-key.ts`.

## Why two kids must coexist

APR receipts carry a `kid` field. Verifiers resolve `kid → public key`. If you replace the old kid's public key with the new one in the catalog, every receipt signed under the old kid stops verifying — they become indistinguishable from forgeries.

The catalog is the rotation anchor. Anything else is just key generation.

## Step-by-step

### 1. Generate the new keypair

Use `generateKeypair(kid)` from `@dekimuhq/apr/issue`. Naming convention: `<issuer>-<year>`, e.g. `commander-2027`. The kid is opaque to the protocol; pick something stable and human-readable.

Store the private seed in a secrets vault (Vercel envs, HashiCorp Vault, 1Password Connect, HSM). **Never commit the seed.** Keep the previous kid's seed alive too until step 4.

### 2. Add the new kid to the verifier catalog

For verifiers backed by `CLAIMS_VERIFY_KEYS_JSON` (the reference pattern):

```jsonc
{
  "commander-2026": {                 // existing
    "issuer": "commander",
    "publicKey": "OLDPUB..."
  },
  "commander-2027": {                 // new — added alongside
    "issuer": "commander",
    "publicKey": "NEWPUB...",
    "notBefore": 1735689600           // optional: now-as-unix-seconds
  }
}
```

`notBefore` is recommended on the new kid: any receipt claiming to be signed under the new kid before this moment is rejected with `kid_not_yet_valid`. This bounds the window in which a stolen pre-publication key could be abused.

Wait for the catalog to propagate to every verifier instance. For verify.dekimu.com this is a Vercel env-var redeploy. For air-gapped or embedded verifiers, this is the time-to-distribute the new catalog.

### 3. Flip the issuer's active kid

Whatever your issuer code reads as "the current signing key," update it to point at the new keypair. From this point onward all new receipts carry the new kid.

There is no protocol-level handshake; this is a configuration flip in your issuer.

### 4. Optional: set `notAfter` on the old kid

If you want to mark the old kid as "still verifies past receipts but no new ones SHOULD appear under it":

```jsonc
"commander-2026": {
  "issuer": "commander",
  "publicKey": "OLDPUB...",
  "notAfter": 1738368000        // freeze date — past this, new receipts rejected
}
```

Receipts whose `iat` is BEFORE `notAfter` still verify (the `notAfter` check runs against the verifier's `now`, not the receipt's `iat`, per spec §5.3 — but in practice most verifiers will be running well after `notAfter` when retiring a kid; what matters is that you DON'T set `notAfter` to a value earlier than receipts you still want to honour).

Important nuance: per the v1 spec, `notAfter` is checked against the verifier's clock, not the claim's `iat`. If you want to retroactively invalidate every receipt signed under a leaked kid regardless of issuance date, removing the kid entirely (step 5) is the correct mechanism — `notAfter` is for graceful retirement of an uncompromised key.

### 5. Retire the old kid

When no live consumer needs to verify a receipt signed under the old kid (typically when receipt freshness windows have all elapsed, or when downstream systems have re-anchored against the new kid), remove the entry from the catalog entirely.

After this step, receipts signed under the old kid fail with `unknown_kid` and are treated as `tampered` per spec §8.

This is the destructive step. Do it on a schedule (months after the rotation, not days), and announce it.

## Compromised-key emergency rotation

If the old kid's private seed leaks, the playbook is different:

1. Generate the new keypair (step 1 above).
2. Add the new kid AND remove the old kid from the catalog in the **same** publish — do not run an overlap window.
3. Audit every receipt signed under the old kid against your internal records. Any receipt your system did not produce, but which verifies under the leaked seed, is a forgery and SHOULD be invalidated downstream via your application logic (APR has no protocol-level revocation in v1).
4. Publish a short disclosure noting the affected kid, the rotation date, and how downstream consumers should respond.

The `notBefore` / `notAfter` fields are NOT defences against a leaked seed. They are operational scheduling. The defence against a leak is unconditional removal from the catalog.

## Audit trail

Issuers SHOULD keep an internal record of:

- Which kid was active during which time range.
- Which receipts were signed under each kid (issuers already have this — every receipt carries `kid`).
- Why each rotation happened (scheduled / compromise / re-keying for an HSM swap / etc.).

This is forensic insurance; the protocol does not require it.
