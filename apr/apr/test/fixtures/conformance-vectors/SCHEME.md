# Vector reference Merkle scheme

Vectors document a single reference Merkle scheme so any conforming verifier
can rebuild a daily root from a published id set. **This scheme is the format
used by these test vectors only.** The spec (§7.3 of `v1.md`) leaves the
on-the-wire inclusion-proof format verifier-defined. Implementers running
these vectors MUST implement this scheme to consume the vector files; they
are free to ship additional inclusion-proof formats for production use.

## Scheme

- **Leaf ordering.** Sort all claim ids for the day ascending, by UTF-8 byte
  order (equivalent to JavaScript string `<` on ASCII).
- **Leaf hashing.** `leaf_i = sha256(claimId_i UTF-8 bytes)`.
- **Internal nodes.** `parent = sha256(left || right)` where `||` is raw
  32-byte concatenation.
- **Odd levels.** If a level has an odd number of nodes, duplicate the
  trailing node before pairing. Apply the same rule at every level until one
  node remains.
- **Root encoding.** `rootHash = lowercase hex of the final 32 bytes`.
- **Empty days.** A day with zero claims has `rootHash = "0".repeat(64)`
  and `count = 0`.

## Inputs in each vector directory

- `claim.json` — the APR under test.
- `anchor.json` — the daily root envelope (`{v, date, rootHash, count, kid, sig}`).
- `anchor-ids.json` — the deterministic id list the day's root was built from.
  The verifier MUST rebuild the Merkle root from this list using the scheme
  above and compare it byte-for-byte against `anchor.rootHash`.
- `verify-keys.json` — claim-key catalog (`{kid → {issuer, publicKey base64url 32 bytes}}`).
- `root-keys.json` — root-key catalog (`{kid → {publicKey base64url 32 bytes}}`).
- `expected.json` — `{status, reasons[]}` the verifier MUST produce.
- `notes.md` — prose explaining what the vector exercises.

## Reproducing

```bash
cd apr-verifier  # clone from https://github.com/dekimuhq/anchors/tree/main/apr/apr
node --experimental-strip-types scripts/regen-vectors.ts
```

The script uses fixed Ed25519 seeds (`0xaa…`, `0xbb…`, `0xcc…`, `0xdd…`,
each repeated 32 bytes) and fixed iat timestamps + fixed ULIDs. Output is
byte-identical across runs and across platforms.
