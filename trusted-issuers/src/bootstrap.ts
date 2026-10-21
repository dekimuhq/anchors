/**
 * BOOTSTRAP_PUBLISHER_KEY — pinned SPKI fingerprint for the Dekimu
 * publisher key that signs `ar.trusted_issuers.v1` lists.
 *
 * Minted in the Phase B6 key ceremony on 2026-07-17 (genesis v01 admits
 * did:web:dekimu.com:autonomy, families: action). The private seed is
 * no-escrow — it exists only as SIGNING_KEY_BASE64 on
 * dekimuhq/anchors-trusted-issuers-chain. Loss = re-mint + key rotation.
 *
 * Rotation policy: 1 year cadence, 90-day overlap (publish both keys
 * simultaneously during overlap). Each rotation = MAJOR version bump on this
 * package (verifiers on older versions cannot trust a list signed by the new
 * key). See master plan §2.5 + Q5.
 */
export const BOOTSTRAP_PUBLISHER_KEY = {
  publisher_key: "ed25519:1xTV4r0WgqzcrRy-A-JPJBdQPleWUReSxfRO9x9Yifk",
  spki_der: new Uint8Array([
    48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0, 215, 20, 213, 226, 189, 22,
    130, 172, 220, 173, 28, 190, 3, 226, 79, 36, 23, 80, 62, 87, 150, 81, 23,
    146, 197, 244, 78, 247, 31, 88, 137, 249,
  ]),
} as const;
