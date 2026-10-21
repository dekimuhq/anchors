/**
 * e2e cross-issuer helper — mint a freshly-signed v=2 ACR consent envelope
 * plus its public key, with the anchor.log URL parameterised so `trustedLogs`
 * gate tests can exercise match / mismatch / absent-allowlist branches.
 *
 * Copied (not imported) from acr/acr-verifier/test/_helpers/v2-receipt.ts —
 * per plan §Risk acceptance, three near-identical helpers beat exporting a
 * private test fixture across workspace boundaries.
 *
 * ACR claim types are POLICY_BOUND, so the helper carries policy_uri / hash /
 * version — otherwise validatePolicyFields rejects before the absent-allowlist
 * test can reach signature_valid=true.
 */

import * as crypto from "node:crypto";
import { signEnvelope, base64UrlEncode } from "@dekimuhq/anchors-envelope";
import type { Envelope } from "@dekimuhq/anchors-envelope";

export interface MakeAcrOpts {
  anchorLog: string | undefined;
}

export async function makeValidV2AcrReceipt(
  opts: MakeAcrOpts,
): Promise<{ receipt: Envelope; pub: Uint8Array }> {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const pkDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const pkRaw = pkDer.subarray(-32);
  const iss_key = `ed25519:${base64UrlEncode(new Uint8Array(pkRaw))}` as const;

  const anchor =
    opts.anchorLog === undefined
      ? (null as unknown as Envelope["anchor"])
      : {
          log: opts.anchorLog,
          leaf_index: 0,
          inclusion_proof: [] as string[],
          tree_head_root: "sha256:" + "0".repeat(64),
          tree_size: 1,
          log_time: "2026-05-17T00:00:01Z",
        };

  const unsigned: Envelope = {
    v: 2,
    id: "01HXX0000000000000000ACRTRST",
    claim_type: "ar.consent.v1",
    iss: "did:web:example.com",
    iss_key,
    subject: "sha256:" + "a".repeat(64),
    iat: "2026-05-17T00:00:00Z",
    exp: null,
    prev: null,
    policy_uri: "https://example.com/policy",
    policy_hash: "sha256:" + "a".repeat(64),
    policy_version: "1.0",
    tsa: null,
    credentialStatus: null,
    anchor,
    sig: "",
    countersig: null,
    body: { lawful_basis: "6(1)(a)" },
  };

  const signed = await signEnvelope(unsigned, privateKey);
  return { receipt: signed, pub: new Uint8Array(pkDer) };
}

export function makeResolveKey(
  pub: Uint8Array,
): (envelope: unknown) => Promise<Uint8Array> {
  return async () => pub;
}
