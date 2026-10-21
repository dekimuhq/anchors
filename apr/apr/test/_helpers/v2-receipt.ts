/**
 * Local test helper — mint a freshly-signed v=2 APR envelope plus its public
 * key, with the anchor.log URL parameterised so `trustedLogs` gate tests can
 * exercise match / mismatch / no-anchor branches.
 *
 * Deliberately NOT shared across APR/ACR/ARR — each verifier carries its own
 * ~60-line variant. Three nearly-identical files beat a premature abstraction
 * (per plan §Risk).
 */

import * as crypto from "node:crypto";
import { signEnvelope, base64UrlEncode } from "@dekimuhq/anchors-envelope";
import type { Envelope } from "@dekimuhq/anchors-envelope";

export interface MakeOpts {
  anchorLog: string | undefined;
}

export async function makeValidV2Receipt(
  opts: MakeOpts,
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
    id: "01HXX0000000000000000APRTRST",
    claim_type: "ar.provenance.v1",
    iss: "did:web:example.com",
    iss_key,
    subject: "sha256:" + "a".repeat(64),
    iat: "2026-05-17T00:00:00Z",
    exp: null,
    prev: null,
    // APR forbids envelope-level policy_* fields.
    policy_uri: null,
    policy_hash: null,
    policy_version: null,
    tsa: null,
    credentialStatus: null,
    anchor,
    sig: "",
    countersig: null,
    body: { artifact_type: "commander.run.output", agent_kind: "ai" },
  };

  const signed = await signEnvelope(unsigned, privateKey);
  return { receipt: signed, pub: new Uint8Array(pkDer) };
}

export function makeResolveKey(
  pub: Uint8Array,
): (envelope: unknown) => Promise<Uint8Array> {
  return async () => pub;
}
