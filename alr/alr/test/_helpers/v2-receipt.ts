/**
 * Local helper — mint a deterministic v=2 ALR envelope plus its public key.
 *
 * Parameterised over `event_type` so per-event tests (e.g. tsa-mandate
 * matrix coverage) can mint each variant without copy-pasting the fixture.
 *
 * Deliberately NOT shared with APR/ACR/ARR (per the same risk-tradeoff
 * recorded in the ARR helper: three near-identical helpers beat a
 * premature abstraction).
 */

import * as crypto from "node:crypto";
import { signEnvelope, base64UrlEncode } from "@dekimuhq/anchors-envelope";
import type { Envelope } from "@dekimuhq/anchors-envelope";
import type { AlrBody, AlrEventType } from "../../src/types.ts";

const H = (b: string) => `sha256:${b.repeat(64)}`;
const A = H("a");
const B = H("b");
const C = H("c");

function pref(artifact_hash: string) {
  return {
    artifact_hash,
    parent_apr_id: null,
    parent_alr_id: null,
    uri: null,
  };
}

function bodyFor(event_type: AlrEventType): AlrBody {
  const base = {
    profile: "aiact.art13.transparency" as const,
    artifact_hash: C,
    event_at: "2026-05-16T14:23:00Z",
    qts_attestation_hash: null,
  };
  switch (event_type) {
    case "derived_from":
      return {
        ...base,
        event_type,
        parents: [pref(A), pref(B)],
        successor: null,
        transform_claim: { summary: "fine-tune", uri: null },
        disclosure: null,
      };
    case "forked_from":
      return {
        ...base,
        event_type,
        parents: [pref(A)],
        successor: null,
        transform_claim: { summary: "fork", uri: null },
        disclosure: null,
      };
    case "superseded_by":
      return {
        ...base,
        event_type,
        parents: [],
        successor: pref(B),
        transform_claim: { summary: "supersede", uri: null },
        disclosure: null,
      };
    case "disclosed":
      return {
        ...base,
        event_type,
        parents: [],
        successor: null,
        transform_claim: null,
        disclosure: {
          recipient: "did:web:auditor.example",
          recipient_role: "auditor",
          scope_hash: H("d"),
          basis: "gdpr.art6.1.c",
        },
      };
  }
}

export interface MintedAlr {
  envelope: Envelope;
  publicKey: Uint8Array;
}

export async function mintValidAlr(
  event_type: AlrEventType = "derived_from",
): Promise<MintedAlr> {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const pkDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const pkRaw = pkDer.subarray(-32);
  const iss_key = `ed25519:${base64UrlEncode(new Uint8Array(pkRaw))}` as const;

  const unsigned: Envelope = {
    v: 2,
    id: "01HXX0000000000000000ALRTEST",
    claim_type: "ar.lineage.v1",
    iss: "did:web:processor.example",
    iss_key,
    subject: null as unknown as string,
    iat: "2026-05-17T00:00:00Z",
    exp: null,
    prev: null,
    policy_uri: "https://processor.example/lineage-policy",
    policy_hash: "sha256:" + "e".repeat(64),
    policy_version: "1.0.0",
    tsa: null,
    credentialStatus: null,
    anchor: null as unknown as Envelope["anchor"],
    sig: "",
    countersig: null,
    body: bodyFor(event_type),
  };

  const signed = await signEnvelope(unsigned, privateKey);
  return { envelope: signed, publicKey: new Uint8Array(pkDer) };
}

export function makeResolveKey(
  pub: Uint8Array,
): (envelope: unknown) => Promise<Uint8Array> {
  return async () => pub;
}
