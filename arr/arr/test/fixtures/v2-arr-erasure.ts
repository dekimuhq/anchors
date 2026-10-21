/**
 * Deterministic v=2 ARR erasure envelope fixture for dispatch tests.
 *
 * Exports: { envelope, publicKey, privateKey }
 *   envelope  — signed Envelope with claim_type "ar.erasure.v1"
 *   publicKey — Uint8Array of the SPKI DER-encoded public key (for verifyEnvelopeSignature)
 *   privateKey — KeyObject (for test mutation helpers)
 */

import * as crypto from "node:crypto";
import { signEnvelope, base64UrlEncode } from "@dekimuhq/anchors-envelope";
import type { Envelope } from "@dekimuhq/anchors-envelope";

const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");

const pkDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
// Last 32 bytes of the SPKI DER are the raw public key.
const pkRaw = pkDer.subarray(-32);
const issKey = `ed25519:${base64UrlEncode(new Uint8Array(pkRaw))}` as const;

const unsigned: Envelope = {
  v: 2,
  id: "01HXX0000000000000000ARRTEST",
  claim_type: "ar.erasure.v1",
  iss: "did:web:processor.example",
  iss_key: issKey,
  subject: "sha256:" + "a".repeat(64),
  iat: "2026-05-17T00:00:00Z",
  exp: null,
  prev: null,
  policy_uri: "https://processor.example/policy",
  policy_hash: "sha256:" + "b".repeat(64),
  policy_version: "1.0.0",
  tsa: null,
  credentialStatus: null,
  anchor: null as unknown as Envelope["anchor"], // anchor is null before log submission
  sig: "",
  countersig: null,
  body: { target_kind: "subject", trigger: "subject_request" },
};

// Top-level await is fine — file loads as ESM in Node 22+.
const signed = await signEnvelope(unsigned, privateKey);

export default {
  envelope: signed,
  publicKey: new Uint8Array(pkDer),
  privateKey,
};
