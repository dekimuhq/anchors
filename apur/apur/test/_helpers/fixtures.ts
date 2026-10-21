/**
 * Shared signing-key / anchor helpers for apur-issuer-kit tests.
 */

import * as crypto from "node:crypto";
import { base64UrlDecode } from "@dekimuhq/anchors-envelope";
import type { AnchorProof } from "@dekimuhq/anchors-envelope";
import { generateApurKeypair } from "../../src/issue/keys.ts";
import type { SigningKey } from "../../src/issue/mint-v2.ts";

const ED25519_SPKI_PREFIX = Buffer.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

export const H = (b: string): string => `sha256:${b.repeat(64)}`;

export function makeSigningKey(): SigningKey {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const seed = (
    privateKey.export({ format: "der", type: "pkcs8" }) as Buffer
  ).subarray(-32);
  return {
    kid: "k-" + Math.random().toString(36).slice(2),
    privateKey: new Uint8Array(seed),
  };
}

export function makeAnchor(): AnchorProof {
  return {
    log: "https://verify.dekimu.com/apur/v1",
    leaf_index: 0,
    inclusion_proof: [],
    tree_head_root: "sha256:" + "aa".repeat(32),
    tree_size: 1,
    log_time: new Date().toISOString(),
  };
}

export function makeKeypair() {
  return generateApurKeypair("test-key-1");
}

export function makeResolveKey() {
  return async (envelope: unknown): Promise<Uint8Array> => {
    const issKey = (envelope as { iss_key: string }).iss_key;
    const raw = base64UrlDecode(issKey.replace("ed25519:", ""));
    return new Uint8Array(Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]));
  };
}

export const anchor = makeAnchor();

export const baseCommon = {
  issuer: "did:web:controller.example",
  profile: "purpose.gdpr.art5" as const,
  policy_uri: "https://controller.example/purpose/v1",
  policy_hash: H("e"),
  policy_version: "1.0.0",
  anchor,
};

export const bindingFields = {
  activity_id_commit: H("a"),
  purpose_commit: H("p"),
  purpose_class: "marketing",
  lawful_basis: "consent",
  data_categories: ["email", "name"],
  data_subjects_class: "customers",
  policy_hash_body: H("ph"),
  minimisation_hash: H("m"),
  bound_at: "2026-05-21T00:00:00Z",
};

export const repurposeFields = {
  new_purpose_commit: H("np"),
  new_purpose_class: "analytics",
  compat_link_hash: H("cl"),
  compat_context_hash: H("cc"),
  compat_subjects_reasonable_hash: H("cs"),
  compat_consequences_hash: H("cq"),
  compat_safeguards_hash: H("cg"),
  compat_conclusion: "compatible" as const,
  minimisation_hash: H("m2"),
  tested_at: "2026-05-21T01:00:00Z",
};

export const unbindingFields = {
  reason: "purpose_fulfilled" as const,
  unbound_at: "2026-05-21T02:00:00Z",
};
