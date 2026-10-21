/**
 * Shared signing-key / anchor helpers for @dekimuhq/action tests.
 */

import * as crypto from "node:crypto";
import { base64UrlDecode } from "@dekimuhq/anchors-envelope";
import type { AnchorProof } from "@dekimuhq/anchors-envelope";
import { generateActionKeypair } from "../../src/issue/keys.ts";
import type { SigningKey, MintActionV2Input } from "../../src/issue/mint-v2.ts";

const ED25519_SPKI_PREFIX = Buffer.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

/** sha256:<64-hex> commit built from a single hex char. */
export const H = (c: string): string => `sha256:${c.repeat(64)}`;

export function makeSigningKey(): SigningKey {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const seed = (
    privateKey.export({ format: "der", type: "pkcs8" }) as Buffer
  ).subarray(-32);
  return {
    kid: "k-" + crypto.randomBytes(6).toString("hex"),
    privateKey: new Uint8Array(seed),
  };
}

export function makeAnchor(): AnchorProof {
  return {
    log: "https://verify.dekimu.com/action/v1",
    leaf_index: 0,
    inclusion_proof: [],
    tree_head_root: "sha256:" + "aa".repeat(32),
    tree_size: 1,
    log_time: "2026-06-08T00:00:00.000Z",
  };
}

export function makeKeypair() {
  return generateActionKeypair("test-key-1");
}

export function makeResolveKey() {
  return async (envelope: unknown): Promise<Uint8Array> => {
    const issKey = (envelope as { iss_key: string }).iss_key;
    const raw = base64UrlDecode(issKey.replace("ed25519:", ""));
    return new Uint8Array(Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]));
  };
}

export const anchor = makeAnchor();

/** Full, valid mintActionV2 input (executed outcome). */
export function baseInput(): MintActionV2Input {
  return {
    issuer: "did:web:app.dekimu.com",
    signingKey: makeSigningKey(),
    anchor: makeAnchor(),
    profile: "hub.automation",
    verb: "invoiceup.remind",
    rule_id: "r1",
    recipe_id: "auto-remind-overdue",
    outcome: "executed",
    executed_at: "2026-06-08T10:00:00.000Z",
    decision_commit: H("a"),
    params_commit: H("b"),
    request_id_commit: H("c"),
    policy_uri: "https://app.dekimu.com/automations",
    policy_hash: H("e"),
    policy_version: "plan-2.v1",
  };
}

/** A structurally-valid AActR body (for verify-single / profile tests). */
export function validBody() {
  return {
    profile: "hub.automation",
    verb: "invoiceup.remind",
    rule_id: "r1",
    recipe_id: "auto-remind-overdue",
    outcome: "executed",
    executed_at: "2026-06-08T10:00:00.000Z",
    decision_commit: H("a"),
    params_commit: H("b"),
    request_id_commit: H("c"),
  };
}
