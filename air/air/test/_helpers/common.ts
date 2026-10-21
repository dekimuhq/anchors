/**
 * Shared signing-key / anchor / resolveKey helpers for air-issuer-kit tests.
 * Per-family local helper (mirrors alr/anr/abr-issuer-kit pattern).
 */

import * as crypto from "node:crypto";
import { base64UrlDecode } from "@dekimuhq/anchors-envelope";
import type { AnchorProof } from "@dekimuhq/anchors-envelope";
import type { SigningKey } from "../../src/issue/mint-v2.ts";

const ED25519_SPKI_PREFIX = Buffer.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

/**
 * Deterministic test hash. Accepts any seed string and hashes it to a stable
 * lowercase 64-hex digest so tests can use mnemonic seeds (`H("g")`, `H("h")`)
 * without worrying about non-hex characters.
 */
export const H = (b: string): string =>
  `sha256:${crypto.createHash("sha256").update(b).digest("hex")}`;

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

export const anchor: AnchorProof = {
  log: "https://verify.dekimu.com/air/v1",
  leaf_index: 0,
  inclusion_proof: [],
  tree_head_root: "sha256:" + "0".repeat(64),
  tree_size: 1,
  log_time: "2026-05-19T00:00:00Z",
};

export const baseCommon = {
  issuer: "did:web:controller.example",
  profile: "impact.voluntary" as const,
  air_receipt_id: "AIR-2026-0001",
  processing_activity_id: "PA-customer-analytics-v1",
  policy_uri: "https://controller.example/dpia-methodology/v1",
  policy_hash: "sha256:" + "e".repeat(64),
  policy_version: "1.0.0",
  anchor,
};

export function makeResolveKey() {
  return async (envelope: unknown): Promise<Uint8Array> => {
    const issKey = (envelope as { iss_key: string }).iss_key;
    const raw = base64UrlDecode(issKey.replace("ed25519:", ""));
    return new Uint8Array(Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]));
  };
}
