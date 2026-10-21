/**
 * Shared signing-key / anchor helpers for @dekimuhq/quality tests.
 */

import * as crypto from "node:crypto";
import { base64UrlDecode } from "@dekimuhq/anchors-envelope";
import type { AnchorProof } from "@dekimuhq/anchors-envelope";
import { generateQualityKeypair } from "../../src/issue/keys.ts";
import type { SigningKey, MintQualityV1Input } from "../../src/issue/mint-v1.ts";

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
    log: "https://verify.dekimu.com/quality/v1",
    leaf_index: 0,
    inclusion_proof: [],
    tree_head_root: "sha256:" + "aa".repeat(32),
    tree_size: 1,
    log_time: "2026-06-08T00:00:00.000Z",
  };
}

export function makeKeypair() {
  return generateQualityKeypair("test-key-1");
}

export function makeResolveKey() {
  return async (envelope: unknown): Promise<Uint8Array> => {
    const issKey = (envelope as { iss_key: string }).iss_key;
    const raw = base64UrlDecode(issKey.replace("ed25519:", ""));
    return new Uint8Array(Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]));
  };
}

export const anchor = makeAnchor();

/** Full, valid mintQualityV1 input — quality.output profile. */
export function baseOutputInput(): MintQualityV1Input {
  return {
    issuer: "did:web:app.dekimu.com",
    signingKey: makeSigningKey(),
    anchor: makeAnchor(),
    profile: "quality.output",
    suite_id: "suite.summarize.v3",
    suite_hash: H("a"),
    scorer: { kind: "deterministic" },
    result: {
      score: 0.92,
      verdict: "pass",
      threshold: 0.8,
      cases_total: 50,
      cases_passed: 47,
    },
    ran_at: "2026-06-08T10:00:00.000Z",
    output_commit: H("b"),
    request_id_commit: H("c"),
    policy_uri: "https://app.dekimu.com/quality",
    policy_hash: H("e"),
    policy_version: "quality.v1",
  };
}

/** Full, valid mintQualityV1 input — quality.release profile. */
export function baseReleaseInput(): MintQualityV1Input {
  return {
    issuer: "did:web:app.dekimu.com",
    signingKey: makeSigningKey(),
    anchor: makeAnchor(),
    profile: "quality.release",
    suite_id: "suite.regression.v2",
    suite_hash: H("a"),
    scorer: { kind: "llm-judge", model: "claude-opus-4-8" },
    result: {
      score: 0.88,
      verdict: "pass",
      threshold: 0.85,
      cases_total: 120,
      cases_passed: 110,
    },
    ran_at: "2026-06-08T11:00:00.000Z",
    subject_ref: "release:app.dekimu.com@2026-06-08",
    gate: "blocking",
    policy_uri: "https://app.dekimu.com/quality",
    policy_hash: H("e"),
    policy_version: "quality.v1",
  };
}
