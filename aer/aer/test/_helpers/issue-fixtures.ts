/**
 * Shared signing-key / anchor / resolveKey helpers for aer-issuer-kit tests.
 */

import * as crypto from "node:crypto";
import { base64UrlDecode } from "@dekimuhq/anchors-envelope";
import type { AnchorProof } from "@dekimuhq/anchors-envelope";
import type { SigningKey } from "../../src/issue/mint-v2.ts";
import type { AerAnnexIiiCategory } from "../../src/index.ts";

const ED25519_SPKI_PREFIX = Buffer.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

/** Produces a fake sha256 hex hash by repeating a single hex char 64 times. */
export const H = (b: string): string => `sha256:${b.repeat(64)}`;
/** Produces a valid sha256 hex hash (all zeros). */
export const H0 = (): string => `sha256:${"0".repeat(64)}`;
/** Produces a valid sha256 hex hash (all f's). */
export const HF = (): string => `sha256:${"f".repeat(64)}`;

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
  log: "https://verify.dekimu.com/aer/v1",
  leaf_index: 0,
  inclusion_proof: [],
  tree_head_root: "sha256:" + "0".repeat(64),
  tree_size: 1,
  log_time: "2026-05-21T00:00:00Z",
};

export const baseConformityInput = {
  issuer: "did:web:provider.example",
  profile: "aiact.art43.internal" as const,
  system_id_commit: `sha256:${"0".repeat(64)}`,
  system_version: "1.0.0",
  model_id_commit: `sha256:${"1".repeat(64)}`,
  risk_class: "high" as const,
  annex_iii_categories: ["biometrics"] as AerAnnexIiiCategory[],
  assessment_route: "internal_control" as const,
  notified_body_id: null,
  harmonized_standards: ["EN ISO/IEC 27001:2023"],
  tech_doc_hash: `sha256:${"2".repeat(64)}`,
  risk_management_system_hash: `sha256:${"3".repeat(64)}`,
  data_governance_hash: `sha256:${"4".repeat(64)}`,
  valid_from: "2026-01-01T00:00:00Z",
  anchor,
};

export const baseTransparencyInput = {
  issuer: "did:web:deployer.example",
  profile: "aiact.art50.chatbot" as const,
  subject: `sha256:${"a".repeat(64)}`,
  system_id_commit: `sha256:${"0".repeat(64)}`,
  conformity_receipt_hash: `sha256:${"c".repeat(64)}`,
  subject_commit: `sha256:${"b".repeat(64)}`,
  disclosure_scope: "single" as const,
  disclosure_type: "chatbot" as const,
  disclosure_text_hash: `sha256:${"d".repeat(64)}`,
  disclosure_locale: "en",
  interaction_window_start: "2026-05-21T10:00:00Z",
  interaction_window_end: "2026-05-21T10:30:00Z",
  watermark_scheme: "none" as const,
  anchor,
};

export function makeResolveKey() {
  return async (envelope: unknown): Promise<Uint8Array> => {
    const issKey = (envelope as { iss_key: string }).iss_key;
    const raw = base64UrlDecode(issKey.replace("ed25519:", ""));
    return new Uint8Array(Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]));
  };
}
