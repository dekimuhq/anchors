/**
 * Shared test fixtures: mint a real signed ASR receipt through the published
 * family manifest so the CLI verifies a genuine envelope end-to-end (not a
 * hand-built mock). The embedded `iss_key` is what the offline resolver decodes.
 */

import { generateKeypair } from "@dekimuhq/anchors-envelope";
import type { AnchorProof, FamilyMintV2Input } from "@dekimuhq/anchors-envelope";
import { asr } from "@dekimuhq/anchors";

export const KP = generateKeypair("anchors-cli-test-key");

const sha256 = (c: string): string => `sha256:${c.repeat(64)}`;

export const SUBJECT = sha256("a");

const ANCHOR: AnchorProof = {
  log: "https://verify.dekimu.com/asr/v1",
  leaf_index: 0,
  inclusion_proof: [sha256("b")],
  tree_head_root: sha256("c"),
  tree_size: 1,
  log_time: "2026-05-19T00:00:00Z",
};

/** Mint a valid `ar.subject_rights.v1` (request.received) receipt. */
export async function mintAsrReceipt(): Promise<Record<string, unknown>> {
  const body = {
    event_type: "request.received",
    subject_rights_request_id: "f4b2d4c0-6e1c-4b9f-9b6d-1a2b3c4d5e6f",
    qts_attestation_hash: null,
    channel: "email",
    received_at: "2026-05-19T08:00:00Z",
    deadline_at: "2026-06-18T08:00:00Z",
  };
  const input: FamilyMintV2Input = {
    body,
    issuerPrivateKey: KP.privateKey,
    issuerDid: "did:web:test.example.com",
    subject: SUBJECT,
    anchor: ANCHOR,
    policy_uri: "https://example.test/policy.json",
    policy_hash: sha256("9"),
    policy_version: "2026-05-19",
    kind: "observation",
    cause: "manual",
  };
  const env = await asr.asrFamily.mintV2(input);
  return env as unknown as Record<string, unknown>;
}

/** Build an injected `readFile` over an in-memory file map for runCli tests. */
export function fakeReadFile(
  files: Readonly<Record<string, string>>,
): (path: string) => Promise<string> {
  return async (path: string) => {
    const content = files[path];
    if (content === undefined) {
      throw new Error(`ENOENT: no such file '${path}'`);
    }
    return content;
  };
}
