import * as crypto from "node:crypto";
import { base64UrlDecode } from "@dekimuhq/anchors-envelope";
import type { AnchorProof } from "@dekimuhq/anchors-envelope";
import type { MintScreeningInput } from "../src/issue/mint-v1.ts";

const SPKI = Buffer.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);
export function makeSigningKey() {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const seed = (privateKey.export({ format: "der", type: "pkcs8" }) as Buffer).subarray(-32);
  return { kid: "k-" + crypto.randomBytes(6).toString("hex"), privateKey: new Uint8Array(seed) };
}
export const makeAnchor = (): AnchorProof => ({
  log: "https://verify.dekimu.com/screening/v1", leaf_index: 0, inclusion_proof: [],
  tree_head_root: "sha256:" + "aa".repeat(32), tree_size: 1, log_time: "2026-11-19T10:00:00.000Z",
});
export const resolveKey = async (envelope: unknown): Promise<Uint8Array> => {
  const raw = base64UrlDecode((envelope as { iss_key: string }).iss_key.replace("ed25519:", ""));
  return new Uint8Array(Buffer.concat([SPKI, Buffer.from(raw)]));
};
const H = "sha256:" + "b".repeat(64);
const iso = (offMs: number) => new Date(Date.now() + offMs).toISOString();
export const baseInput = (): MintScreeningInput => ({
  issuer: "did:web:invoiceup.app",
  signingKey: makeSigningKey(),
  anchor: makeAnchor(),
  screen_id: "01J9Z3K4M5N6P7Q8R9S0T1V2W3",
  subject_commit: "sha256:" + "c".repeat(64),
  list: { id: "eu-fsf", file_name: "20261119-FULL-1_1.xml", file_date: iso(-3 * 3600_000), file_sha256: H, parsed_sha256: H, entry_count: 5123, fetched_at: iso(-2 * 3600_000) },
  matcher: { name: "@dekimuhq/sanctions", version: "0.2.0", threshold: 0.85 },
  result: "none_at_threshold",
  candidates: [],
  trigger: "manual",
  screened_at: iso(-60_000),
});
