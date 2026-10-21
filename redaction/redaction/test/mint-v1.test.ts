import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mintRedactionV1 } from "../src/issue/mint-v1.ts";
import { verifyReceipt, buildRedactionBody } from "../src/index.ts";
import { commit, randomSalt, base64UrlDecode, verifyCommitment } from "@dekimuhq/anchors-envelope";
import type { AnchorProof, Envelope } from "@dekimuhq/anchors-envelope";

const ED25519_SPKI_PREFIX = Buffer.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

function makeResolveKey() {
  return async (envelope: unknown): Promise<Uint8Array> => {
    const issKey = (envelope as Envelope).iss_key;
    const raw = base64UrlDecode(issKey.replace("ed25519:", ""));
    return new Uint8Array(Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]));
  };
}

const signingKey = { kid: "test-1", privateKey: new Uint8Array(randomBytes(32)) };
const anchor: AnchorProof = {
  log: "https://verify.dekimu.com/redaction/v1",
  leaf_index: 0,
  inclusion_proof: [],
  tree_head_root: "sha256:" + "aa".repeat(32),
  tree_size: 1,
  log_time: "2026-06-20T00:00:00.000Z",
};
const salt = randomSalt();
const SECRET_EMAIL = "alice@acme.com";
const SECRET_IBAN = "DE89370400440532013000";
const raw = `contact ${SECRET_EMAIL} IBAN ${SECRET_IBAN} please`;
const redacted = "contact [EMAIL_1] IBAN [IBAN_1] please";

async function mint() {
  return mintRedactionV1({
    issuer: "did:web:test", signingKey, anchor,
    counts: { EMAIL: 1, IBAN: 1 },
    ruleset_hash: "sha256:" + "a".repeat(64),
    input_commit: commit(salt, raw),
    output_commit: commit(salt, redacted),
    redactor: "@dekimuhq/ai@test",
  });
}

// ── existing baseline ────────────────────────────────────────────────────────

test("mint → verifyReceipt round-trips", async () => {
  const env = await mint();
  assert.equal(env.claim_type, "ar.redaction.v1");
  assert.equal(env.subject, null);
  const res = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal((res as { signature_valid?: boolean }).signature_valid, true);
});

test("the reversible PII value never appears in the minted envelope", async () => {
  const env = await mint();
  assert.ok(!JSON.stringify(env).includes(SECRET_EMAIL), "PII leaked into receipt");
});

test("tampered body fails verification", async () => {
  const env = await mint();
  (env.body as { counts: Record<string, number> }).counts.EMAIL = 99;
  // Pass a real resolveKey so this specifically tests field_root/signature
  // coverage of the body — not merely the absence of a key resolver.
  const res = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.notEqual((res as { signature_valid?: boolean }).signature_valid, true);
});

test("commit-reveal: output_commit re-derives from (salt, redacted)", () => {
  assert.equal(commit(salt, redacted), commit(salt, redacted));
});

// ── guard throws ─────────────────────────────────────────────────────────────

test("throws when issuer is missing", async () => {
  await assert.rejects(
    () => mintRedactionV1({
      issuer: "", signingKey, anchor,
      counts: { EMAIL: 1 },
      ruleset_hash: "sha256:" + "a".repeat(64),
      input_commit: commit(salt, raw),
      output_commit: commit(salt, redacted),
      redactor: "@dekimuhq/ai@test",
    }),
    /issuer required/,
  );
});

test("throws when signingKey.kid is missing", async () => {
  await assert.rejects(
    () => mintRedactionV1({
      issuer: "did:web:test",
      signingKey: { kid: "", privateKey: new Uint8Array(randomBytes(32)) },
      anchor,
      counts: { EMAIL: 1 },
      ruleset_hash: "sha256:" + "a".repeat(64),
      input_commit: commit(salt, raw),
      output_commit: commit(salt, redacted),
      redactor: "@dekimuhq/ai@test",
    }),
    /signingKey.kid required/,
  );
});

test("throws when privateKey length is not 32", async () => {
  await assert.rejects(
    () => mintRedactionV1({
      issuer: "did:web:test",
      signingKey: { kid: "k1", privateKey: new Uint8Array(16) },
      anchor,
      counts: { EMAIL: 1 },
      ruleset_hash: "sha256:" + "a".repeat(64),
      input_commit: commit(salt, raw),
      output_commit: commit(salt, redacted),
      redactor: "@dekimuhq/ai@test",
    }),
    /privateKey must be 32 bytes/,
  );
});

test("throws when anchor is missing", async () => {
  await assert.rejects(
    () => mintRedactionV1({
      issuer: "did:web:test", signingKey,
      anchor: null as unknown as AnchorProof,
      counts: { EMAIL: 1 },
      ruleset_hash: "sha256:" + "a".repeat(64),
      input_commit: commit(salt, raw),
      output_commit: commit(salt, redacted),
      redactor: "@dekimuhq/ai@test",
    }),
    /anchor required/,
  );
});

test("throws when tsa is set without tsaFetcher", async () => {
  await assert.rejects(
    () => mintRedactionV1({
      issuer: "did:web:test", signingKey, anchor,
      counts: { EMAIL: 1 },
      ruleset_hash: "sha256:" + "a".repeat(64),
      input_commit: commit(salt, raw),
      output_commit: commit(salt, redacted),
      redactor: "@dekimuhq/ai@test",
      tsa: { url: "https://freetsa.org/tsr", trustAnchorIds: ["test-tsa"], hashAlg: "sha-256" as const, driftToleranceSec: 300, timeoutMs: 5000 },
      // tsaFetcher intentionally omitted
    }),
    /tsaFetcher required/,
  );
});

// ── verify-before-sign ───────────────────────────────────────────────────────

test("verify-before-sign: bad input_commit throws before signing", async () => {
  await assert.rejects(
    () => mintRedactionV1({
      issuer: "did:web:test", signingKey, anchor,
      counts: { EMAIL: 1 },
      ruleset_hash: "sha256:" + "a".repeat(64),
      input_commit: "not-a-valid-commit",
      output_commit: commit(salt, redacted),
      redactor: "@dekimuhq/ai@test",
    }),
    /invalid body/,
  );
});

// ── minted envelope shape ────────────────────────────────────────────────────

test("claim_type is ar.redaction.v1", async () => {
  const env = await mint();
  assert.equal(env.claim_type, "ar.redaction.v1");
});

test("subject is null", async () => {
  const env = await mint();
  assert.equal(env.subject, null);
});

test("body has field_root", async () => {
  const env = await mint();
  assert.ok(typeof (env.body as { field_root?: unknown }).field_root === "string");
  assert.ok((env.body as { field_root: string }).field_root.length > 0);
});

// ── PII absence (both email and IBAN) ────────────────────────────────────────

test("IBAN never appears in JSON-serialised envelope", async () => {
  const env = await mint();
  assert.ok(!JSON.stringify(env).includes(SECRET_IBAN), "IBAN leaked into receipt");
});

// ── salt absence ─────────────────────────────────────────────────────────────

test("salt (base64url) used for commits never appears in envelope JSON", async () => {
  const env = await mint();
  assert.ok(!JSON.stringify(env).includes(salt), "salt leaked into receipt");
});

// ── commit-reveal (verifyCommitment) ─────────────────────────────────────────

test("verifyCommitment: output_commit verifies against (salt, redactedText)", async () => {
  const env = await mint();
  const outputCommit = (env.body as { output_commit: string }).output_commit;
  assert.ok(verifyCommitment(outputCommit, salt, redacted));
});

test("verifyCommitment: output_commit does NOT verify against different text", async () => {
  const env = await mint();
  const outputCommit = (env.body as { output_commit: string }).output_commit;
  assert.ok(!verifyCommitment(outputCommit, salt, "contact [EMAIL_1] IBAN [IBAN_2] please"));
});

test("verifyCommitment: input_commit verifies against (salt, raw input)", async () => {
  const env = await mint();
  const inputCommit = (env.body as { input_commit: string }).input_commit;
  assert.ok(verifyCommitment(inputCommit, salt, raw));
});

// ── buildRedactionBody ────────────────────────────────────────────────────────

test("buildRedactionBody: always sets profile='redaction.prompt'", () => {
  const body = buildRedactionBody({
    counts: { EMAIL: 1 },
    ruleset_hash: "sha256:" + "c".repeat(64),
    input_commit: "sha256:" + "c".repeat(64),
    output_commit: "sha256:" + "c".repeat(64),
    redactor: "test-redactor",
  });
  assert.equal(body.profile, "redaction.prompt");
});

test("buildRedactionBody: always sets commit_alg='sha256'", () => {
  const body = buildRedactionBody({
    counts: { IBAN: 2 },
    ruleset_hash: "sha256:" + "c".repeat(64),
    input_commit: "sha256:" + "c".repeat(64),
    output_commit: "sha256:" + "c".repeat(64),
    redactor: "test-redactor",
  });
  assert.equal(body.commit_alg, "sha256");
});

test("buildRedactionBody: output has exactly 7 keys", () => {
  const body = buildRedactionBody({
    counts: { PHONE: 3 },
    ruleset_hash: "sha256:" + "c".repeat(64),
    input_commit: "sha256:" + "c".repeat(64),
    output_commit: "sha256:" + "c".repeat(64),
    redactor: "test-redactor",
  });
  const keys = Object.keys(body).sort();
  assert.deepEqual(keys, [
    "commit_alg", "counts", "input_commit", "output_commit",
    "profile", "redactor", "ruleset_hash",
  ]);
});

test("buildRedactionBody: passes counts/ruleset_hash/commits/redactor through unchanged", () => {
  const rh = "sha256:" + "d".repeat(64);
  const ic = "sha256:" + "e".repeat(64);
  const oc = "sha256:" + "f".repeat(64);
  const counts = { VAT: 4, CLIENT: 2 };
  const body = buildRedactionBody({ counts, ruleset_hash: rh, input_commit: ic, output_commit: oc, redactor: "my-redactor@1.0.0" });
  assert.deepEqual(body.counts, counts);
  assert.equal(body.ruleset_hash, rh);
  assert.equal(body.input_commit, ic);
  assert.equal(body.output_commit, oc);
  assert.equal(body.redactor, "my-redactor@1.0.0");
});
