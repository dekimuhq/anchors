/**
 * Mint-path coverage for `mintComplianceV1` — the five input guards, the
 * verify-before-sign contract, envelope field derivation, and signature /
 * tamper behaviour.
 *
 * The pre-existing `mint.test.ts` covered the happy path and one invalid body.
 * The guards below were entirely untested, which mattered more than the count:
 * this is the only surface in the package that produces a SIGNED artefact, and
 * a guard that never runs in a test is a guard nobody has seen work.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mintComplianceV1 } from "../src/issue/mint-v1.ts";
import { generateComplianceKeypair } from "../src/issue/keys.ts";
import { verifyReceipt } from "../src/index.ts";
import type { ComplianceBundleBody } from "../src/types.ts";

const SHA = "sha256:" + "a".repeat(64);
const anchor = {
  log: "test", leaf_index: 0, inclusion_proof: [], tree_head_root: "r",
  tree_size: 1, log_time: "2026-06-20T10:00:00Z",
} as never;

function body(): ComplianceBundleBody {
  return {
    profile: "compliance.bundle",
    workspaceId: "ws_1",
    controller: { entityName: "Acme SL", registeredAddress: null, contactEmail: null },
    regulation: { manifestId: "gdpr", manifestVersion: "1.2.0", manifestHash: SHA },
    coverage: { applicable: 8, satisfied: 8, ratio: 1 },
    constituents: {
      ropa: { ref: "ropa:" + "b".repeat(64), contentHash: SHA, satisfiedObligations: ["gdpr.records"] },
      dpia: { status: "not_applicable", reason: "no high-risk processing", basis: "engine" },
      obligations: { ref: "report", contentHash: SHA, satisfiedObligations: [] },
    },
    generated_at: "2026-06-20T10:00:00Z",
  };
}

const key = (kid = "kid-1") => generateComplianceKeypair(kid);
const base = () => ({ issuer: "did:web:test", signingKey: key().signingKey, anchor, body: body() });

// ------------------------------------------------------------------- guard 1

test("mint requires an issuer", async () => {
  await assert.rejects(
    () => mintComplianceV1({ ...base(), issuer: "" }),
    /issuer required/,
  );
});

test("mint rejects an undefined issuer", async () => {
  await assert.rejects(
    () => mintComplianceV1({ ...base(), issuer: undefined as unknown as string }),
    /issuer required/,
  );
});

// ------------------------------------------------------------------- guard 2

test("mint requires signingKey.kid", async () => {
  const { signingKey } = key();
  await assert.rejects(
    () => mintComplianceV1({ ...base(), signingKey: { ...signingKey, kid: "" } }),
    /signingKey\.kid required/,
  );
});

test("mint rejects a missing signingKey entirely", async () => {
  await assert.rejects(
    () => mintComplianceV1({ ...base(), signingKey: undefined as never }),
    /signingKey\.kid required/,
  );
});

// ------------------------------------------------------------------- guard 3

test("mint rejects a private key shorter than 32 bytes", async () => {
  const { signingKey } = key();
  await assert.rejects(
    () => mintComplianceV1({ ...base(), signingKey: { ...signingKey, privateKey: new Uint8Array(31) } }),
    /must be 32 bytes/,
  );
});

test("mint rejects a private key longer than 32 bytes", async () => {
  const { signingKey } = key();
  await assert.rejects(
    () => mintComplianceV1({ ...base(), signingKey: { ...signingKey, privateKey: new Uint8Array(33) } }),
    /must be 32 bytes/,
  );
});

test("mint rejects an empty private key", async () => {
  const { signingKey } = key();
  await assert.rejects(
    () => mintComplianceV1({ ...base(), signingKey: { ...signingKey, privateKey: new Uint8Array(0) } }),
    /must be 32 bytes/,
  );
});

// ------------------------------------------------------------------- guard 4

test("mint requires an anchor", async () => {
  await assert.rejects(
    () => mintComplianceV1({ ...base(), anchor: undefined as never }),
    /anchor required/,
  );
});

test("mint rejects a null anchor", async () => {
  await assert.rejects(
    () => mintComplianceV1({ ...base(), anchor: null as never }),
    /anchor required/,
  );
});

// ------------------------------------------------------------------- guard 5

test("mint requires a tsaFetcher whenever a tsa config is supplied", async () => {
  await assert.rejects(
    () => mintComplianceV1({ ...base(), tsa: {} as never }),
    /tsaFetcher required/,
  );
});

test("mint does NOT require a tsaFetcher when no tsa config is supplied", async () => {
  // exactOptionalPropertyTypes is on, so `tsaFetcher: undefined` is a type
  // error — absence is expressed by omitting the key, which is also the shape
  // a real caller uses.
  const env = await mintComplianceV1(base());
  assert.equal(env.tsa, null);
});

// -------------------------------------------------------- verify-before-sign

test("mint refuses an invalid body and names the validator errors", async () => {
  const bad = body();
  bad.coverage.ratio = 9;
  await assert.rejects(
    () => mintComplianceV1({ ...base(), body: bad }),
    /invalid body — .*coverage\.ratio/,
  );
});

test("mint refuses a body with the wrong profile", async () => {
  const bad = body() as unknown as Record<string, unknown>;
  bad.profile = "not.compliance";
  await assert.rejects(
    () => mintComplianceV1({ ...base(), body: bad as never }),
    /profile\.invalid/,
  );
});

test("mint refuses a body whose satisfied exceeds applicable", async () => {
  const bad = body();
  bad.coverage = { applicable: 2, satisfied: 5, ratio: 1 };
  await assert.rejects(
    () => mintComplianceV1({ ...base(), body: bad }),
    /satisfied_exceeds_applicable/,
  );
});

test("mint reports EVERY validator error, not just the first", async () => {
  const bad = body() as unknown as Record<string, unknown>;
  bad.profile = "wrong";
  delete bad.workspaceId;
  await assert.rejects(
    () => mintComplianceV1({ ...base(), body: bad as never }),
    (e: Error) =>
      /profile\.invalid/.test(e.message) && /workspaceId\.missing/.test(e.message),
  );
});

// ------------------------------------------------------ envelope derivation

test("the minted envelope carries the family claim type", async () => {
  const env = await mintComplianceV1(base());
  assert.equal(env.claim_type, "ar.compliance.v1");
});

test("subject is null — ACBR is workspace-level, never per-data-subject", async () => {
  const env = await mintComplianceV1(base());
  assert.equal(env.subject, null);
});

test("the envelope is v2", async () => {
  const env = await mintComplianceV1(base());
  assert.equal(env.v, 2);
});

test("credentialStatus is null — ACBR is non-revocable in this slice", async () => {
  const env = await mintComplianceV1(base());
  assert.equal(env.credentialStatus, null);
});

test("iat_ms agrees with iat", async () => {
  const env = await mintComplianceV1(base());
  assert.equal(env.iat_ms, Date.parse(env.iat));
});

test("each mint gets a distinct receipt id", async () => {
  const a = await mintComplianceV1(base());
  const b = await mintComplianceV1(base());
  assert.notEqual(a.id, b.id);
});

test("kind defaults to observation when unspecified", async () => {
  const env = await mintComplianceV1(base());
  assert.equal(env.kind, "observation");
});

test("an EXPLICIT null kind is preserved, not overwritten by the default", async () => {
  // `undefined` means "unspecified" and takes the default; `null` is a choice.
  const env = await mintComplianceV1({ ...base(), envelope_kind: null });
  assert.equal(env.kind, null);
});

test("an explicit kind is preserved", async () => {
  const env = await mintComplianceV1({ ...base(), envelope_kind: "attestation" as never });
  assert.equal(env.kind, "attestation");
});

test("cause defaults to null", async () => {
  const env = await mintComplianceV1(base());
  assert.equal(env.cause, null);
});

test("an explicit cause is preserved", async () => {
  const env = await mintComplianceV1({ ...base(), cause: "renewal" as never });
  assert.equal(env.cause, "renewal");
});

test("prev defaults to null", async () => {
  const env = await mintComplianceV1(base());
  assert.equal(env.prev, null);
});

test("an explicit prev is preserved", async () => {
  const env = await mintComplianceV1({ ...base(), prev: "rcpt_prev" });
  assert.equal(env.prev, "rcpt_prev");
});

test("exp defaults to null", async () => {
  const env = await mintComplianceV1(base());
  assert.equal(env.exp, null);
});

test("an explicit exp is preserved", async () => {
  const env = await mintComplianceV1({ ...base(), exp: "2027-01-01T00:00:00Z" });
  assert.equal(env.exp, "2027-01-01T00:00:00Z");
});

test("policy fields are null — ACBR carries no policy binding", async () => {
  const env = await mintComplianceV1(base());
  assert.equal(env.policy_uri, null);
  assert.equal(env.policy_hash, null);
  assert.equal(env.policy_version, null);
});

test("predicate is null", async () => {
  const env = await mintComplianceV1(base());
  assert.equal(env.predicate, null);
});

test("the anchor is carried through unchanged", async () => {
  const env = await mintComplianceV1(base());
  assert.deepEqual(env.anchor, anchor);
});

test("the issuer is carried through unchanged", async () => {
  const env = await mintComplianceV1({ ...base(), issuer: "did:web:acme.example" });
  assert.equal(env.iss, "did:web:acme.example");
});

test("a field_root is computed onto the body", async () => {
  const env = await mintComplianceV1(base());
  assert.ok((env.body as Record<string, unknown>).field_root, "field_root missing");
});

test("the same body yields the same field_root across mints", async () => {
  const a = await mintComplianceV1(base());
  const b = await mintComplianceV1(base());
  assert.equal(
    (a.body as Record<string, unknown>).field_root,
    (b.body as Record<string, unknown>).field_root,
  );
});

test("a DIFFERENT body yields a different field_root", async () => {
  const a = await mintComplianceV1(base());
  const changed = body();
  changed.workspaceId = "ws_2";
  const b = await mintComplianceV1({ ...base(), body: changed });
  assert.notEqual(
    (a.body as Record<string, unknown>).field_root,
    (b.body as Record<string, unknown>).field_root,
  );
});

test("mint does not mutate the caller's body object", async () => {
  const input = body();
  const before = JSON.stringify(input);
  await mintComplianceV1({ ...base(), body: input });
  assert.equal(JSON.stringify(input), before);
});

test("the body fields survive the mint intact", async () => {
  const env = await mintComplianceV1(base());
  const out = env.body as unknown as ComplianceBundleBody;
  assert.equal(out.workspaceId, "ws_1");
  assert.equal(out.controller.entityName, "Acme SL");
  assert.equal(out.coverage.applicable, 8);
});

test("a signature is actually attached", async () => {
  const env = await mintComplianceV1(base());
  assert.ok(typeof env.sig === "string" && env.sig.length > 0);
});

test("countersig is null on a freshly minted receipt", async () => {
  const env = await mintComplianceV1(base());
  assert.equal(env.countersig, null);
});

// -------------------------------------------------- signature / tamper

test("a minted receipt verifies under its own public key", async () => {
  const { signingKey, publicKeyDer } = key();
  const env = await mintComplianceV1({ ...base(), signingKey });
  const r = await verifyReceipt(env, { resolveKey: () => publicKeyDer });
  assert.equal((r as { signature_valid?: boolean }).signature_valid, true, JSON.stringify(r));
});

test("a receipt does NOT verify under a DIFFERENT key", async () => {
  const { signingKey } = key("kid-1");
  const other = key("kid-2");
  const env = await mintComplianceV1({ ...base(), signingKey });
  const r = await verifyReceipt(env, { resolveKey: () => other.publicKeyDer });
  assert.notEqual((r as { signature_valid?: boolean }).signature_valid, true);
});

test("tampering with the body breaks the signature", async () => {
  const { signingKey, publicKeyDer } = key();
  const env = await mintComplianceV1({ ...base(), signingKey });
  (env.body as unknown as ComplianceBundleBody).workspaceId = "ws_tampered";
  const r = await verifyReceipt(env, { resolveKey: () => publicKeyDer });
  assert.notEqual((r as { signature_valid?: boolean }).signature_valid, true);
});

test("tampering with the issuer breaks the signature", async () => {
  const { signingKey, publicKeyDer } = key();
  const env = await mintComplianceV1({ ...base(), signingKey });
  env.iss = "did:web:attacker.example";
  const r = await verifyReceipt(env, { resolveKey: () => publicKeyDer });
  assert.notEqual((r as { signature_valid?: boolean }).signature_valid, true);
});

test("tampering with the coverage numbers breaks the signature", async () => {
  const { signingKey, publicKeyDer } = key();
  const env = await mintComplianceV1({ ...base(), signingKey });
  (env.body as unknown as ComplianceBundleBody).coverage.satisfied = 999;
  const r = await verifyReceipt(env, { resolveKey: () => publicKeyDer });
  assert.notEqual((r as { signature_valid?: boolean }).signature_valid, true);
});

test("a truncated signature does not verify", async () => {
  const { signingKey, publicKeyDer } = key();
  const env = await mintComplianceV1({ ...base(), signingKey });
  env.sig = env.sig.slice(0, -4);
  const r = await verifyReceipt(env, { resolveKey: () => publicKeyDer });
  assert.notEqual((r as { signature_valid?: boolean }).signature_valid, true);
});
