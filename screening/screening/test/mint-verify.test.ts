import { test } from "node:test";
import assert from "node:assert/strict";
import { commit, verifyCommitment } from "@dekimuhq/anchors-envelope";
import { mintScreeningV1, commitScreenedName } from "../src/issue/index.ts";
import { verifyReceipt, matcherPolicyHash, screeningFamily } from "../src/index.ts";
import { baseInput, resolveKey } from "./helpers.ts";

const NAME = "  Acme Trading Ltd ";
const mint = async (f?: (i: ReturnType<typeof baseInput>) => void) => {
  const c = commitScreenedName(NAME);
  const i = { ...baseInput(), subject_commit: c.subject_commit };
  f?.(i);
  return { receipt: await mintScreeningV1(i), reveal: c.reveal };
};
const rejectsMint = (name: string, f: (i: ReturnType<typeof baseInput>) => void, re: RegExp) =>
  test(`mint refuses: ${name}`, async () => { await assert.rejects(() => mint(f), re); });

test("family manifest: chip 22, must-be-null, claim type", () => {
  assert.equal(screeningFamily.meta.chip, 22);
  assert.equal(screeningFamily.meta.subject_presence, "must-be-null");
  assert.deepEqual(screeningFamily.meta.claim_types, ["ar.screening.v1"]);
  assert.equal(screeningFamily.meta.status_list_slot, null);
});

test("mint → verify round-trips valid", async () => {
  const { receipt } = await mint();
  const r = await verifyReceipt(receipt, { resolveKey });
  assert.equal(r.signature_valid, true, (r as { reason?: string }).reason ?? "ok");
  assert.equal((r as { policy_binding: string }).policy_binding, "ok");
  assert.equal((r as { claim_type: string }).claim_type, "ar.screening.v1");
});
test("envelope: subject null, prev null, kind decision, no status list", async () => {
  const { receipt } = await mint();
  assert.equal(receipt.subject, null);
  assert.equal(receipt.prev, null);
  assert.equal(receipt.kind, "decision");
  assert.equal(receipt.credentialStatus, null);
});
test("policy_hash binds the matcher", async () => {
  const { receipt } = await mint();
  assert.equal(receipt.policy_hash, matcherPolicyHash({ name: "@dekimuhq/sanctions", version: "0.2.0", threshold: 0.85 }));
  assert.equal(receipt.policy_version, "0.2.0");
});
test("policy hash changes with version and threshold", () => {
  const a = matcherPolicyHash({ name: "p", version: "1.0.0", threshold: 0.8 });
  assert.notEqual(a, matcherPolicyHash({ name: "p", version: "1.0.1", threshold: 0.8 }));
  assert.notEqual(a, matcherPolicyHash({ name: "p", version: "1.0.0", threshold: 0.9 }));
  assert.notEqual(a, matcherPolicyHash({ name: "q", version: "1.0.0", threshold: 0.8 }));
  assert.match(a, /^sha256:[0-9a-f]{64}$/);
});

test("the receipt never contains the name", async () => {
  const { receipt } = await mint();
  assert.ok(!JSON.stringify(receipt).toLowerCase().includes("acme"));
});
test("reveal opens the commitment; trimmed name is what is committed", async () => {
  const { receipt, reveal } = await mint();
  const body = receipt.body as { subject_commit: string };
  assert.equal(reveal.name, "Acme Trading Ltd");
  assert.equal(verifyCommitment(body.subject_commit, reveal.salt, "Acme Trading Ltd"), true);
  assert.equal(verifyCommitment(body.subject_commit, reveal.salt, "Other Ltd"), false);
  assert.equal(body.subject_commit, commit(reveal.salt, "Acme Trading Ltd"));
});
test("fresh salt per screen: same name → different commits", async () => {
  const a = await mint(); const b = await mint();
  assert.notEqual(a.reveal.salt, b.reveal.salt);
  assert.notEqual((a.receipt.body as { subject_commit: string }).subject_commit, (b.receipt.body as { subject_commit: string }).subject_commit);
});
test("candidate result round-trips", async () => {
  const { receipt } = await mint((i) => { i.result = "candidate"; i.candidates = [{ entry_ref: "EU.1.2", score: 0.93 }]; });
  const r = await verifyReceipt(receipt, { resolveKey });
  assert.equal(r.signature_valid, true);
  assert.equal((receipt.body as { result: string }).result, "candidate");
});
test("scheduled trigger round-trips", async () => {
  const { receipt } = await mint((i) => { i.trigger = "scheduled"; });
  assert.equal((await verifyReceipt(receipt, { resolveKey })).signature_valid, true);
});
test("body carries field_root", async () => {
  const { receipt } = await mint();
  assert.equal(typeof (receipt.body as { field_root: unknown }).field_root, "string");
});

test("commitScreenedName refuses an empty name", () => assert.throws(() => commitScreenedName("   "), /name required/));
rejectsMint("no issuer", (i) => { i.issuer = ""; }, /issuer required/);
rejectsMint("short key", (i) => { i.signingKey = { kid: "k", privateKey: new Uint8Array(5) }; }, /32 bytes/);
rejectsMint("tsa without fetcher", (i) => { (i as { tsa?: unknown }).tsa = {}; }, /tsaFetcher/);
rejectsMint("stale list (screened > fetched + 48h)", (i) => { i.list.fetched_at = new Date(Date.now() - 72 * 3600_000).toISOString(); i.list.file_date = i.list.fetched_at; }, /screening\.list\.stale/);
rejectsMint("screen before fetch", (i) => { i.screened_at = new Date(Date.now() - 3 * 3600_000).toISOString(); }, /screening\.list\.stale/);
rejectsMint("empty list", (i) => { i.list.entry_count = 0; }, /screening\.list\.empty/);
rejectsMint("none_at_threshold with candidates", (i) => { i.candidates = [{ entry_ref: "a", score: 0.9 }]; }, /result\.incoherent/);
rejectsMint("candidate without candidates", (i) => { i.result = "candidate"; }, /result\.incoherent/);
rejectsMint("bad threshold", (i) => { i.matcher.threshold = 0; }, /threshold_invalid/);
rejectsMint("bad list hash", (i) => { i.list.file_sha256 = "abc"; }, /hash_malformed/);
rejectsMint("bad screen_id", (i) => { i.screen_id = "x"; }, /screen_id/);

test("verify: non-object → schema_invalid", async () => {
  const r = await verifyReceipt("x");
  assert.equal(r.signature_valid, false);
  assert.equal((r as { reason: string }).reason, "schema_invalid");
});
test("verify: v=1 → unsupported_envelope_version", async () => {
  assert.equal(((await verifyReceipt({ v: 1 })) as { reason: string }).reason, "unsupported_envelope_version");
});
for (const [name, f] of [
  ["result", (b: Record<string, unknown>) => { b.result = "candidate"; }],
  ["subject_commit", (b: Record<string, unknown>) => { b.subject_commit = "sha256:" + "c".repeat(64); }],
  ["screened_at", (b: Record<string, unknown>) => { b.screened_at = "2026-11-19T11:00:00.000Z"; }],
  ["list.file_sha256", (b: Record<string, unknown>) => { (b.list as Record<string, unknown>).file_sha256 = "sha256:" + "d".repeat(64); }],
  ["matcher.threshold", (b: Record<string, unknown>) => { (b.matcher as Record<string, unknown>).threshold = 0.5; }],
] as const) {
  test(`tampering body.${name} breaks signature`, async () => {
    const { receipt } = await mint();
    const body = structuredClone(receipt.body) as Record<string, unknown>;
    f(body);
    const r = await verifyReceipt({ ...receipt, body }, { resolveKey });
    assert.equal(r.signature_valid, false);
  });
}
import { signEnvelope, keyObjectFromSeed } from "@dekimuhq/anchors-envelope";

/** Re-sign a modified envelope with the same key, so only the AScR-specific rules can reject it. */
async function resign(i: ReturnType<typeof baseInput>, patch: Record<string, unknown>) {
  const receipt = await mintScreeningV1(i);
  const { privateKey } = keyObjectFromSeed(i.signingKey.privateKey);
  return signEnvelope({ ...receipt, ...patch, sig: "" } as never, privateKey);
}
const okInput = () => ({ ...baseInput(), subject_commit: commitScreenedName("Acme").subject_commit });

test("re-signed receipt with a wrong policy_hash is rejected", async () => {
  const r = await verifyReceipt(await resign(okInput(), { policy_hash: "sha256:" + "0".repeat(64) }), { resolveKey });
  assert.equal(r.signature_valid, false);
  assert.equal((r as { reason: string }).reason, "screening.policy_hash.mismatch");
  assert.equal((r as { policy_binding: string }).policy_binding, "mismatch");
});
test("re-signed receipt with a null policy_hash is rejected", async () => {
  const r = await verifyReceipt(await resign(okInput(), { policy_hash: null }), { resolveKey });
  assert.equal(r.signature_valid, false);
  assert.equal((r as { reason: string }).reason, "screening.policy_hash.mismatch");
});
test("re-signed receipt with a non-null prev is rejected", async () => {
  const r = await verifyReceipt(await resign(okInput(), { prev: "ar.screening.v1:01J9Z3K4M5N6P7Q8R9S0T1V2W3" }), { resolveKey });
  assert.equal(r.signature_valid, false);
  assert.equal((r as { reason: string }).reason, "screening.prev.not_null");
});
test("re-signed receipt with a non-decision kind is rejected", async () => {
  const r = await verifyReceipt(await resign(okInput(), { kind: "observation" }), { resolveKey });
  assert.equal(r.signature_valid, false);
  assert.equal((r as { reason: string }).reason, "screening.kind.not_decision");
});
test("re-signed receipt whose screen postdates iat is rejected", async () => {
  const i = okInput();
  const receipt = await mintScreeningV1(i);
  const body = { ...(receipt.body as object), screened_at: "2999-01-01T00:00:00.000Z" };
  const { privateKey } = keyObjectFromSeed(i.signingKey.privateKey);
  const re = await signEnvelope({ ...receipt, body, sig: "" } as never, privateKey);
  const r = await verifyReceipt(re, { resolveKey });
  assert.equal(r.signature_valid, false);
});
test("verifyReceipt does not throw on a malformed matcher", async () => {
  for (const matcher of [{ name: "x" }, null, 5, { name: 1, version: 2, threshold: "a" }]) {
    const r = await verifyReceipt({ v: 2, body: { matcher } }, { resolveKey });
    assert.equal(r.signature_valid, false);
  }
});
test("matcherPolicyHash rejects an incomplete matcher", () => {
  assert.throws(() => matcherPolicyHash({ name: "x" } as never), /matcher must be/);
  assert.throws(() => matcherPolicyHash({ name: "x", version: "1", threshold: NaN }), /matcher must be/);
});
test("mint refuses a screen that postdates now", async () => {
  await assert.rejects(() => mintScreeningV1({ ...okInput(), list: { ...okInput().list, fetched_at: "2999-01-01T00:00:00.000Z", file_date: "2999-01-01T00:00:00.000Z" }, screened_at: "2999-01-01T01:00:00.000Z" }), /in_future/);
});
test("policy_uri is null (policy_hash binds the matcher JSON, not a document)", async () => {
  assert.equal((await mintScreeningV1(okInput())).policy_uri, null);
});
test("a non-null subject is rejected", async () => {
  const r = await verifyReceipt(await resign(okInput(), { subject: "sha256:" + "e".repeat(64) }), { resolveKey });
  assert.equal(r.signature_valid, false);
});
