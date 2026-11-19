import { test } from "node:test";
import assert from "node:assert/strict";
import { commit, verifyCommitment } from "@dekimuhq/anchors-envelope";
import { mintScreeningV1 } from "../src/issue/index.ts";
import { verifyReceipt, matcherPolicyHash, screeningFamily } from "../src/index.ts";
import { baseInput, resolveKey } from "./helpers.ts";

const mint = (f?: (i: ReturnType<typeof baseInput>) => void) => { const i = baseInput(); f?.(i); return mintScreeningV1(i); };
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
  assert.match((receipt.body as { field_root: string }).field_root, /^sha256:|^[0-9a-f]{64}$|./);
});

rejectsMint("empty name", (i) => { i.name = "   "; }, /name required/);
rejectsMint("no issuer", (i) => { i.issuer = ""; }, /issuer required/);
rejectsMint("short key", (i) => { i.signingKey = { kid: "k", privateKey: new Uint8Array(5) }; }, /32 bytes/);
rejectsMint("tsa without fetcher", (i) => { (i as { tsa?: unknown }).tsa = {}; }, /tsaFetcher/);
rejectsMint("stale list (screened > fetched + 48h)", (i) => { i.screened_at = "2026-11-22T00:00:00.000Z"; }, /screening\.list\.stale/);
rejectsMint("screen before fetch", (i) => { i.screened_at = "2026-11-19T00:00:00.000Z"; }, /screening\.list\.stale/);
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
test("a wrong policy_hash is reported as binding mismatch (re-signing aside)", async () => {
  const { receipt } = await mint();
  const r = await verifyReceipt({ ...receipt, policy_hash: "sha256:" + "0".repeat(64) }, { resolveKey });
  assert.equal(r.signature_valid, false);
  assert.equal((r as { policy_binding: string }).policy_binding, "mismatch");
});
test("a null policy_hash is a binding mismatch", async () => {
  const { receipt } = await mint();
  const r = await verifyReceipt({ ...receipt, policy_hash: null }, { resolveKey });
  assert.equal((r as { policy_binding: string }).policy_binding, "mismatch");
});
test("a non-null subject is rejected", async () => {
  const { receipt } = await mint();
  const r = await verifyReceipt({ ...receipt, subject: "sha256:" + "e".repeat(64) }, { resolveKey });
  assert.equal(r.signature_valid, false);
});
