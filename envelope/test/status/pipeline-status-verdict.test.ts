/**
 * Pipeline status verdict (security audit finding F4).
 *
 * Step 11 is advisory by design: it never changes `signature_valid`. But a
 * consumer that gates only on `signature_valid` then accepts a REVOKED receipt
 * (or one whose list could not be verified). The additive `status_blocking`
 * flag gives consumers one boolean to gate on; `signature_valid` keeps its
 * meaning.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";

import type { Envelope, AnchorProof, ClaimType } from "../../src/envelope-types.ts";
import { signEnvelope } from "../../src/envelope.ts";
import { defineFamily, type BodyValidator } from "../../src/define-family.ts";
import { buildVerifyReceipt } from "../../src/family-verify-pipeline.ts";
import { InMemoryStatusCache } from "../../src/status/cache.ts";
import { makeSignedStatusList } from "./_make-signed-list.mts";

const { privateKey: PRIV, publicKey: PUB } = generateKeyPairSync("ed25519");
const PUB_DER = new Uint8Array(PUB.export({ format: "der", type: "spki" }) as Buffer);
const URL_L = "https://verify.dekimu.com/status/verdict";

const ANCHOR: AnchorProof = {
  log: "https://verify.dekimu.com/alr/v1",
  leaf_index: 0,
  inclusion_proof: ["sha256:aabbcc"],
  tree_head_root: "sha256:deadbeef",
  tree_size: 1,
  log_time: "2026-05-19T00:00:00Z",
};

const bodySchema: BodyValidator<{ kind: string; events: unknown[] }> = {
  validate: (b) => ({ ok: true, value: b as { kind: string; events: unknown[] } }),
};

const family = defineFamily({
  acronym: "ALR",
  name: "x",
  claim_types: ["ar.lineage.v1"] satisfies readonly ClaimType[],
  spec_path: "x",
  chip: 4,
  status_list_slot: 1,
  subject_presence: "must-be-null",
  tsa_upgrade_path: "free",
  body_schema: bodySchema,
} as Parameters<typeof defineFamily>[0]);

const verify = buildVerifyReceipt({
  meta: family.meta,
  validateBody: (b) => family.validateBody(b),
  isOwnedClaimType: (c) => family.isOwnedClaimType(c),
  checkSubjectPresence: (s, b) => family.checkSubjectPresence(s, b),
  tsaMandateLevel: (p) => family.tsaMandateLevel(p),
  profileValidators: family.profileValidators,
  profileIds: family.profileIds,
  hasProfile: (p) => family.hasProfile(p),
});

async function receipt(): Promise<Envelope> {
  return signEnvelope(
    {
      v: 2,
      id: "01HZ0000000000000000000009",
      iat: "2026-05-19T00:00:00Z",
      claim_type: "ar.lineage.v1",
      iss: "did:key:z6MkTestIssuer",
      iss_key: "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      subject: null as unknown as string,
      exp: null,
      prev: null,
      policy_uri: "https://example.com/policy.json",
      policy_hash: "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
      policy_version: "1.0",
      tsa: null,
      credentialStatus: {
        id: `${URL_L}#7`,
        type: "StatusList2021Entry",
        statusPurpose: "revocation",
        statusListIndex: "7",
        statusListCredential: URL_L,
      },
      anchor: ANCHOR,
      sig: "",
      countersig: null,
      body: { kind: "ar.lineage.v1", events: [] },
    } as Envelope,
    PRIV,
  );
}

async function run(opts: { bitValue: 0 | 1; listUrl?: string; wrongKey?: boolean }) {
  const { credential, rootKey } = makeSignedStatusList({
    bitIndex: 7,
    bitValue: opts.bitValue,
    credentialUrl: opts.listUrl ?? URL_L,
  });
  const cache = new InMemoryStatusCache(4);
  const now = Date.now();
  await cache.set(URL_L, { fetched_at: now, fresh_until: now + 3600_000, body: credential });
  const other = makeSignedStatusList({ bitIndex: 0, bitValue: 0 }).rootKey;
  return verify(await receipt(), {
    resolveKey: () => PUB_DER,
    statusListRootKey: opts.wrongKey ? other : rootKey,
    statusCacheConfig: { freshTtlSec: 3600, staleTtlSec: 86400, storage: cache },
  });
}

test("F4: revoked receipt keeps signature_valid (unchanged) but status_blocking is true", async () => {
  const r = await run({ bitValue: 1 });
  assert.equal(r.status_state, "revoked");
  assert.equal(r.signature_valid, true, "signature_valid meaning is unchanged");
  assert.equal(r.status_blocking, true);
});

test("F4: active receipt → status_blocking false", async () => {
  const r = await run({ bitValue: 0 });
  assert.equal(r.status_state, "active");
  assert.equal(r.status_blocking, false);
});

test("F4: list_signature_invalid → status_blocking true", async () => {
  const r = await run({ bitValue: 0, wrongKey: true });
  assert.equal(r.status_state, "list_signature_invalid");
  assert.equal(r.status_blocking, true);
});

test("F4: list_mismatch (list id != url, F3) → status_blocking true", async () => {
  const r = await run({ bitValue: 0, listUrl: "https://verify.dekimu.com/status/other" });
  assert.equal(r.status_state, "list_mismatch");
  assert.equal(r.status_blocking, true);
});

test("F4: no statusListRootKey → not_attempted, status_blocking false (caller opted out of the check)", async () => {
  const r = await verify(await receipt(), { resolveKey: () => PUB_DER });
  assert.equal(r.status_state, "not_attempted");
  assert.equal(r.status_blocking, false);
});
