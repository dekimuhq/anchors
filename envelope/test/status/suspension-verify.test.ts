/**
 * Tests for verifySuspensionStatus — Wave 3.
 *
 * Covers the non-I/O guard branches (no suspension pointer, not attempted,
 * invalid pointer). Full end-to-end fetch tests are integration-level.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { verifySuspensionStatus } from "../../src/status/suspension-verify.ts";
import type { Envelope } from "../../src/envelope-types.ts";

function baseEnvelope(opts?: { withSuspension?: boolean }): Envelope {
  const env: Envelope = {
    v: 2,
    id: "01HXX00000000000000SUSPVERIFTST",
    iat: "2026-05-22T00:00:00Z",
    claim_type: "ar.consent.v1",
    iss: "did:web:bank.example",
    iss_key: `ed25519:${"A".repeat(43)}`,
    subject: "sha256:" + "b".repeat(64),
    exp: null,
    prev: null,
    policy_uri: null,
    policy_hash: null,
    policy_version: null,
    tsa: null,
    credentialStatus: null,
    anchor: null as unknown as Envelope["anchor"],
    sig: "sig-placeholder",
    countersig: null,
    body: {},
  };
  if (opts?.withSuspension) {
    env.suspensionStatus = {
      id: "https://verify.dekimu.com/acr/v1/suspension/2026/05#7",
      type: "StatusList2021Entry",
      statusPurpose: "suspension",
      statusListIndex: "7",
      statusListCredential: "https://verify.dekimu.com/acr/v1/suspension/2026/05",
    };
  }
  return env;
}

test("no suspension pointer → no_suspension_pointer", async () => {
  const env = baseEnvelope();
  const r = await verifySuspensionStatus(env, {});
  assert.equal(r.state, "no_suspension_pointer");
});

test("no rootKey → not_attempted", async () => {
  const env = baseEnvelope({ withSuspension: true });
  const r = await verifySuspensionStatus(env, {});
  assert.equal(r.state, "not_attempted");
});

test("invalid pointer shape → invalid_pointer", async () => {
  const env = baseEnvelope();
  (env as unknown as Record<string, unknown>).suspensionStatus = {
    id: "https://x",
    type: "StatusList2021Entry",
    statusPurpose: "revocation",
    statusListIndex: "7",
    statusListCredential: "https://x",
  };
  const r = await verifySuspensionStatus(env, {
    rootKey: { kid: "did:web:x#k", publicKeyDer: "AAAA" },
  });
  assert.equal(r.state, "invalid_pointer");
  assert.ok(r.state === "invalid_pointer" && r.reason.includes("suspension"));
});
