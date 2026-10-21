/**
 * Tests for envelope/src/tsa/attach.ts — attachTsaBlock helper.
 * Phase B Task 12a.
 *
 * All tests are offline (no network). A mock TsaFetcher is used throughout.
 * End-to-end mint tests (happy path with real TSR round-trip) live in the
 * per-member issuer-kit tests (Tasks 12b/c/d).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { attachTsaBlock, TsaMintError } from "../../src/tsa/attach.ts";
import type { TsaFetcher } from "../../src/tsa/attach.ts";
import type { Envelope } from "../../src/envelope-types.ts";
import type { TsaConfig } from "../../src/tsa/types.ts";

const __dir = dirname(fileURLToPath(import.meta.url));
const TSR_PATH = join(__dir, "fixtures/freetsa-sample.tsr");
const fixtureTsr = new Uint8Array(readFileSync(TSR_PATH));

// ── Minimal synthetic signed envelope ────────────────────────────────────────
// Used across tests that need an Envelope argument. Only structural shape
// matters here — the TSA imprint computation uses the canonical bytes of
// this object, and tests exercise TsaMintError paths or structural checks.

const syntheticEnvelope: Envelope = {
  v: 2,
  id: "01HZZZZZZZZZZZZZZZZZZZZZZZZ",
  iat: "2026-05-17T00:00:00Z",
  claim_type: "ar.provenance.v1",
  iss: "did:key:test",
  iss_key: "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  subject: "urn:test:subject",
  exp: null,
  prev: null,
  policy_uri: null,
  policy_hash: null,
  policy_version: null,
  tsa: null,
  credentialStatus: null,
  anchor: {
    log: "https://verify.example/test",
    leaf_index: 0,
    inclusion_proof: [],
    tree_head_root: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    tree_size: 1,
    log_time: "2026-05-17T00:00:00Z",
  },
  sig: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  countersig: null,
  body: { type: "test" },
};

// ── Base TsaConfig ────────────────────────────────────────────────────────────

const baseCfg: TsaConfig = {
  url: "https://freetsa.org/tsr",
  trustAnchorIds: ["freetsa-root"],
  hashAlg: "sha-256",
  driftToleranceSec: 60,
  timeoutMs: 5000,
};

// ── Minimal synthetic status≠0 TSR bytes ─────────────────────────────────────
// SEQUENCE { SEQUENCE { INTEGER 2 } } — status=2, no TimeStampToken.
// Reuses the same 7-byte encoding from response.test.ts.
const rejectedTsr = new Uint8Array([0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02]);

// ── Tests ─────────────────────────────────────────────────────────────────────

test("TsaMintError: extends Error with correct name and cause", () => {
  const cause = new TypeError("underlying");
  const err = new TsaMintError("tsa: test", cause);

  assert.ok(err instanceof Error, "should be an instanceof Error");
  assert.ok(err instanceof TsaMintError, "should be an instanceof TsaMintError");
  assert.equal(err.name, "TsaMintError");
  assert.equal(err.message, "tsa: test");
  assert.strictEqual(err.cause, cause);
});

test("TsaMintError: cause may be null", () => {
  const err = new TsaMintError("tsa: no underlying cause", null);
  assert.equal(err.cause, null);
  assert.equal(err.name, "TsaMintError");
});

test("attachTsaBlock: requests certReq=true so the TSA embeds its cert chain (verifier anchor match)", async () => {
  const captured: Uint8Array[] = [];
  const fetcher: TsaFetcher = async (req) => {
    captured.push(req);
    return fixtureTsr;
  };
  // The fixture imprint won't match the synthetic envelope, so attach throws after
  // the fetch — but the request is already captured. We only assert the request shape.
  await attachTsaBlock(syntheticEnvelope, baseCfg, fetcher).catch(() => undefined);

  const req0 = captured[0];
  assert.ok(req0, "fetcher should have been called with a request");
  // certReq is the only BOOLEAN in a TimeStampReq; BOOLEAN TRUE encodes as 01 01 FF.
  // Without it FreeTSA returns a token with no certs → verifyTsa fails
  // tsa_unrecognised_anchor against the bundled root.
  const hex = Array.from(req0, (b) => b.toString(16).padStart(2, "0")).join("");
  assert.ok(hex.includes("0101ff"), "TimeStampReq must encode certReq=true (01 01 ff)");
});

test("attachTsaBlock: throws TsaMintError on unsupported hashAlg", async () => {
  const fetcher: TsaFetcher = async () => fixtureTsr;
  const badCfg = { ...baseCfg, hashAlg: "sha-1" as "sha-256" };

  await assert.rejects(
    () => attachTsaBlock(syntheticEnvelope, badCfg, fetcher),
    (err: unknown) => {
      assert.ok(err instanceof TsaMintError, "expected TsaMintError");
      assert.match(err.message, /unsupported hashAlg/);
      return true;
    },
  );
});

test("attachTsaBlock: throws TsaMintError when fetcher rejects", async () => {
  const networkError = new Error("ECONNREFUSED");
  const fetcher: TsaFetcher = async () => {
    throw networkError;
  };

  await assert.rejects(
    () => attachTsaBlock(syntheticEnvelope, baseCfg, fetcher),
    (err: unknown) => {
      assert.ok(err instanceof TsaMintError, "expected TsaMintError");
      assert.match(err.message, /TSP call failed/);
      assert.strictEqual(err.cause, networkError);
      return true;
    },
  );
});

test("attachTsaBlock: TsaMintError shape when wrapping a timeout-like error", () => {
  // Directly construct a TsaMintError that mirrors what the timeout branch
  // produces, and verify shape. The actual timeout behaviour is an integration
  // concern tested in the per-member issuer-kit suites (Tasks 12b/c/d).
  const timeoutCause = new Error("tsa: timeout after 50ms");
  const err = new TsaMintError("tsa: TSP call failed", timeoutCause);

  assert.ok(err instanceof TsaMintError, "expected TsaMintError");
  assert.equal(err.name, "TsaMintError");
  assert.match(err.message, /TSP call failed/);
  assert.ok(err.cause instanceof Error);
  assert.match((err.cause as Error).message, /timeout/i);
});

test("attachTsaBlock: throws TsaMintError when TSP returns status≠0", async () => {
  // fetcher returns the synthetic status=2 TSR regardless of input.
  const fetcher: TsaFetcher = async () => rejectedTsr;

  await assert.rejects(
    () => attachTsaBlock(syntheticEnvelope, baseCfg, fetcher),
    (err: unknown) => {
      assert.ok(err instanceof TsaMintError, "expected TsaMintError");
      assert.match(err.message, /non-zero status 2/);
      return true;
    },
  );
});

test("attachTsaBlock: throws TsaMintError on imprint mismatch (fixture TSR returned for wrong input)", async () => {
  // The FreeTSA fixture embeds the imprint captured at fixture-capture time.
  // When attachTsaBlock canonicalises syntheticEnvelope, it computes a
  // different SHA-256 — so the round-trip imprint check fails.
  const fetcher: TsaFetcher = async () => fixtureTsr;

  await assert.rejects(
    () => attachTsaBlock(syntheticEnvelope, baseCfg, fetcher),
    (err: unknown) => {
      assert.ok(err instanceof TsaMintError, "expected TsaMintError");
      assert.match(err.message, /imprint does not match/);
      return true;
    },
  );
});

test("attachTsaBlock: returns Promise<Envelope> (structural / type smoke)", async () => {
  // Verify attachTsaBlock is async and its return is thenable before it
  // reaches any network call. We cancel with an immediate rejection so we
  // do not need a real TSR — we just confirm the call returns a Promise.
  const fetcher: TsaFetcher = async () => {
    throw new Error("intentional early abort");
  };

  const result = attachTsaBlock(syntheticEnvelope, baseCfg, fetcher);
  assert.ok(result instanceof Promise, "attachTsaBlock must return a Promise");

  // Drain the rejection so Node doesn't emit an unhandledRejection warning.
  await result.catch(() => { /* expected */ });
});
