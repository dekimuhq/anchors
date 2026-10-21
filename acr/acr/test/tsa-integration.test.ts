/**
 * TSA integration tests for @dekimuhq/acr-verifier v=2 dispatch — Phase B Task 13.
 *
 * T1 — envelope without tsa → tsa_state: "tsa_absent", tsa_listed: false
 * T2 — (skipped: unit-level happy-path covered in envelope/test/tsa/verify.test.ts)
 * T3 — envelope with injected (imprint-mismatched) tsa block → tsa_state: "tsa_imprint_mismatch",
 *       signature_valid remains true (TSA failure doesn't poison sig)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { base64UrlEncode } from "@dekimuhq/anchors-envelope";
import type { FamilyVerifyResult } from "@dekimuhq/anchors-envelope";
import { loadTrustAnchors } from "@dekimuhq/anchors-envelope/tsa";
import v2Fixture from "./fixtures/v2-acr-consent.ts";
import { verifyReceipt } from "../src/index.ts";

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── Fixture: FreeTSA sample TSR (real RFC 3161 response, wrong imprint for our envelope) ──

const tsrPath = resolve(__dirname, "../../../envelope/test/tsa/fixtures/freetsa-sample.tsr");
const sampleTsrB64 = base64UrlEncode(new Uint8Array(readFileSync(tsrPath)));

// Bundled trust anchors
const anchorPath = resolve(__dirname, "../../../data/freetsa-trust-anchor.json");
const anchors = loadTrustAnchors([anchorPath]);

// ── T1: envelope without tsa returns tsa_state: "tsa_absent" ─────────────────

test("acr tsa-integration: envelope without tsa returns tsa_state absent", async () => {
  const { envelope, publicKey } = v2Fixture;
  assert.equal(envelope.tsa, null);

  const result = await verifyReceipt(envelope, {
    resolveKey: async () => publicKey,
    tsaAnchors: anchors,
  }) as FamilyVerifyResult;
  assert.equal(result.signature_valid, true);
  assert.equal(result.tsa_state, "tsa_absent");
  assert.equal(result.tsa_listed, false);
});

// ── T3: injected TSR (imprint mismatch) → tsa_imprint_mismatch, sig still valid ──

test("acr tsa-integration: injected tsa with mismatched imprint → tsa_imprint_mismatch, sig valid", async () => {
  const { envelope, publicKey } = v2Fixture;

  const injectedEnvelope = {
    ...envelope,
    tsa: {
      v: 1 as const,
      tsr: sampleTsrB64,
      alg: "sha-256" as const,
      tsa_url: "https://freetsa.org/tsr",
      tsa_cert_chain_sha256: [],
      issued_at: "2026-05-17T09:06:45Z",
    },
  };

  const { parseTimeStampResp } = await import("@dekimuhq/anchors-envelope/tsa");
  const parsedTsr = parseTimeStampResp(new Uint8Array(readFileSync(tsrPath)));
  assert.ok(parsedTsr.granted, "fixture setup: tsr must be granted");
  const refTime = new Date(parsedTsr.tstInfo.genTime);

  const result = await verifyReceipt(injectedEnvelope as never, {
    resolveKey: async () => publicKey,
    tsaAnchors: anchors,
    tsaDriftToleranceSec: 300,
    tsaReferenceTime: refTime,
  }) as FamilyVerifyResult;

  assert.equal(result.signature_valid, true, "sig must remain valid when tsa is corrupted");
  assert.equal(result.tsa_state, "tsa_imprint_mismatch");
  assert.equal(result.tsa_listed, false);
  // I1 — policy_oid surfaces past the granted check, even on imprint mismatch.
  // FreeTSA fixture uses 1.2.3.4.1.
  assert.equal(result.tsa_policy_oid, "1.2.3.4.1");
});
