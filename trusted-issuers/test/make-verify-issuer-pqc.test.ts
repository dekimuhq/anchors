/**
 * makeVerifyIssuerPqc — composition factory for the v1.3 R3 Phase 2 enforcement
 * seam. The pure policy (issuerPqcRequirement / satisfiesIssuerPqc) is covered
 * exhaustively in pqc-policy.test.ts; this suite proves the factory wiring:
 *   - threads the matched record + receiptSigAlg into satisfiesIssuerPqc
 *   - sources effectiveTime from resolveEffectiveTime, falling back to now()
 *     (fail-toward-rejection) when it is absent or returns null/undefined
 *   - passes the envelope to resolveEffectiveTime
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/envelope
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { makeVerifyIssuerPqc } from "../src/index.ts";
import { defaultIssuerRecord } from "./fixtures.ts";

const CUTOVER = "2030-01-01T00:00:00Z";
const BEFORE = new Date("2029-12-31T23:59:59Z");
const AFTER = new Date("2030-06-01T00:00:00Z");

const migrated = defaultIssuerRecord({
  pqc_mandatory: { min_sig_alg: "ml-dsa-65", mandatory_from: CUTOVER },
});
const ENV = { id: "receipt-under-test" };

describe("makeVerifyIssuerPqc", () => {
  it("no mandate → ok regardless of time/alg", () => {
    const fn = makeVerifyIssuerPqc({ now: () => AFTER });
    assert.deepEqual(
      fn({ record: defaultIssuerRecord(), receiptSigAlg: "ed25519", envelope: ENV }),
      { ok: true },
    );
  });

  it("migrated issuer, classical receipt, effectiveTime after cutover → rejected", () => {
    const fn = makeVerifyIssuerPqc({ resolveEffectiveTime: () => AFTER });
    assert.deepEqual(
      fn({ record: migrated, receiptSigAlg: "ed25519", envelope: ENV }),
      { ok: false, reason: "issuer_pqc_mandatory:ml-dsa-65" },
    );
  });

  it("migrated issuer, classical receipt, effectiveTime BEFORE cutover → accepted", () => {
    const fn = makeVerifyIssuerPqc({ resolveEffectiveTime: () => BEFORE });
    assert.deepEqual(
      fn({ record: migrated, receiptSigAlg: "ed25519", envelope: ENV }),
      { ok: true },
    );
  });

  it("migrated issuer, ml-dsa-65 receipt after cutover → accepted (floor satisfied)", () => {
    const fn = makeVerifyIssuerPqc({ resolveEffectiveTime: () => AFTER });
    assert.deepEqual(
      fn({ record: migrated, receiptSigAlg: "ml-dsa-65", envelope: ENV }),
      { ok: true },
    );
  });

  it("resolveEffectiveTime returns null → falls back to now() (fail-toward-rejection)", () => {
    const fn = makeVerifyIssuerPqc({
      resolveEffectiveTime: () => null,
      now: () => AFTER,
    });
    assert.deepEqual(
      fn({ record: migrated, receiptSigAlg: "ed25519", envelope: ENV }),
      { ok: false, reason: "issuer_pqc_mandatory:ml-dsa-65" },
    );
  });

  it("no resolveEffectiveTime → uses now() fallback", () => {
    const fn = makeVerifyIssuerPqc({ now: () => AFTER });
    assert.deepEqual(
      fn({ record: migrated, receiptSigAlg: "ed25519", envelope: ENV }),
      { ok: false, reason: "issuer_pqc_mandatory:ml-dsa-65" },
    );
  });

  it("default now() (real clock, pre-2030) → migrated mandate not yet in force", () => {
    const fn = makeVerifyIssuerPqc();
    assert.deepEqual(
      fn({ record: migrated, receiptSigAlg: "ed25519", envelope: ENV }),
      { ok: true },
    );
  });

  it("passes the envelope through to resolveEffectiveTime", () => {
    let seen: unknown;
    const fn = makeVerifyIssuerPqc({
      resolveEffectiveTime: (env) => {
        seen = env;
        return BEFORE;
      },
    });
    fn({ record: migrated, receiptSigAlg: "ed25519", envelope: ENV });
    assert.strictEqual(seen, ENV);
  });
});
