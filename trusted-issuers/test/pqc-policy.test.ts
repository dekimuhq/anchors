import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  issuerPqcRequirement,
  satisfiesIssuerPqc,
  parseTrustedIssuerList,
} from "../src/index.ts";
import { defaultIssuerRecord, makeSignedDoc } from "./fixtures.ts";

const CUTOVER = "2030-01-01T00:00:00Z";
const BEFORE = new Date("2029-12-31T23:59:59Z");
const AT = new Date(CUTOVER);
const AFTER = new Date("2030-06-01T00:00:00Z");

describe("issuerPqcRequirement", () => {
  it("returns none when there is no mandate", () => {
    const rec = defaultIssuerRecord();
    assert.deepEqual(issuerPqcRequirement(rec, AFTER), { kind: "none" });
  });

  it("returns none when pqc_mandatory is explicitly null", () => {
    const rec = defaultIssuerRecord({ pqc_mandatory: null });
    assert.deepEqual(issuerPqcRequirement(rec, AFTER), { kind: "none" });
  });

  it("returns none before the cutover, even with a mandate set", () => {
    const rec = defaultIssuerRecord({
      pqc_mandatory: { min_sig_alg: "ml-dsa-65", mandatory_from: CUTOVER },
    });
    assert.deepEqual(issuerPqcRequirement(rec, BEFORE), { kind: "none" });
  });

  it("enforces at the exact cutover instant (>= boundary, inclusive)", () => {
    const rec = defaultIssuerRecord({
      pqc_mandatory: { min_sig_alg: "ml-dsa-65", mandatory_from: CUTOVER },
    });
    assert.deepEqual(issuerPqcRequirement(rec, AT), {
      kind: "min",
      alg: "ml-dsa-65",
    });
  });

  it("returns min for a registered floor after the cutover", () => {
    const rec = defaultIssuerRecord({
      pqc_mandatory: { min_sig_alg: "ml-dsa-65", mandatory_from: CUTOVER },
    });
    assert.deepEqual(issuerPqcRequirement(rec, AFTER), {
      kind: "min",
      alg: "ml-dsa-65",
    });
  });

  it("fails closed (unsatisfiable) for an UNREGISTERED floor after the cutover", () => {
    const rec = defaultIssuerRecord({
      pqc_mandatory: {
        min_sig_alg: "slh-dsa-sha2-128s",
        mandatory_from: CUTOVER,
      },
    });
    assert.deepEqual(issuerPqcRequirement(rec, AFTER), {
      kind: "unsatisfiable",
      declared: "slh-dsa-sha2-128s",
    });
  });

  it("fails closed (unsatisfiable) for a malformed cutover date (bypasses parser)", () => {
    const rec = defaultIssuerRecord({
      pqc_mandatory: { min_sig_alg: "ml-dsa-65", mandatory_from: "not-a-date" },
    });
    assert.deepEqual(issuerPqcRequirement(rec, AFTER), {
      kind: "unsatisfiable",
      declared: "ml-dsa-65",
    });
  });

  it("fails closed for LENIENT-but-non-strict dates Date.parse would accept", () => {
    // `Date.parse` accepts these (some as LOCAL time → silent cutover drift);
    // strict ISO 8601 rejects them → fail closed, no timezone-dependent window.
    for (const bad of [
      "2030/01/01",
      "2030-01-01T00:00:00", // no zone
      "2030-1-1",
      "Jan 1 2030",
    ]) {
      const rec = defaultIssuerRecord({
        pqc_mandatory: { min_sig_alg: "ml-dsa-65", mandatory_from: bad },
      });
      assert.deepEqual(
        issuerPqcRequirement(rec, AFTER),
        { kind: "unsatisfiable", declared: "ml-dsa-65" },
        `expected ${bad} to be rejected as non-strict-ISO`,
      );
    }
  });

  it("fails closed for an empty min_sig_alg via the policy path (bypasses parser)", () => {
    const rec = defaultIssuerRecord({
      pqc_mandatory: { min_sig_alg: "", mandatory_from: CUTOVER },
    });
    assert.deepEqual(issuerPqcRequirement(rec, AFTER), {
      kind: "unsatisfiable",
      declared: "",
    });
  });
});

describe("satisfiesIssuerPqc", () => {
  it("accepts any algorithm when there is no mandate", () => {
    const rec = defaultIssuerRecord();
    assert.deepEqual(satisfiesIssuerPqc(rec, AFTER, "ed25519"), { ok: true });
  });

  it("accepts a pre-cutover classical receipt (history preserved)", () => {
    const rec = defaultIssuerRecord({
      pqc_mandatory: { min_sig_alg: "ml-dsa-65", mandatory_from: CUTOVER },
    });
    assert.deepEqual(satisfiesIssuerPqc(rec, BEFORE, "ed25519"), { ok: true });
  });

  it("REJECTS a classical receipt from a migrated issuer after the cutover", () => {
    const rec = defaultIssuerRecord({
      pqc_mandatory: { min_sig_alg: "ml-dsa-65", mandatory_from: CUTOVER },
    });
    const res = satisfiesIssuerPqc(rec, AFTER, "ed25519");
    assert.equal(res.ok, false);
    if (!res.ok) assert.equal(res.reason, "issuer_pqc_mandatory:ml-dsa-65");
  });

  it("accepts a PQC receipt that meets the floor after the cutover", () => {
    const rec = defaultIssuerRecord({
      pqc_mandatory: { min_sig_alg: "ml-dsa-65", mandatory_from: CUTOVER },
    });
    assert.deepEqual(satisfiesIssuerPqc(rec, AFTER, "ml-dsa-65"), { ok: true });
  });

  it("accepts a receipt that EXCEEDS the floor (rank >=, not ==)", () => {
    // Floor ed25519 (rank 0); ml-dsa-65 (rank 1) exceeds it.
    const rec = defaultIssuerRecord({
      pqc_mandatory: { min_sig_alg: "ed25519", mandatory_from: CUTOVER },
    });
    assert.deepEqual(satisfiesIssuerPqc(rec, AFTER, "ml-dsa-65"), { ok: true });
  });

  it("fails closed for an unregistered floor regardless of receipt algorithm", () => {
    const rec = defaultIssuerRecord({
      pqc_mandatory: {
        min_sig_alg: "slh-dsa-sha2-128s",
        mandatory_from: CUTOVER,
      },
    });
    for (const alg of ["ed25519", "ml-dsa-65"] as const) {
      const res = satisfiesIssuerPqc(rec, AFTER, alg);
      assert.equal(res.ok, false);
      if (!res.ok) {
        assert.equal(res.reason, "issuer_pqc_unsatisfiable:slh-dsa-sha2-128s");
      }
    }
  });

  it("fails closed for a prototype-member receiptSigAlg (own-value guard, no index bypass)", () => {
    const rec = defaultIssuerRecord({
      pqc_mandatory: { min_sig_alg: "ml-dsa-65", mandatory_from: CUTOVER },
    });
    // A forged/unsanitised receipt algorithm that is a JS object-prototype
    // member name MUST NOT resolve through `SIG_ALG_RANK` to a truthy method.
    for (const evil of ["toString", "constructor", "__proto__", "hasOwnProperty"]) {
      const res = satisfiesIssuerPqc(rec, AFTER, evil as unknown as Parameters<typeof satisfiesIssuerPqc>[2]);
      assert.equal(res.ok, false, `expected ${evil} to be rejected`);
      if (!res.ok) {
        assert.equal(res.reason, `unsupported_receipt_sig_alg:${evil}`);
      }
    }
  });
});

describe("parseTrustedIssuerList — pqc_mandatory field", () => {
  it("parses a valid pqc_mandatory onto the record", () => {
    const { doc } = makeSignedDoc({
      issuers: [
        defaultIssuerRecord({
          pqc_mandatory: { min_sig_alg: "ml-dsa-65", mandatory_from: CUTOVER },
        }),
      ],
    });
    const res = parseTrustedIssuerList(doc);
    assert.equal(res.ok, true);
    if (res.ok) {
      const rec = res.doc.issuers[0];
      assert.ok(rec);
      assert.deepEqual(rec.pqc_mandatory, {
        min_sig_alg: "ml-dsa-65",
        mandatory_from: CUTOVER,
      });
    }
  });

  it("omits pqc_mandatory entirely when absent (preserves prior record shape)", () => {
    const { doc } = makeSignedDoc(); // default record has no pqc_mandatory
    const res = parseTrustedIssuerList(doc);
    assert.equal(res.ok, true);
    if (res.ok) {
      const rec = res.doc.issuers[0];
      assert.ok(rec);
      assert.equal("pqc_mandatory" in rec, false);
      assert.equal(rec.pqc_mandatory, undefined);
    }
  });

  it("treats an explicit pqc_mandatory:null input as absent (omits the key)", () => {
    const { doc } = makeSignedDoc({
      issuers: [defaultIssuerRecord({ pqc_mandatory: null })],
    });
    const res = parseTrustedIssuerList(doc);
    assert.equal(res.ok, true);
    if (res.ok) {
      const rec = res.doc.issuers[0];
      assert.ok(rec);
      assert.equal("pqc_mandatory" in rec, false);
    }
  });

  it("accepts an UNREGISTERED min_sig_alg structurally (forward-compat)", () => {
    // Parse must not gate on SIG_ALGS membership — a manifest may name a future
    // algorithm. The fail-closed happens at policy eval, not parse.
    const { doc } = makeSignedDoc({
      issuers: [
        defaultIssuerRecord({
          pqc_mandatory: {
            min_sig_alg: "ml-dsa-87",
            mandatory_from: CUTOVER,
          },
        }),
      ],
    });
    const res = parseTrustedIssuerList(doc);
    assert.equal(res.ok, true);
  });

  it("rejects an empty min_sig_alg", () => {
    const { doc } = makeSignedDoc({
      issuers: [
        defaultIssuerRecord({
          pqc_mandatory: { min_sig_alg: "", mandatory_from: CUTOVER },
        }),
      ],
    });
    const res = parseTrustedIssuerList(doc);
    assert.equal(res.ok, false);
  });

  it("rejects a malformed mandatory_from", () => {
    const { doc } = makeSignedDoc({
      issuers: [
        defaultIssuerRecord({
          pqc_mandatory: { min_sig_alg: "ml-dsa-65", mandatory_from: "2030" },
        }),
      ],
    });
    const res = parseTrustedIssuerList(doc);
    assert.equal(res.ok, false);
  });

  it("rejects a non-object pqc_mandatory", () => {
    const { doc } = makeSignedDoc({
      issuers: [
        defaultIssuerRecord({
          // deliberately wrong shape
          pqc_mandatory: "ml-dsa-65" as unknown as null,
        }),
      ],
    });
    const res = parseTrustedIssuerList(doc);
    assert.equal(res.ok, false);
  });
});
