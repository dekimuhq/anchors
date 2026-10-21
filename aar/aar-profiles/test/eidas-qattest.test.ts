/**
 * Tests for the eidas.qattest profile validator (AAR §5.8).
 */

import { describe, it } from "node:test";
import * as assert from "node:assert/strict";
import type { AarIssuanceBody, AarRevocationBody } from "@dekimuhq/aar";
import {
  validateEidasQattest,
  validateEidasQattestProfile,
  EIDAS_QATTEST_PROFILE_ID,
} from "../src/eidas-qattest.ts";

const H = (c: string) => `sha256:${c.repeat(64)}`;

function validIssuance(): AarIssuanceBody {
  return {
    event_type: "issuance",
    service_type: "qattest",
    service_policy_oid: "0.4.0.2024.2.1",
    service_recipient_commit: H("r"),
    artefact_hash: null,
    artefact_metadata_commit: H("m"),
    signature_format: null,
    qcert_serial_commit: null,
    tsl_country: "FI",
    tsl_entry_hash: H("e"),
    tsl_signed_tree_head_root: H("t"),
    tsl_tree_size: 3,
    tsl_inclusion_proof: [],
    tsl_log_time: "2026-05-21T10:00:00Z",
    atr_transfer_hash: null,
    qts_attestation_hash: null,
  };
}

function validRevocation(): AarRevocationBody {
  return {
    event_type: "revocation",
    reason: "controller_decision",
    reason_ref_hash: null,
    tsl_country: "FI",
    tsl_entry_hash: H("e"),
    tsl_signed_tree_head_root: H("t"),
    tsl_tree_size: 4,
    tsl_inclusion_proof: [],
    tsl_log_time: "2026-05-21T11:00:00Z",
    qts_attestation_hash: null,
  };
}

describe("eidas.qattest profile validator", () => {
  it("passes for a valid issuance body", () => {
    const out = validateEidasQattest(validIssuance());
    assert.deepEqual(out.errors, []);
  });

  it("skips validation on revocation events", () => {
    const out = validateEidasQattest(validRevocation());
    assert.deepEqual(out.errors, []);
  });

  it("rejects wrong service_type", () => {
    const body = validIssuance();
    body.service_type = "qwallet";
    const out = validateEidasQattest(body);
    assert.ok(out.errors.includes("eidas.qattest.service_type_mismatch"));
  });

  it("rejects any non-qattest service_type", () => {
    const serviceTypes = ["qes", "qeseal", "qts", "qereg", "qcert_natural", "qcert_legal", "qwallet"] as const;
    for (const st of serviceTypes) {
      const body = validIssuance();
      body.service_type = st;
      const out = validateEidasQattest(body);
      assert.ok(out.errors.includes("eidas.qattest.service_type_mismatch"), `${st} should be rejected`);
    }
  });

  it("adapter returns profile_id and ok=true on valid", () => {
    const out = validateEidasQattestProfile({} as never, validIssuance(), {});
    assert.equal(out.profile_id, EIDAS_QATTEST_PROFILE_ID);
    assert.equal(out.ok, true);
    assert.equal(out.reason, undefined);
  });

  it("adapter surfaces first error on invalid", () => {
    const body = validIssuance();
    body.service_type = "qwallet";
    const out = validateEidasQattestProfile({} as never, body, {});
    assert.equal(out.ok, false);
    assert.equal(out.reason, "eidas.qattest.service_type_mismatch");
  });

  it("adapter passes on revocation", () => {
    const out = validateEidasQattestProfile({} as never, validRevocation(), {});
    assert.equal(out.ok, true);
  });
});
