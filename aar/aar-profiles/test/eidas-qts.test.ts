/**
 * Tests for the eidas.qts profile validator (AAR §5.3).
 */

import { describe, it } from "node:test";
import * as assert from "node:assert/strict";
import type { AarIssuanceBody, AarRevocationBody } from "@dekimuhq/aar";
import {
  validateEidasQts,
  validateEidasQtsProfile,
  EIDAS_QTS_PROFILE_ID,
} from "../src/eidas-qts.ts";

const H = (c: string) => `sha256:${c.repeat(64)}`;

function validIssuance(): AarIssuanceBody {
  return {
    event_type: "issuance",
    service_type: "qts",
    service_policy_oid: "0.4.0.2023.1.1",
    service_recipient_commit: H("r"),
    artefact_hash: H("a"),
    artefact_metadata_commit: H("m"),
    signature_format: null,
    qcert_serial_commit: H("q"),
    tsl_country: "NL",
    tsl_entry_hash: H("e"),
    tsl_signed_tree_head_root: H("t"),
    tsl_tree_size: 20,
    tsl_inclusion_proof: [H("p")],
    tsl_log_time: "2026-05-21T10:00:00Z",
    atr_transfer_hash: null,
    qts_attestation_hash: null,
  };
}

function validRevocation(): AarRevocationBody {
  return {
    event_type: "revocation",
    reason: "policy_violation",
    reason_ref_hash: null,
    tsl_country: "NL",
    tsl_entry_hash: H("e"),
    tsl_signed_tree_head_root: H("t"),
    tsl_tree_size: 21,
    tsl_inclusion_proof: [],
    tsl_log_time: "2026-05-21T11:00:00Z",
    qts_attestation_hash: null,
  };
}

describe("eidas.qts profile validator", () => {
  it("passes for a valid issuance body", () => {
    const out = validateEidasQts(validIssuance());
    assert.deepEqual(out.errors, []);
  });

  it("skips validation on revocation events", () => {
    const out = validateEidasQts(validRevocation());
    assert.deepEqual(out.errors, []);
  });

  it("rejects wrong service_type", () => {
    const body = validIssuance();
    body.service_type = "qes";
    const out = validateEidasQts(body);
    assert.ok(out.errors.includes("eidas.qts.service_type_mismatch"));
  });

  it("rejects null qcert_serial_commit", () => {
    const body = validIssuance();
    body.qcert_serial_commit = null;
    const out = validateEidasQts(body);
    assert.ok(out.errors.includes("eidas.qts.qcert_serial_commit_missing"));
  });

  it("rejects non-EU/EEA tsl_country", () => {
    const body = validIssuance();
    body.tsl_country = "CH";
    const out = validateEidasQts(body);
    assert.ok(out.errors.includes("eidas.qts.tsl_country_not_eu_eea"));
  });

  it("does NOT check signature_format (QTS profile does not mandate it)", () => {
    const body = validIssuance();
    body.signature_format = null;
    const out = validateEidasQts(body);
    assert.ok(!out.errors.some(e => e.includes("signature_format")));
  });

  it("collects multiple errors", () => {
    const body = validIssuance();
    body.service_type = "qereg";
    body.qcert_serial_commit = null;
    body.tsl_country = "US";
    const out = validateEidasQts(body);
    assert.equal(out.errors.length, 3);
  });

  it("adapter returns profile_id and ok=true on valid", () => {
    const out = validateEidasQtsProfile({} as never, validIssuance(), {});
    assert.equal(out.profile_id, EIDAS_QTS_PROFILE_ID);
    assert.equal(out.ok, true);
    assert.equal(out.reason, undefined);
  });

  it("adapter surfaces first error on invalid", () => {
    const body = validIssuance();
    body.service_type = "qes";
    const out = validateEidasQtsProfile({} as never, body, {});
    assert.equal(out.ok, false);
    assert.equal(out.reason, "eidas.qts.service_type_mismatch");
  });

  it("adapter passes on revocation", () => {
    const out = validateEidasQtsProfile({} as never, validRevocation(), {});
    assert.equal(out.ok, true);
  });
});
