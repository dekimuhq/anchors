/**
 * Tests for the eidas.qcert.legal profile validator (AAR §5.6).
 */

import { describe, it } from "node:test";
import * as assert from "node:assert/strict";
import type { AarIssuanceBody, AarRevocationBody } from "@dekimuhq/aar";
import {
  validateEidasQcertLegal,
  validateEidasQcertLegalProfile,
  EIDAS_QCERT_LEGAL_PROFILE_ID,
} from "../src/eidas-qcert-legal.ts";

const H = (c: string) => `sha256:${c.repeat(64)}`;

function validIssuance(): AarIssuanceBody {
  return {
    event_type: "issuance",
    service_type: "qcert_legal",
    service_policy_oid: "0.4.0.194112.1.5",
    service_recipient_commit: H("r"),
    artefact_hash: null,
    artefact_metadata_commit: H("m"),
    signature_format: null,
    qcert_serial_commit: H("q"),
    tsl_country: "PL",
    tsl_entry_hash: H("e"),
    tsl_signed_tree_head_root: H("t"),
    tsl_tree_size: 50,
    tsl_inclusion_proof: [H("p")],
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
    tsl_country: "PL",
    tsl_entry_hash: H("e"),
    tsl_signed_tree_head_root: H("t"),
    tsl_tree_size: 51,
    tsl_inclusion_proof: [],
    tsl_log_time: "2026-05-21T11:00:00Z",
    qts_attestation_hash: null,
  };
}

describe("eidas.qcert.legal profile validator", () => {
  it("passes for a valid issuance body", () => {
    const out = validateEidasQcertLegal(validIssuance());
    assert.deepEqual(out.errors, []);
  });

  it("skips validation on revocation events", () => {
    const out = validateEidasQcertLegal(validRevocation());
    assert.deepEqual(out.errors, []);
  });

  it("rejects wrong service_type", () => {
    const body = validIssuance();
    body.service_type = "qcert_natural";
    const out = validateEidasQcertLegal(body);
    assert.ok(out.errors.includes("eidas.qcert.legal.service_type_mismatch"));
  });

  it("rejects null qcert_serial_commit", () => {
    const body = validIssuance();
    body.qcert_serial_commit = null;
    const out = validateEidasQcertLegal(body);
    assert.ok(out.errors.includes("eidas.qcert.legal.qcert_serial_commit_missing"));
  });

  it("rejects non-null signature_format", () => {
    const body = validIssuance();
    body.signature_format = "cades_b_lt";
    const out = validateEidasQcertLegal(body);
    assert.ok(out.errors.includes("eidas.qcert.legal.signature_format_must_be_null"));
  });

  it("rejects non-EU/EEA tsl_country", () => {
    const body = validIssuance();
    body.tsl_country = "IN";
    const out = validateEidasQcertLegal(body);
    assert.ok(out.errors.includes("eidas.qcert.legal.tsl_country_not_eu_eea"));
  });

  it("collects multiple errors", () => {
    const body = validIssuance();
    body.service_type = "qwallet";
    body.qcert_serial_commit = null;
    body.signature_format = "jades_b_b";
    body.tsl_country = "KR";
    const out = validateEidasQcertLegal(body);
    assert.equal(out.errors.length, 4);
  });

  it("adapter returns profile_id and ok=true on valid", () => {
    const out = validateEidasQcertLegalProfile({} as never, validIssuance(), {});
    assert.equal(out.profile_id, EIDAS_QCERT_LEGAL_PROFILE_ID);
    assert.equal(out.ok, true);
    assert.equal(out.reason, undefined);
  });

  it("adapter surfaces first error on invalid", () => {
    const body = validIssuance();
    body.service_type = "qcert_natural";
    const out = validateEidasQcertLegalProfile({} as never, body, {});
    assert.equal(out.ok, false);
    assert.equal(out.reason, "eidas.qcert.legal.service_type_mismatch");
  });

  it("adapter passes on revocation", () => {
    const out = validateEidasQcertLegalProfile({} as never, validRevocation(), {});
    assert.equal(out.ok, true);
  });
});
