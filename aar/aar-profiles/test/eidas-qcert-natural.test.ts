/**
 * Tests for the eidas.qcert.natural profile validator (AAR §5.5).
 */

import { describe, it } from "node:test";
import * as assert from "node:assert/strict";
import type { AarIssuanceBody, AarRevocationBody } from "@dekimuhq/aar";
import {
  validateEidasQcertNatural,
  validateEidasQcertNaturalProfile,
  EIDAS_QCERT_NATURAL_PROFILE_ID,
} from "../src/eidas-qcert-natural.ts";

const H = (c: string) => `sha256:${c.repeat(64)}`;

function validIssuance(): AarIssuanceBody {
  return {
    event_type: "issuance",
    service_type: "qcert_natural",
    service_policy_oid: "0.4.0.194112.1.1",
    service_recipient_commit: H("r"),
    artefact_hash: null,
    artefact_metadata_commit: H("m"),
    signature_format: null,
    qcert_serial_commit: H("q"),
    tsl_country: "ES",
    tsl_entry_hash: H("e"),
    tsl_signed_tree_head_root: H("t"),
    tsl_tree_size: 100,
    tsl_inclusion_proof: [H("p")],
    tsl_log_time: "2026-05-21T10:00:00Z",
    atr_transfer_hash: null,
    qts_attestation_hash: null,
  };
}

function validRevocation(): AarRevocationBody {
  return {
    event_type: "revocation",
    reason: "superseded",
    reason_ref_hash: null,
    tsl_country: "ES",
    tsl_entry_hash: H("e"),
    tsl_signed_tree_head_root: H("t"),
    tsl_tree_size: 101,
    tsl_inclusion_proof: [],
    tsl_log_time: "2026-05-21T11:00:00Z",
    qts_attestation_hash: null,
  };
}

describe("eidas.qcert.natural profile validator", () => {
  it("passes for a valid issuance body", () => {
    const out = validateEidasQcertNatural(validIssuance());
    assert.deepEqual(out.errors, []);
  });

  it("skips validation on revocation events", () => {
    const out = validateEidasQcertNatural(validRevocation());
    assert.deepEqual(out.errors, []);
  });

  it("rejects wrong service_type", () => {
    const body = validIssuance();
    body.service_type = "qcert_legal";
    const out = validateEidasQcertNatural(body);
    assert.ok(out.errors.includes("eidas.qcert.natural.service_type_mismatch"));
  });

  it("rejects null qcert_serial_commit", () => {
    const body = validIssuance();
    body.qcert_serial_commit = null;
    const out = validateEidasQcertNatural(body);
    assert.ok(out.errors.includes("eidas.qcert.natural.qcert_serial_commit_missing"));
  });

  it("rejects non-null signature_format", () => {
    const body = validIssuance();
    body.signature_format = "pades_b_b";
    const out = validateEidasQcertNatural(body);
    assert.ok(out.errors.includes("eidas.qcert.natural.signature_format_must_be_null"));
  });

  it("rejects non-EU/EEA tsl_country", () => {
    const body = validIssuance();
    body.tsl_country = "AU";
    const out = validateEidasQcertNatural(body);
    assert.ok(out.errors.includes("eidas.qcert.natural.tsl_country_not_eu_eea"));
  });

  it("collects multiple errors", () => {
    const body = validIssuance();
    body.service_type = "qes";
    body.qcert_serial_commit = null;
    body.signature_format = "xades_b_t";
    body.tsl_country = "MX";
    const out = validateEidasQcertNatural(body);
    assert.equal(out.errors.length, 4);
  });

  it("adapter returns profile_id and ok=true on valid", () => {
    const out = validateEidasQcertNaturalProfile({} as never, validIssuance(), {});
    assert.equal(out.profile_id, EIDAS_QCERT_NATURAL_PROFILE_ID);
    assert.equal(out.ok, true);
    assert.equal(out.reason, undefined);
  });

  it("adapter surfaces first error on invalid", () => {
    const body = validIssuance();
    body.service_type = "qcert_legal";
    const out = validateEidasQcertNaturalProfile({} as never, body, {});
    assert.equal(out.ok, false);
    assert.equal(out.reason, "eidas.qcert.natural.service_type_mismatch");
  });

  it("adapter passes on revocation", () => {
    const out = validateEidasQcertNaturalProfile({} as never, validRevocation(), {});
    assert.equal(out.ok, true);
  });
});
