/**
 * Tests for the eidas.qes profile validator (AAR §5.1).
 */

import { describe, it } from "node:test";
import * as assert from "node:assert/strict";
import type { AarIssuanceBody, AarRevocationBody } from "@dekimuhq/aar";
import {
  validateEidasQes,
  validateEidasQesProfile,
  EIDAS_QES_PROFILE_ID,
} from "../src/eidas-qes.ts";

const H = (c: string) => `sha256:${c.repeat(64)}`;

function validIssuance(): AarIssuanceBody {
  return {
    event_type: "issuance",
    service_type: "qes",
    service_policy_oid: "0.4.0.194112.1.2",
    service_recipient_commit: H("r"),
    artefact_hash: H("a"),
    artefact_metadata_commit: H("m"),
    signature_format: "pades_b_lt",
    qcert_serial_commit: H("q"),
    tsl_country: "DE",
    tsl_entry_hash: H("e"),
    tsl_signed_tree_head_root: H("t"),
    tsl_tree_size: 42,
    tsl_inclusion_proof: [H("p1"), H("p2")],
    tsl_log_time: "2026-05-21T10:00:00Z",
    atr_transfer_hash: null,
    qts_attestation_hash: null,
  };
}

function validRevocation(): AarRevocationBody {
  return {
    event_type: "revocation",
    reason: "key_compromise",
    reason_ref_hash: null,
    tsl_country: "DE",
    tsl_entry_hash: H("e"),
    tsl_signed_tree_head_root: H("t"),
    tsl_tree_size: 43,
    tsl_inclusion_proof: [],
    tsl_log_time: "2026-05-21T11:00:00Z",
    qts_attestation_hash: null,
  };
}

describe("eidas.qes profile validator", () => {
  it("passes for a valid issuance body", () => {
    const out = validateEidasQes(validIssuance());
    assert.deepEqual(out.errors, []);
  });

  it("skips validation on revocation events", () => {
    const out = validateEidasQes(validRevocation());
    assert.deepEqual(out.errors, []);
  });

  it("rejects wrong service_type", () => {
    const body = validIssuance();
    body.service_type = "qeseal";
    const out = validateEidasQes(body);
    assert.ok(out.errors.includes("eidas.qes.service_type_mismatch"));
  });

  it("rejects null signature_format", () => {
    const body = validIssuance();
    body.signature_format = null;
    const out = validateEidasQes(body);
    assert.ok(out.errors.includes("eidas.qes.signature_format_invalid"));
  });

  it("rejects unknown signature_format string", () => {
    const body = validIssuance();
    (body as AarIssuanceBody).signature_format = "unknown_format" as never;
    const out = validateEidasQes(body);
    assert.ok(out.errors.includes("eidas.qes.signature_format_invalid"));
  });

  it("accepts all valid signature formats", () => {
    const formats = [
      "pades_b_b", "pades_b_t", "pades_b_lt", "pades_b_lta",
      "xades_b_b", "xades_b_t", "xades_b_lt", "xades_b_lta",
      "cades_b_b", "cades_b_t", "cades_b_lt", "cades_b_lta",
      "jades_b_b", "jades_b_t", "jades_b_lt", "jades_b_lta",
    ] as const;
    for (const fmt of formats) {
      const body = validIssuance();
      body.signature_format = fmt;
      const out = validateEidasQes(body);
      assert.ok(!out.errors.includes("eidas.qes.signature_format_invalid"), `format ${fmt} should be valid`);
    }
  });

  it("rejects null qcert_serial_commit", () => {
    const body = validIssuance();
    body.qcert_serial_commit = null;
    const out = validateEidasQes(body);
    assert.ok(out.errors.includes("eidas.qes.qcert_serial_commit_missing"));
  });

  it("rejects non-EU/EEA tsl_country", () => {
    const body = validIssuance();
    body.tsl_country = "US";
    const out = validateEidasQes(body);
    assert.ok(out.errors.includes("eidas.qes.tsl_country_not_eu_eea"));
  });

  it("accepts all EU/EEA countries", () => {
    const countries = [
      "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR",
      "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL",
      "PL", "PT", "RO", "SK", "SI", "ES", "SE", "IS", "LI", "NO",
    ];
    for (const cc of countries) {
      const body = validIssuance();
      body.tsl_country = cc;
      const out = validateEidasQes(body);
      assert.ok(!out.errors.includes("eidas.qes.tsl_country_not_eu_eea"), `country ${cc} should be accepted`);
    }
  });

  it("collects multiple errors", () => {
    const body = validIssuance();
    body.service_type = "qts";
    body.signature_format = null;
    body.qcert_serial_commit = null;
    body.tsl_country = "CN";
    const out = validateEidasQes(body);
    assert.equal(out.errors.length, 4);
  });

  it("adapter returns profile_id and ok=true on valid", () => {
    const out = validateEidasQesProfile({} as never, validIssuance(), {});
    assert.equal(out.profile_id, EIDAS_QES_PROFILE_ID);
    assert.equal(out.ok, true);
    assert.equal(out.reason, undefined);
  });

  it("adapter surfaces first error on invalid", () => {
    const body = validIssuance();
    body.service_type = "qts";
    const out = validateEidasQesProfile({} as never, body, {});
    assert.equal(out.ok, false);
    assert.equal(out.reason, "eidas.qes.service_type_mismatch");
  });

  it("adapter passes on revocation", () => {
    const out = validateEidasQesProfile({} as never, validRevocation(), {});
    assert.equal(out.ok, true);
  });
});
