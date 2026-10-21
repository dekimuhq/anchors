/**
 * Tests for the eidas.qereg profile validator (AAR §5.4).
 */

import { describe, it } from "node:test";
import * as assert from "node:assert/strict";
import type { AarIssuanceBody, AarRevocationBody } from "@dekimuhq/aar";
import {
  validateEidasQereg,
  validateEidasQeregProfile,
  EIDAS_QEREG_PROFILE_ID,
} from "../src/eidas-qereg.ts";

const H = (c: string) => `sha256:${c.repeat(64)}`;

function validIssuance(): AarIssuanceBody {
  return {
    event_type: "issuance",
    service_type: "qereg",
    service_policy_oid: "0.4.0.194112.1.4",
    service_recipient_commit: H("r"),
    artefact_hash: H("a"),
    artefact_metadata_commit: H("m"),
    signature_format: null,
    qcert_serial_commit: null,
    tsl_country: "IT",
    tsl_entry_hash: H("e"),
    tsl_signed_tree_head_root: H("t"),
    tsl_tree_size: 5,
    tsl_inclusion_proof: [],
    tsl_log_time: "2026-05-21T10:00:00Z",
    atr_transfer_hash: null,
    qts_attestation_hash: null,
  };
}

function validRevocation(): AarRevocationBody {
  return {
    event_type: "revocation",
    reason: "recipient_request",
    reason_ref_hash: null,
    tsl_country: "IT",
    tsl_entry_hash: H("e"),
    tsl_signed_tree_head_root: H("t"),
    tsl_tree_size: 6,
    tsl_inclusion_proof: [],
    tsl_log_time: "2026-05-21T11:00:00Z",
    qts_attestation_hash: null,
  };
}

describe("eidas.qereg profile validator", () => {
  it("passes for a valid issuance body", () => {
    const out = validateEidasQereg(validIssuance());
    assert.deepEqual(out.errors, []);
  });

  it("skips validation on revocation events", () => {
    const out = validateEidasQereg(validRevocation());
    assert.deepEqual(out.errors, []);
  });

  it("rejects wrong service_type", () => {
    const body = validIssuance();
    body.service_type = "qes";
    const out = validateEidasQereg(body);
    assert.ok(out.errors.includes("eidas.qereg.service_type_mismatch"));
  });

  it("rejects null artefact_hash", () => {
    const body = validIssuance();
    body.artefact_hash = null;
    const out = validateEidasQereg(body);
    assert.ok(out.errors.includes("eidas.qereg.artefact_hash_required"));
  });

  it("rejects non-EU/EEA tsl_country", () => {
    const body = validIssuance();
    body.tsl_country = "BR";
    const out = validateEidasQereg(body);
    assert.ok(out.errors.includes("eidas.qereg.tsl_country_not_eu_eea"));
  });

  it("collects multiple errors", () => {
    const body = validIssuance();
    body.service_type = "qts";
    body.artefact_hash = null;
    body.tsl_country = "US";
    const out = validateEidasQereg(body);
    assert.equal(out.errors.length, 3);
  });

  it("adapter returns profile_id and ok=true on valid", () => {
    const out = validateEidasQeregProfile({} as never, validIssuance(), {});
    assert.equal(out.profile_id, EIDAS_QEREG_PROFILE_ID);
    assert.equal(out.ok, true);
    assert.equal(out.reason, undefined);
  });

  it("adapter surfaces first error on invalid", () => {
    const body = validIssuance();
    body.service_type = "qts";
    const out = validateEidasQeregProfile({} as never, body, {});
    assert.equal(out.ok, false);
    assert.equal(out.reason, "eidas.qereg.service_type_mismatch");
  });

  it("adapter passes on revocation", () => {
    const out = validateEidasQeregProfile({} as never, validRevocation(), {});
    assert.equal(out.ok, true);
  });
});
