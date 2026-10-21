/**
 * Tests for the eidas.qeseal profile validator (AAR §5.2).
 */

import { describe, it } from "node:test";
import * as assert from "node:assert/strict";
import type { AarIssuanceBody, AarRevocationBody } from "@dekimuhq/aar";
import {
  validateEidasQeseal,
  validateEidasQesealProfile,
  EIDAS_QESEAL_PROFILE_ID,
} from "../src/eidas-qeseal.ts";

const H = (c: string) => `sha256:${c.repeat(64)}`;

function validIssuance(): AarIssuanceBody {
  return {
    event_type: "issuance",
    service_type: "qeseal",
    service_policy_oid: "0.4.0.194112.1.3",
    service_recipient_commit: H("r"),
    artefact_hash: H("a"),
    artefact_metadata_commit: H("m"),
    signature_format: "xades_b_lta",
    qcert_serial_commit: H("q"),
    tsl_country: "FR",
    tsl_entry_hash: H("e"),
    tsl_signed_tree_head_root: H("t"),
    tsl_tree_size: 10,
    tsl_inclusion_proof: [H("p1")],
    tsl_log_time: "2026-05-21T10:00:00Z",
    atr_transfer_hash: null,
    qts_attestation_hash: null,
  };
}

function validRevocation(): AarRevocationBody {
  return {
    event_type: "revocation",
    reason: "tsl_delisted",
    reason_ref_hash: null,
    tsl_country: "FR",
    tsl_entry_hash: H("e"),
    tsl_signed_tree_head_root: H("t"),
    tsl_tree_size: 11,
    tsl_inclusion_proof: [],
    tsl_log_time: "2026-05-21T12:00:00Z",
    qts_attestation_hash: null,
  };
}

describe("eidas.qeseal profile validator", () => {
  it("passes for a valid issuance body", () => {
    const out = validateEidasQeseal(validIssuance());
    assert.deepEqual(out.errors, []);
  });

  it("skips validation on revocation events", () => {
    const out = validateEidasQeseal(validRevocation());
    assert.deepEqual(out.errors, []);
  });

  it("rejects wrong service_type", () => {
    const body = validIssuance();
    body.service_type = "qes";
    const out = validateEidasQeseal(body);
    assert.ok(out.errors.includes("eidas.qeseal.service_type_mismatch"));
  });

  it("rejects null signature_format", () => {
    const body = validIssuance();
    body.signature_format = null;
    const out = validateEidasQeseal(body);
    assert.ok(out.errors.includes("eidas.qeseal.signature_format_invalid"));
  });

  it("rejects null qcert_serial_commit", () => {
    const body = validIssuance();
    body.qcert_serial_commit = null;
    const out = validateEidasQeseal(body);
    assert.ok(out.errors.includes("eidas.qeseal.qcert_serial_commit_missing"));
  });

  it("rejects non-EU/EEA tsl_country", () => {
    const body = validIssuance();
    body.tsl_country = "JP";
    const out = validateEidasQeseal(body);
    assert.ok(out.errors.includes("eidas.qeseal.tsl_country_not_eu_eea"));
  });

  it("collects multiple errors", () => {
    const body = validIssuance();
    body.service_type = "qes";
    body.signature_format = null;
    body.qcert_serial_commit = null;
    body.tsl_country = "US";
    const out = validateEidasQeseal(body);
    assert.equal(out.errors.length, 4);
  });

  it("adapter returns profile_id and ok=true on valid", () => {
    const out = validateEidasQesealProfile({} as never, validIssuance(), {});
    assert.equal(out.profile_id, EIDAS_QESEAL_PROFILE_ID);
    assert.equal(out.ok, true);
    assert.equal(out.reason, undefined);
  });

  it("adapter surfaces first error on invalid", () => {
    const body = validIssuance();
    body.service_type = "qes";
    const out = validateEidasQesealProfile({} as never, body, {});
    assert.equal(out.ok, false);
    assert.equal(out.reason, "eidas.qeseal.service_type_mismatch");
  });

  it("adapter passes on revocation", () => {
    const out = validateEidasQesealProfile({} as never, validRevocation(), {});
    assert.equal(out.ok, true);
  });
});
