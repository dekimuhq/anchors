/**
 * Tests for the eidas.qwallet profile validator (AAR §5.7).
 */

import { describe, it } from "node:test";
import * as assert from "node:assert/strict";
import type { AarIssuanceBody, AarRevocationBody } from "@dekimuhq/aar";
import {
  validateEidasQwallet,
  validateEidasQwalletProfile,
  EIDAS_QWALLET_PROFILE_ID,
} from "../src/eidas-qwallet.ts";

const H = (c: string) => `sha256:${c.repeat(64)}`;

function validIssuance(): AarIssuanceBody {
  return {
    event_type: "issuance",
    service_type: "qwallet",
    service_policy_oid: "0.4.0.2024.1.1",
    service_recipient_commit: H("r"),
    artefact_hash: null,
    artefact_metadata_commit: H("m"),
    signature_format: null,
    qcert_serial_commit: null,
    tsl_country: "SE",
    tsl_entry_hash: H("e"),
    tsl_signed_tree_head_root: H("t"),
    tsl_tree_size: 1,
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
    tsl_country: "SE",
    tsl_entry_hash: H("e"),
    tsl_signed_tree_head_root: H("t"),
    tsl_tree_size: 2,
    tsl_inclusion_proof: [],
    tsl_log_time: "2026-05-21T11:00:00Z",
    qts_attestation_hash: null,
  };
}

describe("eidas.qwallet profile validator", () => {
  it("passes for a valid issuance body", () => {
    const out = validateEidasQwallet(validIssuance());
    assert.deepEqual(out.errors, []);
  });

  it("skips validation on revocation events", () => {
    const out = validateEidasQwallet(validRevocation());
    assert.deepEqual(out.errors, []);
  });

  it("rejects wrong service_type", () => {
    const body = validIssuance();
    body.service_type = "qattest";
    const out = validateEidasQwallet(body);
    assert.ok(out.errors.includes("eidas.qwallet.service_type_mismatch"));
  });

  it("rejects any non-qwallet service_type", () => {
    const serviceTypes = ["qes", "qeseal", "qts", "qereg", "qcert_natural", "qcert_legal", "qattest"] as const;
    for (const st of serviceTypes) {
      const body = validIssuance();
      body.service_type = st;
      const out = validateEidasQwallet(body);
      assert.ok(out.errors.includes("eidas.qwallet.service_type_mismatch"), `${st} should be rejected`);
    }
  });

  it("adapter returns profile_id and ok=true on valid", () => {
    const out = validateEidasQwalletProfile({} as never, validIssuance(), {});
    assert.equal(out.profile_id, EIDAS_QWALLET_PROFILE_ID);
    assert.equal(out.ok, true);
    assert.equal(out.reason, undefined);
  });

  it("adapter surfaces first error on invalid", () => {
    const body = validIssuance();
    body.service_type = "qattest";
    const out = validateEidasQwalletProfile({} as never, body, {});
    assert.equal(out.ok, false);
    assert.equal(out.reason, "eidas.qwallet.service_type_mismatch");
  });

  it("adapter passes on revocation", () => {
    const out = validateEidasQwalletProfile({} as never, validRevocation(), {});
    assert.equal(out.ok, true);
  });
});
