import { describe, it } from "node:test";
import * as assert from "node:assert/strict";
import { composeAar } from "../src/compose.ts";

const H = (c: string) => `sha256:${c.repeat(64)}`;

const issuanceEnvelope = {
  id: "r1",
  iss: "did:web:qtsp.example",
  iat: "2026-05-16T10:00:00Z",
  prev: null,
  subject: H("s"),
  body: {
    event_type: "issuance",
    service_type: "qes",
    service_policy_oid: "0.4.0.194112.1.2",
    service_recipient_commit: H("a"),
    artefact_hash: H("b"),
    artefact_metadata_commit: H("c"),
    signature_format: "pades_b_lta",
    qcert_serial_commit: H("d"),
    tsl_country: "ES",
    tsl_entry_hash: H("e"),
    tsl_signed_tree_head_root: H("f"),
    tsl_tree_size: 100,
    tsl_inclusion_proof: [H("g")],
    tsl_log_time: "2026-05-16T08:00:00Z",
    atr_transfer_hash: null,
  },
};

describe("composeAar", () => {
  it("returns ok when no resolver is provided", async () => {
    const r = await composeAar(
      { envelope: issuanceEnvelope as never, opts: {} } as never,
    );
    assert.strictEqual(r.ok, true);
  });

  it("returns ok for standalone issuance with resolver", async () => {
    const resolve = async () => null;
    const r = await composeAar({
      envelope: issuanceEnvelope as never,
      opts: { resolveReceiptById: resolve },
    } as never);
    assert.strictEqual(r.ok, true);
  });
});
