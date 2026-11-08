/**
 * Body-keyed TSA mandate on every verify path (FAMILY-CONSISTENCY §2).
 *
 * ABR `breach.detected`, AAR issuance + `service_type: qts` and ANR
 * `notice.aiact.art50_transparency` are MANDATORY, keyed on the signed body
 * rather than on `opts.profile`. The mandate used to run only as a post-step
 * in each package's top-level `verifyReceipt`, so the CLI dispatch (which
 * calls `<family>Family.verifyReceipt`) and direct manifest callers accepted
 * such receipts with no `tsa` or a junk one. It is now the family's
 * `body_tsa_mandate` hook, applied inside the shared pipeline.
 *
 * Each case checks both the CLI dispatch (`verifyAnchor`) and the family
 * manifest's `verifyReceipt` called directly, with no `profile` option.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import type { FamilyManifest } from "@dekimuhq/anchors-envelope";
import { aar, abr, anr } from "@dekimuhq/anchors";
import { verifyAnchor } from "../src/dispatch.ts";
import { selfCertifyingResolveKey } from "../src/resolve-key.ts";

const opts = { resolveKey: selfCertifyingResolveKey, tsaAnchors: [] };
const H = (c: string): string => `sha256:${c.repeat(64)}`;

function signingKey(): { kid: string; privateKey: Uint8Array } {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const der = privateKey.export({ format: "der", type: "pkcs8" }) as Buffer;
  return { kid: "k-cli-test", privateKey: new Uint8Array(der.subarray(-32)) };
}

const anchor = (log: string) => ({
  log,
  leaf_index: 0,
  inclusion_proof: [],
  tree_head_root: H("0"),
  tree_size: 1,
  log_time: "2026-05-19T00:00:00Z",
});

const policy = {
  policy_uri: "https://issuer.example/policy/v1",
  policy_hash: H("e"),
  policy_version: "1.0.0",
};

/** `tsa` is outside the signature: anyone can attach this to a genuine receipt. */
const JUNK_TSA = {
  v: 1 as const,
  tsr: "AAAA",
  alg: "sha-256" as const,
  tsa_url: "https://tsa.example",
  tsa_cert_chain_sha256: [],
  issued_at: "2026-05-19T00:00:00Z",
};

interface Case {
  name: string;
  family: FamilyManifest;
  mint: () => Promise<Record<string, unknown>>;
}

const CASES: Case[] = [
  {
    name: "ABR breach.detected",
    family: abr.abrFamily as FamilyManifest,
    mint: async () =>
      (await abr.mintDetected({
        issuer: "did:web:controller.example",
        profile: "breach.gdpr.art33",
        incident_correlation_id: "INC-2026-0001",
        ...policy,
        anchor: anchor("https://verify.dekimu.com/abr/v1"),
        signingKey: signingKey(),
        detected_at: "2026-05-19T12:00:00Z",
        severity_class: "risk",
        affected_data_categories: ["email", "name"],
        affected_data_hash: H("a"),
        affected_count: 1234,
        jurisdiction: "EU",
      })) as unknown as Record<string, unknown>,
  },
  {
    name: "AAR issuance + qts",
    family: aar.aarFamily as FamilyManifest,
    mint: async () =>
      (await aar.mintIssuance({
        issuer: "did:web:qtsp.example",
        profile: "eidas.qts",
        subject: H("a"),
        ...policy,
        anchor: anchor("https://verify.dekimu.com/aar/v1"),
        signingKey: signingKey(),
        service_type: "qts",
        service_policy_oid: "0.4.0.1862.1.1",
        service_recipient_commit: H("b"),
        artefact_hash: H("a"),
        artefact_metadata_commit: H("c"),
        signature_format: "pades_b_lta",
        qcert_serial_commit: H("9"),
        tsl_country: "ES",
        tsl_entry_hash: H("d"),
        tsl_signed_tree_head_root: H("f"),
        tsl_tree_size: 42,
        tsl_inclusion_proof: [],
        tsl_log_time: "2026-05-16T10:00:00Z",
      })) as unknown as Record<string, unknown>,
  },
  {
    name: "ANR notice.aiact.art50_transparency",
    family: anr.anrFamily as FamilyManifest,
    mint: async () =>
      (await anr.mintPresented({
        issuer: "did:web:controller.example",
        profile: "notice.aiact.art50_transparency",
        lang_tag: "en-GB",
        ...policy,
        anchor: anchor("https://verify.dekimu.com/anr/v1"),
        signingKey: signingKey(),
        jurisdiction: "EU",
        delivery_channel: "web",
        render_uri: "https://example.test/notice/v1",
        rights_surface: ["art15", "art17"],
        ai_system_kind: "interaction",
        ai_system_provider_did: "did:web:ai-provider.example",
      })) as unknown as Record<string, unknown>,
  },
];

for (const c of CASES) {
  test(`${c.name}: no tsa → CLI and direct family verifyReceipt reject (tsa_required)`, async () => {
    const receipt = await c.mint();
    assert.equal(receipt.tsa, null, "fixture: tsa must be absent");

    const cli = await verifyAnchor(receipt, opts);
    assert.equal(cli.ok, false, `CLI accepted: ${JSON.stringify(cli.result)}`);
    assert.equal(cli.result?.reason, "tsa_required");
    assert.equal(cli.result?.tsa_state, "tsa_required");

    const direct = await c.family.verifyReceipt(receipt, opts);
    assert.equal(direct.signature_valid, false);
    assert.equal(direct.reason, "tsa_required");
  });

  test(`${c.name}: junk tsa → CLI and direct family verifyReceipt reject (tsa_unverified)`, async () => {
    const receipt = { ...(await c.mint()), tsa: JUNK_TSA };

    const cli = await verifyAnchor(receipt, opts);
    assert.equal(cli.ok, false, `CLI accepted: ${JSON.stringify(cli.result)}`);
    assert.equal(cli.result?.reason, "tsa_unverified");
    assert.equal(cli.result?.tsa_state, "tsa_malformed");

    const direct = await c.family.verifyReceipt(receipt, opts);
    assert.equal(direct.signature_valid, false);
    assert.equal(direct.reason, "tsa_unverified");
    assert.equal(direct.tsa_state, "tsa_malformed");
  });
}

test("RECOMMENDED body-keyed event (ABR breach.assessed) without tsa stays valid on the CLI path, surfaced as tsa_recommended", async () => {
  const receipt = (await abr.mintAssessed({
    issuer: "did:web:controller.example",
    profile: "breach.gdpr.art33",
    incident_correlation_id: "INC-2026-0001",
    ...policy,
    anchor: anchor("https://verify.dekimu.com/abr/v1"),
    signingKey: signingKey(),
    severity_class: "high_risk",
    assessment_method_hash: H("b"),
  })) as unknown as Record<string, unknown>;
  const cli = await verifyAnchor(receipt, opts);
  assert.equal(cli.ok, true, `unexpected: ${cli.result?.reason}`);
  assert.equal(cli.result?.tsa_state, "tsa_recommended");
});
