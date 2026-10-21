/**
 * Tests for the APR composition surface (Phase 1 §G).
 *
 * Covers:
 *   - extractAprComposition per event_type (derived_from, forked_from,
 *     superseded_by, disclosed)
 *   - covered / uncovered parent partition
 *   - APR-id deduplication and lexicographic ordering
 *   - buildAprReverseIndex (one APR id cited by many children)
 *   - buildAprCoverageReport totals and citing-receipt dedupe
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  extractAprComposition,
  buildAprReverseIndex,
  buildAprCoverageReport,
} from "../src/composition.ts";
import type { AlrChainReceipt } from "../src/chain.ts";
import type { AlrBody, AlrParentRef } from "../src/types.ts";

const H = (b: string) => `sha256:${b.repeat(64)}`;

function pref(artifact_hash: string, parent_apr_id: string | null): AlrParentRef {
  return {
    artifact_hash,
    parent_apr_id,
    parent_alr_id: null,
    uri: null,
  };
}

function derivedBody(parents: AlrParentRef[]): AlrBody {
  return {
    profile: "aiact.art13.transparency",
    event_type: "derived_from",
    artifact_hash: H("c"),
    event_at: "2026-05-17T00:00:00Z",
    qts_attestation_hash: null,
    parents,
    successor: null,
    transform_claim: { summary: "fine-tune", uri: null },
    disclosure: null,
  };
}

function forkedBody(parent: AlrParentRef): AlrBody {
  return {
    profile: "c2pa.non-media",
    event_type: "forked_from",
    artifact_hash: H("c"),
    event_at: "2026-05-17T00:00:00Z",
    qts_attestation_hash: null,
    parents: [parent],
    successor: null,
    transform_claim: null,
    disclosure: null,
  };
}

function supersededBody(): AlrBody {
  return {
    profile: "c2pa.non-media",
    event_type: "superseded_by",
    artifact_hash: H("c"),
    event_at: "2026-05-17T00:00:00Z",
    qts_attestation_hash: null,
    parents: [],
    successor: pref(H("d"), "01HXX0000000000000000APR111"),
    transform_claim: { summary: "supersede", uri: null },
    disclosure: null,
  };
}

function disclosedBody(): AlrBody {
  return {
    profile: "disclosure.recipients",
    event_type: "disclosed",
    artifact_hash: H("c"),
    event_at: "2026-05-17T00:00:00Z",
    qts_attestation_hash: null,
    parents: [],
    successor: null,
    transform_claim: null,
    disclosure: {
      recipient: "did:web:x",
      recipient_role: "controller",
      scope_hash: H("d"),
      basis: "gdpr.art6.1.c",
    },
  };
}

// ── extractAprComposition ────────────────────────────────────────────────────

test("composition.extract: derived_from partitions covered + uncovered", () => {
  const body = derivedBody([
    pref(H("a"), "01HXX0000000000000000APR222"),
    pref(H("b"), null),
    pref(H("e"), "01HXX0000000000000000APR111"),
  ]);
  const s = extractAprComposition(body);
  assert.deepEqual(s.aprRefs, [
    "01HXX0000000000000000APR111",
    "01HXX0000000000000000APR222",
  ]);
  assert.equal(s.coveredParents.length, 2);
  assert.equal(s.uncoveredParents.length, 1);
});

test("composition.extract: forked_from with covered parent surfaces apr ref", () => {
  const body = forkedBody(pref(H("a"), "01HXX0000000000000000APRFOO"));
  const s = extractAprComposition(body);
  assert.deepEqual(s.aprRefs, ["01HXX0000000000000000APRFOO"]);
  assert.equal(s.coveredParents.length, 1);
  assert.equal(s.uncoveredParents.length, 0);
});

test("composition.extract: superseded_by carries no composition (successor is not a parent)", () => {
  const s = extractAprComposition(supersededBody());
  assert.deepEqual(s.aprRefs, []);
  assert.equal(s.coveredParents.length, 0);
  assert.equal(s.uncoveredParents.length, 0);
});

test("composition.extract: disclosed carries no composition", () => {
  const s = extractAprComposition(disclosedBody());
  assert.deepEqual(s.aprRefs, []);
  assert.equal(s.coveredParents.length, 0);
  assert.equal(s.uncoveredParents.length, 0);
});

test("composition.extract: duplicate parent_apr_id across two parents dedupes", () => {
  const body = derivedBody([
    pref(H("a"), "01HXX0000000000000000APRABC"),
    pref(H("b"), "01HXX0000000000000000APRABC"),
  ]);
  const s = extractAprComposition(body);
  assert.deepEqual(s.aprRefs, ["01HXX0000000000000000APRABC"]);
  assert.equal(s.coveredParents.length, 2);
});

// ── buildAprReverseIndex ─────────────────────────────────────────────────────

test("composition.reverseIndex: APR id → multiple ALR children", () => {
  const apr1 = "01HXX0000000000000000APR111";
  const apr2 = "01HXX0000000000000000APR222";
  const receipts: AlrChainReceipt[] = [
    { id: "01HXX0000000000000000ALR001", body: derivedBody([pref(H("a"), apr1)]) },
    { id: "01HXX0000000000000000ALR002", body: derivedBody([pref(H("a"), apr1), pref(H("b"), apr2)]) },
    { id: "01HXX0000000000000000ALR003", body: disclosedBody() },
  ];
  const ix = buildAprReverseIndex(receipts);
  assert.equal(ix.size, 2);
  assert.equal(ix.get(apr1)?.length, 2);
  assert.equal(ix.get(apr2)?.length, 1);
});

test("composition.reverseIndex: same receipt citing one apr_id twice surfaces once", () => {
  const apr = "01HXX0000000000000000APRABC";
  const receipts: AlrChainReceipt[] = [
    {
      id: "01HXX0000000000000000ALR001",
      body: derivedBody([pref(H("a"), apr), pref(H("b"), apr)]),
    },
  ];
  const ix = buildAprReverseIndex(receipts);
  assert.equal(ix.get(apr)?.length, 1);
});

// ── buildAprCoverageReport ───────────────────────────────────────────────────

test("composition.coverageReport: totals, citing dedupe, sorted apr ids", () => {
  const apr1 = "01HXX0000000000000000APR111";
  const apr2 = "01HXX0000000000000000APR222";
  const receipts: AlrChainReceipt[] = [
    {
      id: "01HXX0000000000000000ALR001",
      // 2 parents, 1 APR-covered.
      body: derivedBody([pref(H("a"), apr1), pref(H("b"), null)]),
    },
    {
      id: "01HXX0000000000000000ALR002",
      // 1 parent, APR-covered, different apr id.
      body: forkedBody(pref(H("c"), apr2)),
    },
    {
      id: "01HXX0000000000000000ALR003",
      // Disclosed — contributes nothing to lineage totals.
      body: disclosedBody(),
    },
  ];
  const r = buildAprCoverageReport(receipts);
  assert.equal(r.totalLineageParents, 3);
  assert.equal(r.aprCoveredParents, 2);
  assert.deepEqual(r.citedAprIds, [apr1, apr2]);
  assert.equal(r.citingReceipts.length, 2);
});

test("composition.coverageReport: corpus with zero APR linkage returns zeros", () => {
  const receipts: AlrChainReceipt[] = [
    { id: "01HXX0000000000000000ALR001", body: derivedBody([pref(H("a"), null)]) },
    { id: "01HXX0000000000000000ALR002", body: disclosedBody() },
  ];
  const r = buildAprCoverageReport(receipts);
  assert.equal(r.totalLineageParents, 1);
  assert.equal(r.aprCoveredParents, 0);
  assert.deepEqual(r.citedAprIds, []);
  assert.equal(r.citingReceipts.length, 0);
});
