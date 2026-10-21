/**
 * Tests for the envelope-`prev` chain walker (spec §6.1 + §6.2).
 *
 * Coverage:
 *   - Linear chain traversal (presented → re_presented → withdrawn / acknowledged).
 *   - Cycle detection on direct + indirect loops.
 *   - `iss` consistency flag.
 *   - `policy_uri` host consistency flag (incl. null policy_uri + unparseable URL).
 *   - Dangling `prev` pointer.
 *   - Depth-limit truncation + clamping.
 *   - Translation-branch resolution (base in index / not in index).
 *   - Index dedup behaviour for duplicate IDs.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  buildAnrChainIndex,
  walkAnrChain,
  ANR_DEFAULT_DEPTH_LIMIT,
  ANR_DEPTH_LIMIT_MIN,
  ANR_DEPTH_LIMIT_MAX,
} from "../src/index.ts";
import type {
  AnrChainReceipt,
  AnrBody,
  AnrPresentedBody,
  AnrRePresentedBody,
  AnrAcknowledgedBody,
  AnrWithdrawnBody,
  AnrTranslatedBody,
} from "../src/index.ts";

// ── Body builders (only the fields the walker reads) ──────────────────────────

const ISS_A = "did:web:controller-a.example";
const ISS_B = "did:web:controller-b.example";

function presentedBody(over: Partial<AnrPresentedBody> = {}): AnrPresentedBody {
  return {
    profile: "notice.art13.collected_direct",
    lang_tag: "en-GB",
    lang_inferred: null,
    qts_attestation_hash: null,
    event_type: "notice.presented",
    jurisdiction: "EU",
    delivery_channel: "web",
    render_uri: "https://example.test/notice/v1",
    rights_surface: ["art15"],
    subject_age_band: null,
    data_source: null,
    collection_horizon: null,
    data_acquired_at: null,
    layer_uris: null,
    ai_system_kind: null,
    ai_system_provider_did: null,
    aer_id: null,
    supersedes_anr_id: null,
    base_anr_id: null,
    ack_method: null,
    joint_controllers: null,
    cessation_reason: null,
    translation_provenance_alr_id: null,
    ...over,
  };
}

function rePresentedBody(supersedes: string): AnrRePresentedBody {
  return {
    profile: "notice.art13.collected_direct",
    lang_tag: "en-GB",
    lang_inferred: null,
    qts_attestation_hash: null,
    event_type: "notice.re_presented",
    jurisdiction: "EU",
    delivery_channel: "web",
    render_uri: "https://example.test/notice/v2",
    rights_surface: ["art15"],
    supersedes_anr_id: supersedes,
    subject_age_band: null,
    data_source: null,
    collection_horizon: null,
    data_acquired_at: null,
    layer_uris: null,
    ai_system_kind: null,
    ai_system_provider_did: null,
    aer_id: null,
    base_anr_id: null,
    ack_method: null,
    joint_controllers: null,
    cessation_reason: null,
    translation_provenance_alr_id: null,
  };
}

function acknowledgedBody(): AnrAcknowledgedBody {
  return {
    profile: "notice.art13.collected_direct",
    lang_tag: "en-GB",
    lang_inferred: null,
    qts_attestation_hash: null,
    event_type: "notice.acknowledged",
    jurisdiction: "EU",
    ack_method: "checkbox",
    delivery_channel: null,
    render_uri: null,
    rights_surface: null,
    subject_age_band: null,
    data_source: null,
    collection_horizon: null,
    data_acquired_at: null,
    layer_uris: null,
    ai_system_kind: null,
    ai_system_provider_did: null,
    aer_id: null,
    supersedes_anr_id: null,
    base_anr_id: null,
    joint_controllers: null,
    cessation_reason: null,
    translation_provenance_alr_id: null,
  };
}

function withdrawnBody(): AnrWithdrawnBody {
  return {
    profile: "notice.art13.collected_direct",
    lang_tag: "en-GB",
    lang_inferred: null,
    qts_attestation_hash: null,
    event_type: "notice.withdrawn",
    jurisdiction: "EU",
    supersedes_anr_id: null,
    cessation_reason: "processing-ceased",
    delivery_channel: null,
    render_uri: null,
    rights_surface: null,
    subject_age_band: null,
    data_source: null,
    collection_horizon: null,
    data_acquired_at: null,
    layer_uris: null,
    ai_system_kind: null,
    ai_system_provider_did: null,
    aer_id: null,
    base_anr_id: null,
    ack_method: null,
    joint_controllers: null,
    translation_provenance_alr_id: null,
  };
}

function translatedBody(baseAnrId: string): AnrTranslatedBody {
  return {
    profile: "notice.art13.collected_direct",
    lang_tag: "de-DE",
    lang_inferred: null,
    qts_attestation_hash: null,
    event_type: "notice.translated",
    base_anr_id: baseAnrId,
    jurisdiction: null,
    translation_provenance_alr_id: null,
    delivery_channel: null,
    render_uri: null,
    rights_surface: null,
    subject_age_band: null,
    data_source: null,
    collection_horizon: null,
    data_acquired_at: null,
    layer_uris: null,
    ai_system_kind: null,
    ai_system_provider_did: null,
    aer_id: null,
    supersedes_anr_id: null,
    ack_method: null,
    joint_controllers: null,
    cessation_reason: null,
  };
}

function r(
  id: string,
  body: AnrBody,
  prev: string | null,
  over: Partial<AnrChainReceipt> = {},
): AnrChainReceipt {
  return {
    id,
    iss: ISS_A,
    policy_uri: "https://example.test/notice.html",
    prev,
    body,
    ...over,
  };
}

// ── Happy paths ───────────────────────────────────────────────────────────────

test("walks a single-receipt chain (prev: null on starting receipt)", () => {
  const head = r("01HEAD", presentedBody(), null);
  const idx = buildAnrChainIndex([head]);
  const res = walkAnrChain("01HEAD", idx);
  assert.equal(res.hops.length, 1);
  assert.equal(res.head?.id, "01HEAD");
  assert.equal(res.cycle, false);
  assert.equal(res.dangling, false);
  assert.equal(res.truncated, false);
  assert.equal(res.translation_branch, null);
});

test("walks a three-hop linear chain back to chain head", () => {
  const head = r("01A", presentedBody(), null);
  const mid = r("01B", rePresentedBody("01A"), "01A");
  const tail = r("01C", rePresentedBody("01B"), "01B");
  const idx = buildAnrChainIndex([head, mid, tail]);
  const res = walkAnrChain("01C", idx);
  assert.deepEqual(
    res.hops.map((h) => h.id),
    ["01C", "01B", "01A"],
  );
  assert.equal(res.head?.id, "01A");
  assert.equal(res.iss_inconsistent, false);
  assert.equal(res.policy_host_inconsistent, false);
});

test("walks a chain that terminates in notice.withdrawn", () => {
  const head = r("01P", presentedBody(), null);
  const tail = r("01W", withdrawnBody(), "01P");
  const idx = buildAnrChainIndex([head, tail]);
  const res = walkAnrChain("01W", idx);
  assert.deepEqual(
    res.hops.map((h) => h.id),
    ["01W", "01P"],
  );
  assert.equal(res.head?.id, "01P");
});

test("walks a chain that terminates in notice.acknowledged", () => {
  const head = r("01P", presentedBody(), null);
  const ack = r("01K", acknowledgedBody(), "01P");
  const idx = buildAnrChainIndex([head, ack]);
  const res = walkAnrChain("01K", idx);
  assert.equal(res.head?.id, "01P");
  assert.equal(res.hops[0]?.body.event_type, "notice.acknowledged");
});

test("returns empty hops + null head when startId is not in the index", () => {
  const idx = buildAnrChainIndex([r("01A", presentedBody(), null)]);
  const res = walkAnrChain("01MISSING", idx);
  assert.equal(res.hops.length, 0);
  assert.equal(res.head, null);
  assert.equal(res.dangling, true);
});

// ── Cycle detection ───────────────────────────────────────────────────────────

test("detects a direct self-cycle (prev points to self)", () => {
  // Synthetic: forge a re_presented whose prev points to itself.
  const looped = r("01L", rePresentedBody("01PRIOR"), "01L");
  const idx = buildAnrChainIndex([looped]);
  const res = walkAnrChain("01L", idx);
  assert.equal(res.cycle, true);
  assert.equal(res.head, null);
  assert.equal(res.hops.length, 1); // recorded the receipt once before detecting revisit
});

test("detects an indirect cycle A → B → A", () => {
  const a = r("01A", rePresentedBody("01B"), "01B");
  const b = r("01B", rePresentedBody("01A"), "01A");
  const idx = buildAnrChainIndex([a, b]);
  const res = walkAnrChain("01A", idx);
  assert.equal(res.cycle, true);
  assert.equal(res.head, null);
});

// ── iss consistency ───────────────────────────────────────────────────────────

test("flags iss_inconsistent when a hop carries a different controller DID", () => {
  const head = r("01A", presentedBody(), null);
  const mid = r("01B", rePresentedBody("01A"), "01A", { iss: ISS_B });
  const idx = buildAnrChainIndex([head, mid]);
  const res = walkAnrChain("01B", idx);
  assert.equal(res.iss_inconsistent, true);
  assert.equal(res.head?.id, "01A");
});

test("keeps iss_inconsistent false when every hop carries the same DID", () => {
  const head = r("01A", presentedBody(), null);
  const mid = r("01B", rePresentedBody("01A"), "01A");
  const idx = buildAnrChainIndex([head, mid]);
  const res = walkAnrChain("01B", idx);
  assert.equal(res.iss_inconsistent, false);
});

// ── policy_uri host consistency ───────────────────────────────────────────────

test("flags policy_host_inconsistent when a hop's URL host differs", () => {
  const head = r("01A", presentedBody(), null, { policy_uri: "https://a.test/n" });
  const mid = r("01B", rePresentedBody("01A"), "01A", { policy_uri: "https://b.test/n" });
  const idx = buildAnrChainIndex([head, mid]);
  const res = walkAnrChain("01B", idx);
  assert.equal(res.policy_host_inconsistent, true);
});

test("treats same host across different paths as consistent", () => {
  const head = r("01A", presentedBody(), null, { policy_uri: "https://a.test/v1" });
  const mid = r("01B", rePresentedBody("01A"), "01A", { policy_uri: "https://a.test/v2" });
  const idx = buildAnrChainIndex([head, mid]);
  const res = walkAnrChain("01B", idx);
  assert.equal(res.policy_host_inconsistent, false);
});

test("skips host comparison when policy_uri is null on a hop", () => {
  const head = r("01A", presentedBody(), null, { policy_uri: "https://a.test/v1" });
  const mid = r("01B", rePresentedBody("01A"), "01A", { policy_uri: null });
  const idx = buildAnrChainIndex([head, mid]);
  const res = walkAnrChain("01B", idx);
  assert.equal(res.policy_host_inconsistent, false);
  assert.equal(res.policy_uri_unparseable, false);
});

test("flags policy_uri_unparseable when a URL fails to parse", () => {
  const head = r("01A", presentedBody(), null, { policy_uri: "not a url" });
  const idx = buildAnrChainIndex([head]);
  const res = walkAnrChain("01A", idx);
  assert.equal(res.policy_uri_unparseable, true);
  // Unparseable host does not also flip host_inconsistent — they're mutually
  // exclusive: the walker cannot reason about host equality without a host.
  assert.equal(res.policy_host_inconsistent, false);
});

test("treats host with a different port as inconsistent (URL.host includes port)", () => {
  const head = r("01A", presentedBody(), null, { policy_uri: "https://a.test:8443/n" });
  const mid = r("01B", rePresentedBody("01A"), "01A", { policy_uri: "https://a.test/n" });
  const idx = buildAnrChainIndex([head, mid]);
  const res = walkAnrChain("01B", idx);
  assert.equal(res.policy_host_inconsistent, true);
});

// ── Dangling prev ─────────────────────────────────────────────────────────────

test("flags dangling when a prev pointer references an unknown ID", () => {
  const tail = r("01T", rePresentedBody("01MISSING"), "01MISSING");
  const idx = buildAnrChainIndex([tail]);
  const res = walkAnrChain("01T", idx);
  assert.equal(res.dangling, true);
  assert.equal(res.head, null);
  assert.equal(res.hops.length, 1);
});

// ── Depth limit ───────────────────────────────────────────────────────────────

test("truncates when the chain exceeds the configured depth limit", () => {
  // Build a chain of 40 hops: idx 0 is head (prev=null), idx 39 is the tail.
  const receipts: AnrChainReceipt[] = [];
  for (let i = 0; i < 40; i++) {
    const id = `01H${String(i).padStart(3, "0")}`;
    if (i === 0) {
      receipts.push(r(id, presentedBody(), null));
    } else {
      const prev = `01H${String(i - 1).padStart(3, "0")}`;
      receipts.push(r(id, rePresentedBody(prev), prev));
    }
  }
  const idx = buildAnrChainIndex(receipts);
  const res = walkAnrChain("01H039", idx, { depthLimit: ANR_DEPTH_LIMIT_MIN });
  // Min depth limit is 32; chain is 40 deep — walker truncates.
  assert.equal(res.truncated, true);
  assert.equal(res.head, null);
  assert.equal(res.hops.length, ANR_DEPTH_LIMIT_MIN);
});

test("clamps depthLimit below floor up to ANR_DEPTH_LIMIT_MIN", () => {
  // 40 hops, ask for depthLimit=1 (below floor of 32) — walker uses 32.
  const receipts: AnrChainReceipt[] = [];
  for (let i = 0; i < 40; i++) {
    const id = `01M${String(i).padStart(3, "0")}`;
    if (i === 0) receipts.push(r(id, presentedBody(), null));
    else {
      const prev = `01M${String(i - 1).padStart(3, "0")}`;
      receipts.push(r(id, rePresentedBody(prev), prev));
    }
  }
  const idx = buildAnrChainIndex(receipts);
  const res = walkAnrChain("01M039", idx, { depthLimit: 1 });
  assert.equal(res.hops.length, ANR_DEPTH_LIMIT_MIN);
  assert.equal(res.truncated, true);
});

test("clamps depthLimit above ceiling down to ANR_DEPTH_LIMIT_MAX (does not throw)", () => {
  const head = r("01A", presentedBody(), null);
  const idx = buildAnrChainIndex([head]);
  const res = walkAnrChain("01A", idx, { depthLimit: ANR_DEPTH_LIMIT_MAX * 10 });
  // Walk completes because chain length 1 is well under the clamped ceiling.
  assert.equal(res.head?.id, "01A");
  assert.equal(res.truncated, false);
});

test("uses ANR_DEFAULT_DEPTH_LIMIT when no option supplied", () => {
  // Build a short chain so the default cap (256) doesn't bite. The point of
  // this test is that the constant is exported and consumed when opts omitted.
  assert.equal(ANR_DEFAULT_DEPTH_LIMIT, 256);
  const head = r("01A", presentedBody(), null);
  const mid = r("01B", rePresentedBody("01A"), "01A");
  const idx = buildAnrChainIndex([head, mid]);
  const res = walkAnrChain("01B", idx);
  assert.equal(res.truncated, false);
  assert.equal(res.head?.id, "01A");
});

// ── Translation-branch resolution ─────────────────────────────────────────────

test("resolves translation branch when base receipt is in the index", () => {
  const base = r("01BASE", presentedBody(), null);
  const trans = r("01TRANS", translatedBody("01BASE"), null);
  const idx = buildAnrChainIndex([base, trans]);
  const res = walkAnrChain("01TRANS", idx);
  assert.equal(res.head?.id, "01TRANS");
  assert.notEqual(res.translation_branch, null);
  assert.equal(res.translation_branch?.base_anr_id, "01BASE");
  assert.equal(res.translation_branch?.base?.id, "01BASE");
  assert.equal(res.translation_branch?.base_unresolvable, false);
});

test("surfaces base_unresolvable when the translation's base is not in the index", () => {
  const trans = r("01TRANS", translatedBody("01ERASED"), null);
  const idx = buildAnrChainIndex([trans]); // base not included
  const res = walkAnrChain("01TRANS", idx);
  assert.equal(res.head?.id, "01TRANS");
  assert.notEqual(res.translation_branch, null);
  assert.equal(res.translation_branch?.base_unresolvable, true);
  assert.equal(res.translation_branch?.base, null);
  // Translation branch issues do NOT mark the walk failed — chain itself still walked.
  assert.equal(res.dangling, false);
  assert.equal(res.cycle, false);
});

test("walks de-DE translation branch back to translation receipt, then resolves base", () => {
  // base chain (en-GB): 01EN_P (presented)
  // translation branch (de-DE):
  //   01TRANS (notice.translated, prev=null, base_anr_id=01EN_P)
  //   01DE_P  (notice.presented, prev=01TRANS)   ← de-DE re-presented atop the translation
  //   01DE_R  (notice.re_presented, prev=01DE_P)
  const base = r("01EN_P", presentedBody(), null);
  const trans = r("01TRANS", translatedBody("01EN_P"), null);
  const deP = r("01DE_P", presentedBody({ lang_tag: "de-DE" }), "01TRANS");
  const deR = r("01DE_R", rePresentedBody("01DE_P"), "01DE_P");
  // Per spec the de-DE chain branches FROM the translation. The de-DE
  // presented hop's `prev` is the translation receipt; the walker treats
  // the translation as that branch's head.
  const idx = buildAnrChainIndex([base, trans, deP, deR]);
  const res = walkAnrChain("01DE_R", idx);
  assert.deepEqual(
    res.hops.map((h) => h.id),
    ["01DE_R", "01DE_P", "01TRANS"],
  );
  assert.equal(res.head?.id, "01TRANS");
  assert.equal(res.translation_branch?.base?.id, "01EN_P");
  assert.equal(res.translation_branch?.base_unresolvable, false);
});

test("returns null translation_branch when the chain head is not a translation", () => {
  const head = r("01P", presentedBody(), null);
  const idx = buildAnrChainIndex([head]);
  const res = walkAnrChain("01P", idx);
  assert.equal(res.translation_branch, null);
});

test("returns null translation_branch when the walk aborts before reaching a head", () => {
  // Cycle aborts the walk — translation_branch must NOT be resolved.
  const a = r("01A", rePresentedBody("01A"), "01A");
  const idx = buildAnrChainIndex([a]);
  const res = walkAnrChain("01A", idx);
  assert.equal(res.cycle, true);
  assert.equal(res.translation_branch, null);
});

// ── Index ─────────────────────────────────────────────────────────────────────

test("buildAnrChainIndex deduplicates by id, keeping the first occurrence", () => {
  const first = r("01DUP", presentedBody(), null);
  const second = r("01DUP", presentedBody({ jurisdiction: "OTHER" }), null);
  const idx = buildAnrChainIndex([first, second]);
  assert.equal(idx.byId.size, 1);
  assert.equal(idx.byId.get("01DUP"), first);
});

test("buildAnrChainIndex returns an empty index on empty input", () => {
  const idx = buildAnrChainIndex([]);
  assert.equal(idx.byId.size, 0);
  const res = walkAnrChain("01ANY", idx);
  assert.equal(res.dangling, true);
  assert.equal(res.head, null);
});
