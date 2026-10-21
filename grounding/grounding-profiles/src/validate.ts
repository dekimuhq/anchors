import type { SupportLevel } from "./types.ts";

export interface ValidationResult { ok: boolean; errors: string[]; }

const HEX64 = /^[0-9a-f]{64}$/;
const SUPPORT_LEVELS = new Set<string>(["supported", "partial", "unsupported"]);

/** Verbatim from guard-profiles. RFC 3339 check. */
function isRfc3339(s: unknown): boolean {
  if (typeof s !== "string") return false;
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/.test(s)) return false;
  return !Number.isNaN(Date.parse(s));
}

/**
 * Ordered support↔score mapping from spec §3.
 * score === 0  ⇒ "unsupported"
 * score >= threshold ⇒ "supported"
 * else "partial"
 */
function derivedSupport(score: number, threshold: number): SupportLevel {
  if (score === 0) return "unsupported";
  if (score >= threshold) return "supported";
  return "partial";
}

/**
 * Validates an `ar.grounding.v1` grounding.rag body.
 * Recomputes coverage, grounded_count, and per-citation support from the body
 * and rejects mismatches — these are derived fields, not trusted from the issuer.
 */
export function validateGroundingRag(body: unknown): ValidationResult {
  const e: string[] = [];

  if (typeof body !== "object" || body === null) {
    return { ok: false, errors: ["body must be an object"] };
  }

  const b = body as Record<string, unknown>;

  // profile
  if (b["profile"] !== "grounding.rag") {
    e.push("profile must be grounding.rag");
  }

  // answer_commit
  if (!HEX64.test(String(b["answer_commit"]))) {
    e.push("answer_commit must be 64-char lowercase hex sha-256");
  }

  // sources
  if (!Array.isArray(b["sources"]) || (b["sources"] as unknown[]).length === 0) {
    e.push("sources must be a non-empty array");
  }
  const sourceIds = new Set<string>();
  if (Array.isArray(b["sources"])) {
    for (let i = 0; i < (b["sources"] as unknown[]).length; i++) {
      const s = (b["sources"] as unknown[])[i] as Record<string, unknown>;
      if (!s || typeof s["source_id"] !== "string" || !s["source_id"]) {
        e.push(`sources[${i}].source_id must be a non-empty string`);
      } else if (sourceIds.has(s["source_id"] as string)) {
        e.push(`sources[${i}].source_id duplicate: ${s["source_id"]}`);
      } else {
        sourceIds.add(s["source_id"] as string);
      }
      if (!HEX64.test(String(s["source_commit"]))) {
        e.push(`sources[${i}].source_commit must be 64-char lowercase hex`);
      }
      // media_type optional — validate only when present
      if ("media_type" in s && typeof s["media_type"] !== "string") {
        e.push(`sources[${i}].media_type must be a string when present`);
      }
    }
  }

  // claims
  if (!Array.isArray(b["claims"]) || (b["claims"] as unknown[]).length === 0) {
    e.push("claims must be a non-empty array");
  }
  const claimIds = new Set<string>();
  if (Array.isArray(b["claims"])) {
    for (let i = 0; i < (b["claims"] as unknown[]).length; i++) {
      const c = (b["claims"] as unknown[])[i] as Record<string, unknown>;
      if (!c || typeof c["claim_id"] !== "string" || !c["claim_id"]) {
        e.push(`claims[${i}].claim_id must be a non-empty string`);
      } else if (claimIds.has(c["claim_id"] as string)) {
        e.push(`claims[${i}].claim_id duplicate: ${c["claim_id"]}`);
      } else {
        claimIds.add(c["claim_id"] as string);
      }
      if (!HEX64.test(String(c["claim_commit"]))) {
        e.push(`claims[${i}].claim_commit must be 64-char lowercase hex`);
      }
    }
  }

  // scorer (validate early — we need threshold to check support↔score)
  const scorer = b["scorer"] as Record<string, unknown> | undefined;
  let threshold: number | null = null; // established only when scorer.threshold is valid
  if (!scorer || typeof scorer !== "object") {
    e.push("scorer must be an object");
  } else {
    if (scorer["method"] !== "lexical_overlap") {
      e.push('scorer.method must be "lexical_overlap"');
    }
    if (typeof scorer["name"] !== "string" || !scorer["name"]) {
      e.push("scorer.name must be a non-empty string");
    }
    if (typeof scorer["version"] !== "string" || !scorer["version"]) {
      e.push("scorer.version must be a non-empty string");
    }
    if (typeof scorer["threshold"] !== "number" || scorer["threshold"] < 0 || scorer["threshold"] > 1) {
      e.push("scorer.threshold must be a number in [0,1]");
    } else {
      threshold = scorer["threshold"] as number;
    }
  }

  // citations — validate shape, referential integrity, support↔score coherence
  // and accumulate sets needed for coverage + grounded_count recomputation
  const citedClaimIds = new Set<string>();
  const supportedClaimIds = new Set<string>();

  if (!Array.isArray(b["citations"])) {
    e.push("citations must be an array");
  } else {
    for (let i = 0; i < (b["citations"] as unknown[]).length; i++) {
      const cit = (b["citations"] as unknown[])[i] as Record<string, unknown>;
      if (!cit || typeof cit !== "object") { e.push(`citations[${i}] must be an object`); continue; }

      const citClaimId = cit["claim_id"] as string;
      const citSourceId = cit["source_id"] as string;

      // referential integrity
      if (typeof citClaimId !== "string" || !claimIds.has(citClaimId)) {
        e.push(`citations[${i}].claim_id not found in claims: ${String(cit["claim_id"])}`);
      }
      if (typeof citSourceId !== "string" || !sourceIds.has(citSourceId)) {
        e.push(`citations[${i}].source_id not found in sources: ${String(cit["source_id"])}`);
      }

      // span offsets
      const start = cit["start"];
      const end = cit["end"];
      if (typeof start !== "number" || !Number.isInteger(start) || (start as number) < 0) {
        e.push(`citations[${i}].start must be a non-negative integer`);
      }
      if (typeof end !== "number" || !Number.isInteger(end)) {
        e.push(`citations[${i}].end must be a non-negative integer`);
      }
      if (typeof start === "number" && typeof end === "number" && Number.isInteger(start) && Number.isInteger(end)) {
        if ((end as number) <= (start as number)) {
          e.push(`citations[${i}].end must be > start`);
        }
      }

      // span_commit
      if (!HEX64.test(String(cit["span_commit"]))) {
        e.push(`citations[${i}].span_commit must be 64-char lowercase hex`);
      }

      // score
      const score = cit["score"];
      if (typeof score !== "number" || (score as number) < 0 || (score as number) > 1) {
        e.push(`citations[${i}].score must be a number in [0,1]`);
      }

      // support enum
      const support = cit["support"];
      if (!SUPPORT_LEVELS.has(String(support))) {
        e.push(`citations[${i}].support must be supported|partial|unsupported`);
      }

      // support↔score coherence (ordered mapping from spec §3) — only when a valid
      // threshold was established (else the scorer error above is the real root cause)
      if (threshold !== null && typeof score === "number" && score >= 0 && score <= 1 && SUPPORT_LEVELS.has(String(support))) {
        const expected = derivedSupport(score as number, threshold);
        if (support !== expected) {
          e.push(`citations[${i}].support "${String(support)}" disagrees with derived value "${expected}" (score=${score}, threshold=${threshold})`);
        }
      }

      // accumulate for derived-field recomputation
      if (typeof citClaimId === "string" && claimIds.has(citClaimId)) {
        citedClaimIds.add(citClaimId);
        // A claim is "grounded" if it has ≥1 citation with support === "supported"
        if (support === "supported" && typeof score === "number" && score >= 0 && score <= 1) {
          supportedClaimIds.add(citClaimId);
        }
      }
    }
  }

  // coverage recomputation
  const claimsCount = claimIds.size;
  const computedCoverage = claimsCount === 0 ? 0 : citedClaimIds.size / claimsCount;
  const bodyCoverage = b["coverage"];
  if (typeof bodyCoverage !== "number") {
    e.push("coverage must be a number");
  } else if (Math.abs((bodyCoverage as number) - computedCoverage) > 1e-10) {
    e.push(`coverage mismatch: body says ${bodyCoverage}, computed ${computedCoverage} (${citedClaimIds.size}/${claimsCount})`);
  }

  // grounded_count recomputation
  const computedGroundedCount = supportedClaimIds.size;
  const bodyGroundedCount = b["grounded_count"];
  if (typeof bodyGroundedCount !== "number" || !Number.isInteger(bodyGroundedCount)) {
    e.push("grounded_count must be an integer");
  } else if ((bodyGroundedCount as number) !== computedGroundedCount) {
    e.push(`grounded_count mismatch: body says ${bodyGroundedCount}, computed ${computedGroundedCount}`);
  }

  // scored_at
  if (!isRfc3339(b["scored_at"])) {
    e.push("scored_at must be a valid RFC 3339 timestamp");
  }

  // optional fields — validate only when present
  if ("answer_media_type" in b && typeof b["answer_media_type"] !== "string") {
    e.push("answer_media_type must be a string when present");
  }
  if ("credential_id" in b && typeof b["credential_id"] !== "string") {
    e.push("credential_id must be a string when present");
  }
  if ("caveats_consumed" in b) {
    const cc = b["caveats_consumed"] as Record<string, unknown> | null | undefined;
    if (!cc || typeof cc !== "object") {
      e.push("caveats_consumed must be an object when present");
    } else {
      if (typeof cc["data_scope"] !== "string" || !cc["data_scope"]) {
        e.push("caveats_consumed.data_scope must be a non-empty string");
      }
      if (typeof cc["spend_step"] !== "number") {
        e.push("caveats_consumed.spend_step must be a number");
      }
      if (typeof cc["capability"] !== "string" || !cc["capability"]) {
        e.push("caveats_consumed.capability must be a non-empty string");
      }
      if ("spend_currency" in cc && typeof cc["spend_currency"] !== "string") {
        e.push("caveats_consumed.spend_currency must be a string when present");
      }
    }
  }

  return { ok: e.length === 0, errors: e };
}
