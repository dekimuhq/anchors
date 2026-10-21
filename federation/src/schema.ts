/**
 * Hand-rolled structural validator for `ar.issuer_manifest.v1`.
 *
 * Zero runtime deps — mirrors the pattern used by `@dekimuhq/anchors-trusted-issuers`
 * schema.ts and every other anchors validator.
 */

import type {
  IssuerManifestV1,
  IssuerMembership,
  OperatorInfo,
  TrustAnchors,
} from "./types.ts";

const KIND = "ar.issuer_manifest.v1";

const DID_WEB_RE = /^did:web:[a-z0-9.\-:_%]+$/i;
const ISO_8601_RE =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;

/**
 * The 14 locked family slugs. Manifests may only advertise memberships in
 * families from this set. Additive changes require a maintainer decision doc.
 */
const VALID_FAMILY_SLUGS = new Set([
  "apr", "acr", "arr", "alr", "atr", "apur",
  "aer", "aar", "adr", "anr", "asr", "abr",
  "air", "atokr",
]);

/**
 * Known claim_type discriminators from the locked registry.
 * Prefixed with `ar.` — validated at parse time to catch typos.
 */
const CLAIM_TYPE_RE = /^ar\.[a-z_]+\.v\d+$/;

export type ParseIssuerManifestResult =
  | { ok: true; doc: IssuerManifestV1 }
  | { ok: false; reason: string };

export function parseIssuerManifest(
  raw: unknown,
): ParseIssuerManifestResult {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return { ok: false, reason: "doc must be a JSON object" };
  }
  const o = raw as Record<string, unknown>;

  // kind
  if (o.kind !== KIND) {
    return { ok: false, reason: `kind must be "${KIND}", got ${jsonish(o.kind)}` };
  }

  // version
  if (typeof o.version !== "number" || !Number.isInteger(o.version) || o.version <= 0) {
    return { ok: false, reason: `version must be a positive integer, got ${jsonish(o.version)}` };
  }

  // issued_at / valid_until
  if (typeof o.issued_at !== "string" || !isIso8601(o.issued_at)) {
    return { ok: false, reason: `issued_at must be ISO 8601, got ${jsonish(o.issued_at)}` };
  }
  if (typeof o.valid_until !== "string" || !isIso8601(o.valid_until)) {
    return { ok: false, reason: `valid_until must be ISO 8601, got ${jsonish(o.valid_until)}` };
  }
  if (Date.parse(o.issued_at) >= Date.parse(o.valid_until)) {
    return {
      ok: false,
      reason: `issued_at (${o.issued_at}) must be < valid_until (${o.valid_until})`,
    };
  }
  // valid_until bounded to ≤90 days from issued_at (plan §3.4)
  const issuedMs = Date.parse(o.issued_at);
  const validUntilMs = Date.parse(o.valid_until);
  const ninetyDaysMs = 90 * 24 * 60 * 60 * 1000;
  if (validUntilMs - issuedMs > ninetyDaysMs) {
    return {
      ok: false,
      reason: `valid_until must be ≤90 days from issued_at (got ${Math.round((validUntilMs - issuedMs) / 86_400_000)}d)`,
    };
  }

  // iss
  if (typeof o.iss !== "string" || !DID_WEB_RE.test(o.iss)) {
    return { ok: false, reason: `iss must be did:web, got ${jsonish(o.iss)}` };
  }

  // operator
  const op = validateOperator(o.operator);
  if (!op.ok) return op;

  // key_doc_uri
  if (typeof o.key_doc_uri !== "string" || o.key_doc_uri.length === 0) {
    return { ok: false, reason: `key_doc_uri must be a non-empty string` };
  }
  try {
    new URL(o.key_doc_uri);
  } catch {
    return { ok: false, reason: `key_doc_uri must be a valid URL, got ${jsonish(o.key_doc_uri)}` };
  }

  // memberships
  if (!Array.isArray(o.memberships) || o.memberships.length === 0) {
    return { ok: false, reason: "memberships must be a non-empty array" };
  }
  const memberships: IssuerMembership[] = [];
  for (let i = 0; i < o.memberships.length; i++) {
    const m = validateMembership(o.memberships[i], i);
    if (!m.ok) return m;
    memberships.push(m.membership);
  }

  // trust_anchors
  const ta = validateTrustAnchors(o.trust_anchors);
  if (!ta.ok) return ta;

  // sig
  if (typeof o.sig !== "string" || o.sig.length === 0) {
    return { ok: false, reason: `sig must be a non-empty base64url string, got ${jsonish(o.sig)}` };
  }

  return {
    ok: true,
    doc: {
      kind: KIND,
      version: o.version,
      issued_at: o.issued_at,
      valid_until: o.valid_until,
      iss: o.iss,
      operator: op.operator,
      key_doc_uri: o.key_doc_uri,
      memberships,
      trust_anchors: ta.trust_anchors,
      sig: o.sig,
    },
  };
}

// --- Operator ---

type ValidateOperatorResult =
  | { ok: true; operator: OperatorInfo }
  | { ok: false; reason: string };

function validateOperator(raw: unknown): ValidateOperatorResult {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return { ok: false, reason: "operator must be an object" };
  }
  const o = raw as Record<string, unknown>;

  if (typeof o.name !== "string" || o.name.length === 0) {
    return { ok: false, reason: "operator.name must be a non-empty string" };
  }
  if (typeof o.jurisdiction !== "string" || o.jurisdiction.length === 0) {
    return { ok: false, reason: "operator.jurisdiction must be a non-empty string" };
  }
  if (typeof o.contact_uri !== "string" || o.contact_uri.length === 0) {
    return { ok: false, reason: "operator.contact_uri must be a non-empty string" };
  }

  return {
    ok: true,
    operator: {
      name: o.name,
      jurisdiction: o.jurisdiction,
      contact_uri: o.contact_uri,
    },
  };
}

// --- Membership ---

type ValidateMembershipResult =
  | { ok: true; membership: IssuerMembership }
  | { ok: false; reason: string };

function validateMembership(raw: unknown, idx: number): ValidateMembershipResult {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return { ok: false, reason: `memberships[${idx}] must be an object` };
  }
  const m = raw as Record<string, unknown>;

  if (typeof m.family !== "string") {
    return { ok: false, reason: `memberships[${idx}].family must be a string` };
  }
  if (!VALID_FAMILY_SLUGS.has(m.family)) {
    return {
      ok: false,
      reason: `memberships[${idx}].family "${m.family}" is not in the locked 14-member taxonomy`,
    };
  }

  if (!Array.isArray(m.claim_types)) {
    return { ok: false, reason: `memberships[${idx}].claim_types must be an array` };
  }
  for (let j = 0; j < m.claim_types.length; j++) {
    if (typeof m.claim_types[j] !== "string") {
      return { ok: false, reason: `memberships[${idx}].claim_types[${j}] must be a string` };
    }
    if (!CLAIM_TYPE_RE.test(m.claim_types[j] as string)) {
      return {
        ok: false,
        reason: `memberships[${idx}].claim_types[${j}] must match ar.<noun>.v<N>, got ${jsonish(m.claim_types[j])}`,
      };
    }
  }

  if (!Array.isArray(m.profiles)) {
    return { ok: false, reason: `memberships[${idx}].profiles must be an array` };
  }
  for (let j = 0; j < m.profiles.length; j++) {
    if (typeof m.profiles[j] !== "string") {
      return { ok: false, reason: `memberships[${idx}].profiles[${j}] must be a string` };
    }
  }

  if (!Array.isArray(m.spec_versions)) {
    return { ok: false, reason: `memberships[${idx}].spec_versions must be an array` };
  }
  for (let j = 0; j < m.spec_versions.length; j++) {
    if (typeof m.spec_versions[j] !== "string") {
      return { ok: false, reason: `memberships[${idx}].spec_versions[${j}] must be a string` };
    }
  }

  return {
    ok: true,
    membership: {
      family: m.family,
      claim_types: m.claim_types as string[],
      profiles: m.profiles as string[],
      spec_versions: m.spec_versions as string[],
    },
  };
}

// --- Trust anchors ---

type ValidateTrustAnchorsResult =
  | { ok: true; trust_anchors: TrustAnchors }
  | { ok: false; reason: string };

function validateTrustAnchors(raw: unknown): ValidateTrustAnchorsResult {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return { ok: false, reason: "trust_anchors must be an object" };
  }
  const t = raw as Record<string, unknown>;

  if (!Array.isArray(t.endorses)) {
    return { ok: false, reason: "trust_anchors.endorses must be an array" };
  }
  for (let i = 0; i < t.endorses.length; i++) {
    if (typeof t.endorses[i] !== "string" || !DID_WEB_RE.test(t.endorses[i] as string)) {
      return { ok: false, reason: `trust_anchors.endorses[${i}] must be did:web` };
    }
  }

  if (!Array.isArray(t.endorsed_by)) {
    return { ok: false, reason: "trust_anchors.endorsed_by must be an array" };
  }
  for (let i = 0; i < t.endorsed_by.length; i++) {
    if (typeof t.endorsed_by[i] !== "string" || !DID_WEB_RE.test(t.endorsed_by[i] as string)) {
      return { ok: false, reason: `trust_anchors.endorsed_by[${i}] must be did:web` };
    }
  }

  return {
    ok: true,
    trust_anchors: {
      endorses: t.endorses as string[],
      endorsed_by: t.endorsed_by as string[],
    },
  };
}

// --- Helpers ---

function isIso8601(s: string): boolean {
  if (!ISO_8601_RE.test(s)) return false;
  const t = Date.parse(s);
  return !Number.isNaN(t);
}

function jsonish(v: unknown): string {
  try {
    return JSON.stringify(v);
  } catch {
    return String(v);
  }
}
