/**
 * Hand-rolled structural validator for `ar.trusted_issuers.v1`.
 *
 * No heavy/crypto runtime deps — `@dekimuhq/anchors-trusted-issuers` is a pure
 * library. Mirrors the discriminated-union
 * pattern used by every other anchors validator (e.g.
 * `apr-verifier/canonicalize.ts`, `acr-verifier/schema.ts`). The one envelope
 * import is `SIG_ALGS` — a frozen string tuple, the canonical registry of
 * signature algorithms — so the `publisher_key` accepted algorithm-prefix set
 * stays in lockstep with the wire (v1.3 §L6: the key prefix MUST match a
 * registered `sig_alg`). No new dependency: `verify.ts` already imports from
 * `@dekimuhq/anchors-envelope`.
 */

import { SIG_ALGS } from "@dekimuhq/anchors-envelope";
import { isIso8601 } from "./iso8601.ts";
import type {
  PqcMandate,
  TrustedIssuerListV1,
  TrustedIssuerRecord,
} from "./types.ts";

const KIND = "ar.trusted_issuers.v1";

const DID_WEB_RE = /^did:web:[a-z0-9.\-:_%]+$/i;
/**
 * `publisher_key` is `<alg>:<base64url>` where `<alg>` is one of the registered
 * `SIG_ALGS` (v1.3 §L6 self-describing key convention). Generated from
 * `SIG_ALGS` so a newly-registered algorithm widens this automatically — no
 * second list to drift. Accepting the *format* is independent of whether
 * `verify.ts` can yet *verify* a given algorithm (it has its own capability
 * gate — see `unsupported_publisher_key_alg`).
 */
const PUBLISHER_KEY_RE = buildPublisherKeyRe();

function buildPublisherKeyRe(): RegExp {
  const algs = SIG_ALGS.map((a) => a.replace(/[.*+?^${}()|[\]\\-]/g, "\\$&")).join("|");
  return new RegExp(`^(?:${algs}):[A-Za-z0-9_-]+$`);
}
const PREVIOUS_SHA256_RE = /^sha256:[0-9a-f]{64}$/;

export type ParseTrustedIssuerListResult =
  | { ok: true; doc: TrustedIssuerListV1 }
  | { ok: false; reason: string };

export function parseTrustedIssuerList(
  raw: unknown,
): ParseTrustedIssuerListResult {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return { ok: false, reason: "doc must be a JSON object" };
  }
  const o = raw as Record<string, unknown>;

  if (o.kind !== KIND) {
    return { ok: false, reason: `kind must be "${KIND}", got ${jsonish(o.kind)}` };
  }

  if (typeof o.version !== "number" || !Number.isInteger(o.version) || o.version <= 0) {
    return { ok: false, reason: `version must be a positive integer, got ${jsonish(o.version)}` };
  }

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

  if (typeof o.publisher !== "string" || !DID_WEB_RE.test(o.publisher)) {
    return { ok: false, reason: `publisher must be did:web, got ${jsonish(o.publisher)}` };
  }
  if (typeof o.publisher_key !== "string" || !PUBLISHER_KEY_RE.test(o.publisher_key)) {
    return {
      ok: false,
      reason: `publisher_key must be <alg>:<base64url> with alg in {${SIG_ALGS.join(", ")}}, got ${jsonish(o.publisher_key)}`,
    };
  }

  if (o.previous_sha256 !== null) {
    if (typeof o.previous_sha256 !== "string" || !PREVIOUS_SHA256_RE.test(o.previous_sha256)) {
      return {
        ok: false,
        reason: `previous_sha256 must be null or sha256:<64 lowercase hex>, got ${jsonish(o.previous_sha256)}`,
      };
    }
  }

  if (!Array.isArray(o.issuers)) {
    return { ok: false, reason: "issuers must be an array" };
  }
  const records: TrustedIssuerRecord[] = [];
  for (let i = 0; i < o.issuers.length; i++) {
    const rec = validateIssuerRecord(o.issuers[i], i);
    if (!rec.ok) return rec;
    records.push(rec.record);
  }

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
      publisher: o.publisher,
      publisher_key: o.publisher_key,
      previous_sha256: o.previous_sha256 === null ? null : (o.previous_sha256 as string),
      issuers: records,
      sig: o.sig,
    },
  };
}

type ValidateRecordResult =
  | { ok: true; record: TrustedIssuerRecord }
  | { ok: false; reason: string };

function validateIssuerRecord(raw: unknown, idx: number): ValidateRecordResult {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return { ok: false, reason: `issuers[${idx}] must be an object` };
  }
  const r = raw as Record<string, unknown>;

  if (typeof r.iss !== "string" || !DID_WEB_RE.test(r.iss)) {
    return { ok: false, reason: `issuers[${idx}].iss must be did:web, got ${jsonish(r.iss)}` };
  }
  if (typeof r.added_at !== "string" || !isIso8601(r.added_at)) {
    return {
      ok: false,
      reason: `issuers[${idx}].added_at must be ISO 8601, got ${jsonish(r.added_at)}`,
    };
  }
  if (r.revoked_at !== null) {
    if (typeof r.revoked_at !== "string" || !isIso8601(r.revoked_at)) {
      return {
        ok: false,
        reason: `issuers[${idx}].revoked_at must be null or ISO 8601, got ${jsonish(r.revoked_at)}`,
      };
    }
  }
  if (!Array.isArray(r.families) || r.families.length === 0) {
    return {
      ok: false,
      reason: `issuers[${idx}].families must be a non-empty array of strings`,
    };
  }
  for (let j = 0; j < r.families.length; j++) {
    if (typeof r.families[j] !== "string") {
      return {
        ok: false,
        reason: `issuers[${idx}].families[${j}] must be a string`,
      };
    }
  }
  if (r.profiles_pinned !== null) {
    if (
      typeof r.profiles_pinned !== "object" ||
      Array.isArray(r.profiles_pinned)
    ) {
      return {
        ok: false,
        reason: `issuers[${idx}].profiles_pinned must be null or Record<string,string[]>`,
      };
    }
    for (const [k, v] of Object.entries(r.profiles_pinned)) {
      if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) {
        return {
          ok: false,
          reason: `issuers[${idx}].profiles_pinned[${k}] must be string[]`,
        };
      }
    }
  }
  if (r.notes !== null && typeof r.notes !== "string") {
    return {
      ok: false,
      reason: `issuers[${idx}].notes must be string or null`,
    };
  }

  // `pqc_mandatory` — optional issuer-level PQC-migration posture. Validate
  // STRUCTURE only: `min_sig_alg` is deliberately NOT gated on `SIG_ALGS`
  // membership (a manifest may name a future algorithm an older verifier does
  // not yet know — forward-compat). The unknown-alg fail-closed happens at
  // policy-eval time (`issuerPqcRequirement`), not here.
  let pqcMandatory: PqcMandate | null = null;
  if (r.pqc_mandatory !== undefined && r.pqc_mandatory !== null) {
    const pm = r.pqc_mandatory;
    if (typeof pm !== "object" || Array.isArray(pm)) {
      return {
        ok: false,
        reason: `issuers[${idx}].pqc_mandatory must be null or an object`,
      };
    }
    const pmo = pm as Record<string, unknown>;
    if (typeof pmo.min_sig_alg !== "string" || pmo.min_sig_alg.length === 0) {
      return {
        ok: false,
        reason: `issuers[${idx}].pqc_mandatory.min_sig_alg must be a non-empty string, got ${jsonish(pmo.min_sig_alg)}`,
      };
    }
    if (typeof pmo.mandatory_from !== "string" || !isIso8601(pmo.mandatory_from)) {
      return {
        ok: false,
        reason: `issuers[${idx}].pqc_mandatory.mandatory_from must be ISO 8601, got ${jsonish(pmo.mandatory_from)}`,
      };
    }
    pqcMandatory = { min_sig_alg: pmo.min_sig_alg, mandatory_from: pmo.mandatory_from };
  }

  return {
    ok: true,
    record: {
      iss: r.iss,
      added_at: r.added_at,
      revoked_at: r.revoked_at === null ? null : (r.revoked_at as string),
      families: r.families as string[],
      profiles_pinned:
        r.profiles_pinned === null
          ? null
          : (r.profiles_pinned as Record<string, string[]>),
      notes: r.notes === null ? null : (r.notes as string),
      // Optional + additive: only present on the parsed record when the manifest
      // carried it, so a record without a mandate keeps its exact prior shape
      // (no `pqc_mandatory: null` key). The policy consumer treats absent ===
      // null === "no mandate".
      ...(pqcMandatory !== null ? { pqc_mandatory: pqcMandatory } : {}),
    },
  };
}

function jsonish(v: unknown): string {
  try {
    return JSON.stringify(v);
  } catch {
    return String(v);
  }
}
