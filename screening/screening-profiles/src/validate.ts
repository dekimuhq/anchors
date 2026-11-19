import type { ScreeningListBody } from "./body.ts";

export interface ValidationResult { ok: boolean; errors: string[]; }

export const FRESHNESS_WINDOW_MS = 48 * 60 * 60 * 1000;
export const MAX_CANDIDATES = 50;

const SHA = /^sha256:[0-9a-f]{64}$/;
const ULID = /^[0-9A-HJKMNP-TV-Z]{26}$/;

function ts(s: unknown): number | null {
  if (typeof s !== "string") return null;
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/.test(s)) return null;
  const n = Date.parse(s);
  return Number.isNaN(n) ? null : n;
}

const isStr = (v: unknown): v is string => typeof v === "string" && v.length > 0;

/**
 * Validate a screening.list body. Error strings are the spec §6 taxonomy codes.
 * SHAPE + freshness only: never re-runs the matcher, never judges sanctions status.
 */
export function validateScreeningList(body: unknown): ValidationResult {
  const e: string[] = [];
  const b = body as Partial<ScreeningListBody> | null;
  if (typeof b !== "object" || b === null) return { ok: false, errors: ["body.not_object"] };
  if (b.profile !== "screening.list") e.push("screening.profile.unknown");
  if (!ULID.test(String(b.screen_id))) e.push("screening.screen_id.malformed");

  const l = b.list;
  let fetched: number | null = null;
  if (typeof l !== "object" || l === null) e.push("screening.list.missing");
  else {
    if (!isStr(l.id)) e.push("screening.list.id_missing");
    if (!isStr(l.file_name)) e.push("screening.list.file_name_missing");
    if (ts(l.file_date) === null) e.push("screening.list.file_date_malformed");
    if (!SHA.test(String(l.file_sha256)) || !SHA.test(String(l.parsed_sha256))) e.push("screening.list.hash_malformed");
    if (!Number.isInteger(l.entry_count) || (l.entry_count as number) < 1) e.push("screening.list.empty");
    fetched = ts(l.fetched_at);
    if (fetched === null) e.push("screening.list.fetched_at_malformed");
  }

  const m = b.matcher;
  const thr = m?.threshold;
  if (typeof m !== "object" || m === null || !isStr(m.name) || !isStr(m.version)) e.push("screening.matcher.missing");
  if (typeof thr !== "number" || !(thr > 0 && thr <= 1)) e.push("screening.matcher.threshold_invalid");

  if (!SHA.test(String(b.subject_commit))) e.push("screening.subject_commit.malformed");
  if (b.trigger !== "manual" && b.trigger !== "scheduled") e.push("screening.trigger.invalid");

  const screened = ts(b.screened_at);
  if (screened === null) e.push("screening.screened_at_malformed");
  else if (fetched !== null && (screened < fetched || screened > fetched + FRESHNESS_WINDOW_MS)) e.push("screening.list.stale");

  if (b.result !== "none_at_threshold" && b.result !== "candidate") e.push("screening.result.invalid");
  if (!Array.isArray(b.candidates)) e.push("screening.candidates.not_array");
  else {
    const c = b.candidates;
    if (b.result === "none_at_threshold" && c.length !== 0) e.push("screening.result.incoherent");
    if (b.result === "candidate" && c.length === 0) e.push("screening.result.incoherent");
    if (c.length > MAX_CANDIDATES) e.push("screening.candidates.too_many");
    let prev = Infinity;
    for (const x of c) {
      if (!x || !isStr(x.entry_ref) || typeof x.score !== "number" || !(x.score >= 0 && x.score <= 1)) {
        e.push("screening.candidates.malformed");
        break;
      }
      if (typeof thr === "number" && x.score < thr) e.push("screening.candidates.below_threshold");
      if (x.score > prev) e.push("screening.candidates.unordered");
      prev = x.score;
    }
  }
  return { ok: e.length === 0, errors: [...new Set(e)] };
}
