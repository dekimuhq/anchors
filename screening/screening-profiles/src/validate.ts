import type { ScreeningListBody } from "./body.ts";

export interface ValidationResult { ok: boolean; errors: string[]; }

export const FRESHNESS_WINDOW_MS = 48 * 60 * 60 * 1000;
export const MAX_CANDIDATES = 50;

const SHA_RE = /^sha256:[0-9a-f]{64}$/;
const ULID_RE = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/;
const REF_RE = /^[A-Za-z0-9._:-]{1,64}$/;
const SHA = { test: (v: unknown): boolean => typeof v === "string" && SHA_RE.test(v) };
const ULID = { test: (v: unknown): boolean => typeof v === "string" && ULID_RE.test(v) };

/** Keys a v1 body may carry. Anything else is rejected so plaintext party data cannot ride along. */
const BODY_KEYS = new Set(["profile", "screen_id", "list", "matcher", "subject_commit", "result", "candidates", "trigger", "screened_at", "field_root"]);
const LIST_KEYS = new Set(["id", "file_name", "file_date", "file_sha256", "parsed_sha256", "entry_count", "fetched_at"]);
const MATCHER_KEYS = new Set(["name", "version", "threshold"]);
const CANDIDATE_KEYS = new Set(["entry_ref", "score"]);
/** v1 defines one list. New ids are additive via a registry decision. */
export const LIST_IDS: ReadonlySet<string> = new Set(["eu-fsf"]);

const extra = (o: unknown, allowed: Set<string>): boolean =>
  typeof o === "object" && o !== null && Object.keys(o).some((k) => !allowed.has(k));

function ts(s: unknown): number | null {
  if (typeof s !== "string") return null;
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/.test(s)) return null;
  const n = Date.parse(s);
  return Number.isNaN(n) ? null : n;
}

const isStr = (v: unknown): v is string => typeof v === "string" && v.trim().length > 0;

/**
 * Validate a screening.list body. Error strings are the spec §6 taxonomy codes.
 * SHAPE + freshness only: never re-runs the matcher, never judges sanctions status.
 */
export function validateScreeningList(body: unknown): ValidationResult {
  const e: string[] = [];
  const b = body as Partial<ScreeningListBody> | null;
  if (typeof b !== "object" || b === null) return { ok: false, errors: ["body.not_object"] };
  if (b.profile !== "screening.list") e.push("screening.profile.unknown");
  if (extra(b, BODY_KEYS)) e.push("screening.body.unknown_field");
  if (!ULID.test(b.screen_id)) e.push("screening.screen_id.malformed");

  const l = b.list;
  let fetched: number | null = null;
  if (typeof l !== "object" || l === null) e.push("screening.list.missing");
  else {
    if (!isStr(l.id) || !LIST_IDS.has(l.id)) e.push("screening.list.id_unknown");
    if (extra(l, LIST_KEYS)) e.push("screening.body.unknown_field");
    if (!isStr(l.file_name)) e.push("screening.list.file_name_missing");
    if (ts(l.file_date) === null) e.push("screening.list.file_date_malformed");
    if (!SHA.test(l.file_sha256) || !SHA.test(l.parsed_sha256)) e.push("screening.list.hash_malformed");
    if (!Number.isInteger(l.entry_count) || (l.entry_count as number) < 1) e.push("screening.list.empty");
    fetched = ts(l.fetched_at);
    if (fetched === null) e.push("screening.list.fetched_at_malformed");
    const fd = ts(l.file_date);
    if (fd !== null && fetched !== null && fd > fetched) e.push("screening.list.file_date_after_fetch");
  }

  const m = b.matcher;
  if (extra(m, MATCHER_KEYS)) e.push("screening.body.unknown_field");
  const thr = m?.threshold;
  if (typeof m !== "object" || m === null || !isStr(m.name) || !isStr(m.version)) e.push("screening.matcher.missing");
  if (typeof thr !== "number" || !(thr > 0 && thr <= 1)) e.push("screening.matcher.threshold_invalid");

  if (!SHA.test(b.subject_commit)) e.push("screening.subject_commit.malformed");
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
      if (extra(x, CANDIDATE_KEYS)) e.push("screening.body.unknown_field");
      if (!x || typeof x.entry_ref !== "string" || !REF_RE.test(x.entry_ref) || typeof x.score !== "number" || !(x.score >= 0 && x.score <= 1)) {
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
