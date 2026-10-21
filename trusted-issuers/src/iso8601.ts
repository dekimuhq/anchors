/**
 * Strict ISO 8601 timestamp validation — single source of truth.
 *
 * Shared by the manifest schema validator (`schema.ts`) AND the PQC-migration
 * policy (`pqc-policy.ts`). The policy treats the cutover instant as
 * security-relevant, so both layers MUST agree on what a valid timestamp is —
 * a lone `Date.parse` is implementation-lenient (accepts `"2030/01/01"`,
 * zone-less strings parsed as LOCAL time, etc.), which would silently shift a
 * PQC cutover by the host timezone offset. The strict regex pins
 * `YYYY-MM-DDTHH:MM:SS(.frac)?(Z|±HH:MM)` so the instant is unambiguous.
 */

// Strict ISO 8601: 2026-05-19T12:34:56(.fraction)?Z or with ±HH:MM offset.
export const ISO_8601_RE =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;

export function isIso8601(s: string): boolean {
  if (!ISO_8601_RE.test(s)) return false;
  const t = Date.parse(s);
  return !Number.isNaN(t);
}
