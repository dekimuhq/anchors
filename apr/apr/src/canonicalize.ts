/**
 * RFC 8785-lite canonical JSON, matching `apr-spec/v1.md` §4.1.
 *
 * Rules:
 *  - object keys sorted by UTF-16 code unit
 *  - no whitespace
 *  - numbers via Number.toString
 *  - strings UTF-8, NFC-normalised
 *  - rejects NaN, Infinity, undefined, functions, symbols, bigint
 *  - rejects circular references
 *  - drops object members whose value is undefined? — no: throws, per spec
 */

function sortValue(value: unknown, seen: WeakSet<object>): unknown {
  if (value === null) return null;
  if (typeof value === "boolean") return value;
  if (typeof value === "string") return value.normalize("NFC");
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("canonicalize: non-finite number");
    }
    return value;
  }
  if (typeof value === "bigint") {
    throw new Error("canonicalize: bigint not supported");
  }
  if (typeof value === "undefined") {
    throw new Error("canonicalize: undefined not supported");
  }
  if (typeof value === "function" || typeof value === "symbol") {
    throw new Error(`canonicalize: ${typeof value} not supported`);
  }
  if (Array.isArray(value)) {
    if (seen.has(value)) throw new Error("canonicalize: circular reference");
    seen.add(value);
    const result = value.map((v) => sortValue(v, seen));
    seen.delete(value);
    return result;
  }
  if (typeof value === "object") {
    if (seen.has(value)) throw new Error("canonicalize: circular reference");
    seen.add(value);
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const out: Record<string, unknown> = {};
    for (const k of keys) {
      const v = obj[k];
      if (v === undefined) {
        throw new Error(`canonicalize: undefined value at key "${k}"`);
      }
      out[k.normalize("NFC")] = sortValue(v, seen);
    }
    seen.delete(value);
    return out;
  }
  throw new Error(`canonicalize: unsupported type ${typeof value}`);
}

export function canonicalize(value: unknown): string {
  const sorted = sortValue(value, new WeakSet<object>());
  return JSON.stringify(sorted);
}
