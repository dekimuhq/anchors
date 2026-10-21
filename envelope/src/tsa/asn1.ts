/**
 * Minimal ASN.1 DER reader — Phase B Task 8.
 *
 * Implements TLV walk over DER, OID decoding, and helpers for the specific
 * tag types RFC 3161 TimeStampResp + CMS SignedData use. Not a general
 * ASN.1 library — only the subset needed by the TSA integration.
 *
 * Ref: RFC 3161 §2, RFC 5652 §5 (CMS SignedData)
 */

// ── Types ─────────────────────────────────────────────────────────────────────

/** Tag-Length-Value descriptor. `contentStart` is the byte offset of the
 *  content (value) within the original buffer. */
export interface TLV {
  tag: number;
  length: number;
  contentStart: number;
}

// ── Core TLV walker ───────────────────────────────────────────────────────────

/**
 * Read one TLV at `offset` within `buf`.
 *
 * Supports:
 *  - Short-form length (< 128 bytes).
 *  - Long-form length with 1–4 length octets (covers all practical DER).
 *
 * Throws on: read-past-end, unsupported indefinite/reserved length forms,
 * and TLV content overrun.
 */
export function readTLV(buf: Uint8Array, offset: number): TLV {
  if (offset + 1 >= buf.length) throw new Error("asn1: read past end (no length byte)");
  const tag = buf[offset]!;
  const lenByte = buf[offset + 1]!;
  let length: number;
  let contentStart: number;

  if ((lenByte & 0x80) === 0) {
    // Short form
    length = lenByte;
    contentStart = offset + 2;
  } else {
    const lenBytes = lenByte & 0x7f;
    if (lenBytes === 0 || lenBytes > 4) {
      throw new Error("asn1: unsupported length form");
    }
    length = 0;
    for (let i = 0; i < lenBytes; i++) {
      length = (length << 8) | buf[offset + 2 + i]!;
    }
    contentStart = offset + 2 + lenBytes;
  }

  if (contentStart + length > buf.length) {
    throw new Error("asn1: TLV exceeds buffer");
  }

  return { tag, length, contentStart };
}

// ── OID decoder ───────────────────────────────────────────────────────────────

/**
 * Decode an OID from raw content bytes (the value part, without TL header).
 *
 * @param buf    Buffer containing the OID content.
 * @param start  Byte offset of the first OID content byte.
 * @param len    Number of OID content bytes.
 * @returns      Dot-separated OID string, e.g. "2.16.840.1.101.3.4.2.1".
 */
export function decodeOID(buf: Uint8Array, start: number, len: number): string {
  if (len === 0) throw new Error("asn1: empty OID");

  const first = buf[start]!;
  const a = Math.floor(first / 40);
  const b = first % 40;
  const out: string[] = [String(a), String(b)];

  let value = 0;
  for (let i = 1; i < len; i++) {
    const byte = buf[start + i]!;
    value = (value << 7) | (byte & 0x7f);
    if ((byte & 0x80) === 0) {
      out.push(String(value));
      value = 0;
    }
  }

  if (value !== 0) throw new Error("asn1: truncated OID component");

  return out.join(".");
}

// ── Typed readers ─────────────────────────────────────────────────────────────

/**
 * Read an OCTET STRING (tag 0x04) at `offset`.
 * Returns a subarray view over the content bytes.
 */
export function readOctetString(buf: Uint8Array, offset: number): Uint8Array {
  const t = readTLV(buf, offset);
  if (t.tag !== 0x04) {
    throw new Error(
      `asn1: expected OCTET STRING (0x04), got 0x${t.tag.toString(16)}`
    );
  }
  return buf.subarray(t.contentStart, t.contentStart + t.length);
}

/**
 * Read an INTEGER (tag 0x02) at `offset`.
 * Returns a BigInt — handles multi-byte serial numbers and nonces.
 */
export function readInteger(buf: Uint8Array, offset: number): bigint {
  const t = readTLV(buf, offset);
  if (t.tag !== 0x02) throw new Error("asn1: expected INTEGER");
  let v = 0n;
  for (let i = 0; i < t.length; i++) {
    v = (v << 8n) | BigInt(buf[t.contentStart + i]!);
  }
  return v;
}

/**
 * Read a GeneralizedTime (tag 0x18) at `offset`.
 * RFC 3161 timestamps use GeneralizedTime with UTC suffix "Z".
 * Returns an ISO 8601 UTC string, e.g. "2026-05-17T14:30:00Z".
 */
export function readGeneralizedTime(buf: Uint8Array, offset: number): string {
  const t = readTLV(buf, offset);
  if (t.tag !== 0x18) throw new Error("asn1: expected GeneralizedTime");
  const raw = new TextDecoder().decode(
    buf.subarray(t.contentStart, t.contentStart + t.length)
  );
  // Raw form: YYYYMMDDHHMMSS[.fff]Z
  const m = raw.match(
    /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d+)?Z$/
  );
  if (!m) throw new Error(`asn1: malformed GeneralizedTime ${raw}`);
  return `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}Z`;
}
