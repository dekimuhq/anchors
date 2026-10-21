/**
 * RFC 3161 TimeStampReq encoder — Phase B Task 9.
 *
 * Encodes a TimeStampReq as DER per RFC 3161 §2.4.1:
 *
 *   TimeStampReq ::= SEQUENCE {
 *     version        INTEGER { v1(1) },
 *     messageImprint MessageImprint,
 *     reqPolicy      TSAPolicyId OPTIONAL,
 *     nonce          INTEGER OPTIONAL,
 *     certReq        BOOLEAN DEFAULT FALSE,
 *     extensions     [0] IMPLICIT Extensions OPTIONAL
 *   }
 *
 *   MessageImprint ::= SEQUENCE {
 *     hashAlgorithm AlgorithmIdentifier,
 *     hashedMessage OCTET STRING
 *   }
 *
 * Only sha-256 is supported in v1.1.
 */

// ── SHA-256 AlgorithmIdentifier (pre-encoded DER) ─────────────────────────────
//
// SEQUENCE { OID 2.16.840.1.101.3.4.2.1, NULL }
// Tag/len:  30 0D
//   OID:    06 09 60 86 48 01 65 03 04 02 01
//   NULL:   05 00
const SHA256_ALG_ID_DER = new Uint8Array([
  0x30, 0x0d,
  0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
  0x05, 0x00,
]);

// ── DER encoding helpers ──────────────────────────────────────────────────────

function encodeLength(n: number): Uint8Array {
  if (n < 128) return new Uint8Array([n]);
  if (n < 256) return new Uint8Array([0x81, n]);
  if (n < 65536) return new Uint8Array([0x82, (n >> 8) & 0xff, n & 0xff]);
  throw new Error("tsa: TimeStampReq exceeds 64KB");
}

function concat(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function tlv(tag: number, content: Uint8Array): Uint8Array {
  return concat([new Uint8Array([tag]), encodeLength(content.length), content]);
}

/** Encode a non-negative bigint as DER INTEGER. */
function encodeInteger(v: bigint): Uint8Array {
  if (v === 0n) return tlv(0x02, new Uint8Array([0x00]));
  const bytes: number[] = [];
  let n = v;
  while (n > 0n) {
    bytes.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  // If the high bit is set, prepend 0x00 to keep the integer positive
  if ((bytes[0]! & 0x80) !== 0) bytes.unshift(0x00);
  return tlv(0x02, new Uint8Array(bytes));
}

/** Encode an OID string as DER OID value (tag + length + content). */
function encodeOID(oid: string): Uint8Array {
  const parts = oid.split(".").map(Number);
  if (parts.length < 2) throw new Error(`tsa: invalid OID ${oid}`);
  const bytes: number[] = [];
  // First two components encoded as 40*first + second
  bytes.push(40 * parts[0]! + parts[1]!);
  for (let i = 2; i < parts.length; i++) {
    let val = parts[i]!;
    if (val === 0) {
      bytes.push(0x00);
      continue;
    }
    const sub: number[] = [];
    while (val > 0) {
      sub.unshift(val & 0x7f);
      val >>= 7;
    }
    // Set continuation bits on all but the last byte
    const encoded = sub.map((b, idx) => (idx < sub.length - 1 ? b | 0x80 : b));
    bytes.push(...encoded);
  }
  return tlv(0x06, new Uint8Array(bytes));
}

// ── Public API ────────────────────────────────────────────────────────────────

export function buildTimeStampReq(
  imprint: Uint8Array,
  hashAlg: "sha-256",
  opts: { policyOid?: string; nonce?: bigint; certReq?: boolean } = {},
): Uint8Array {
  if (hashAlg !== "sha-256") throw new Error("tsa: only sha-256 in v1.1");
  if (imprint.length !== 32) {
    throw new Error("tsa: sha-256 imprint must be 32 bytes");
  }

  // version INTEGER { v1(1) }
  const version = tlv(0x02, new Uint8Array([0x01]));

  // MessageImprint: SEQUENCE { AlgorithmIdentifier, OCTET STRING }
  const hashedMsg = tlv(0x04, imprint);
  const msgImprint = tlv(0x30, concat([SHA256_ALG_ID_DER, hashedMsg]));

  const fields: Uint8Array[] = [version, msgImprint];

  // reqPolicy OID OPTIONAL
  if (opts.policyOid !== undefined) {
    fields.push(encodeOID(opts.policyOid));
  }

  // nonce INTEGER OPTIONAL
  if (opts.nonce !== undefined) {
    fields.push(encodeInteger(opts.nonce));
  }

  // certReq BOOLEAN DEFAULT FALSE — only encode if true
  if (opts.certReq === true) {
    fields.push(tlv(0x01, new Uint8Array([0xff]))); // BOOLEAN TRUE = 0xFF
  }

  return tlv(0x30, concat(fields));
}
