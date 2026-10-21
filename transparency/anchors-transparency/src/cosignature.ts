import { createHash } from "node:crypto";
import { signBytes, verifyBytes, ed25519RawPublicKey } from "./ed25519.ts";
import { checkpointBody, parseCheckpoint } from "./checkpoint.ts";
import type { CheckpointNote } from "./types.ts";

/**
 * Phase 1.5 — witness co-signing (C2SP cosignature/v1).
 *
 * A witness fetches the latest checkpoint, verifies (off-line, in its own software) a consistency
 * proof from the checkpoint it last cosigned, then returns a cosignature over the checkpoint note.
 * The cosignature is an Ed25519 signature over the C2SP cosignature/v1 *timestamped* message — this
 * gives a witnessed timestamp and matches off-the-shelf witness software, so independent third
 * parties can co-sign without bespoke tooling. The operator's own signature line is unchanged
 * (plain Ed25519 over the body) so existing checkpoints stay byte-equal.
 *
 * The cosignature line is byte-compatible with the C2SP signed-note framing: the base64url blob is
 * `4-byte key id ‖ 8-byte BE timestamp ‖ 64-byte Ed25519 signature` (76 bytes). The key id binds the
 * witness's name to its key per the signed-note spec — `SHA-256(name ‖ 0x0A ‖ algByte ‖ rawPubkey)[:4]`
 * — so off-the-shelf C2SP witnesses/verifiers route by the same id we emit.
 */

type CheckpointFields = Pick<CheckpointNote, "origin" | "size" | "rootHashB64">;

/**
 * C2SP signed-note algorithm byte for timestamped checkpoint cosignatures (`cosignature/v1`).
 * NOT the plain-Ed25519 byte (0x01) — the key id of a cosigning witness is derived with 0x04.
 * See C2SP signed-note.md (key-id) + tlog-cosignature.md.
 */
const ALG_ED25519_COSIGNATURE_V1 = 0x04;

const KEY_ID_BYTES = 4;
const TIMESTAMP_BYTES = 8;
const SIGNATURE_BYTES = 64;
const COSIG_BLOB_BYTES = KEY_ID_BYTES + TIMESTAMP_BYTES + SIGNATURE_BYTES; // 76

/**
 * C2SP signed-note key id: the first 4 bytes of `SHA-256(name ‖ 0x0A ‖ 0x04 ‖ rawPubkey)`.
 * `publicKey` may be a PEM (public or private — the public key is derived) or the raw 32-byte key.
 */
export function c2spKeyHash(name: string, publicKey: string | Uint8Array): Buffer {
  const raw = typeof publicKey === "string" ? ed25519RawPublicKey(publicKey) : Buffer.from(publicKey);
  if (raw.length !== 32) throw new Error("c2spKeyHash: expected a 32-byte Ed25519 public key");
  return createHash("sha256")
    .update(Buffer.from(name, "utf8"))
    .update(Buffer.from([0x0a, ALG_ED25519_COSIGNATURE_V1]))
    .update(raw)
    .digest()
    .subarray(0, KEY_ID_BYTES);
}

/** Cosignature/v1 signed message: `cosignature/v1\ntime <T>\n<checkpoint body>`. */
export function cosignatureMessage(c: CheckpointFields, timestamp: number): Uint8Array {
  if (!Number.isInteger(timestamp) || timestamp < 0) {
    throw new Error("cosignature timestamp must be a non-negative integer (unix seconds)");
  }
  return new TextEncoder().encode(`cosignature/v1\ntime ${timestamp}\n${checkpointBody(c)}`);
}

/**
 * Decode a cosignature line blob into its C2SP key id, timestamp, and raw 64-byte signature.
 * Throws on malformed input (including a legacy pre-B3 72-byte blob with no key id).
 */
export function decodeCosignatureBlob(blobB64url: string): { keyId: Buffer; timestamp: number; sig: Buffer } {
  const raw = Buffer.from(blobB64url, "base64url");
  if (raw.length !== COSIG_BLOB_BYTES) {
    throw new Error(
      "malformed cosignature blob: expected 76 bytes (4-byte key id + 8-byte timestamp + 64-byte signature)",
    );
  }
  return {
    keyId: raw.subarray(0, KEY_ID_BYTES),
    timestamp: Number(raw.subarray(KEY_ID_BYTES, KEY_ID_BYTES + TIMESTAMP_BYTES).readBigUInt64BE()),
    sig: raw.subarray(KEY_ID_BYTES + TIMESTAMP_BYTES),
  };
}

/** Extract the 4-byte C2SP key id from a cosignature line (`— <keyHint> <blob>`). Throws on malformed input. */
export function decodeCosignatureLineId(line: string): Buffer {
  const blob = line.trim().split(" ")[2] ?? "";
  return decodeCosignatureBlob(blob).keyId;
}

/**
 * Produce a witness cosignature line: `— <keyHint> <base64url(keyId‖timestamp‖signature)>\n`.
 * The blob is C2SP-framed (76 bytes); the line slots into the checkpoint's signature block after
 * the operator line. The key id is derived from `keyHint` + the public key of `privateKeyPem`.
 */
export function signCosignature(
  c: CheckpointFields,
  keyHint: string,
  privateKeyPem: string,
  timestamp: number,
): string {
  const sig = Buffer.from(signBytes(cosignatureMessage(c, timestamp), privateKeyPem), "base64url");
  const ts = Buffer.alloc(TIMESTAMP_BYTES);
  ts.writeBigUInt64BE(BigInt(timestamp));
  const keyId = c2spKeyHash(keyHint, ed25519RawPublicKey(privateKeyPem));
  return `— ${keyHint} ${Buffer.concat([keyId, ts, sig]).toString("base64url")}\n`;
}

/**
 * Verify a witness cosignature blob against a checkpoint body + public key. Never throws.
 * The embedded C2SP key id is returned for callers that route/validate by it; the signature
 * itself is the trust decision (the key id is not signed and is checked at the policy layer).
 */
export function verifyCosignature(
  c: CheckpointFields,
  blobB64url: string,
  publicKeyPem: string,
): { valid: boolean; timestamp: number | null; keyId: Buffer | null } {
  let decoded: { keyId: Buffer; timestamp: number; sig: Buffer };
  try {
    decoded = decodeCosignatureBlob(blobB64url);
  } catch {
    return { valid: false, timestamp: null, keyId: null };
  }
  const msg = cosignatureMessage(c, decoded.timestamp);
  return {
    valid: verifyBytes(decoded.sig.toString("base64url"), msg, publicKeyPem),
    timestamp: decoded.timestamp,
    keyId: decoded.keyId,
  };
}

/**
 * Operator-side gather: append witness cosignature lines into the operator's signed checkpoint note,
 * keeping a single contiguous signature block.
 */
export function gatherCosignatures(operatorNote: string, witnessLines: string[]): string {
  const tail = witnessLines.map((l) => (l.endsWith("\n") ? l : `${l}\n`)).join("");
  return operatorNote.endsWith("\n") ? operatorNote + tail : `${operatorNote}\n${tail}`;
}

export interface WitnessCosignature {
  keyHint: string;
  timestamp: number;
  valid: boolean;
}

export interface CheckpointCosignVerification {
  operatorValid: boolean;
  witnessCosignatures: WitnessCosignature[];
  validWitnessCount: number;
  warnings: "checkpoint_undercosigned"[];
  /** operatorValid only — a witness shortfall is a warning, never a HARD-fail in v1.5 (spec §5). */
  ok: boolean;
}

export interface VerifyCheckpointCosignedOptions {
  operatorKeys: Record<string, string>;
  witnessKeys: Record<string, string>;
  /** Opt-in policy. Below this many valid witness cosignatures ⇒ `checkpoint_undercosigned` warning. */
  requireWitnessCosignatures?: number;
}

/**
 * Verify a checkpoint's operator signature and any witness cosignatures.
 *
 * The operator is the first signature line (plain Ed25519 over the body); every line after it is
 * treated as a witness cosignature/v1. With `requireWitnessCosignatures: N`, fewer than N valid
 * witness cosignatures yields a `checkpoint_undercosigned` warning — it never HARD-fails, so
 * verification does not brick while witnesses are still being recruited.
 */
export function verifyCheckpointCosigned(
  note: string,
  opts: VerifyCheckpointCosignedOptions,
): CheckpointCosignVerification {
  let parsed: CheckpointNote;
  try {
    parsed = parseCheckpoint(note);
  } catch {
    return { operatorValid: false, witnessCosignatures: [], validWitnessCount: 0, warnings: [], ok: false };
  }

  const c: CheckpointFields = { origin: parsed.origin, size: parsed.size, rootHashB64: parsed.rootHashB64 };

  const op = parsed.signatures[0];
  const opPem = op ? opts.operatorKeys[op.keyHint] : undefined;
  const operatorValid =
    !!op && !!opPem && verifyBytes(op.sigB64, new TextEncoder().encode(checkpointBody(c)), opPem);

  const witnessCosignatures: WitnessCosignature[] = parsed.signatures.slice(1).map((line) => {
    const pem = opts.witnessKeys[line.keyHint];
    if (!pem) return { keyHint: line.keyHint, timestamp: 0, valid: false };
    const r = verifyCosignature(c, line.sigB64, pem);
    // C2SP conformance: the embedded key id MUST bind the line's name to the allowlisted key,
    // otherwise the line is not a well-formed cosignature for this witness.
    let valid = r.valid;
    if (valid) {
      try {
        valid = !!r.keyId && c2spKeyHash(line.keyHint, pem).equals(r.keyId);
      } catch {
        valid = false;
      }
    }
    return { keyHint: line.keyHint, timestamp: r.timestamp ?? 0, valid };
  });

  const validWitnessCount = witnessCosignatures.filter((w) => w.valid).length;
  const required = opts.requireWitnessCosignatures ?? 0;
  const warnings: "checkpoint_undercosigned"[] =
    required > 0 && validWitnessCount < required ? ["checkpoint_undercosigned"] : [];

  return { operatorValid, witnessCosignatures, validWitnessCount, warnings, ok: operatorValid };
}
