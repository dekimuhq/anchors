import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as nodeSign } from "node:crypto";
import { createHash } from "node:crypto";
import { signCheckpoint } from "../src/checkpoint.ts";
import { ed25519RawPublicKey } from "../src/ed25519.ts";
import {
  cosignatureMessage,
  signCosignature,
  verifyCosignature,
  decodeCosignatureBlob,
  decodeCosignatureLineId,
  c2spKeyHash,
  gatherCosignatures,
  verifyCheckpointCosigned,
} from "../src/cosignature.ts";

function keys() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    pub: publicKey.export({ type: "spki", format: "pem" }).toString(),
    priv: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
}

const CP = { origin: "dekimu-anchors-log-2026", size: 42, rootHashB64: "YWJj" };
const T = 1_717_200_000; // fixed unix seconds for determinism

// --- cosignatureMessage (C2SP cosignature/v1 signed message) ---

test("cosignatureMessage is exactly `cosignature/v1\\ntime <T>\\n<body>`", () => {
  const msg = new TextDecoder().decode(cosignatureMessage(CP, T));
  assert.equal(msg, `cosignature/v1\ntime ${T}\n${CP.origin}\n${CP.size}\n${CP.rootHashB64}\n`);
});

test("cosignatureMessage rejects a non-integer timestamp", () => {
  assert.throws(() => cosignatureMessage(CP, 1.5), /integer/);
});

test("cosignatureMessage rejects a negative timestamp", () => {
  assert.throws(() => cosignatureMessage(CP, -1), /integer/);
});

// --- sign / verify round-trip ---

test("signCosignature → verifyCosignature round-trips", () => {
  const { pub, priv } = keys();
  const line = signCosignature(CP, "witness-a", priv, T);
  assert.ok(line.startsWith("— witness-a "));
  const blob = line.slice("— witness-a ".length).trim();
  const r = verifyCosignature(CP, blob, pub);
  assert.equal(r.valid, true);
  assert.equal(r.timestamp, T);
});

test("verifyCosignature fails on a tampered checkpoint body", () => {
  const { pub, priv } = keys();
  const blob = signCosignature(CP, "w", priv, T).split(" ")[2]!.trim();
  const r = verifyCosignature({ ...CP, size: 43 }, blob, pub);
  assert.equal(r.valid, false);
});

test("verifyCosignature fails against the wrong public key", () => {
  const { priv } = keys();
  const { pub: otherPub } = keys();
  const blob = signCosignature(CP, "w", priv, T).split(" ")[2]!.trim();
  assert.equal(verifyCosignature(CP, blob, otherPub).valid, false);
});

test("verifyCosignature never throws on a garbage blob", () => {
  const { pub } = keys();
  assert.doesNotThrow(() => {
    const r = verifyCosignature(CP, "!!!not-base64url!!!", pub);
    assert.equal(r.valid, false);
    assert.equal(r.timestamp, null);
  });
});

// --- blob encoding ---

test("decodeCosignatureBlob round-trips a large unix timestamp", () => {
  const { priv } = keys();
  const big = 4_102_444_800; // year 2100
  const blob = signCosignature(CP, "w", priv, big).split(" ")[2]!.trim();
  assert.equal(decodeCosignatureBlob(blob).timestamp, big);
});

test("decodeCosignatureBlob throws on a wrong-length blob", () => {
  assert.throws(() => decodeCosignatureBlob(Buffer.alloc(10).toString("base64url")), /76 bytes/);
});

test("decodeCosignatureBlob rejects a legacy 72-byte (un-prefixed) blob", () => {
  // A pre-B3 cosignature line (timestamp ‖ sig, no 4-byte key id) is no longer accepted.
  assert.throws(() => decodeCosignatureBlob(Buffer.alloc(72).toString("base64url")), /76 bytes/);
});

// --- cross-lib interop: a witness using raw node:crypto (no helper) must verify ---

test("cross-lib: raw ed25519 signature over the cosignature/v1 message verifies", () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pub = publicKey.export({ type: "spki", format: "pem" }).toString();
  // An independent witness builds the message itself and signs with node:crypto directly,
  // then frames the line per C2SP: base64url(4-byte key id ‖ 8-byte BE timestamp ‖ 64-byte sig).
  const msg = Buffer.from(`cosignature/v1\ntime ${T}\n${CP.origin}\n${CP.size}\n${CP.rootHashB64}\n`);
  const rawSig = nodeSign(null, msg, privateKey); // 64-byte Ed25519 sig
  const ts = Buffer.alloc(8);
  ts.writeBigUInt64BE(BigInt(T));
  // C2SP key id over the raw 32-byte public key, alg byte 0x04 (timestamped cosignature/v1).
  const rawPub = publicKey.export({ type: "spki", format: "der" }).subarray(-32);
  const keyId = createHash("sha256")
    .update(Buffer.from("witness-x", "utf8"))
    .update(Buffer.from([0x0a, 0x04]))
    .update(rawPub)
    .digest()
    .subarray(0, 4);
  const blob = Buffer.concat([keyId, ts, rawSig]).toString("base64url");
  const r = verifyCosignature(CP, blob, pub);
  assert.equal(r.valid, true);
  assert.equal(r.timestamp, T);
});

// --- C2SP 4-byte key-hash prefix (B3) ---

test("c2spKeyHash is SHA-256(name ‖ 0x0A ‖ 0x04 ‖ rawPubkey)[:4]", () => {
  const { pub } = keys();
  const rawPub = ed25519RawPublicKey(pub);
  const expected = createHash("sha256")
    .update(Buffer.from("dekimu-witness-1", "utf8"))
    .update(Buffer.from([0x0a, 0x04])) // newline + alg byte 0x04 (timestamped cosignature/v1)
    .update(rawPub)
    .digest()
    .subarray(0, 4);
  const id = c2spKeyHash("dekimu-witness-1", rawPub);
  assert.equal(id.length, 4);
  assert.ok(id.equals(expected));
});

test("c2spKeyHash accepts a PEM and derives the raw key (same result as raw bytes)", () => {
  const { pub } = keys();
  assert.ok(c2spKeyHash("w", pub).equals(c2spKeyHash("w", ed25519RawPublicKey(pub))));
});

test("c2spKeyHash uses the cosignature alg byte 0x04, not the plain-Ed25519 0x01", () => {
  const { pub } = keys();
  const rawPub = ed25519RawPublicKey(pub);
  const plainEd25519 = createHash("sha256")
    .update(Buffer.from("w", "utf8"))
    .update(Buffer.from([0x0a, 0x01]))
    .update(rawPub)
    .digest()
    .subarray(0, 4);
  assert.ok(!c2spKeyHash("w", rawPub).equals(plainEd25519));
});

test("cosignature line carries the C2SP 4-byte key-hash id", () => {
  const { pub, priv } = keys();
  const id = c2spKeyHash("dekimu-witness-1", ed25519RawPublicKey(pub));
  const line = signCosignature(CP, "dekimu-witness-1", priv, T);
  assert.ok(decodeCosignatureLineId(line).equals(id));
});

test("signCosignature produces a 76-byte (4 ‖ 8 ‖ 64) C2SP-framed blob", () => {
  const { priv } = keys();
  const blob = signCosignature(CP, "w", priv, T).split(" ")[2]!.trim();
  assert.equal(Buffer.from(blob, "base64url").length, 76);
  const d = decodeCosignatureBlob(blob);
  assert.equal(d.keyId.length, 4);
  assert.equal(d.timestamp, T);
  assert.equal(d.sig.length, 64);
});

test("verifyCheckpointCosigned rejects a witness line whose key id does not bind name+key", () => {
  const op = keys(), w1 = keys();
  const operatorNote = signCheckpoint(CP, "op", op.priv);
  // forge a line: valid signature + timestamp, but a wrong (zeroed) 4-byte key id.
  const ts = Buffer.alloc(8);
  ts.writeBigUInt64BE(BigInt(T));
  const { sig } = decodeCosignatureBlob(signCosignature(CP, "w1", w1.priv, T).split(" ")[2]!.trim());
  const forged = Buffer.concat([Buffer.alloc(4), ts, sig]).toString("base64url");
  const note = gatherCosignatures(operatorNote, [`— w1 ${forged}\n`]);
  const r = verifyCheckpointCosigned(note, {
    operatorKeys: { op: op.pub },
    witnessKeys: { w1: w1.pub },
    requireWitnessCosignatures: 1,
  });
  assert.equal(r.validWitnessCount, 0);
  assert.deepEqual(r.warnings, ["checkpoint_undercosigned"]);
});

// --- gatherCosignatures + verifyCheckpointCosigned (verifier policy) ---

function cosignedNote(opKeyHint: string, opPriv: string, witnesses: { hint: string; priv: string; t: number }[]) {
  const operatorNote = signCheckpoint(CP, opKeyHint, opPriv);
  const witnessLines = witnesses.map((w) => signCosignature(CP, w.hint, w.priv, w.t));
  return gatherCosignatures(operatorNote, witnessLines);
}

test("verifyCheckpointCosigned: operator + 2 witnesses, require 2 → ok, no warnings", () => {
  const op = keys(), w1 = keys(), w2 = keys();
  const note = cosignedNote("op", op.priv, [
    { hint: "w1", priv: w1.priv, t: T },
    { hint: "w2", priv: w2.priv, t: T + 5 },
  ]);
  const r = verifyCheckpointCosigned(note, {
    operatorKeys: { op: op.pub },
    witnessKeys: { w1: w1.pub, w2: w2.pub },
    requireWitnessCosignatures: 2,
  });
  assert.equal(r.operatorValid, true);
  assert.equal(r.validWitnessCount, 2);
  assert.deepEqual(r.warnings, []);
  assert.equal(r.ok, true);
});

test("verifyCheckpointCosigned: below threshold → checkpoint_undercosigned WARNING, still ok (operator valid)", () => {
  const op = keys(), w1 = keys();
  const note = cosignedNote("op", op.priv, [{ hint: "w1", priv: w1.priv, t: T }]);
  const r = verifyCheckpointCosigned(note, {
    operatorKeys: { op: op.pub },
    witnessKeys: { w1: w1.pub },
    requireWitnessCosignatures: 2,
  });
  assert.equal(r.operatorValid, true);
  assert.equal(r.validWitnessCount, 1);
  assert.deepEqual(r.warnings, ["checkpoint_undercosigned"]);
  assert.equal(r.ok, true); // v1.5: undercosigned never HARD-fails
});

test("verifyCheckpointCosigned: no policy (require 0) → never undercosigned, even with 0 witnesses", () => {
  const op = keys();
  const note = signCheckpoint(CP, "op", op.priv);
  const r = verifyCheckpointCosigned(note, { operatorKeys: { op: op.pub }, witnessKeys: {} });
  assert.equal(r.operatorValid, true);
  assert.equal(r.validWitnessCount, 0);
  assert.deepEqual(r.warnings, []);
  assert.equal(r.ok, true);
});

test("verifyCheckpointCosigned: unknown witness key is not counted", () => {
  const op = keys(), w1 = keys();
  const note = cosignedNote("op", op.priv, [{ hint: "w1", priv: w1.priv, t: T }]);
  const r = verifyCheckpointCosigned(note, {
    operatorKeys: { op: op.pub },
    witnessKeys: {}, // w1 not in allowlist
    requireWitnessCosignatures: 1,
  });
  assert.equal(r.validWitnessCount, 0);
  assert.equal(r.witnessCosignatures[0]?.valid, false);
  assert.deepEqual(r.warnings, ["checkpoint_undercosigned"]);
});

test("verifyCheckpointCosigned: bad operator signature → operatorValid false, ok false", () => {
  const op = keys(), other = keys(), w1 = keys();
  const note = cosignedNote("op", op.priv, [{ hint: "w1", priv: w1.priv, t: T }]);
  const r = verifyCheckpointCosigned(note, {
    operatorKeys: { op: other.pub }, // wrong operator key
    witnessKeys: { w1: w1.pub },
    requireWitnessCosignatures: 1,
  });
  assert.equal(r.operatorValid, false);
  assert.equal(r.ok, false);
});

test("verifyCheckpointCosigned: a witness cosig over a tampered checkpoint is rejected", () => {
  const op = keys(), w1 = keys();
  const operatorNote = signCheckpoint(CP, "op", op.priv);
  // witness signs a DIFFERENT (larger) tree than the operator published
  const rogueLine = signCosignature({ ...CP, size: 99 }, "w1", w1.priv, T);
  const note = gatherCosignatures(operatorNote, [rogueLine]);
  const r = verifyCheckpointCosigned(note, {
    operatorKeys: { op: op.pub },
    witnessKeys: { w1: w1.pub },
    requireWitnessCosignatures: 1,
  });
  assert.equal(r.operatorValid, true);
  assert.equal(r.validWitnessCount, 0);
  assert.deepEqual(r.warnings, ["checkpoint_undercosigned"]);
});

test("verifyCheckpointCosigned: operator-only note with require 1 → undercosigned", () => {
  const op = keys();
  const note = signCheckpoint(CP, "op", op.priv);
  const r = verifyCheckpointCosigned(note, {
    operatorKeys: { op: op.pub },
    witnessKeys: {},
    requireWitnessCosignatures: 1,
  });
  assert.equal(r.operatorValid, true);
  assert.equal(r.validWitnessCount, 0);
  assert.deepEqual(r.warnings, ["checkpoint_undercosigned"]);
});

test("verifyCheckpointCosigned never throws on a malformed note", () => {
  assert.doesNotThrow(() => {
    const r = verifyCheckpointCosigned("garbage", { operatorKeys: {}, witnessKeys: {} });
    assert.equal(r.ok, false);
    assert.equal(r.operatorValid, false);
    assert.deepEqual(r.witnessCosignatures, []);
  });
});

test("gatherCosignatures keeps a single contiguous signature block", () => {
  const op = keys(), w1 = keys();
  const note = cosignedNote("op", op.priv, [{ hint: "w1", priv: w1.priv, t: T }]);
  // exactly one blank-line separator between head and signature block
  assert.equal(note.split("\n\n").length, 2);
});
