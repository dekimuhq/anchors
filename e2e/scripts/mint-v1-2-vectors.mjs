/**
 * mint-v1-2-vectors.mjs — deterministic minter for the v1.2 deferred conformance vectors.
 *
 * Writes 8 JSON vector files to anchors/e2e/test/vectors-v1-1/:
 *
 *   3 TSA failure modes (reuse existing arr-erasure-v2-tsa.json TSR — fully offline):
 *     arr-erasure-v2-tsa-imprint-mismatch.json
 *     arr-erasure-v2-tsa-anchor-expired.json
 *     arr-erasure-v2-tsa-drift-exceeded.json
 *
 *   5 Status List 2021 variants (in-memory signed lists, no network):
 *     arr-erasure-v2-statuslist-active.json
 *     arr-erasure-v2-statuslist-revoked.json
 *     arr-erasure-v2-statuslist-chain-revoked-list-stale.json
 *     arr-erasure-v2-statuslist-stale.json
 *     arr-erasure-v2-statuslist-unreachable.json
 *
 * ── DETERMINISM ──────────────────────────────────────────────────────────────
 * Issuer seed: Buffer.alloc(32, 0x42) — shared with mint-vectors.mjs.
 * Root key seed: Buffer.alloc(32, 0x52) — used to sign Status List credentials.
 * Re-running this script produces byte-identical JSON.
 *
 * ── NO NETWORK ──────────────────────────────────────────────────────────────
 * TSA failure vectors reuse the captured FreeTSA TSR from arr-erasure-v2-tsa.json.
 * Status List vectors mint signed VCs in-memory (gzip + Ed25519Signature2020).
 *
 * Brief: an internal design record (not published)
 *
 * @module mint-v1-2-vectors
 */

import * as crypto from "node:crypto";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import { gzipSync } from "node:zlib";

// ── Workspace path resolution ────────────────────────────────────────────────

const __dir = dirname(fileURLToPath(import.meta.url));
const E2E_DIR = resolve(__dir, "..");
const VECTORS_DIR = join(E2E_DIR, "test", "vectors-v1-1");

// ── Package imports (resolved via workspace node_modules) ────────────────────

const { signEnvelope, base64UrlEncode, base64UrlDecode, canonicalize } =
  await import("@dekimuhq/anchors-envelope");

// ── Fixed deterministic constants ────────────────────────────────────────────

/** PUBLIC TEST KEY — 32-byte Ed25519 seed all-0x42 (issuer). */
const ISSUER_SEED = Buffer.alloc(32, 0x42);
/** PUBLIC TEST KEY — 32-byte Ed25519 seed all-0x52 (Status List root). */
const ROOT_SEED = Buffer.alloc(32, 0x52);
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

function makePrivateKey(seed) {
  const der = Buffer.concat([PKCS8_PREFIX, seed]);
  return crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

function makePublicKeyRaw(seed) {
  const sk = makePrivateKey(seed);
  const pkDer = crypto.createPublicKey(sk).export({ format: "der", type: "spki" });
  return Buffer.from(pkDer).subarray(-32);
}

function makePublicKeyDer(seed) {
  const sk = makePrivateKey(seed);
  return crypto.createPublicKey(sk).export({ format: "der", type: "spki" });
}

const ISSUER_PRIVATE_KEY = makePrivateKey(ISSUER_SEED);
const ISSUER_PUBLIC_KEY_RAW = makePublicKeyRaw(ISSUER_SEED);
const ISSUER_PUBLIC_KEY_B64URL = base64UrlEncode(new Uint8Array(ISSUER_PUBLIC_KEY_RAW));
const ISS_KEY = `ed25519:${ISSUER_PUBLIC_KEY_B64URL}`;

const ROOT_PRIVATE_KEY = makePrivateKey(ROOT_SEED);
const ROOT_PUBLIC_KEY_DER = makePublicKeyDer(ROOT_SEED);
const ROOT_PUBLIC_KEY_DER_B64URL = base64UrlEncode(new Uint8Array(ROOT_PUBLIC_KEY_DER));
const ROOT_KID = "did:web:verify.dekimu.com#root";

const IAT_ISO = "2026-05-17T00:00:00Z";

const ANCHOR = {
  log: "https://verify.dekimu.com/test/v1",
  leaf_index: 0,
  inclusion_proof: [],
  tree_head_root: "sha256:" + "0".repeat(64),
  tree_size: 1,
  log_time: IAT_ISO,
};

const STATUS_LIST_URL = "https://verify.dekimu.com/test/status/2026/05-v12";
const STATUS_LIST_ID_FIELD = `${STATUS_LIST_URL}#list`;
const STATUS_LIST_VALID_FROM = "2026-05-01T00:00:00Z";
const STATUS_LIST_PROOF_CREATED = "2026-05-17T00:00:00Z";
const BITSTRING_LENGTH_BITS = 131072;

// ── ARR body helper ─────────────────────────────────────────────────────────

/**
 * Build an ARR v2 erasure receipt body. Mirrors mint-vectors.mjs::buildArrErasureV2
 * but parameterised on target_commit + ULID for per-vector divergence.
 */
function buildArrBody(targetCommitHex, policyHashHex) {
  const fieldInputs = {
    kind: "ar.erasure.v1",
    profile: "gdpr.art17",
    target_kind: "subject",
    target_commit: `sha256:${targetCommitHex}`,
    salt_epoch: "2026Q2",
    policy_hash: `sha256:${policyHashHex}`,
    policy_uri: "https://processor-cross-v12.example/p/v1",
    policy_version: "1.0.0",
    trigger: "subject_request",
    trigger_receipt: "sha256:" + "fc".repeat(32),
    event_at: "2026-05-17T11:00:00Z",
    granted_at: "2026-05-17T11:02:00Z",
    effective_until: null,
  };

  const fieldBytes = new TextEncoder().encode(canonicalize(fieldInputs));
  const prefixed = Buffer.concat([Buffer.from([0x00]), Buffer.from(fieldBytes)]);
  const field_root = "sha256:" + crypto.createHash("sha256").update(prefixed).digest("hex");

  return {
    profile: "gdpr.art17",
    target_kind: "subject",
    target_commit: `sha256:${targetCommitHex}`,
    salt_epoch: "2026Q2",
    policy_hash: `sha256:${policyHashHex}`,
    policy_uri: "https://processor-cross-v12.example/p/v1",
    policy_version: "1.0.0",
    trigger: "subject_request",
    trigger_receipt: "sha256:" + "fc".repeat(32),
    event_at: "2026-05-17T11:00:00Z",
    granted_at: "2026-05-17T11:02:00Z",
    effective_until: null,
    state_snapshot: {
      retention_status: "erased",
      current_policy_hash: `sha256:${policyHashHex}`,
      hold_active: false,
      hold_reason_commit: null,
      anonymized: false,
      archived: false,
    },
    field_root,
  };
}

/** Build + sign an ARR v=2 erasure envelope. */
async function buildArrEnvelope({ ulid, targetCommitHex, policyHashHex, credentialStatus }) {
  const body = buildArrBody(targetCommitHex, policyHashHex);
  const preSign = {
    v: 2,
    id: ulid,
    iat: IAT_ISO,
    claim_type: "ar.erasure.v1",
    iss: "did:web:processor-cross-v12.example",
    iss_key: ISS_KEY,
    subject: `sha256:${targetCommitHex}`,
    exp: null,
    prev: null,
    policy_uri: "https://processor-cross-v12.example/p/v1",
    policy_hash: `sha256:${policyHashHex}`,
    policy_version: "1.0.0",
    tsa: null,
    credentialStatus,
    anchor: ANCHOR,
    sig: "",
    countersig: null,
    body,
  };
  return await signEnvelope(preSign, ISSUER_PRIVATE_KEY);
}

// ── Status List 2021 credential helpers ─────────────────────────────────────

/**
 * Build a gzip+base64url-encoded bitstring of length BITSTRING_LENGTH_BITS
 * with the bit at `bitIndex` set to `bitValue`. MSB-first per W3C VC SL 2021.
 */
function encodedListFromBit(bitIndex, bitValue) {
  if (bitIndex < 0 || bitIndex >= BITSTRING_LENGTH_BITS) {
    throw new Error(`bitIndex ${bitIndex} out of range`);
  }
  const bits = new Uint8Array(BITSTRING_LENGTH_BITS / 8);
  if (bitValue === 1) {
    const byteIdx = bitIndex >>> 3;
    const bitOff = 7 - (bitIndex & 7);
    bits[byteIdx] = (bits[byteIdx] ?? 0) | (1 << bitOff);
  }
  const gz = gzipSync(Buffer.from(bits));
  return base64UrlEncode(new Uint8Array(gz));
}

/** Mint a signed StatusListCredential with bit set as specified. */
function mintStatusListCredential(bitIndex, bitValue) {
  const encodedList = encodedListFromBit(bitIndex, bitValue);
  const unsigned = {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://w3id.org/vc/status-list/2021/v1",
    ],
    id: STATUS_LIST_URL,
    type: ["VerifiableCredential", "StatusList2021Credential"],
    issuer: "did:web:verify.dekimu.com",
    validFrom: STATUS_LIST_VALID_FROM,
    credentialSubject: {
      id: STATUS_LIST_ID_FIELD,
      type: "StatusList2021",
      statusPurpose: "revocation",
      encodedList,
    },
  };
  const canonicalBytes = new TextEncoder().encode(canonicalize(unsigned));
  const sigBytes = crypto.sign(null, canonicalBytes, ROOT_PRIVATE_KEY);
  return {
    ...unsigned,
    proof: {
      type: "Ed25519Signature2020",
      created: STATUS_LIST_PROOF_CREATED,
      verificationMethod: ROOT_KID,
      proofPurpose: "assertionMethod",
      proofValue: base64UrlEncode(new Uint8Array(sigBytes)),
    },
  };
}

function statusPointer(bitIndex) {
  return {
    id: `${STATUS_LIST_URL}#${bitIndex}`,
    type: "StatusList2021Entry",
    statusPurpose: "revocation",
    statusListIndex: String(bitIndex),
    statusListCredential: STATUS_LIST_URL,
  };
}

// ── TSA failure vectors (reuse existing TSR from arr-erasure-v2-tsa.json) ───

function loadBaseTsaReceipt() {
  const tsaVectorPath = join(VECTORS_DIR, "arr-erasure-v2-tsa.json");
  if (!existsSync(tsaVectorPath)) {
    throw new Error(
      `mint-v1-2-vectors: arr-erasure-v2-tsa.json not found at ${tsaVectorPath} — ` +
        `run mint-vectors.mjs first to capture the FreeTSA TSR.`,
    );
  }
  return JSON.parse(readFileSync(tsaVectorPath, "utf8"));
}

/**
 * TSA imprint mismatch: re-sign the receipt with body mutated AFTER the TSR
 * was captured. Verifier recomputes the imprint over the mutated canonical
 * form and finds it ≠ TSR.messageImprint. Envelope sig is valid (over the new body).
 */
async function buildTsaImprintMismatch(base) {
  const r = base.receipt;
  // Mutate one byte of body.target_commit. Original starts "sha256:dada..."
  // — flip the second-to-last hex pair so the SHA decodes to a different value.
  const mutatedBody = {
    ...r.body,
    target_commit: r.body.target_commit.replace(/dada$/, "dadc"),
  };
  // Build preSign envelope with mutated body. Keep iss_key, subject, etc.
  // identical; only body diverges so the v=2 envelope canonical form changes.
  const preSign = {
    v: r.v,
    id: r.id,
    iat: r.iat,
    claim_type: r.claim_type,
    iss: r.iss,
    iss_key: r.iss_key,
    subject: r.subject,
    exp: r.exp,
    prev: r.prev,
    policy_uri: r.policy_uri,
    policy_hash: r.policy_hash,
    policy_version: r.policy_version,
    tsa: null, // signEnvelope zeros tsa anyway; explicit for clarity
    credentialStatus: r.credentialStatus,
    anchor: r.anchor,
    sig: "",
    countersig: null,
    body: mutatedBody,
  };
  const signed = await signEnvelope(preSign, ISSUER_PRIVATE_KEY);
  // Attach the ORIGINAL TSR. Verifier will compute imprint over mutated body
  // → mismatch.
  signed.tsa = r.tsa;

  return {
    name: "arr-erasure-v2-tsa-imprint-mismatch",
    family: "arr",
    envelope_version: 2,
    receipt: signed,
    publicKey_b64url: ISSUER_PUBLIC_KEY_B64URL,
    verify_opts: {
      // Pin reference time to TSR.issued_at so drift never trips first.
      tsaReferenceTime: r.tsa.issued_at,
    },
    expected: {
      envelope_version: 2,
      signature_valid: true,
      tsa_state: "tsa_imprint_mismatch",
    },
  };
}

/**
 * TSA anchor expired: keep the receipt and TSR untouched. Override
 * trust anchors with a TrustAnchor whose cert matches the FreeTSA root
 * (so it matches in step 2) but `valid_until` is in the past (so step 3 fails).
 */
function buildTsaAnchorExpired(base) {
  return {
    name: "arr-erasure-v2-tsa-anchor-expired",
    family: "arr",
    envelope_version: 2,
    receipt: base.receipt,
    publicKey_b64url: ISSUER_PUBLIC_KEY_B64URL,
    verify_opts: {
      tsaReferenceTime: base.receipt.tsa.issued_at,
      trustAnchorOverride: "freetsa-expired-2020",
    },
    expected: {
      envelope_version: 2,
      signature_valid: true,
      tsa_state: "tsa_anchor_expired",
      tsa_listed: false,
    },
  };
}

/**
 * TSA drift exceeded: keep receipt + TSR untouched. Override
 * tsaReferenceTime to a date >300s from TSR.issued_at.
 */
function buildTsaDriftExceeded(base) {
  return {
    name: "arr-erasure-v2-tsa-drift-exceeded",
    family: "arr",
    envelope_version: 2,
    receipt: base.receipt,
    publicKey_b64url: ISSUER_PUBLIC_KEY_B64URL,
    verify_opts: {
      tsaReferenceTime: "2020-01-01T00:00:00Z",
      // Drift tolerance left at default 300s; 6+ years easily exceeds.
    },
    expected: {
      envelope_version: 2,
      signature_valid: true,
      tsa_state: "tsa_drift_exceeded",
    },
  };
}

// ── Status List vectors ─────────────────────────────────────────────────────

async function buildStatusListActive() {
  const bitIndex = 7;
  const credential = mintStatusListCredential(bitIndex, 0);
  const credentialStatus = statusPointer(bitIndex);
  const receipt = await buildArrEnvelope({
    ulid: "01HXXARRSL12ACTIVE0000001",
    targetCommitHex: "a1".repeat(32),
    policyHashHex: "b1".repeat(32),
    credentialStatus,
  });
  return {
    name: "arr-erasure-v2-statuslist-active",
    family: "arr",
    envelope_version: 2,
    receipt,
    publicKey_b64url: ISSUER_PUBLIC_KEY_B64URL,
    verify_opts: {
      statusListRootKey: { kid: ROOT_KID, publicKeyDer: ROOT_PUBLIC_KEY_DER_B64URL },
      statusCacheSeed: {
        url: STATUS_LIST_URL,
        fresh: true,
        credential,
      },
    },
    expected: {
      envelope_version: 2,
      signature_valid: true,
      tsa_state: "tsa_absent",
      status_state: "active",
      status_list_id: STATUS_LIST_URL,
    },
  };
}

async function buildStatusListRevoked() {
  const bitIndex = 42;
  const credential = mintStatusListCredential(bitIndex, 1);
  const credentialStatus = statusPointer(bitIndex);
  const receipt = await buildArrEnvelope({
    ulid: "01HXXARRSL12REVOKED000001",
    targetCommitHex: "a2".repeat(32),
    policyHashHex: "b2".repeat(32),
    credentialStatus,
  });
  return {
    name: "arr-erasure-v2-statuslist-revoked",
    family: "arr",
    envelope_version: 2,
    receipt,
    publicKey_b64url: ISSUER_PUBLIC_KEY_B64URL,
    verify_opts: {
      statusListRootKey: { kid: ROOT_KID, publicKeyDer: ROOT_PUBLIC_KEY_DER_B64URL },
      // No chain successor → list-says-revoked + chain-inconsistency warning.
      // The verifier reports status_state="revoked" with a chain_inconsistency
      // warning regardless. status_state is what we assert on.
      statusCacheSeed: {
        url: STATUS_LIST_URL,
        fresh: true,
        credential,
      },
    },
    expected: {
      envelope_version: 2,
      signature_valid: true,
      tsa_state: "tsa_absent",
      status_state: "revoked",
      status_list_id: STATUS_LIST_URL,
    },
  };
}

async function buildStatusListChainRevokedListStale() {
  const bitIndex = 13;
  // Bit is 0 (list says active) BUT chain successor exists → revoked_by_chain.
  const credential = mintStatusListCredential(bitIndex, 0);
  const credentialStatus = statusPointer(bitIndex);
  const receipt = await buildArrEnvelope({
    ulid: "01HXXARRSL12CHNREV000001",
    targetCommitHex: "a3".repeat(32),
    policyHashHex: "b3".repeat(32),
    credentialStatus,
  });
  return {
    name: "arr-erasure-v2-statuslist-chain-revoked-list-stale",
    family: "arr",
    envelope_version: 2,
    receipt,
    publicKey_b64url: ISSUER_PUBLIC_KEY_B64URL,
    verify_opts: {
      statusListRootKey: { kid: ROOT_KID, publicKeyDer: ROOT_PUBLIC_KEY_DER_B64URL },
      statusCacheSeed: {
        url: STATUS_LIST_URL,
        fresh: true,
        credential,
      },
      chainSuccessorExists: true,
    },
    expected: {
      envelope_version: 2,
      signature_valid: true,
      tsa_state: "tsa_absent",
      status_state: "revoked_by_chain",
      status_list_id: STATUS_LIST_URL,
    },
  };
}

async function buildStatusListStale() {
  const bitIndex = 21;
  // Bit is 0 (active). Cache is past freshTtl but within staleTtl. Fetch fails
  // (forced by loader fetch-mock) → fetcher returns "stale" → active_stale.
  const credential = mintStatusListCredential(bitIndex, 0);
  const credentialStatus = statusPointer(bitIndex);
  const receipt = await buildArrEnvelope({
    ulid: "01HXXARRSL12STALE0000001",
    targetCommitHex: "a4".repeat(32),
    policyHashHex: "b4".repeat(32),
    credentialStatus,
  });
  return {
    name: "arr-erasure-v2-statuslist-stale",
    family: "arr",
    envelope_version: 2,
    receipt,
    publicKey_b64url: ISSUER_PUBLIC_KEY_B64URL,
    verify_opts: {
      statusListRootKey: { kid: ROOT_KID, publicKeyDer: ROOT_PUBLIC_KEY_DER_B64URL },
      // cacheConfig with very small freshTtl + large staleTtl + cache seeded
      // far in the past (past freshTtl, within staleTtl).
      statusCacheConfig: { freshTtlSec: 60, staleTtlSec: 86400 },
      statusCacheSeed: {
        url: STATUS_LIST_URL,
        fresh: false, // past freshTtl
        // 2 hours old — well past 60s freshTtl, well within 86400s staleTtl.
        ageSec: 7200,
        credential,
      },
      statusFetchMode: "fail", // loader patches globalThis.fetch to reject
    },
    expected: {
      envelope_version: 2,
      signature_valid: true,
      tsa_state: "tsa_absent",
      status_state: "active_stale",
      status_list_id: STATUS_LIST_URL,
    },
  };
}

async function buildStatusListUnreachable() {
  const bitIndex = 99;
  // No cache seed → fetcher tries network → patched fetch fails → unreachable.
  const credentialStatus = statusPointer(bitIndex);
  const receipt = await buildArrEnvelope({
    ulid: "01HXXARRSL12UNREACH00001",
    targetCommitHex: "a5".repeat(32),
    policyHashHex: "b5".repeat(32),
    credentialStatus,
  });
  return {
    name: "arr-erasure-v2-statuslist-unreachable",
    family: "arr",
    envelope_version: 2,
    receipt,
    publicKey_b64url: ISSUER_PUBLIC_KEY_B64URL,
    verify_opts: {
      statusListRootKey: { kid: ROOT_KID, publicKeyDer: ROOT_PUBLIC_KEY_DER_B64URL },
      // No statusCacheSeed → no entry in cache → fetch attempted.
      statusFetchMode: "fail",
    },
    expected: {
      envelope_version: 2,
      signature_valid: true,
      tsa_state: "tsa_absent",
      status_state: "unreachable",
    },
  };
}

// ── Write helper ─────────────────────────────────────────────────────────────

function write(name, vector) {
  const dest = join(VECTORS_DIR, `${name}.json`);
  writeFileSync(dest, JSON.stringify(vector, null, 2) + "\n");
  console.log(`wrote ${dest}`);
}

// ── Main ─────────────────────────────────────────────────────────────────────

console.log("mint-v1-2-vectors: building 8 deferred conformance vectors...\n");

const base = loadBaseTsaReceipt();

const imprintMismatch = await buildTsaImprintMismatch(base);
write(imprintMismatch.name, imprintMismatch);

const anchorExpired = buildTsaAnchorExpired(base);
write(anchorExpired.name, anchorExpired);

const driftExceeded = buildTsaDriftExceeded(base);
write(driftExceeded.name, driftExceeded);

const slActive = await buildStatusListActive();
write(slActive.name, slActive);

const slRevoked = await buildStatusListRevoked();
write(slRevoked.name, slRevoked);

const slChain = await buildStatusListChainRevokedListStale();
write(slChain.name, slChain);

const slStale = await buildStatusListStale();
write(slStale.name, slStale);

const slUnreach = await buildStatusListUnreachable();
write(slUnreach.name, slUnreach);

console.log("\nmint-v1-2-vectors: done.");
