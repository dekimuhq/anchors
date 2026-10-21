#!/usr/bin/env -S node --experimental-strip-types
/**
 * Regenerate APR v1 conformance test vectors.
 *
 * Run: node --experimental-strip-types scripts/regen-vectors.ts
 *
 * Writes to ../../apr-spec/conformance/test-vectors/. Deterministic: same input
 * Ed25519 seeds + same fixed iat + same fixed ULIDs + same canonicalisation
 * → byte-identical output every time.
 *
 * No runtime deps. Uses Node 22 built-in crypto (Ed25519 via PKCS8/SPKI raw-32
 * wrappers). No imports from @dekimuhq/* or verify.dekimu.com — vectors must be
 * reproducible with no Dekimu code path.
 *
 * INTENTIONAL DUPLICATION: this script re-implements `canonicalize`, the SHA-256
 * helpers, and base64url inline rather than importing from `../src/`. That
 * duplication is the point. The committed vectors are an independent attestation
 * of the canonicalisation contract — if `src/canonicalize.ts` ever drifts away
 * from RFC 8785-lite, the existing committed vectors stop verifying under the
 * verifier, making the regression loud. If you "fix" this by importing from
 * src/, you erase that cross-check. Don't, unless canonicalisation grows
 * complex enough that maintaining two implementations risks divergence in the
 * WRONG direction (a parallel undetected bug in both). See also
 * `apr/conformance/test-vectors/SCHEME.md` in dekimuhq/anchors-spec.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as crypto from "node:crypto";
import { fileURLToPath } from "node:url";

// ---------------------------------------------------------------------------
// Output target
// ---------------------------------------------------------------------------

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const OUT_ROOT = path.resolve(
  __dirname,
  "..",
  "..",
  "apr-spec",
  "conformance",
  "test-vectors",
);

// ---------------------------------------------------------------------------
// Canonicalisation (RFC 8785-lite, matches apr-spec/v1.md §4.1 exactly)
// ---------------------------------------------------------------------------

function sortValue(value: unknown): unknown {
  if (value === null) return null;
  if (typeof value === "boolean") return value;
  if (typeof value === "string") return value.normalize("NFC");
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("non-finite number");
    return value;
  }
  if (typeof value === "bigint") throw new Error("bigint not supported");
  if (typeof value === "undefined") throw new Error("undefined not supported");
  if (typeof value === "function" || typeof value === "symbol") {
    throw new Error(`${typeof value} not supported`);
  }
  if (Array.isArray(value)) return value.map(sortValue);
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const out: Record<string, unknown> = {};
    for (const k of keys) {
      const v = obj[k];
      if (v === undefined) throw new Error(`undefined value at "${k}"`);
      out[k.normalize("NFC")] = sortValue(v);
    }
    return out;
  }
  throw new Error(`unsupported type ${typeof value}`);
}

function canonicalize(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

// ---------------------------------------------------------------------------
// Ed25519 helpers (Node built-in, raw 32-byte seed I/O)
// ---------------------------------------------------------------------------

const PKCS8_ED25519_PREFIX = Buffer.from(
  "302e020100300506032b657004220420",
  "hex",
);

function privKeyFromSeed(seed: Buffer): crypto.KeyObject {
  if (seed.length !== 32) throw new Error("seed must be 32 bytes");
  const der = Buffer.concat([PKCS8_ED25519_PREFIX, seed]);
  return crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

function rawPubFromPriv(sk: crypto.KeyObject): Buffer {
  const spki = crypto
    .createPublicKey(sk)
    .export({ format: "der", type: "spki" }) as Buffer;
  return spki.subarray(spki.length - 32);
}

function edSign(sk: crypto.KeyObject, msg: Buffer): Buffer {
  return crypto.sign(null, msg, sk);
}

function b64u(b: Buffer): string {
  return b
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

// ---------------------------------------------------------------------------
// SHA-256 helpers
// ---------------------------------------------------------------------------

function sha256(b: Buffer): Buffer {
  return crypto.createHash("sha256").update(b).digest();
}

// ---------------------------------------------------------------------------
// Reference Merkle scheme used by v1 vectors
// (described in conformance/test-vectors/SCHEME.md).
//
//   leaf_i      = sha256(claimId_i UTF-8 bytes)
//   parent      = sha256(left || right)            // raw 32-byte concat
//   odd level   = duplicate the trailing node      // standard pattern
//   rootHash    = hex of the final 32 bytes
//   ordering    = claim ids sorted ascending (UTF-8 byte order)
// ---------------------------------------------------------------------------

function merkleRoot(claimIdsAscending: string[]): string {
  if (claimIdsAscending.length === 0) return "0".repeat(64);
  let level: Buffer[] = claimIdsAscending.map((id) =>
    sha256(Buffer.from(id, "utf8")),
  );
  while (level.length > 1) {
    const next: Buffer[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const a = level[i]!;
      const b = level[i + 1] ?? a;
      next.push(sha256(Buffer.concat([a, b])));
    }
    level = next;
  }
  return level[0]!.toString("hex");
}

// ---------------------------------------------------------------------------
// Daily-root envelope builder
// ---------------------------------------------------------------------------

interface DailyRoot {
  v: 1;
  date: string;
  rootHash: string;
  count: number;
  kid: string;
  sig: string;
}

function buildDailyRoot(
  date: string,
  claimIds: string[],
  rootKid: string,
  rootSk: crypto.KeyObject,
): DailyRoot {
  const sortedIds = [...claimIds].sort();
  const rootHash = merkleRoot(sortedIds);
  const payload = canonicalize({ v: 1, date, rootHash });
  const sig = edSign(rootSk, Buffer.from(payload, "utf8"));
  return {
    v: 1,
    date,
    rootHash,
    count: sortedIds.length,
    kid: rootKid,
    sig: b64u(sig),
  };
}

// ---------------------------------------------------------------------------
// Claim minter (matches apr-spec/v1.md §4.3)
// ---------------------------------------------------------------------------

interface APRBody {
  artifact: {
    type: string;
    id: string;
    hash: string;
    hashAlgorithm: "sha256";
    contentType?: string;
    sizeBytes?: number;
  };
  agent: {
    kind: "human" | "ai" | "template" | "hybrid";
    model?: string;
    provider?: string;
    humanRole?: "review" | "edit" | "draft" | "approve" | "none";
  };
  authorization: { principalId: string };
  inputs?: Array<{
    kind: "prompt" | "file" | "url" | "claim" | "schedule";
    hash?: string;
    source?: string;
    claimId?: string;
  }>;
  startedAt: number;
  completedAt: number;
  durationMs?: number;
  disclosure: "public_minimal" | "public_full" | "metadata_only";
  summary?: string;
}

interface AprClaim {
  v: 1;
  id: string;
  kind: "ar.provenance.v1";
  issuer: string;
  subject: string;
  iat: number;
  kid: string;
  body: APRBody;
  sig: string;
}

interface MintArgs {
  id: string;
  issuer: string;
  subject: string;
  iat: number;
  kid: string;
  body: APRBody;
  sk: crypto.KeyObject;
}

function mintClaim(args: MintArgs): AprClaim {
  const unsigned = {
    v: 1 as const,
    id: args.id,
    kind: "ar.provenance.v1" as const,
    issuer: args.issuer,
    subject: args.subject,
    iat: args.iat,
    kid: args.kid,
    body: args.body,
  };
  const bytes = Buffer.from(canonicalize(unsigned), "utf8");
  const sig = edSign(args.sk, bytes);
  return { ...unsigned, sig: b64u(sig) };
}

// ---------------------------------------------------------------------------
// Fixed test keys + catalogs (NOT production)
// ---------------------------------------------------------------------------

const SEED_CLAIM_2026 = Buffer.alloc(32, 0xaa);
const SEED_CLAIM_2025 = Buffer.alloc(32, 0xbb);
const SEED_CLAIM_ROGUE = Buffer.alloc(32, 0xcc);
const SEED_ROOT = Buffer.alloc(32, 0xdd);

const SK_CLAIM_2026 = privKeyFromSeed(SEED_CLAIM_2026);
const SK_CLAIM_2025 = privKeyFromSeed(SEED_CLAIM_2025);
const SK_CLAIM_ROGUE = privKeyFromSeed(SEED_CLAIM_ROGUE);
const SK_ROOT = privKeyFromSeed(SEED_ROOT);

const PK_CLAIM_2026 = rawPubFromPriv(SK_CLAIM_2026);
const PK_CLAIM_2025 = rawPubFromPriv(SK_CLAIM_2025);
const PK_ROOT = rawPubFromPriv(SK_ROOT);

const KID_CLAIM_2026 = "test-claim-2026";
const KID_CLAIM_2025 = "test-claim-2025";
const KID_ROOT = "test-root-2026";
const ISSUER = "test-issuer";

const CLAIM_KEYS_CATALOG = {
  [KID_CLAIM_2026]: {
    issuer: ISSUER,
    publicKey: b64u(PK_CLAIM_2026),
  },
  [KID_CLAIM_2025]: {
    issuer: ISSUER,
    publicKey: b64u(PK_CLAIM_2025),
  },
};

const ROOT_KEYS_CATALOG = {
  [KID_ROOT]: {
    publicKey: b64u(PK_ROOT),
  },
};

// ---------------------------------------------------------------------------
// Body factory — same shape across vectors, varies by id
// ---------------------------------------------------------------------------

function bodyFor(suffix: string, started: number): APRBody {
  return {
    artifact: {
      type: "commander.run.output",
      id: `artifact-${suffix}`,
      hash: sha256(Buffer.from(`artifact-${suffix}`, "utf8")).toString("hex"),
      hashAlgorithm: "sha256",
      contentType: "text/plain",
      sizeBytes: 12,
    },
    agent: {
      kind: "ai",
      model: "test-model",
      provider: "test-provider",
    },
    authorization: { principalId: `principal-${suffix}` },
    inputs: [{ kind: "prompt", hash: "deadbeef", source: "test" }],
    startedAt: started,
    completedAt: started + 1,
    durationMs: 1000,
    disclosure: "public_minimal",
    summary: `vector ${suffix}`,
  };
}

// ---------------------------------------------------------------------------
// Vector definitions
// ---------------------------------------------------------------------------

interface VectorOutput {
  dir: string;
  claim: AprClaim;
  anchor: DailyRoot | null;
  // Inclusion-set on the anchor's date: deterministic list the verifier
  // rebuilds the Merkle root from. Vector-specific test surface; documented
  // in conformance/test-vectors/SCHEME.md (not normative for the spec).
  anchorIds: string[];
  expected: { status: "verified" | "tampered" | "unverified"; reasons: string[] };
  notes: string;
}

const ID_01 = "01J0TEST00000000000000A001";
const ID_02 = "01J0TEST00000000000000A002";
const ID_03 = "01J0TEST00000000000000A003";
const ID_04 = "01J0TEST00000000000000A004";
const ID_05 = "01J0TEST00000000000000A005";
const ID_FILLER_03 = "01J0TEST00000000000000A099";

const IAT_01 = Date.UTC(2025, 0, 1) / 1000;
const IAT_02 = Date.UTC(2025, 0, 2) / 1000;
const IAT_03 = Date.UTC(2025, 0, 3) / 1000;
const IAT_04 = Date.UTC(2025, 0, 4) / 1000;
const IAT_05 = Date.UTC(2025, 0, 5) / 1000;

function utcDate(unixSec: number): string {
  const d = new Date(unixSec * 1000);
  const yyyy = d.getUTCFullYear().toString().padStart(4, "0");
  const mm = (d.getUTCMonth() + 1).toString().padStart(2, "0");
  const dd = d.getUTCDate().toString().padStart(2, "0");
  return `${yyyy}-${mm}-${dd}`;
}

// ---------------------------------------------------------------------------
// Build all five vectors
// ---------------------------------------------------------------------------

const vectors: VectorOutput[] = [];

// ---- 01 valid anchored ----
{
  const claim = mintClaim({
    id: ID_01,
    issuer: ISSUER,
    subject: `artifact-${ID_01}`,
    iat: IAT_01,
    kid: KID_CLAIM_2026,
    body: bodyFor(ID_01, IAT_01),
    sk: SK_CLAIM_2026,
  });
  const anchorIds = [ID_01];
  const anchor = buildDailyRoot(utcDate(IAT_01), anchorIds, KID_ROOT, SK_ROOT);
  vectors.push({
    dir: "01-valid-anchored",
    claim,
    anchor,
    anchorIds,
    expected: { status: "verified", reasons: [] },
    notes:
      "Baseline. Single-claim day. Signature verifies under `test-claim-2026`, " +
      "claim id is the only leaf in the Merkle root, root signature verifies " +
      "under `test-root-2026`. Conforming verifier MUST return `verified`.",
  });
}

// ---- 02 tampered body ----
{
  // Mint valid claim, then mutate ONE body field to break the signature.
  const valid = mintClaim({
    id: ID_02,
    issuer: ISSUER,
    subject: `artifact-${ID_02}`,
    iat: IAT_02,
    kid: KID_CLAIM_2026,
    body: bodyFor(ID_02, IAT_02),
    sk: SK_CLAIM_2026,
  });
  const tampered: AprClaim = {
    ...valid,
    body: { ...valid.body, summary: "TAMPERED" },
  };
  const anchorIds = [ID_02];
  const anchor = buildDailyRoot(utcDate(IAT_02), anchorIds, KID_ROOT, SK_ROOT);
  vectors.push({
    dir: "02-tampered-body",
    claim: tampered,
    anchor,
    anchorIds,
    expected: { status: "tampered", reasons: ["signature_invalid"] },
    notes:
      "Valid claim mutated post-signing (`body.summary` changed from `vector " +
      ID_02 +
      "` to `TAMPERED`). Signature was computed over the original body, so " +
      "Ed25519 verification fails. The anchor would otherwise verify the id " +
      "for this date — the verifier MUST return `tampered` / `signature_invalid` " +
      "without ever consulting the anchor.",
  });
}

// ---- 03 missing from anchor ----
{
  const claim = mintClaim({
    id: ID_03,
    issuer: ISSUER,
    subject: `artifact-${ID_03}`,
    iat: IAT_03,
    kid: KID_CLAIM_2026,
    body: bodyFor(ID_03, IAT_03),
    sk: SK_CLAIM_2026,
  });
  // Anchor for that date does NOT include this claim id.
  const anchorIds = [ID_FILLER_03];
  const anchor = buildDailyRoot(utcDate(IAT_03), anchorIds, KID_ROOT, SK_ROOT);
  vectors.push({
    dir: "03-missing-from-anchor",
    claim,
    anchor,
    anchorIds,
    expected: { status: "tampered", reasons: ["missing-from-anchor"] },
    notes:
      "Claim signature is valid in isolation (key `test-claim-2026`). But the " +
      "published daily root for the anchor date covers a different id set " +
      "(`" +
      ID_FILLER_03 +
      "`). Conforming verifier MUST rebuild the root from the published id " +
      "set, observe that the claim id is NOT in it, and return `tampered` / " +
      "`missing-from-anchor`. Per spec §8 step 4 this is a hard failure.",
  });
}

// ---- 04 rotated kid (older still valid) ----
{
  const claim = mintClaim({
    id: ID_04,
    issuer: ISSUER,
    subject: `artifact-${ID_04}`,
    iat: IAT_04,
    kid: KID_CLAIM_2025,
    body: bodyFor(ID_04, IAT_04),
    sk: SK_CLAIM_2025,
  });
  const anchorIds = [ID_04];
  const anchor = buildDailyRoot(utcDate(IAT_04), anchorIds, KID_ROOT, SK_ROOT);
  vectors.push({
    dir: "04-rotated-kid",
    claim,
    anchor,
    anchorIds,
    expected: { status: "verified", reasons: [] },
    notes:
      "Claim was signed by the older key `test-claim-2025`. The catalog still " +
      "carries that key alongside the newer `test-claim-2026`. Receipts signed " +
      "before rotation MUST keep verifying after rotation, as long as the old " +
      "kid is retained in the catalog. Conforming verifier MUST return " +
      "`verified`.",
  });
}

// ---- 05 unknown kid ----
{
  // Claim references a kid the catalog does not carry.
  const claim = mintClaim({
    id: ID_05,
    issuer: ISSUER,
    subject: `artifact-${ID_05}`,
    iat: IAT_05,
    kid: "test-claim-not-in-catalog",
    body: bodyFor(ID_05, IAT_05),
    sk: SK_CLAIM_ROGUE,
  });
  const anchorIds = [ID_05];
  const anchor = buildDailyRoot(utcDate(IAT_05), anchorIds, KID_ROOT, SK_ROOT);
  vectors.push({
    dir: "05-unknown-kid",
    claim,
    anchor,
    anchorIds,
    expected: { status: "tampered", reasons: ["unknown_kid"] },
    notes:
      "Claim's `kid` (`test-claim-not-in-catalog`) is not present in the " +
      "verify-keys catalog. Per spec §8 step 2 this MUST return `tampered` / " +
      "`unknown_kid` — a missing key is indistinguishable from a forged claim " +
      "from the verifier's perspective. The anchor exists and the claim id " +
      "is in it, but the verifier MUST NOT reach the anchor stage.",
  });
}

// ---------------------------------------------------------------------------
// Write everything
// ---------------------------------------------------------------------------

function writePretty(target: string, value: unknown): void {
  fs.writeFileSync(target, JSON.stringify(value, null, 2) + "\n", "utf8");
}

function writeText(target: string, value: string): void {
  fs.writeFileSync(target, value.endsWith("\n") ? value : value + "\n", "utf8");
}

if (!fs.existsSync(OUT_ROOT)) {
  throw new Error(`output root does not exist: ${OUT_ROOT}`);
}

// Wipe existing vector dirs (but keep .gitkeep + SCHEME.md if present)
for (const entry of fs.readdirSync(OUT_ROOT)) {
  if (/^\d{2}-/.test(entry)) {
    fs.rmSync(path.join(OUT_ROOT, entry), { recursive: true, force: true });
  }
}

for (const v of vectors) {
  const dir = path.join(OUT_ROOT, v.dir);
  fs.mkdirSync(dir, { recursive: true });
  writePretty(path.join(dir, "claim.json"), v.claim);
  if (v.anchor) writePretty(path.join(dir, "anchor.json"), v.anchor);
  writePretty(path.join(dir, "anchor-ids.json"), v.anchorIds);
  writePretty(path.join(dir, "verify-keys.json"), CLAIM_KEYS_CATALOG);
  writePretty(path.join(dir, "root-keys.json"), ROOT_KEYS_CATALOG);
  writePretty(path.join(dir, "expected.json"), v.expected);
  writeText(path.join(dir, "notes.md"), `# ${v.dir}\n\n${v.notes}\n`);
}

// Write SCHEME.md describing the reference Merkle scheme used by vectors.
const scheme = `# Vector reference Merkle scheme

Vectors document a single reference Merkle scheme so any conforming verifier
can rebuild a daily root from a published id set. **This scheme is the format
used by these test vectors only.** The spec (§7.3 of \`v1.md\`) leaves the
on-the-wire inclusion-proof format verifier-defined. Implementers running
these vectors MUST implement this scheme to consume the vector files; they
are free to ship additional inclusion-proof formats for production use.

## Scheme

- **Leaf ordering.** Sort all claim ids for the day ascending, by UTF-8 byte
  order (equivalent to JavaScript string \`<\` on ASCII).
- **Leaf hashing.** \`leaf_i = sha256(claimId_i UTF-8 bytes)\`.
- **Internal nodes.** \`parent = sha256(left || right)\` where \`||\` is raw
  32-byte concatenation.
- **Odd levels.** If a level has an odd number of nodes, duplicate the
  trailing node before pairing. Apply the same rule at every level until one
  node remains.
- **Root encoding.** \`rootHash = lowercase hex of the final 32 bytes\`.
- **Empty days.** A day with zero claims has \`rootHash = "0".repeat(64)\`
  and \`count = 0\`.

## Inputs in each vector directory

- \`claim.json\` — the APR under test.
- \`anchor.json\` — the daily root envelope (\`{v, date, rootHash, count, kid, sig}\`).
- \`anchor-ids.json\` — the deterministic id list the day's root was built from.
  The verifier MUST rebuild the Merkle root from this list using the scheme
  above and compare it byte-for-byte against \`anchor.rootHash\`.
- \`verify-keys.json\` — claim-key catalog (\`{kid → {issuer, publicKey base64url 32 bytes}}\`).
- \`root-keys.json\` — root-key catalog (\`{kid → {publicKey base64url 32 bytes}}\`).
- \`expected.json\` — \`{status, reasons[]}\` the verifier MUST produce.
- \`notes.md\` — prose explaining what the vector exercises.

## Reproducing

\`\`\`bash
cd ../../../apr-verifier
node --experimental-strip-types scripts/regen-vectors.ts
\`\`\`

The script uses fixed Ed25519 seeds (\`0xaa…\`, \`0xbb…\`, \`0xcc…\`, \`0xdd…\`,
each repeated 32 bytes) and fixed iat timestamps + fixed ULIDs. Output is
byte-identical across runs and across platforms.
`;
writeText(path.join(OUT_ROOT, "SCHEME.md"), scheme);

console.log(`wrote ${vectors.length} vector groups to ${OUT_ROOT}`);
