/**
 * Hash-chain verification tests for `ar.trusted_issuers.v1`.
 *
 * Plan §B3 Step 3 — ≥30 cases covering empty/genesis/multi-link verification,
 * 4 reason codes, large-chain performance, and the on-disk fixture chain
 * (`data/chain/v0{1,2,3}.json`) regeneratable via `scripts/build-fixtures.mjs`.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  generateKeypair,
  type Keypair,
} from "@dekimuhq/anchors-envelope";
import {
  verifyHashChain,
  sha256OfCanonical,
} from "../src/chain.ts";
import type { TrustedIssuerListV1 } from "../src/types.ts";
import { makeSignedDoc, defaultIssuerRecord } from "./fixtures.ts";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE_DIR = resolve(__dirname, "..", "data", "chain");

function loadFixture(name: string): TrustedIssuerListV1 {
  return JSON.parse(
    readFileSync(resolve(FIXTURE_DIR, name), "utf8"),
  ) as TrustedIssuerListV1;
}

interface BuildChainOpts {
  length: number;
  keypair?: Keypair;
}

/** Build an N-link chain signed by a single keypair, with monotonic versions. */
function buildChain(opts: BuildChainOpts): TrustedIssuerListV1[] {
  const keypair = opts.keypair ?? generateKeypair("chain-test");
  const chain: TrustedIssuerListV1[] = [];
  for (let i = 0; i < opts.length; i++) {
    const previous_sha256 = i === 0 ? null : sha256OfCanonical(chain[i - 1]!);
    const { doc } = makeSignedDoc({
      keypair,
      version: i + 1,
      issued_at: `2026-0${i < 9 ? i + 1 : 9}-01T00:00:00Z`,
      valid_until: `2026-0${i < 9 ? i + 2 : 9}-01T00:00:00Z`,
      previous_sha256,
      issuers: [defaultIssuerRecord({ iss: `did:web:link-${i}.example` })],
    });
    chain.push(doc);
  }
  return chain;
}

// ─────────────────────────────────────────────────────────────────────────────
// C1 — degenerate / boundary chains
// ─────────────────────────────────────────────────────────────────────────────

describe("verifyHashChain — degenerate chains", () => {
  it("C1.1 empty chain → empty_chain (brokenAt:null)", () => {
    const r = verifyHashChain([]);
    assert.equal(r.ok, false);
    assert.equal(r.reason, "empty_chain");
    assert.equal(r.brokenAt, null);
  });

  it("C1.2 single genesis link verifies trivially (brokenAt:null)", () => {
    const chain = buildChain({ length: 1 });
    const r = verifyHashChain(chain);
    assert.equal(r.ok, true);
    assert.equal(r.reason, "ok");
    assert.equal(r.brokenAt, null);
  });

  it("C1.3 two-link chain (genesis + v02) verifies", () => {
    const chain = buildChain({ length: 2 });
    const r = verifyHashChain(chain);
    assert.equal(r.ok, true);
    assert.equal(r.reason, "ok");
  });

  it("C1.4 three-link chain (happy path) verifies", () => {
    const chain = buildChain({ length: 3 });
    const r = verifyHashChain(chain);
    assert.equal(r.ok, true);
    assert.equal(r.reason, "ok");
    assert.equal(r.brokenAt, null);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// C2 — first_not_genesis
// ─────────────────────────────────────────────────────────────────────────────

describe("verifyHashChain — first_not_genesis", () => {
  it("C2.1 genesis with non-null previous_sha256 → first_not_genesis (brokenAt:0)", () => {
    const chain = buildChain({ length: 1 });
    const mutated = [
      {
        ...chain[0]!,
        previous_sha256:
          "sha256:0000000000000000000000000000000000000000000000000000000000000000",
      },
    ];
    const r = verifyHashChain(mutated);
    assert.equal(r.ok, false);
    assert.equal(r.reason, "first_not_genesis");
    assert.equal(r.brokenAt, 0);
  });

  it("C2.2 reverse chain order (v03, v02, v01) → first_not_genesis (brokenAt:0)", () => {
    const chain = buildChain({ length: 3 });
    const reversed = [chain[2]!, chain[1]!, chain[0]!];
    const r = verifyHashChain(reversed);
    assert.equal(r.ok, false);
    assert.equal(r.reason, "first_not_genesis");
    assert.equal(r.brokenAt, 0);
  });

  it("C2.3 second link as 'genesis' (single-element chain that's not actually genesis)", () => {
    const chain = buildChain({ length: 3 });
    const r = verifyHashChain([chain[1]!]);
    assert.equal(r.ok, false);
    assert.equal(r.reason, "first_not_genesis");
    assert.equal(r.brokenAt, 0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// C3 — version_not_increasing
// ─────────────────────────────────────────────────────────────────────────────

describe("verifyHashChain — version_not_increasing", () => {
  it("C3.1 v02.version=5 → version_not_increasing (brokenAt:1)", () => {
    const chain = buildChain({ length: 3 });
    const mutated = [
      chain[0]!,
      { ...chain[1]!, version: 5 },
      chain[2]!,
    ];
    const r = verifyHashChain(mutated);
    assert.equal(r.ok, false);
    assert.equal(r.reason, "version_not_increasing");
    assert.equal(r.brokenAt, 1);
  });

  it("C3.2 two genesis lists (v01 + v01 again) → version_not_increasing (brokenAt:1)", () => {
    const chain = buildChain({ length: 1 });
    const dupGenesis = [chain[0]!, chain[0]!];
    const r = verifyHashChain(dupGenesis);
    assert.equal(r.ok, false);
    assert.equal(r.reason, "version_not_increasing");
    assert.equal(r.brokenAt, 1);
  });

  it("C3.3 skipped version (v01 + v03, no v02) → version_not_increasing (brokenAt:1)", () => {
    const chain = buildChain({ length: 3 });
    const skipped = [chain[0]!, chain[2]!];
    const r = verifyHashChain(skipped);
    assert.equal(r.ok, false);
    assert.equal(r.reason, "version_not_increasing");
    assert.equal(r.brokenAt, 1);
  });

  it("C3.4 decreasing version (v02 followed by v01.version=1) → first_not_genesis (v02 first; previous_sha256 not null)", () => {
    const chain = buildChain({ length: 2 });
    const decreasing = [chain[1]!, chain[0]!];
    const r = verifyHashChain(decreasing);
    assert.equal(r.ok, false);
    // v02 has previous_sha256 set, so first_not_genesis fires before any version compare.
    assert.equal(r.reason, "first_not_genesis");
    assert.equal(r.brokenAt, 0);
  });

  it("C3.5 version increment of 2 (chain[i+1].version === chain[i].version + 2) → version_not_increasing", () => {
    const chain = buildChain({ length: 3 });
    // Force v02 to claim version 3 — gap of 2 from v01.
    const mutated = [chain[0]!, { ...chain[1]!, version: 3 }];
    const r = verifyHashChain(mutated);
    assert.equal(r.ok, false);
    assert.equal(r.reason, "version_not_increasing");
    assert.equal(r.brokenAt, 1);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// C4 — previous_sha256_mismatch
// ─────────────────────────────────────────────────────────────────────────────

describe("verifyHashChain — previous_sha256_mismatch", () => {
  it("C4.1 v02.previous_sha256 mutated (1 hex flipped) → previous_sha256_mismatch (brokenAt:1)", () => {
    const chain = buildChain({ length: 3 });
    const orig = chain[1]!.previous_sha256!;
    const flipped =
      orig.slice(0, -1) + (orig.endsWith("a") ? "b" : "a");
    const mutated = [
      chain[0]!,
      { ...chain[1]!, previous_sha256: flipped },
      chain[2]!,
    ];
    const r = verifyHashChain(mutated);
    assert.equal(r.ok, false);
    assert.equal(r.reason, "previous_sha256_mismatch");
    assert.equal(r.brokenAt, 1);
  });

  it("C4.2 v02 tampered post-sign (issuers mutated) → previous_sha256_mismatch at brokenAt:2", () => {
    const chain = buildChain({ length: 3 });
    // Mutate v02 body without re-computing v03.previous_sha256. v02's
    // canonical bytes change → v03.previous_sha256 no longer matches.
    const tamperedV02 = {
      ...chain[1]!,
      issuers: [defaultIssuerRecord({ iss: "did:web:attacker.example" })],
    };
    const mutated = [chain[0]!, tamperedV02, chain[2]!];
    const r = verifyHashChain(mutated);
    assert.equal(r.ok, false);
    assert.equal(r.reason, "previous_sha256_mismatch");
    assert.equal(r.brokenAt, 2);
  });

  it("C4.3 v02.previous_sha256 = sha256:000…000 (zero hash) → previous_sha256_mismatch", () => {
    const chain = buildChain({ length: 2 });
    const mutated = [
      chain[0]!,
      {
        ...chain[1]!,
        previous_sha256:
          "sha256:0000000000000000000000000000000000000000000000000000000000000000",
      },
    ];
    const r = verifyHashChain(mutated);
    assert.equal(r.ok, false);
    assert.equal(r.reason, "previous_sha256_mismatch");
    assert.equal(r.brokenAt, 1);
  });

  it("C4.4 missing sha256: prefix → previous_sha256_mismatch (we expect the literal prefix)", () => {
    const chain = buildChain({ length: 2 });
    const orig = chain[1]!.previous_sha256!;
    const stripped = orig.replace(/^sha256:/, "");
    const mutated = [
      chain[0]!,
      { ...chain[1]!, previous_sha256: stripped },
    ];
    const r = verifyHashChain(mutated);
    assert.equal(r.ok, false);
    assert.equal(r.reason, "previous_sha256_mismatch");
    assert.equal(r.brokenAt, 1);
  });

  it("C4.5 hex case — uppercase previous_sha256 still verifies (we lowercase before compare)", () => {
    const chain = buildChain({ length: 2 });
    const upper = chain[1]!.previous_sha256!.toUpperCase();
    const mutated = [chain[0]!, { ...chain[1]!, previous_sha256: upper }];
    const r = verifyHashChain(mutated);
    assert.equal(r.ok, true, `expected ok=true, got reason=${r.reason}`);
  });

  it("C4.6 genesis tampered post-build → propagates to brokenAt:1", () => {
    const chain = buildChain({ length: 2 });
    // Mutate v01 body. v02.previous_sha256 was computed off the original v01.
    const tamperedV01 = {
      ...chain[0]!,
      issuers: [defaultIssuerRecord({ iss: "did:web:swapped.example" })],
    };
    const mutated = [tamperedV01, chain[1]!];
    const r = verifyHashChain(mutated);
    assert.equal(r.ok, false);
    assert.equal(r.reason, "previous_sha256_mismatch");
    assert.equal(r.brokenAt, 1);
  });

  it("C4.7 sig field included in canonical hash — re-signed v01 with different key breaks chain", () => {
    const chain = buildChain({ length: 2 });
    // Replace v01.sig with another (valid base64url-looking but different) sig.
    const reSigned = {
      ...chain[0]!,
      sig: "X".repeat(86),
    };
    const mutated = [reSigned, chain[1]!];
    const r = verifyHashChain(mutated);
    assert.equal(r.ok, false);
    assert.equal(r.reason, "previous_sha256_mismatch");
    assert.equal(r.brokenAt, 1);
  });

  it("C4.8 empty-string previous_sha256 → previous_sha256_mismatch", () => {
    const chain = buildChain({ length: 2 });
    // `previous_sha256: ""` is type-valid (string|null) at runtime but invalid as hash.
    const mutated = [
      chain[0]!,
      { ...chain[1]!, previous_sha256: "" as unknown as string },
    ];
    const r = verifyHashChain(mutated);
    assert.equal(r.ok, false);
    assert.equal(r.reason, "previous_sha256_mismatch");
    assert.equal(r.brokenAt, 1);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// C5 — sha256OfCanonical helper
// ─────────────────────────────────────────────────────────────────────────────

describe("sha256OfCanonical helper", () => {
  it("C5.1 returns 'sha256:' + 64 lowercase hex chars", () => {
    const chain = buildChain({ length: 1 });
    const h = sha256OfCanonical(chain[0]!);
    assert.match(h, /^sha256:[0-9a-f]{64}$/);
  });

  it("C5.2 deterministic — same doc yields same hash", () => {
    const chain = buildChain({ length: 1 });
    const a = sha256OfCanonical(chain[0]!);
    const b = sha256OfCanonical(chain[0]!);
    assert.equal(a, b);
  });

  it("C5.3 different docs yield different hashes", () => {
    const chain = buildChain({ length: 2 });
    const a = sha256OfCanonical(chain[0]!);
    const b = sha256OfCanonical(chain[1]!);
    assert.notEqual(a, b);
  });

  it("C5.4 hash includes sig — mutating sig changes the hash", () => {
    const chain = buildChain({ length: 1 });
    const original = sha256OfCanonical(chain[0]!);
    const mutated = sha256OfCanonical({ ...chain[0]!, sig: "Z".repeat(86) });
    assert.notEqual(original, mutated);
  });

  it("C5.5 chain[i+1].previous_sha256 byte-equals sha256OfCanonical(chain[i])", () => {
    const chain = buildChain({ length: 3 });
    assert.equal(chain[1]!.previous_sha256, sha256OfCanonical(chain[0]!));
    assert.equal(chain[2]!.previous_sha256, sha256OfCanonical(chain[1]!));
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// C6 — large chains (performance smoke)
// ─────────────────────────────────────────────────────────────────────────────

describe("verifyHashChain — large chains", () => {
  it("C6.1 10-link chain verifies", () => {
    const chain = buildChain({ length: 10 });
    const r = verifyHashChain(chain);
    assert.equal(r.ok, true);
  });

  it("C6.2 10-link chain with tampered middle link → brokenAt at the next link", () => {
    const chain = buildChain({ length: 10 });
    // Tamper chain[4] body. chain[5].previous_sha256 was computed over original chain[4].
    const tampered = {
      ...chain[4]!,
      issuers: [defaultIssuerRecord({ iss: "did:web:rogue.example" })],
    };
    const broken = chain.slice(0, 4).concat([tampered]).concat(chain.slice(5));
    const r = verifyHashChain(broken);
    assert.equal(r.ok, false);
    assert.equal(r.reason, "previous_sha256_mismatch");
    assert.equal(r.brokenAt, 5);
  });

  it("C6.3 50-link chain verifies in under 500ms", () => {
    const chain = buildChain({ length: 50 });
    const t = performance.now();
    const r = verifyHashChain(chain);
    const elapsed = performance.now() - t;
    assert.equal(r.ok, true);
    assert.ok(elapsed < 500, `expected <500ms, got ${elapsed.toFixed(1)}ms`);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// C7 — fixture chain on disk
// ─────────────────────────────────────────────────────────────────────────────

describe("verifyHashChain — disk fixture chain (data/chain/v0{1,2,3}.json)", () => {
  it("C7.1 loads and verifies", () => {
    const v01 = loadFixture("v01.json");
    const v02 = loadFixture("v02.json");
    const v03 = loadFixture("v03.json");
    const r = verifyHashChain([v01, v02, v03]);
    assert.equal(r.ok, true, `expected ok=true, got reason=${r.reason}`);
    assert.equal(r.brokenAt, null);
  });

  it("C7.2 fixture v01 is genesis (previous_sha256 === null)", () => {
    const v01 = loadFixture("v01.json");
    assert.equal(v01.previous_sha256, null);
    assert.equal(v01.version, 1);
  });

  it("C7.3 fixture v02.previous_sha256 === sha256OfCanonical(v01)", () => {
    const v01 = loadFixture("v01.json");
    const v02 = loadFixture("v02.json");
    assert.equal(v02.previous_sha256, sha256OfCanonical(v01));
  });

  it("C7.4 fixture v03.previous_sha256 === sha256OfCanonical(v02)", () => {
    const v02 = loadFixture("v02.json");
    const v03 = loadFixture("v03.json");
    assert.equal(v03.previous_sha256, sha256OfCanonical(v02));
  });

  it("C7.5 fixture v03 revokes did:web:other.example", () => {
    const v03 = loadFixture("v03.json");
    const otherRecord = v03.issuers.find(
      (r) => r.iss === "did:web:other.example",
    );
    assert.ok(otherRecord, "expected other.example record in v03");
    assert.equal(otherRecord.revoked_at, "2026-06-14T00:00:00Z");
  });

  it("C7.6 fixture chain detects v02 swap (v01 + v03 only, skipping v02) → version_not_increasing", () => {
    const v01 = loadFixture("v01.json");
    const v03 = loadFixture("v03.json");
    const r = verifyHashChain([v01, v03]);
    assert.equal(r.ok, false);
    assert.equal(r.reason, "version_not_increasing");
    assert.equal(r.brokenAt, 1);
  });

  it("C7.7 fixture chain detects post-load tamper at v02 → brokenAt:2", () => {
    const v01 = loadFixture("v01.json");
    const v02 = loadFixture("v02.json");
    const v03 = loadFixture("v03.json");
    const tamperedV02 = {
      ...v02,
      issuers: [defaultIssuerRecord({ iss: "did:web:attacker.example" })],
    };
    const r = verifyHashChain([v01, tamperedV02, v03]);
    assert.equal(r.ok, false);
    assert.equal(r.reason, "previous_sha256_mismatch");
    assert.equal(r.brokenAt, 2);
  });
});
