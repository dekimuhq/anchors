/**
 * Tests for schema/validate.ts — anchors validate CLI.
 *
 * Run: node --experimental-strip-types --test schema/validate.test.ts
 */

import { describe, it } from "node:test";
import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { spawnSync } from "node:child_process";

const SCHEMA_DIR = path.resolve(
  import.meta.dirname ?? path.dirname(new URL(import.meta.url).pathname)
);
const CLI = path.join(SCHEMA_DIR, "validate.ts");
const FAMILIES_DIR = path.join(SCHEMA_DIR, "families");
const TMP_DIR = path.join(SCHEMA_DIR, ".test-tmp");

/**
 * Fast path: skips §6 (runs every family's `npm test`, ~90s for 21 families) via
 * ANCHORS_VALIDATE_SKIP_TEST_COUNTS. §6 gets its own dedicated slow describe
 * block below with the env var unset, so it's still exercised for real at least
 * once — `npm run validate` (CI, no env override) always runs it too.
 */
function run(...args: string[]): {
  stdout: string;
  stderr: string;
  code: number;
} {
  const result = spawnSync(
    "node",
    ["--experimental-strip-types", CLI, ...args],
    {
      encoding: "utf-8",
      cwd: path.resolve(SCHEMA_DIR, ".."),
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...process.env, ANCHORS_VALIDATE_SKIP_TEST_COUNTS: "1" },
    }
  );
  return {
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    code: result.status ?? 1,
  };
}

/** Slow path — runs §6 for real (every family's `npm test`). ~90s. */
function runSlow(...args: string[]): {
  stdout: string;
  stderr: string;
  code: number;
} {
  const result = spawnSync(
    "node",
    ["--experimental-strip-types", CLI, ...args],
    {
      encoding: "utf-8",
      cwd: path.resolve(SCHEMA_DIR, ".."),
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 180_000,
    }
  );
  return {
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    code: result.status ?? 1,
  };
}

function writeTemp(name: string, obj: Record<string, unknown>): string {
  fs.mkdirSync(TMP_DIR, { recursive: true });
  const p = path.join(TMP_DIR, name);
  fs.writeFileSync(p, JSON.stringify(obj, null, 2));
  return p;
}

function cleanTemp(): void {
  if (fs.existsSync(TMP_DIR)) {
    fs.rmSync(TMP_DIR, { recursive: true, force: true });
  }
}

/** Minimal valid manifest for testing. */
function validManifest(
  overrides?: Record<string, unknown>
): Record<string, unknown> {
  return {
    id: "ar.test_family.v1",
    acronym: "TST",
    name: "Test Family Receipts",
    claim_types: ["ar.test_family.v1"],
    envelope: "v2",
    chip: 99,
    status_list_slot: null,
    subject_presence: "must-be-null",
    body: {
      event_type: { type: "enum", enum_values: ["test.created"] },
    },
    event_types: ["test.created"],
    ...overrides,
  };
}

// ── Tests ──────────────────────────────────────────────────────────────────

describe("anchors validate — all families", () => {
  it("validates all 21 manifested families with zero manifest-roster gaps", () => {
    // §6 test-count is skipped here (see `run()`). APIIR/ACBR manifests landed
    // 2026-07-06 (schema/families/ar.redaction.v1.anchor.json + ar.compliance.v1.anchor.json),
    // closing the §7 checklist-automation roster gap — §1-§5 stay clean and exit 0.
    const result = run();
    assert.equal(
      result.code,
      0,
      `Expected exit 0 (roster gap closed), got ${result.code}.\n${result.stderr}`
    );
    assert.match(result.stdout, /manifest\(s\)\.\.\./);
    assert.doesNotMatch(result.stderr, /"APIIR".*no schema\/families/s);
    assert.doesNotMatch(result.stderr, /"ACBR".*no schema\/families/s);
    const errorLines = result.stderr
      .split("\n")
      .filter((l) => l.trim().startsWith("ERROR"));
    assert.equal(
      errorLines.length,
      0,
      `Expected zero errors, got:\n${errorLines.join("\n")}`
    );
  });

  it("each .anchor.json file is valid JSON", () => {
    const files = fs
      .readdirSync(FAMILIES_DIR)
      .filter((f) => f.endsWith(".anchor.json"));
    assert.ok(
      files.length >= 21,
      `expected >= 21 manifests, got ${files.length}`
    );
    for (const f of files) {
      const raw = fs.readFileSync(path.join(FAMILIES_DIR, f), "utf-8");
      assert.doesNotThrow(() => JSON.parse(raw), `${f} is not valid JSON`);
    }
  });
});

describe("anchors validate — structural checks", () => {
  it("passes a valid minimal manifest", () => {
    const p = writeTemp("valid.anchor.json", validManifest());
    const result = run(p);
    cleanTemp();
    assert.equal(result.code, 0, result.stderr);
  });

  it("rejects missing required key: id", () => {
    const m = validManifest();
    delete m.id;
    const p = writeTemp("no-id.anchor.json", m);
    const result = run(p);
    cleanTemp();
    assert.equal(result.code, 1);
    assert.match(result.stderr, /missing required key "id"/);
  });

  it("rejects invalid id pattern", () => {
    const p = writeTemp(
      "bad-id.anchor.json",
      validManifest({ id: "not.valid" })
    );
    const result = run(p);
    cleanTemp();
    assert.equal(result.code, 1);
    assert.match(result.stderr, /does not match ar\.<noun>\.v<N>/);
  });

  it("rejects invalid acronym", () => {
    const p = writeTemp(
      "bad-acr.anchor.json",
      validManifest({ acronym: "ab" })
    );
    const result = run(p);
    cleanTemp();
    assert.equal(result.code, 1);
    assert.match(result.stderr, /acronym/);
  });

  it("rejects short name", () => {
    const p = writeTemp(
      "short-name.anchor.json",
      validManifest({ name: "hi" })
    );
    const result = run(p);
    cleanTemp();
    assert.equal(result.code, 1);
    assert.match(result.stderr, /shorter than 5/);
  });

  it("rejects empty claim_types", () => {
    const p = writeTemp(
      "no-ct.anchor.json",
      validManifest({ claim_types: [] })
    );
    const result = run(p);
    cleanTemp();
    assert.equal(result.code, 1);
    assert.match(result.stderr, /at least 1/);
  });

  it("rejects id not in claim_types", () => {
    const p = writeTemp(
      "id-mismatch.anchor.json",
      validManifest({
        id: "ar.test_family.v1",
        claim_types: ["ar.other.v1"],
      })
    );
    const result = run(p);
    cleanTemp();
    assert.equal(result.code, 1);
    assert.match(result.stderr, /not in claim_types/);
  });

  it("rejects invalid envelope version", () => {
    const p = writeTemp(
      "bad-env.anchor.json",
      validManifest({ envelope: "v3" })
    );
    const result = run(p);
    cleanTemp();
    assert.equal(result.code, 1);
    assert.match(result.stderr, /envelope/);
  });

  it("rejects chip out of range", () => {
    const p = writeTemp("bad-chip.anchor.json", validManifest({ chip: 0 }));
    const result = run(p);
    cleanTemp();
    assert.equal(result.code, 1);
    assert.match(result.stderr, /chip 0/);
  });

  it("rejects invalid subject_presence", () => {
    const p = writeTemp(
      "bad-sp.anchor.json",
      validManifest({ subject_presence: "maybe" })
    );
    const result = run(p);
    cleanTemp();
    assert.equal(result.code, 1);
    assert.match(result.stderr, /subject_presence/);
  });

  it("rejects unknown top-level key", () => {
    const p = writeTemp(
      "extra-key.anchor.json",
      validManifest({ unknown_field: true })
    );
    const result = run(p);
    cleanTemp();
    assert.equal(result.code, 1);
    assert.match(result.stderr, /unknown top-level key/);
  });

  it("rejects invalid field type in body", () => {
    const p = writeTemp(
      "bad-field.anchor.json",
      validManifest({
        body: { x: { type: "bigint" } },
      })
    );
    const result = run(p);
    cleanTemp();
    assert.equal(result.code, 1);
    assert.match(result.stderr, /unknown field type/);
  });

  it("rejects enum field without enum_values", () => {
    const p = writeTemp(
      "enum-no-vals.anchor.json",
      validManifest({
        body: { x: { type: "enum" } },
      })
    );
    const result = run(p);
    cleanTemp();
    assert.equal(result.code, 1);
    assert.match(result.stderr, /enum_values/);
  });

  it("rejects array field without items", () => {
    const p = writeTemp(
      "arr-no-items.anchor.json",
      validManifest({
        body: { x: { type: "array" } },
      })
    );
    const result = run(p);
    cleanTemp();
    assert.equal(result.code, 1);
    assert.match(result.stderr, /requires items/);
  });

  it("rejects invalid tsa_mandate value", () => {
    const p = writeTemp(
      "bad-tsa.anchor.json",
      validManifest({
        tsa_mandate: { "*": "always" },
      })
    );
    const result = run(p);
    cleanTemp();
    assert.equal(result.code, 1);
    assert.match(result.stderr, /tsa_mandate/);
  });
});

describe("anchors validate — event_type / profile alignment", () => {
  it("detects event_type mismatch between event_types and body.event_type.enum_values", () => {
    const p = writeTemp(
      "evt-mismatch.anchor.json",
      validManifest({
        event_types: ["a", "b"],
        body: { event_type: { type: "enum", enum_values: ["a", "c"] } },
      })
    );
    const result = run(p);
    cleanTemp();
    assert.equal(result.code, 1);
    assert.match(result.stderr, /"b".*missing from body/);
    assert.match(result.stderr, /"c".*not in event_types/);
  });

  it("detects profile id mismatch", () => {
    const p = writeTemp(
      "prof-mismatch.anchor.json",
      validManifest({
        profiles: [{ id: "gdpr.art7", regulation: "GDPR Art. 7" }],
        body: {
          event_type: { type: "enum", enum_values: ["test.created"] },
          profile: { type: "enum", enum_values: ["other.profile"] },
        },
        event_types: ["test.created"],
      })
    );
    const result = run(p);
    cleanTemp();
    assert.equal(result.code, 1);
    assert.match(result.stderr, /gdpr\.art7.*missing from body/);
  });
});

describe("anchors validate — cross-manifest uniqueness", () => {
  it("detects duplicate chips across manifests", () => {
    const a = writeTemp(
      "a.anchor.json",
      validManifest({ chip: 50, acronym: "AAA" })
    );
    const b = writeTemp(
      "b.anchor.json",
      validManifest({
        id: "ar.other.v1",
        acronym: "BBB",
        claim_types: ["ar.other.v1"],
        chip: 50,
      })
    );
    const result = run(a, b);
    cleanTemp();
    assert.equal(result.code, 1);
    assert.match(result.stderr, /chip 50 already claimed/);
  });

  it("detects duplicate acronyms", () => {
    const a = writeTemp("a.anchor.json", validManifest({ chip: 50 }));
    const b = writeTemp(
      "b.anchor.json",
      validManifest({
        id: "ar.other.v1",
        claim_types: ["ar.other.v1"],
        chip: 51,
      })
    );
    const result = run(a, b);
    cleanTemp();
    assert.equal(result.code, 1);
    assert.match(result.stderr, /acronym "TST" already claimed/);
  });

  it("detects duplicate status_list_slot", () => {
    const a = writeTemp(
      "a.anchor.json",
      validManifest({
        chip: 50,
        acronym: "AAA",
        status_list_slot: 20,
      })
    );
    const b = writeTemp(
      "b.anchor.json",
      validManifest({
        id: "ar.other.v1",
        acronym: "BBB",
        claim_types: ["ar.other.v1"],
        chip: 51,
        status_list_slot: 20,
      })
    );
    const result = run(a, b);
    cleanTemp();
    assert.equal(result.code, 1);
    assert.match(result.stderr, /status_list_slot 20 already claimed/);
  });
});

describe("anchors validate — FAMILY-CONSISTENCY cross-check", () => {
  it("warns when acronym not in §1 chip table", () => {
    const p = writeTemp("unknown.anchor.json", validManifest());
    const result = run(p);
    cleanTemp();
    // TST not in the table — should warn
    assert.match(result.stderr, /not found in FAMILY-CONSISTENCY/);
  });

  it("detects chip mismatch against §1", () => {
    // APR is chip 1 in the table — claim chip 2
    const p = writeTemp(
      "apr-wrong-chip.anchor.json",
      validManifest({
        id: "ar.provenance.v1",
        acronym: "APR",
        claim_types: ["ar.provenance.v1"],
        chip: 2,
      })
    );
    const result = run(p);
    cleanTemp();
    assert.equal(result.code, 1);
    assert.match(result.stderr, /chip 2 does not match FAMILY-CONSISTENCY/);
  });

  it("detects status_list_slot mismatch against §4", () => {
    // ALR is slot 1 in the table — claim slot 5
    const p = writeTemp(
      "alr-wrong-slot.anchor.json",
      validManifest({
        id: "ar.lineage.v1",
        acronym: "ALR",
        claim_types: ["ar.lineage.v1"],
        chip: 9,
        status_list_slot: 5,
        status_list: true,
      })
    );
    const result = run(p);
    cleanTemp();
    assert.equal(result.code, 1);
    assert.match(
      result.stderr,
      /status_list_slot 5 does not match FAMILY-CONSISTENCY/
    );
  });
});

describe("anchors validate — status_list / status_list_slot consistency", () => {
  it("warns when status_list: true but slot is null", () => {
    const p = writeTemp(
      "sl-true-null.anchor.json",
      validManifest({
        status_list: true,
        status_list_slot: null,
      })
    );
    const result = run(p);
    cleanTemp();
    assert.match(
      result.stderr,
      /status_list is true but status_list_slot is null/
    );
  });

  it("warns when status_list: false but slot is set", () => {
    const p = writeTemp(
      "sl-false-set.anchor.json",
      validManifest({
        status_list: false,
        status_list_slot: 5,
      })
    );
    const result = run(p);
    cleanTemp();
    assert.match(
      result.stderr,
      /status_list is false but status_list_slot is 5/
    );
  });
});

// Base temp manifests on a real family file so chip/slot stay consistent with
// FAMILY-CONSISTENCY.md §1/§4 — isolating the §2/§3/§5 assertion under test.
function loadFamily(name: string): Record<string, unknown> {
  return JSON.parse(
    fs.readFileSync(path.join(FAMILIES_DIR, name), "utf-8")
  ) as Record<string, unknown>;
}

describe("anchors validate — §3 subject-presence matrix", () => {
  it("errors when a must-be-null family declares must-be-present", () => {
    const m = loadFamily("ar.quality.v1.anchor.json");
    m.subject_presence = "must-be-present";
    const p = writeTemp("aqr-subj.anchor.json", m);
    const result = run(p);
    cleanTemp();
    assert.equal(result.code, 1);
    assert.match(result.stderr, /§3.*expected "must-be-null"/s);
  });

  it("errors when a per-event family declares a uniform presence", () => {
    const m = loadFamily("ar.transfer.v1.anchor.json"); // ATR → §3 mixed = either
    m.subject_presence = "must-be-null";
    const p = writeTemp("atr-subj.anchor.json", m);
    const result = run(p);
    cleanTemp();
    assert.equal(result.code, 1);
    assert.match(result.stderr, /§3.*expected "either"/s);
  });

  it("accepts the real subject_presence for every shipped family", () => {
    // The full-family run has zero manifest-roster-gap errors now that APIIR/ACBR
    // have manifests (see the "all families" describe block) — pin that the §3 line ran.
    const result = run();
    assert.match(result.stdout, /subject-presence rows/);
    assert.doesNotMatch(
      result.stderr,
      /§3.*does not match FAMILY-CONSISTENCY/s
    );
  });
});

describe("anchors validate — §2 TSA mandate matrix", () => {
  it("errors when an all-OPTIONAL family declares a non-optional mandate", () => {
    const m = loadFamily("ar.quality.v1.anchor.json"); // AQR → §2 all-OPTIONAL
    m.tsa_mandate = { "*": "recommended" };
    const p = writeTemp("aqr-tsa.anchor.json", m);
    const result = run(p);
    cleanTemp();
    assert.equal(result.code, 1);
    assert.match(result.stderr, /§2 lists AQR as OPTIONAL on every event/);
  });

  it("warns when a mandate-bearing family declares only optional levels", () => {
    const m = loadFamily("ar.breach.v1.anchor.json"); // ABR → §2 has MANDATORY
    m.tsa_mandate = { "*": "optional" };
    const p = writeTemp("abr-tsa.anchor.json", m);
    const result = run(p);
    cleanTemp();
    assert.match(
      result.stderr,
      /§2 lists a MANDATORY\/RECOMMENDED event for ABR/
    );
  });
});

describe("anchors validate — §5 shared envelope", () => {
  it("warns when a non-APR family declares the legacy v1 envelope", () => {
    const m = loadFamily("ar.quality.v1.anchor.json");
    m.envelope = "v1";
    const p = writeTemp("aqr-env.anchor.json", m);
    const result = run(p);
    cleanTemp();
    assert.match(result.stderr, /only APR is grandfathered/);
  });

  it("does not warn for APR on v1", () => {
    const result = run(path.join(FAMILIES_DIR, "ar.provenance.v1.anchor.json"));
    assert.doesNotMatch(result.stderr, /only APR is grandfathered/);
  });
});

describe("anchors validate — manifest-roster coverage (§7 checklist automation)", () => {
  it("does not flag APIIR or ACBR — manifests landed 2026-07-06", () => {
    const result = run();
    assert.doesNotMatch(
      result.stderr,
      /"APIIR" \(FAMILY-CONSISTENCY\.md §1 chip 20\) has no schema\/families/
    );
    assert.doesNotMatch(
      result.stderr,
      /"ACBR" \(FAMILY-CONSISTENCY\.md §1 chip 21\) has no schema\/families/
    );
  });

  it("does not flag any of the 21 manifested families", () => {
    const result = run();
    for (const f of fs.readdirSync(FAMILIES_DIR)) {
      if (!f.endsWith(".anchor.json")) continue;
      const acronym = JSON.parse(
        fs.readFileSync(path.join(FAMILIES_DIR, f), "utf-8")
      ).acronym;
      assert.doesNotMatch(
        result.stderr,
        new RegExp(`"${acronym}".*has no schema/families`)
      );
    }
  });
});

describe("anchors validate — §5 package-import rules (mandatory dependencies)", () => {
  it("every shipped family package.json depends on @dekimuhq/anchors-envelope", () => {
    const result = run();
    assert.doesNotMatch(
      result.stderr,
      /missing mandatory dependency "@dekimuhq\/anchors-envelope"/
    );
  });

  it("AgTR (trace) depends on @dekimuhq/anchors-disclosure per the documented exception", () => {
    const result = run();
    assert.doesNotMatch(
      result.stderr,
      /missing "@dekimuhq\/anchors-disclosure".*REQUIRED import specifically for AgTR/
    );
  });
});

describe("anchors validate — §2/§3 source consistency (manifest ⟷ src/family.ts)", () => {
  it("does not flag drift for any shipped family (manifest and family.ts agree)", () => {
    const result = run();
    assert.doesNotMatch(
      result.stderr,
      /manifest and shipped family\.ts have drifted/
    );
  });

  it("errors when subject_presence disagrees with family.ts (synthetic manifest, real family.ts)", () => {
    // Point a temp manifest's packages.verifier at the real `quality` package
    // (must-be-null in src/family.ts) but declare a mismatching subject_presence.
    const m = loadFamily("ar.quality.v1.anchor.json");
    m.subject_presence = "must-be-present";
    const p = writeTemp("aqr-src-drift.anchor.json", m);
    const result = run(p);
    cleanTemp();
    assert.match(
      result.stderr,
      /quality\/quality\/src\/family\.ts declares subject_presence "must-be-null" but the manifest declares "must-be-present"/
    );
  });
});

// §6 is skipped by default (`run()`) — it runs every family's `npm test`, ~90s
// for 21 families. This block runs it for real via `runSlow()`. Excluded from
// the fast loop; `npm run validate` (CI) always runs it regardless.
describe("anchors validate — §6 test-count floor (slow, runs real test suites)", () => {
  it("does not flag APR, APIIR, or ACBR (documented mini-exemptions)", () => {
    // ACBR joined the exemption list 2026-07-06 (build-to-ready, publish
    // maintainer-gated — see the ACBR test-floor note in FAMILY-CONSISTENCY.md §6);
    // the floor re-applies at publish time.
    const result = runSlow();
    assert.doesNotMatch(
      result.stderr,
      /APR has \d+ actual tests.*below the §6 floor/
    );
    assert.doesNotMatch(
      result.stderr,
      /APIIR has \d+ actual tests.*below the §6 floor/
    );
    assert.doesNotMatch(
      result.stderr,
      /ACBR has \d+ actual tests.*below the §6 floor/
    );
  });

  it("surfaces doc-drift warnings where actual counts outgrew the promised counts", () => {
    const result = runSlow();
    assert.match(result.stderr, /!= §6 "Tests promised" \d+ — table is stale/);
  });
});
