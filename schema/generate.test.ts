/**
 * Tests for schema/generate.ts — anchors generate CLI.
 *
 * Run: node --experimental-strip-types --test schema/generate.test.ts
 */

import { describe, it } from "node:test";
import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { spawnSync } from "node:child_process";

// Direct imports for unit-testing helpers
import {
  toPascalCase,
  toLowerAcronym,
  emitFieldType,
  generateTypes,
  generateFamily,
  claimNoun,
  claimVersion,
  kebab,
  subjectKindCell,
  generatePackageJson,
  generateManualPatches,
  TSCONFIG_JSON,
  TSCONFIG_BUILD_JSON,
} from "./generate.ts";

const SCHEMA_DIR = path.resolve(
  import.meta.dirname ?? path.dirname(new URL(import.meta.url).pathname)
);
const CLI = path.join(SCHEMA_DIR, "generate.ts");
const FAMILIES_DIR = path.join(SCHEMA_DIR, "families");
const SNAPSHOTS_DIR = path.join(SCHEMA_DIR, "test", "snapshots");
const TMP_DIR = path.join(SCHEMA_DIR, ".test-tmp-gen");

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
    }
  );
  return {
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    code: result.status ?? 1,
  };
}

function cleanTmp(): void {
  if (fs.existsSync(TMP_DIR)) {
    fs.rmSync(TMP_DIR, { recursive: true, force: true });
  }
}

// ── Helper unit tests ─────────────────────────────────────────────────────

describe("toPascalCase", () => {
  it("converts dotted names", () => {
    assert.equal(toPascalCase("consent.given"), "ConsentGiven");
  });

  it("converts underscored names", () => {
    assert.equal(toPascalCase("derived_from"), "DerivedFrom");
  });

  it("converts mixed dot+underscore", () => {
    assert.equal(toPascalCase("breach.dpa_notified"), "BreachDpaNotified");
  });

  it("handles single segment", () => {
    assert.equal(toPascalCase("arrangement"), "Arrangement");
  });

  it("handles token.issued style", () => {
    assert.equal(toPascalCase("token.issued"), "TokenIssued");
  });
});

describe("toLowerAcronym", () => {
  it("lowercases simple acronym", () => {
    assert.equal(toLowerAcronym("ACR"), "acr");
  });

  it("lowercases mixed-case acronym", () => {
    assert.equal(toLowerAcronym("ATokR"), "atokr");
  });

  it("lowercases APuR", () => {
    assert.equal(toLowerAcronym("APuR"), "apur");
  });
});

describe("claimNoun", () => {
  it("extracts a single-word noun", () => {
    assert.equal(claimNoun("ar.quality.v1"), "quality");
  });

  it("extracts an underscored multi-word noun", () => {
    assert.equal(claimNoun("ar.subject_rights.v1"), "subject_rights");
  });

  it("returns the input when it is not a dotted claim_type", () => {
    assert.equal(claimNoun("quality"), "quality");
  });
});

describe("claimVersion", () => {
  it("extracts the major version digit", () => {
    assert.equal(claimVersion("ar.quality.v1"), "1");
  });

  it("extracts multi-digit versions", () => {
    assert.equal(claimVersion("ar.quality.v12"), "12");
  });

  it("defaults to 1 when the suffix is not a version", () => {
    assert.equal(claimVersion("ar.quality.draft"), "1");
  });
});

describe("kebab", () => {
  it("kebab-cases a multi-word name", () => {
    assert.equal(kebab("Anchored Quality Receipts"), "anchored-quality-receipts");
  });

  it("collapses non-alphanumerics and trims", () => {
    assert.equal(kebab("  Foo / Bar! "), "foo-bar");
  });
});

describe("subjectKindCell", () => {
  it("maps must-be-null to `null`", () => {
    assert.equal(subjectKindCell("must-be-null"), "`null`");
  });

  it("maps either to per-event", () => {
    assert.equal(subjectKindCell("either"), "per-event");
  });

  it("leaves must-be-present open for a spec call", () => {
    assert.match(subjectKindCell("must-be-present"), /<kind/);
  });
});

describe("TSCONFIG constants", () => {
  it("tsconfig.json is valid JSON with NodeNext resolution", () => {
    const parsed = JSON.parse(TSCONFIG_JSON);
    assert.equal(parsed.compilerOptions.moduleResolution, "NodeNext");
    assert.equal(parsed.compilerOptions.exactOptionalPropertyTypes, true);
  });

  it("tsconfig.build.json extends ./tsconfig.json and emits to dist", () => {
    const parsed = JSON.parse(TSCONFIG_BUILD_JSON);
    assert.equal(parsed.extends, "./tsconfig.json");
    assert.equal(parsed.compilerOptions.outDir, "dist");
    assert.equal(parsed.compilerOptions.noEmit, false);
  });
});

describe("generatePackageJson", () => {
  const quality = JSON.parse(
    fs.readFileSync(path.join(FAMILIES_DIR, "ar.quality.v1.anchor.json"), "utf-8")
  );

  it("names the package after the claim noun, not the acronym", () => {
    const pkg = JSON.parse(generatePackageJson(quality, "0.24.0"));
    assert.equal(pkg.name, "@dekimuhq/quality");
  });

  it("caret-pins the live envelope version passed in", () => {
    const pkg = JSON.parse(generatePackageJson(quality, "0.24.0"));
    assert.equal(pkg.dependencies["@dekimuhq/anchors-envelope"], "^0.24.0");
  });

  it("includes the profiles dep only when the manifest declares profiles", () => {
    const withProfiles = JSON.parse(generatePackageJson(quality, "0.24.0"));
    assert.equal(
      withProfiles.dependencies["@dekimuhq/quality-profiles"],
      "^0.1.0"
    );

    const noProfiles = JSON.parse(
      generatePackageJson({ ...quality, profiles: [] }, "0.24.0")
    );
    assert.equal(
      noProfiles.dependencies["@dekimuhq/quality-profiles"],
      undefined
    );
  });

  it("starts at 0.1.0 with the consolidated ./issue export + publishConfig", () => {
    const pkg = JSON.parse(generatePackageJson(quality, "0.24.0"));
    assert.equal(pkg.version, "0.1.0");
    assert.ok(pkg.exports["./issue"]);
    assert.equal(pkg.publishConfig.access, "public");
    assert.equal(pkg.publishConfig.registry, undefined);
    assert.equal(pkg.engines.node, ">=24.6.0");
  });
});

describe("generateManualPatches", () => {
  const quality = JSON.parse(
    fs.readFileSync(path.join(FAMILIES_DIR, "ar.quality.v1.anchor.json"), "utf-8")
  );

  it("prints the exact envelope CLAIM_TYPES line and a REGISTRY row", () => {
    const patches = generateManualPatches(quality);
    assert.match(patches, /"ar\.quality\.v1",/);
    assert.match(patches, /\| `ar\.quality\.v1` \|/);
    assert.match(patches, /policy\.ts/);
  });
});

describe("CLI — --package scaffold", () => {
  it("writes the full package scaffold + prints manual patches", () => {
    cleanTmp();
    const root = path.join(TMP_DIR, "quality", "quality");
    const { stderr, code } = run(
      "schema/families/ar.quality.v1.anchor.json",
      "--out",
      root,
      "--package"
    );
    assert.equal(code, 0, stderr);

    for (const rel of [
      "package.json",
      "tsconfig.json",
      "tsconfig.build.json",
      "src/types.ts",
      "src/family.ts",
    ]) {
      assert.ok(
        fs.existsSync(path.join(root, rel)),
        `expected ${rel} to be written`
      );
    }
    assert.match(stderr, /MANUAL PATCHES/);

    const pkg = JSON.parse(
      fs.readFileSync(path.join(root, "package.json"), "utf-8")
    );
    assert.equal(pkg.name, "@dekimuhq/quality");

    cleanTmp();
  });

  it("requires --out when --package is given", () => {
    const { stderr, code } = run(
      "schema/families/ar.quality.v1.anchor.json",
      "--package"
    );
    assert.equal(code, 1);
    assert.match(stderr, /--package requires --out/);
  });
});

describe("emitFieldType", () => {
  it("maps string type", () => {
    assert.equal(emitFieldType({ type: "string" }, 0), "string");
  });

  it("maps iso8601 to string", () => {
    assert.equal(emitFieldType({ type: "iso8601" }, 0), "string");
  });

  it("maps sha256 to string", () => {
    assert.equal(emitFieldType({ type: "sha256" }, 0), "string");
  });

  it("maps did to string", () => {
    assert.equal(emitFieldType({ type: "did" }, 0), "string");
  });

  it("maps uri to string", () => {
    assert.equal(emitFieldType({ type: "uri" }, 0), "string");
  });

  it("maps integer to number", () => {
    assert.equal(emitFieldType({ type: "integer" }, 0), "number");
  });

  it("maps number to number", () => {
    assert.equal(emitFieldType({ type: "number" }, 0), "number");
  });

  it("maps boolean", () => {
    assert.equal(emitFieldType({ type: "boolean" }, 0), "boolean");
  });

  it("maps enum to string literal union", () => {
    const result = emitFieldType(
      { type: "enum", enum_values: ["a", "b", "c"] },
      0
    );
    assert.equal(result, '"a" | "b" | "c"');
  });

  it("maps array of strings", () => {
    const result = emitFieldType(
      { type: "array", items: { type: "string" } },
      0
    );
    assert.equal(result, "readonly string[]");
  });

  it("maps object with fields", () => {
    const result = emitFieldType(
      {
        type: "object",
        fields: {
          name: { type: "string" },
          age: { type: "integer" },
        },
      },
      0
    );
    assert.match(result, /name: string;/);
    assert.match(result, /age: number;/);
  });

  it("handles nullable field in object", () => {
    const result = emitFieldType(
      {
        type: "object",
        fields: {
          prev: { type: "sha256", nullable: true },
        },
      },
      0
    );
    assert.match(result, /prev: string \| null;/);
  });

  it("handles optional field in object", () => {
    const result = emitFieldType(
      {
        type: "object",
        fields: {
          extra: { type: "string", required: false },
        },
      },
      0
    );
    assert.match(result, /extra\?: string;/);
  });
});

// ── generateTypes tests ─────────────────────────────────────────────────────

describe("generateTypes — flat body (ACR)", () => {
  const manifest = JSON.parse(
    fs.readFileSync(
      path.join(FAMILIES_DIR, "ar.consent.v1.anchor.json"),
      "utf-8"
    )
  );

  it("emits ACRClaimType union with 3 members", () => {
    const output = generateTypes(manifest);
    assert.match(output, /export type ACRClaimType =/);
    assert.match(output, /"ar\.consent\.v1"/);
    assert.match(output, /"ar\.modification\.v1"/);
    assert.match(output, /"ar\.withdrawal\.v1"/);
  });

  it("emits ACREventType union", () => {
    const output = generateTypes(manifest);
    assert.match(output, /export type ACREventType =/);
    assert.match(output, /"consent\.given"/);
  });

  it("emits ACRProfile union", () => {
    const output = generateTypes(manifest);
    assert.match(output, /export type ACRProfile =/);
    assert.match(output, /"gdpr\.art7"/);
    assert.match(output, /"esig\.accept"/);
  });

  it("emits ACRBody interface with correct fields", () => {
    const output = generateTypes(manifest);
    assert.match(output, /export interface ACRBody \{/);
    assert.match(output, /sub_commit: string;/);
    assert.match(output, /purposes: readonly string\[\];/);
    assert.match(output, /expires_at\?: string;/);
    assert.match(output, /prev: string \| null;/);
    assert.match(output, /countersig: string \| null;/);
  });

  it("emits auto-generated header", () => {
    const output = generateTypes(manifest);
    assert.match(output, /AUTO-GENERATED from ar\.consent\.v1\.anchor\.json/);
  });
});

describe("generateTypes — no profiles (APR)", () => {
  const manifest = JSON.parse(
    fs.readFileSync(
      path.join(FAMILIES_DIR, "ar.provenance.v1.anchor.json"),
      "utf-8"
    )
  );

  it("does not emit APRProfile when profiles is empty", () => {
    const output = generateTypes(manifest);
    assert.doesNotMatch(output, /export type APRProfile/);
  });

  it("emits nested object fields for artifact", () => {
    const output = generateTypes(manifest);
    assert.match(output, /artifact: \{/);
    assert.match(output, /hash: string;/);
  });
});

describe("generateTypes — discriminated union (ATR)", () => {
  const manifest = JSON.parse(
    fs.readFileSync(
      path.join(FAMILIES_DIR, "ar.transfer.v1.anchor.json"),
      "utf-8"
    )
  );

  it("emits per-event interfaces", () => {
    const output = generateTypes(manifest);
    assert.match(output, /export interface ATRArrangementBody \{/);
    assert.match(output, /export interface ATRTransferBody \{/);
    assert.match(output, /export interface ATRTiaBody \{/);
    assert.match(output, /export interface ATRSuspensionBody \{/);
  });

  it("narrows event_type to literal in each variant", () => {
    const output = generateTypes(manifest);
    assert.match(output, /event_type: "arrangement";/);
    assert.match(output, /event_type: "transfer";/);
    assert.match(output, /event_type: "tia";/);
    assert.match(output, /event_type: "suspension";/);
  });

  it("emits ATRBody discriminated union", () => {
    const output = generateTypes(manifest);
    assert.match(output, /export type ATRBody =/);
    assert.match(output, /\| ATRArrangementBody/);
    assert.match(output, /\| ATRSuspensionBody;/);
  });

  it("does not emit a flat ATRBody interface", () => {
    const output = generateTypes(manifest);
    assert.doesNotMatch(output, /export interface ATRBody \{/);
  });
});

describe("generateTypes — ATokR (long acronym + compose links)", () => {
  const manifest = JSON.parse(
    fs.readFileSync(
      path.join(FAMILIES_DIR, "ar.tokenization.v1.anchor.json"),
      "utf-8"
    )
  );

  it("uses ATokR prefix correctly", () => {
    const output = generateTypes(manifest);
    assert.match(output, /export type ATokRClaimType =/);
    assert.match(output, /export type ATokREventType =/);
    assert.match(output, /export type ATokRProfile =/);
    assert.match(output, /export type ATokRBody =/);
  });

  it("emits per-event interfaces for token events", () => {
    const output = generateTypes(manifest);
    assert.match(output, /export interface ATokRTokenIssuedBody \{/);
    assert.match(output, /export interface ATokRTokenRedeemedBody \{/);
    assert.match(output, /export interface ATokRTokenRevokedBody \{/);
    assert.match(output, /export interface ATokRTokenRotatedBody \{/);
  });

  it("emits nested scope object", () => {
    const output = generateTypes(manifest);
    assert.match(output, /scope: \{/);
    assert.match(output, /audience: string;/);
    assert.match(output, /single_use: boolean;/);
    assert.match(output, /valid_until: string \| null;/);
  });
});

// ── generateFamily tests ───────────────────────────────────────────────────

describe("generateFamily — ACR scaffold", () => {
  const manifest = JSON.parse(
    fs.readFileSync(
      path.join(FAMILIES_DIR, "ar.consent.v1.anchor.json"),
      "utf-8"
    )
  );

  it("emits acrFamily export", () => {
    const output = generateFamily(manifest);
    assert.match(output, /export const acrFamily: FamilyManifest<ACRBody>/);
  });

  it("fills chip and status_list_slot from manifest", () => {
    const output = generateFamily(manifest);
    assert.match(output, /chip: 2,/);
    assert.match(output, /status_list_slot: 2,/);
  });

  it("lists all claim_types", () => {
    const output = generateFamily(manifest);
    assert.match(output, /"ar\.consent\.v1"/);
    assert.match(output, /"ar\.modification\.v1"/);
    assert.match(output, /"ar\.withdrawal\.v1"/);
  });

  it("sets subject_presence to must-be-present", () => {
    const output = generateFamily(manifest);
    assert.match(output, /subject_presence: "must-be-present"/);
  });

  it("does not emit SubjectPresenceCheck import for non-either families", () => {
    const output = generateFamily(manifest);
    assert.doesNotMatch(output, /SubjectPresenceCheck/);
  });
});

describe("generateFamily — ATR scaffold (subject_presence either)", () => {
  const manifest = JSON.parse(
    fs.readFileSync(
      path.join(FAMILIES_DIR, "ar.transfer.v1.anchor.json"),
      "utf-8"
    )
  );

  it("emits atrFamily export", () => {
    const output = generateFamily(manifest);
    assert.match(output, /export const atrFamily: FamilyManifest<ATRBody>/);
  });

  it("imports SubjectPresenceCheck", () => {
    const output = generateFamily(manifest);
    assert.match(output, /type SubjectPresenceCheck/);
  });

  it("emits subject_presence_check stub with overrides listed", () => {
    const output = generateFamily(manifest);
    assert.match(output, /subject_presence_check: subjectPresenceCheck/);
    assert.match(output, /arrangement: must-be-null/);
    assert.match(output, /transfer: must-be-present/);
  });
});

describe("generateFamily — ATokR scaffold (compose links)", () => {
  const manifest = JSON.parse(
    fs.readFileSync(
      path.join(FAMILIES_DIR, "ar.tokenization.v1.anchor.json"),
      "utf-8"
    )
  );

  it("emits atokrFamily export", () => {
    const output = generateFamily(manifest);
    assert.match(output, /export const atokrFamily: FamilyManifest<ATokRBody>/);
  });

  it("lists compose links_to in comment", () => {
    const output = generateFamily(manifest);
    assert.match(output, /Links to: ar\.subject_rights\.v1/);
    assert.match(output, /ar\.purpose\.v1/);
  });
});

// ── CLI tests ─────────────────────────────────────────────────────────────────

describe("CLI — argument handling", () => {
  it("exits 1 with no args", () => {
    const result = run();
    assert.equal(result.code, 1);
    assert.match(result.stderr, /Usage:/);
  });

  it("exits 0 with --help", () => {
    const result = run("--help");
    assert.equal(result.code, 0);
    assert.match(result.stderr, /Usage:/);
  });

  it("exits 1 for non-existent manifest", () => {
    const result = run("schema/families/nonexistent.anchor.json");
    assert.equal(result.code, 1);
    assert.match(result.stderr, /not found/);
  });

  it("prints to stdout with file markers for valid manifest", () => {
    const result = run("schema/families/ar.consent.v1.anchor.json");
    assert.equal(result.code, 0);
    assert.match(result.stdout, /\/\/ === FILE: types\.ts ===/);
    assert.match(result.stdout, /\/\/ === FILE: family\.ts ===/);
    assert.match(result.stdout, /export type ACRClaimType/);
    assert.match(result.stdout, /export const acrFamily/);
  });

  it("writes files to --out directory", () => {
    cleanTmp();
    const result = run(
      "schema/families/ar.consent.v1.anchor.json",
      "--out",
      TMP_DIR
    );
    assert.equal(result.code, 0, result.stderr);
    assert.ok(fs.existsSync(path.join(TMP_DIR, "types.ts")));
    assert.ok(fs.existsSync(path.join(TMP_DIR, "family.ts")));
    cleanTmp();
  });

  it("refuses to overwrite without --force", () => {
    cleanTmp();
    fs.mkdirSync(TMP_DIR, { recursive: true });
    fs.writeFileSync(path.join(TMP_DIR, "types.ts"), "existing");
    const result = run(
      "schema/families/ar.consent.v1.anchor.json",
      "--out",
      TMP_DIR
    );
    assert.equal(result.code, 1);
    assert.match(result.stderr, /already exists/);
    cleanTmp();
  });

  it("overwrites with --force", () => {
    cleanTmp();
    fs.mkdirSync(TMP_DIR, { recursive: true });
    fs.writeFileSync(path.join(TMP_DIR, "types.ts"), "existing");
    fs.writeFileSync(path.join(TMP_DIR, "family.ts"), "existing");
    const result = run(
      "schema/families/ar.consent.v1.anchor.json",
      "--out",
      TMP_DIR,
      "--force"
    );
    assert.equal(result.code, 0, result.stderr);
    const content = fs.readFileSync(path.join(TMP_DIR, "types.ts"), "utf-8");
    assert.match(content, /ACRClaimType/);
    cleanTmp();
  });
});

describe("CLI — validation gate", () => {
  it("refuses manifest with invalid id", () => {
    cleanTmp();
    fs.mkdirSync(TMP_DIR, { recursive: true });
    const bad = path.join(TMP_DIR, "bad.anchor.json");
    fs.writeFileSync(
      bad,
      JSON.stringify({
        id: "invalid",
        acronym: "TST",
        name: "Test Receipts",
        claim_types: ["invalid"],
        envelope: "v2",
        chip: 99,
        subject_presence: "must-be-null",
        body: {},
      })
    );
    const result = run(bad);
    assert.equal(result.code, 1);
    assert.match(result.stderr, /does not match/);
    cleanTmp();
  });
});

// ── tsc compilation test ─────────────────────────────────────────────────────

describe("tsc compilation — all 14 families", () => {
  it("all generated types.ts files pass tsc --noEmit", () => {
    cleanTmp();
    fs.mkdirSync(TMP_DIR, { recursive: true });

    // Generate all 14 types files
    const families = fs
      .readdirSync(FAMILIES_DIR)
      .filter((f) => f.endsWith(".anchor.json"));

    for (const family of families) {
      const manifest = JSON.parse(
        fs.readFileSync(path.join(FAMILIES_DIR, family), "utf-8")
      );
      const typesContent = generateTypes(manifest);
      const outFile = path.join(
        TMP_DIR,
        family.replace(".anchor.json", ".types.ts")
      );
      fs.writeFileSync(outFile, typesContent);
    }

    // Write a minimal tsconfig for the temp dir
    const tsconfig = {
      compilerOptions: {
        strict: true,
        noEmit: true,
        target: "ES2022",
        module: "ESNext",
        moduleResolution: "bundler",
        exactOptionalPropertyTypes: true,
      },
      include: ["*.ts"],
    };
    fs.writeFileSync(
      path.join(TMP_DIR, "tsconfig.json"),
      JSON.stringify(tsconfig, null, 2)
    );

    // Run tsc
    const result = spawnSync("npx", ["tsc", "--project", TMP_DIR], {
      encoding: "utf-8",
      cwd: path.resolve(SCHEMA_DIR, ".."),
      stdio: ["pipe", "pipe", "pipe"],
    });

    const output = (result.stdout ?? "") + (result.stderr ?? "");
    assert.equal(result.status, 0, `tsc failed:\n${output}`);

    cleanTmp();
  });
});

// ── Snapshot tests ───────────────────────────────────────────────────────────

describe("snapshot tests", () => {
  const SNAPSHOT_FAMILIES = [
    "ar.consent.v1",
    "ar.provenance.v1",
    "ar.transfer.v1",
    "ar.tokenization.v1",
  ];

  /** Strip timestamp line for comparison. */
  function stripTimestamp(content: string): string {
    return content.replace(/ \* Generated: .*/, " * Generated: [TIMESTAMP]");
  }

  for (const family of SNAPSHOT_FAMILIES) {
    it(`${family} types.ts matches snapshot`, () => {
      const manifest = JSON.parse(
        fs.readFileSync(
          path.join(FAMILIES_DIR, `${family}.anchor.json`),
          "utf-8"
        )
      );
      const generated = stripTimestamp(generateTypes(manifest));
      const snapshot = fs.readFileSync(
        path.join(SNAPSHOTS_DIR, `${family}.types.ts`),
        "utf-8"
      );
      assert.equal(
        generated,
        snapshot,
        `Snapshot mismatch for ${family}.types.ts`
      );
    });

    it(`${family} family.ts matches snapshot`, () => {
      const manifest = JSON.parse(
        fs.readFileSync(
          path.join(FAMILIES_DIR, `${family}.anchor.json`),
          "utf-8"
        )
      );
      const generated = stripTimestamp(generateFamily(manifest));
      const snapshot = fs.readFileSync(
        path.join(SNAPSHOTS_DIR, `${family}.family.ts`),
        "utf-8"
      );
      assert.equal(
        generated,
        snapshot,
        `Snapshot mismatch for ${family}.family.ts`
      );
    });
  }
});
