/**
 * anchors generate — Phase 2 schema-language CLI.
 *
 * Reads a .anchor.json manifest and emits TypeScript types + family scaffold.
 *
 * Run:
 *   node --experimental-strip-types schema/generate.ts <manifest> [--out <dir>] [--force]
 *   npm run generate -- <manifest>
 *
 * Exit code: 0 = success, 1 = error.
 */

import * as fs from "node:fs";
import * as path from "node:path";

// ── Types (reused from validate.ts) ─────────────────────────────────────────

interface AnchorField {
  type: string;
  required?: boolean;
  nullable?: boolean;
  enum_values?: string[];
  items?: AnchorField;
  fields?: Record<string, AnchorField>;
  variants?: AnchorField[];
  description?: string;
}

interface AnchorProfile {
  id: string;
  regulation: string;
  tsa_override?: string;
  extra_fields?: Record<string, AnchorField>;
}

interface SubjectOverride {
  event_type: string;
  subject_presence: string;
  description?: string;
}

interface AnchorCompose {
  walk_parents?: boolean;
  links_to?: string[];
  chain_predecessor?: boolean;
}

interface AnchorPackages {
  verifier?: string;
  issuer_kit?: string;
  profiles?: string;
}

interface AnchorManifest {
  $schema?: string;
  id: string;
  acronym: string;
  name: string;
  claim_types: string[];
  envelope: string;
  sign?: string;
  canonicalize?: string;
  chip: number;
  status_list_slot: number | null;
  subject_presence: string;
  subject_presence_overrides?: SubjectOverride[];
  tsa_upgrade_path?: string;
  tsa_mandate?: Record<string, string>;
  body: Record<string, AnchorField>;
  event_types?: string[];
  profiles?: AnchorProfile[];
  compose?: AnchorCompose;
  continuity?: boolean;
  status_list?: boolean;
  suspension?: boolean;
  spec_path?: string;
  packages?: AnchorPackages;
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Convert a dotted/underscored string to PascalCase.
 * "consent.given" → "ConsentGiven"
 * "derived_from" → "DerivedFrom"
 * "breach.dpa_notified" → "BreachDpaNotified"
 */
export function toPascalCase(str: string): string {
  return str
    .split(/[._]/)
    .map((seg) => seg.charAt(0).toUpperCase() + seg.slice(1))
    .join("");
}

/**
 * Lowercase the entire acronym for family export names.
 * "ACR" → "acr", "ATokR" → "atokr"
 */
export function toLowerAcronym(acronym: string): string {
  return acronym.toLowerCase();
}

/**
 * Extract the package noun from a claim_type id.
 * "ar.quality.v1" → "quality", "ar.subject_rights.v1" → "subject_rights".
 * New families (15th member onward) name their consolidated package
 * `@dekimuhq/<noun>` (the original 14 used lowercased acronyms).
 */
export function claimNoun(id: string): string {
  const parts = id.split(".");
  return parts.length >= 3 ? parts.slice(1, -1).join(".") : id;
}

/**
 * Extract the major version digit from a claim_type id.
 * "ar.quality.v1" → "1".
 */
export function claimVersion(id: string): string {
  const last = id.split(".").pop() ?? "";
  const m = last.match(/^v(\d+)$/);
  return m ? m[1] : "1";
}

/** Convert a human name to kebab-case. "Anchored Quality Receipts" → "anchored-quality-receipts". */
export function kebab(str: string): string {
  return str
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

/**
 * Map a manifest `subject_presence` to the REGISTRY discriminator-table `kind` cell.
 * Leaves the kind open where the manifest can't decide it (must-be-present splits
 * into decision/observation per family — a spec call, not a mechanical one).
 */
export function subjectKindCell(subjectPresence: string): string {
  switch (subjectPresence) {
    case "must-be-null":
      return "`null`";
    case "either":
      return "per-event";
    default:
      return "`<kind — decision | observation>`";
  }
}

/**
 * Recursively map a manifest field descriptor to a TypeScript type string.
 * Returns the type expression (e.g. "string", "readonly string[]", inline interface).
 */
export function emitFieldType(field: AnchorField, indent: number): string {
  const pad = "  ".repeat(indent);
  const innerPad = "  ".repeat(indent + 1);

  switch (field.type) {
    case "string":
    case "did":
    case "uri":
    case "iso8601":
    case "sha256":
      return "string";

    case "integer":
    case "number":
      return "number";

    case "boolean":
      return "boolean";

    case "enum": {
      if (!field.enum_values || field.enum_values.length === 0) return "string";
      return field.enum_values.map((v) => `"${v}"`).join(" | ");
    }

    case "array": {
      if (!field.items) return "readonly unknown[]";
      const itemType = emitFieldType(field.items, indent);
      if (itemType.includes("\n")) {
        return `readonly (${itemType})[]`;
      }
      return `readonly ${itemType}[]`;
    }

    case "object": {
      if (!field.fields) return "Record<string, unknown>";
      const lines: string[] = ["{"];
      for (const [name, subField] of Object.entries(field.fields)) {
        const optional = subField.required === false ? "?" : "";
        const baseType = emitFieldType(subField, indent + 1);
        const fullType = subField.nullable ? `${baseType} | null` : baseType;
        if (subField.description) {
          lines.push(`${innerPad}/** ${subField.description} */`);
        }
        lines.push(`${innerPad}${name}${optional}: ${fullType};`);
      }
      lines.push(`${pad}}`);
      return lines.join("\n");
    }

    case "union": {
      if (!field.variants || field.variants.length === 0) return "unknown";
      return field.variants.map((v) => emitFieldType(v, indent)).join(" | ");
    }

    default:
      return "unknown";
  }
}

// ── Type Generation ─────────────────────────────────────────────────────────

/** Build a JSDoc comment for a field based on its type and description. */
function fieldJsDoc(field: AnchorField): string | null {
  const parts: string[] = [];
  if (field.description) parts.push(field.description);
  if (field.type === "iso8601" && !field.description)
    parts.push("RFC 3339 timestamp.");
  if (field.type === "sha256" && !field.description)
    parts.push("`sha256:<hex>`");
  if (field.type === "did" && !field.description) parts.push("DID identifier.");
  if (field.type === "uri" && !field.description) parts.push("URI.");
  if (parts.length === 0) return null;
  return parts.join(" ");
}

/**
 * Detect whether this manifest's body should emit a discriminated union.
 * Condition: event_types present AND body has event_type field of type enum
 * whose enum_values match event_types.
 */
function isDiscriminatedUnion(manifest: AnchorManifest): boolean {
  if (!manifest.event_types || manifest.event_types.length === 0) return false;
  const etField = manifest.body?.event_type;
  if (!etField || etField.type !== "enum") return false;
  if (!etField.enum_values) return false;
  const bodySet = new Set(etField.enum_values);
  const manifestSet = new Set(manifest.event_types);
  if (bodySet.size !== manifestSet.size) return false;
  for (const e of manifestSet) {
    if (!bodySet.has(e)) return false;
  }
  return true;
}

/** Emit the full types.ts content for a manifest. */
export function generateTypes(manifest: AnchorManifest): string {
  const acronym = manifest.acronym;
  const lines: string[] = [];

  // Header
  lines.push("/**");
  lines.push(` * AUTO-GENERATED from ${manifest.id}.anchor.json`);
  lines.push(` * Generated: ${new Date().toISOString()}`);
  lines.push(" *");
  lines.push(
    " * Do not edit manually — re-run `npm run generate` to regenerate."
  );
  lines.push(" * Manual edits will be lost on next generation.");
  lines.push(" */");
  lines.push("");

  // ClaimType union
  lines.push(`/** Claim type discriminators for ${acronym}. */`);
  lines.push(`export type ${acronym}ClaimType =`);
  for (let i = 0; i < manifest.claim_types.length; i++) {
    const sep = i === manifest.claim_types.length - 1 ? ";" : "";
    lines.push(`  | "${manifest.claim_types[i]}"${sep}`);
  }
  lines.push("");

  // EventType union (only if event_types present)
  if (manifest.event_types && manifest.event_types.length > 0) {
    lines.push(`/** Event types for ${acronym}. */`);
    lines.push(`export type ${acronym}EventType =`);
    for (let i = 0; i < manifest.event_types.length; i++) {
      const sep = i === manifest.event_types.length - 1 ? ";" : "";
      lines.push(`  | "${manifest.event_types[i]}"${sep}`);
    }
    lines.push("");
  }

  // Profile union (only if profiles non-empty)
  if (manifest.profiles && manifest.profiles.length > 0) {
    lines.push(`/** Regulation profiles for ${acronym}. */`);
    lines.push(`export type ${acronym}Profile =`);
    for (let i = 0; i < manifest.profiles.length; i++) {
      const sep = i === manifest.profiles.length - 1 ? ";" : "";
      lines.push(`  | "${manifest.profiles[i].id}"${sep}`);
    }
    lines.push("");
  }

  // Body type(s)
  if (isDiscriminatedUnion(manifest)) {
    lines.push(emitUnionBody(manifest));
  } else {
    lines.push(emitFlatBody(manifest));
  }

  return lines.join("\n") + "\n";
}

/** Emit a single flat body interface. */
function emitFlatBody(manifest: AnchorManifest): string {
  const acronym = manifest.acronym;
  const lines: string[] = [];

  lines.push(`/** Body fields for ${acronym} receipts. */`);
  lines.push(`export interface ${acronym}Body {`);

  for (const [name, field] of Object.entries(manifest.body)) {
    const doc = fieldJsDoc(field);
    if (doc) lines.push(`  /** ${doc} */`);
    const optional = field.required === false ? "?" : "";
    const baseType = emitFieldType(field, 1);
    const fullType = field.nullable ? `${baseType} | null` : baseType;
    lines.push(`  ${name}${optional}: ${fullType};`);
  }

  lines.push("}");
  return lines.join("\n");
}

// ── Family Scaffold Generation ──────────────────────────────────────────────

/** Emit the family.ts scaffold content for a manifest. */
export function generateFamily(manifest: AnchorManifest): string {
  const acronym = manifest.acronym;
  const lower = toLowerAcronym(acronym);
  const lines: string[] = [];

  // Header
  lines.push("/**");
  lines.push(` * AUTO-GENERATED from ${manifest.id}.anchor.json`);
  lines.push(` * Generated: ${new Date().toISOString()}`);
  lines.push(" *");
  lines.push(" * Scaffold for defineFamily() wiring. Fill in TODO stubs with");
  lines.push(
    " * imperative logic (body validation, profile validators, compose)."
  );
  lines.push(" */");
  lines.push("");

  // Imports
  lines.push("import {");
  lines.push("  defineFamily,");
  lines.push("  type FamilyManifest,");
  lines.push("  type BodyValidator,");
  if (manifest.subject_presence === "either") {
    lines.push("  type SubjectPresenceCheck,");
  }
  lines.push('} from "@dekimuhq/anchors-envelope";');
  lines.push(`import type { ${acronym}Body } from "./types.ts";`);
  lines.push("");

  // Body validator stub
  lines.push(`const bodySchema: BodyValidator<${acronym}Body> = {`);
  lines.push("  validate(body) {");
  lines.push('    if (typeof body !== "object" || body === null) {');
  lines.push('      return { ok: false, reason: "body.invalid" };');
  lines.push("    }");
  lines.push("    // TODO: Implement structural body validation");
  lines.push(`    return { ok: true, value: body as ${acronym}Body };`);
  lines.push("  },");
  lines.push("};");
  lines.push("");

  // Subject presence check stub (only if "either")
  if (manifest.subject_presence === "either") {
    lines.push(
      "// TODO: Implement subject_presence_check for per-event splitting"
    );
    if (manifest.subject_presence_overrides) {
      lines.push("// Overrides from manifest:");
      for (const ov of manifest.subject_presence_overrides) {
        const desc = ov.description ? ` — ${ov.description}` : "";
        lines.push(`//   ${ov.event_type}: ${ov.subject_presence}${desc}`);
      }
    }
    lines.push(
      "const subjectPresenceCheck: SubjectPresenceCheck = ({ subject, body }) => {"
    );
    lines.push(
      "  // TODO: Check event_type from body and enforce per-event rules"
    );
    lines.push("  return { ok: true };");
    lines.push("};");
    lines.push("");
  }

  // Compose stub (if compose.links_to or walk_parents)
  if (manifest.compose?.links_to || manifest.compose?.walk_parents) {
    lines.push("// TODO: Implement compose callback");
    if (manifest.compose.links_to) {
      lines.push(`// Links to: ${manifest.compose.links_to.join(", ")}`);
    }
    if (manifest.compose.walk_parents) {
      lines.push("// Walk parents: true");
    }
    lines.push("");
  }

  // Family definition
  lines.push(
    `export const ${lower}Family: FamilyManifest<${acronym}Body> = defineFamily<${acronym}Body>({`
  );
  lines.push(`  acronym: "${acronym}",`);
  lines.push(`  name: "${manifest.name}",`);

  // claim_types
  if (manifest.claim_types.length === 1) {
    lines.push(`  claim_types: ["${manifest.claim_types[0]}"],`);
  } else {
    lines.push("  claim_types: [");
    for (const ct of manifest.claim_types) {
      lines.push(`    "${ct}",`);
    }
    lines.push("  ],");
  }

  lines.push(`  spec_path: "${manifest.spec_path ?? ""}",`);
  lines.push("");
  lines.push(`  chip: ${manifest.chip},`);
  lines.push(`  status_list_slot: ${manifest.status_list_slot},`);
  lines.push(`  subject_presence: "${manifest.subject_presence}",`);

  if (manifest.subject_presence === "either") {
    lines.push("  subject_presence_check: subjectPresenceCheck,");
  }

  lines.push(`  tsa_upgrade_path: "${manifest.tsa_upgrade_path ?? "free"}",`);
  lines.push("");
  lines.push("  body_schema: bodySchema,");
  lines.push("");
  lines.push("  // TODO: Wire profile validators");
  lines.push("  profiles: {},");
  lines.push("");
  lines.push("  // TODO: Wire TSA mandate map (if non-trivial)");
  lines.push("  tsa_mandate: {},");
  lines.push("");
  lines.push(`  continuity: ${manifest.continuity ?? true},`);

  if (manifest.compose?.links_to || manifest.compose?.walk_parents) {
    lines.push("  // TODO: Wire compose callback");
  }

  lines.push("  batch: false,");
  lines.push("  predicate_recommended: false,");
  lines.push("});");
  lines.push("");

  return lines.join("\n");
}

// ── Package Scaffold Generation ──────────────────────────────────────────────

/**
 * Static `tsconfig.json` shared by every consolidated family package.
 * Identical across families (verified against quality/action) — no manifest input.
 */
export const TSCONFIG_JSON = `{
  "compilerOptions": {
    "types": ["node"],
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "lib": ["ES2022"],
    "strict": true,
    "exactOptionalPropertyTypes": true,
    "noEmit": true,
    "skipLibCheck": true,
    "allowImportingTsExtensions": true
  },
  "include": ["src", "test"]
}
`;

/** Static `tsconfig.build.json` shared by every consolidated family package. */
export const TSCONFIG_BUILD_JSON = `{
  "extends": "./tsconfig.json",
  "compilerOptions": {
    "noEmit": false,
    "allowImportingTsExtensions": false,
    "rewriteRelativeImportExtensions": true,
    "declaration": true,
    "declarationMap": false,
    "sourceMap": false,
    "outDir": "dist",
    "rootDir": "src",
    "paths": {}
  },
  "include": [
    "src/**/*"
  ],
  "exclude": [
    "test/**/*",
    "**/*.test.ts"
  ]
}
`;

/**
 * Emit the consolidated `package.json` for a new family (verifier + issuer merged,
 * `./issue` subpath). `envelopeVersion` is the live `@dekimuhq/anchors-envelope`
 * version (caret-pinned at scaffold time — keeps new families current, the way the
 * caret-drift across older families happened because the dep was copy-pasted stale).
 */
export function generatePackageJson(
  manifest: AnchorManifest,
  envelopeVersion: string
): string {
  const noun = claimNoun(manifest.id);
  const acronym = manifest.acronym;
  const version = claimVersion(manifest.id);
  const hasProfiles = !!manifest.profiles && manifest.profiles.length > 0;

  const dependencies: Record<string, string> = {
    "@dekimuhq/anchors-envelope": `^${envelopeVersion}`,
  };
  if (hasProfiles) {
    dependencies[`@dekimuhq/${noun}-profiles`] = "^0.1.0";
  }

  const pkg = {
    name: `@dekimuhq/${noun}`,
    version: "0.1.0",
    description: `${manifest.name} (${acronym}) v${version} — verify (default) + issue (./issue). TODO: one-line tagline (provenance, not truth).`,
    license: "Apache-2.0",
    type: "module",
    main: "./dist/index.js",
    types: "./dist/index.d.ts",
    exports: {
      ".": { types: "./dist/index.d.ts", default: "./dist/index.js" },
      "./issue": {
        types: "./dist/issue/index.d.ts",
        default: "./dist/issue/index.js",
      },
    },
    files: [
      "dist",
      "README.md",
      "LICENSE",
      "CHANGELOG.md",
      "CONTRIBUTING.md",
      "SECURITY.md",
    ],
    repository: {
      type: "git",
      url: "git+https://github.com/dekimuhq/anchors.git",
      directory: `${noun}/${noun}`,
    },
    keywords: [
      acronym.toLowerCase(),
      kebab(manifest.name),
      "verifier",
      "issuer",
      "ed25519",
    ],
    engines: { node: ">=24.6.0" },
    scripts: {
      build: "node ../../scripts/build-anchor-pkg.mjs",
      test: "node --experimental-strip-types --test 'test/**/*.test.ts'",
      typecheck: "tsc --noEmit",
      prepack: "npm run build",
    },
    dependencies,
    devDependencies: { "@types/node": "^24.0.0", typescript: "^6.0.3" },
    // No `registry` here: the release job picks the registry per publish leg
    // (npmjs + GitHub Packages) through the scope config, and a pinned
    // publishConfig.registry would override it.
    publishConfig: {
      access: "public",
    },
  };

  return JSON.stringify(pkg, null, 2) + "\n";
}

/**
 * Emit the block of MANUAL patches for shared files the generator must not edit
 * (envelope union, REGISTRY, policy). Printed, never written — these are
 * single-source-of-truth files where an automated append would race other work.
 */
export function generateManualPatches(manifest: AnchorManifest): string {
  const lines: string[] = [];
  lines.push("── MANUAL PATCHES (apply by hand — shared single-source files) ──");
  lines.push("");
  lines.push("1. envelope/src/envelope-types.ts — add to the CLAIM_TYPES array:");
  lines.push(`      "${manifest.id}",`);
  lines.push("");
  lines.push("2. meta/REGISTRY.md — add to the discriminator table:");
  lines.push(
    `   | \`${manifest.id}\` | ${subjectKindCell(manifest.subject_presence)} | <predicate — fill from spec> |`
  );
  lines.push("");
  lines.push(
    "3. envelope/src/policy.ts — if this family is POLICY_BOUND or POLICY_OPTIONAL,"
  );
  lines.push("   add its claim_type to the matching set there too.");
  lines.push("");
  return lines.join("\n") + "\n";
}

/** Emit per-event variant interfaces + discriminated union type. */
function emitUnionBody(manifest: AnchorManifest): string {
  const acronym = manifest.acronym;
  const eventTypes = manifest.event_types!;
  const lines: string[] = [];

  // Emit one interface per event type
  for (const eventType of eventTypes) {
    const pascalEvent = toPascalCase(eventType);
    lines.push(`/** Body for ${acronym} "${eventType}" events. */`);
    lines.push(`export interface ${acronym}${pascalEvent}Body {`);
    lines.push(`  event_type: "${eventType}";`);

    for (const [name, field] of Object.entries(manifest.body)) {
      if (name === "event_type") continue; // Already emitted as the discriminant
      const doc = fieldJsDoc(field);
      if (doc) lines.push(`  /** ${doc} */`);
      const optional = field.required === false ? "?" : "";
      const baseType = emitFieldType(field, 1);
      const fullType = field.nullable ? `${baseType} | null` : baseType;
      lines.push(`  ${name}${optional}: ${fullType};`);
    }

    lines.push("}");
    lines.push("");
  }

  // Emit the discriminated union
  lines.push(`/** Discriminated union of all ${acronym} body variants. */`);
  lines.push(`export type ${acronym}Body =`);
  for (let i = 0; i < eventTypes.length; i++) {
    const pascalEvent = toPascalCase(eventTypes[i]);
    const sep = i === eventTypes.length - 1 ? ";" : "";
    lines.push(`  | ${acronym}${pascalEvent}Body${sep}`);
  }

  return lines.join("\n");
}

// ── Validation gate ─────────────────────────────────────────────────────────

const CLAIM_TYPE_RE = /^ar\.[a-z_]+\.v[0-9]+$/;
const ACRONYM_RE = /^[A-Z][A-Za-z]{2,5}$/;
const VALID_ENVELOPE = ["v1", "v2"];
const VALID_SUBJECT_PRESENCE = ["must-be-present", "must-be-null", "either"];

function validateManifestForGeneration(
  m: AnchorManifest,
  _filePath: string
): string[] {
  const errors: string[] = [];

  const required: (keyof AnchorManifest)[] = [
    "id",
    "acronym",
    "name",
    "claim_types",
    "envelope",
    "chip",
    "subject_presence",
    "body",
  ];
  for (const key of required) {
    if (m[key] === undefined || m[key] === null) {
      if (key === "status_list_slot") continue;
      errors.push(`missing required key "${key}"`);
    }
  }

  if (m.id && !CLAIM_TYPE_RE.test(m.id)) {
    errors.push(`id "${m.id}" does not match ar.<noun>.v<N>`);
  }
  if (m.acronym && !ACRONYM_RE.test(m.acronym)) {
    errors.push(`acronym "${m.acronym}" does not match [A-Z][A-Za-z]{2,5}`);
  }
  if (m.claim_types && m.claim_types.length === 0) {
    errors.push("claim_types must have at least 1 entry");
  }
  if (m.envelope && !VALID_ENVELOPE.includes(m.envelope)) {
    errors.push(`envelope "${m.envelope}" not in [v1, v2]`);
  }
  if (
    m.subject_presence &&
    !VALID_SUBJECT_PRESENCE.includes(m.subject_presence)
  ) {
    errors.push(`subject_presence "${m.subject_presence}" invalid`);
  }

  return errors;
}

// ── CLI ─────────────────────────────────────────────────────────────────────

function printUsage(): void {
  process.stderr.write(
    "Usage: node --experimental-strip-types schema/generate.ts <manifest.anchor.json> [--out <dir>] [--package] [--force]\n" +
      "\n" +
      "  --out <dir>   Without --package: write types.ts + family.ts into <dir>.\n" +
      "                With --package:   <dir> is the package ROOT; the full\n" +
      "                                  consolidated scaffold is written there.\n" +
      "  --package     Scaffold the whole `@dekimuhq/<noun>` package: src/types.ts,\n" +
      "                src/family.ts, package.json, tsconfig.json, tsconfig.build.json,\n" +
      "                + a printed block of manual patches for shared files.\n" +
      "  --force       Overwrite existing files.\n"
  );
}

/** Read the live `@dekimuhq/anchors-envelope` version, resolved next to this script. */
function readEnvelopeVersion(): string {
  const envPkgPath = path.resolve(
    import.meta.dirname,
    "..",
    "envelope",
    "package.json"
  );
  const raw = fs.readFileSync(envPkgPath, "utf-8");
  const parsed = JSON.parse(raw) as { version?: string };
  if (!parsed.version) {
    throw new Error(`envelope package.json has no version: ${envPkgPath}`);
  }
  return parsed.version;
}

/** Write a file, honouring the --force overwrite guard. Returns the path written. */
function writeGuarded(filePath: string, content: string, force: boolean): string {
  if (!force && fs.existsSync(filePath)) {
    process.stderr.write(
      `Error: ${filePath} already exists. Use --force to overwrite.\n`
    );
    process.exit(1);
  }
  fs.writeFileSync(filePath, content);
  return filePath;
}

function main(): void {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
    printUsage();
    process.exit(args.length === 0 ? 1 : 0);
  }

  // Parse args
  let manifestPath: string | null = null;
  let outDir: string | null = null;
  let force = false;
  let pkgScaffold = false;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--out" && i + 1 < args.length) {
      outDir = args[++i];
    } else if (args[i] === "--force") {
      force = true;
    } else if (args[i] === "--package") {
      pkgScaffold = true;
    } else if (!args[i].startsWith("-")) {
      manifestPath = args[i];
    } else {
      process.stderr.write(`Unknown option: ${args[i]}\n`);
      printUsage();
      process.exit(1);
    }
  }

  if (!manifestPath) {
    process.stderr.write("Error: no manifest path provided.\n");
    printUsage();
    process.exit(1);
  }

  if (pkgScaffold && !outDir) {
    process.stderr.write("Error: --package requires --out <package root>.\n");
    printUsage();
    process.exit(1);
  }

  // Resolve manifest path
  const resolved = path.resolve(manifestPath);
  if (!fs.existsSync(resolved)) {
    process.stderr.write(`Error: manifest not found: ${resolved}\n`);
    process.exit(1);
  }

  // Load and validate
  const raw = fs.readFileSync(resolved, "utf-8");
  let manifest: AnchorManifest;
  try {
    manifest = JSON.parse(raw) as AnchorManifest;
  } catch {
    process.stderr.write(`Error: invalid JSON in ${resolved}\n`);
    process.exit(1);
  }

  const errors = validateManifestForGeneration(manifest, resolved);
  if (errors.length > 0) {
    process.stderr.write(`Validation errors in ${path.basename(resolved)}:\n`);
    for (const e of errors) {
      process.stderr.write(`  - ${e}\n`);
    }
    process.exit(1);
  }

  // Generate
  const typesContent = generateTypes(manifest);
  const familyContent = generateFamily(manifest);

  if (pkgScaffold) {
    // Full consolidated-package scaffold. outDir is the package ROOT.
    const root = path.resolve(outDir!);
    const srcDir = path.join(root, "src");
    fs.mkdirSync(srcDir, { recursive: true });

    const envelopeVersion = readEnvelopeVersion();
    const written = [
      writeGuarded(path.join(srcDir, "types.ts"), typesContent, force),
      writeGuarded(path.join(srcDir, "family.ts"), familyContent, force),
      writeGuarded(
        path.join(root, "package.json"),
        generatePackageJson(manifest, envelopeVersion),
        force
      ),
      writeGuarded(path.join(root, "tsconfig.json"), TSCONFIG_JSON, force),
      writeGuarded(
        path.join(root, "tsconfig.build.json"),
        TSCONFIG_BUILD_JSON,
        force
      ),
    ];
    for (const p of written) process.stderr.write(`Generated: ${p}\n`);
    process.stderr.write("\n" + generateManualPatches(manifest));
    return;
  }

  if (!outDir) {
    // Print to stdout with markers
    process.stdout.write("// === FILE: types.ts ===\n");
    process.stdout.write(typesContent);
    process.stdout.write("\n// === FILE: family.ts ===\n");
    process.stdout.write(familyContent);
  } else {
    // Write to directory
    const resolvedDir = path.resolve(outDir);
    fs.mkdirSync(resolvedDir, { recursive: true });

    const typesPath = writeGuarded(
      path.join(resolvedDir, "types.ts"),
      typesContent,
      force
    );
    const familyPath = writeGuarded(
      path.join(resolvedDir, "family.ts"),
      familyContent,
      force
    );
    process.stderr.write(`Generated: ${typesPath}\n`);
    process.stderr.write(`Generated: ${familyPath}\n`);
  }
}

// Only run CLI when executed directly (not when imported for testing)
const isDirectRun =
  process.argv[1]?.endsWith("generate.ts") &&
  !process.argv[1]?.endsWith("generate.test.ts");
if (isDirectRun) {
  main();
}
