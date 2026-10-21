/**
 * anchors validate — Phase 1 schema-language CLI.
 *
 * Cross-checks .anchor.json manifests against:
 *  1. meta-schema.v1.json structural rules
 *  2. Internal consistency (id ∈ claim_types, event_type alignment, etc.)
 *  3. Cross-manifest uniqueness (chips, status_list_slots, acronyms)
 *  4. FAMILY-CONSISTENCY.md §1 (chip positions) and §4 (status list slots) — exact
 *  5. FAMILY-CONSISTENCY.md §2 (TSA mandate) + §3 (subject-presence) — manifest-level
 *     (coarse: OPTIONAL/non-OPTIONAL split, must-be-null/must-be-present/either)
 *     PLUS source-level (manifest ⟷ shipped `src/family.ts` drift)
 *  6. FAMILY-CONSISTENCY.md §5 (shared-package import rules) — package.json deps
 *  7. FAMILY-CONSISTENCY.md §6 (test-count floor) — actual `node --test` counts
 *  8. Manifest-roster coverage — every acronym in §1 MUST have a
 *     schema/families/*.anchor.json manifest, else §2/§3 manifest-checks can't run
 *
 * §5/§6/roster-coverage are filesystem + test-execution checks — they only run in
 * "validate all families" mode (no CLI args / >1 manifest), not the single-manifest
 * fast path used by `schema/generate.ts` step 2.
 *
 * Run:
 *   node --experimental-strip-types schema/validate.ts [path...]
 *   node --experimental-strip-types schema/validate.ts           # validates all families
 *
 * Exit code: 0 = all pass, 1 = errors found.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { execFileSync } from "node:child_process";

// ── Types ──────────────────────────────────────────────────────────────────

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

type Severity = "error" | "warn";

interface Finding {
  severity: Severity;
  file: string;
  message: string;
}

// ── Meta-schema constants ──────────────────────────────────────────────────

const CLAIM_TYPE_RE = /^ar\.[a-z_]+\.v[0-9]+$/;
const ACRONYM_RE = /^[A-Z][A-Za-z]{2,5}$/;

const VALID_FIELD_TYPES = [
  "string",
  "integer",
  "number",
  "boolean",
  "iso8601",
  "did",
  "uri",
  "sha256",
  "enum",
  "array",
  "object",
  "union",
];
const VALID_ENVELOPE = ["v1", "v2"];
const VALID_SIGN = ["ed25519"];
const VALID_CANONICALIZE = ["jcs"];
const VALID_SUBJECT_PRESENCE = ["must-be-present", "must-be-null", "either"];
const VALID_TSA_UPGRADE = ["free", "internal", "external"];
const VALID_TSA_MANDATE = ["mandatory", "recommended", "optional"];

const REQUIRED_KEYS: (keyof AnchorManifest)[] = [
  "id",
  "acronym",
  "name",
  "claim_types",
  "envelope",
  "chip",
  "subject_presence",
  "body",
];

const ALLOWED_TOP_KEYS = new Set([
  "$schema",
  "id",
  "acronym",
  "name",
  "claim_types",
  "envelope",
  "sign",
  "canonicalize",
  "chip",
  "status_list_slot",
  "subject_presence",
  "subject_presence_overrides",
  "tsa_upgrade_path",
  "tsa_mandate",
  "body",
  "event_types",
  "profiles",
  "compose",
  "continuity",
  "status_list",
  "suspension",
  "spec_path",
  "packages",
]);

// ── Helpers ────────────────────────────────────────────────────────────────

const SCHEMA_DIR = path.resolve(
  import.meta.dirname ?? path.dirname(new URL(import.meta.url).pathname)
);
const FAMILIES_DIR = path.join(SCHEMA_DIR, "families");
const ANCHORS_ROOT = path.join(SCHEMA_DIR, "..");
const CONSISTENCY_PATH = path.join(
  SCHEMA_DIR,
  "..",
  "meta",
  "FAMILY-CONSISTENCY.md"
);

/**
 * Families that ship real code but have no schema/families/*.anchor.json manifest
 * yet (APIIR/ACBR — build-to-ready, scaffolded before a manifest was authored).
 * Hardcoded ONLY so §5 (package-import) and §6 (test-floor) can still cover their
 * shipped packages via a filesystem-derived dir — there is no manifest to derive
 * `packages.verifier` from. `validateManifestCoverage` below flags the missing
 * manifest itself as a §7-checklist violation (ERROR). Delete an entry here once
 * its manifest lands in schema/families/ — deriveDir() takes over automatically.
 */
const MANIFESTLESS_FAMILIES: { acronym: string; dir: string }[] = [
  { acronym: "APIIR", dir: "redaction" },
  { acronym: "ACBR", dir: "compliance" },
];

interface DirInfo {
  acronym: string;
  dir: string;
  hasManifest: boolean;
}

/** `@dekimuhq/action` → `action`; `@dekimuhq/action/issue` → `action`. */
function deriveDir(verifierPkg: string | undefined): string | null {
  if (!verifierPkg) return null;
  const stripped = verifierPkg.replace(/^@dekimuhq\//, "");
  return stripped.split("/")[0] || null;
}

function buildDirInfos(
  entries: Array<{ file: string; manifest: AnchorManifest }>
): DirInfo[] {
  const out: DirInfo[] = [];
  const seen = new Set<string>();
  for (const { manifest: m } of entries) {
    const dir = deriveDir(m.packages?.verifier);
    if (!dir) continue; // no packages.verifier declared — nothing to fs-check yet
    out.push({ acronym: m.acronym, dir, hasManifest: true });
    seen.add(m.acronym);
  }
  for (const f of MANIFESTLESS_FAMILIES) {
    if (!seen.has(f.acronym)) out.push({ ...f, hasManifest: false });
  }
  return out;
}

function loadManifest(filePath: string): AnchorManifest {
  const raw = fs.readFileSync(filePath, "utf-8");
  return JSON.parse(raw) as AnchorManifest;
}

function loadAllManifests(): Array<{ file: string; manifest: AnchorManifest }> {
  const files = fs
    .readdirSync(FAMILIES_DIR)
    .filter((f) => f.endsWith(".anchor.json"))
    .sort();
  return files.map((f) => {
    const filePath = path.join(FAMILIES_DIR, f);
    return { file: f, manifest: loadManifest(filePath) };
  });
}

// ── §1 + §4 markdown table parsers ────────────────────────────────────────

interface ChipRow {
  chip: number;
  acronym: string;
}

interface StatusListRow {
  order: number;
  acronym: string;
}

function parseConsistencyTables(mdPath: string): {
  chipTable: ChipRow[];
  statusListTable: StatusListRow[];
} {
  const md = fs.readFileSync(mdPath, "utf-8");
  const chipTable: ChipRow[] = [];
  const statusListTable: StatusListRow[] = [];

  // Parse §1 chip-position table
  const section1Match = md.match(
    /## 1\. .*?chip-position.*?\n([\s\S]*?)(?=\n---|\n## [0-9])/
  );
  if (section1Match) {
    const lines = section1Match[1].split("\n");
    for (const line of lines) {
      // Match: | 1 | APR | ... |
      const m = line.match(/^\|\s*(\d+)\s*\|\s*([A-Z][A-Za-z]+)\s*\|/);
      if (m) {
        chipTable.push({ chip: parseInt(m[1], 10), acronym: m[2] });
      }
    }
  }

  // Parse §4 status-list consumer table
  const section4Match = md.match(
    /## 4\. .*?Status List.*?\n([\s\S]*?)(?=\nAPR currently|>\s*\*\*Audit|### 4\.1|\n---|\n## [0-9])/
  );
  if (section4Match) {
    const lines = section4Match[1].split("\n");
    for (const line of lines) {
      // Match: | 1 | ALR | ... |
      const m = line.match(/^\|\s*(\d+)\s*\|\s*([A-Z][A-Za-z]+)\s*\|/);
      if (m) {
        statusListTable.push({ order: parseInt(m[1], 10), acronym: m[2] });
      }
    }
  }

  return { chipTable, statusListTable };
}

// ── Validators ─────────────────────────────────────────────────────────────

function validateField(
  field: AnchorField,
  fieldPath: string,
  findings: Finding[],
  file: string
): void {
  if (!VALID_FIELD_TYPES.includes(field.type)) {
    findings.push({
      severity: "error",
      file,
      message: `${fieldPath}: unknown field type "${field.type}"`,
    });
  }

  if (
    field.type === "enum" &&
    (!field.enum_values || field.enum_values.length === 0)
  ) {
    findings.push({
      severity: "error",
      file,
      message: `${fieldPath}: type "enum" requires non-empty enum_values`,
    });
  }

  if (field.type === "array" && !field.items) {
    findings.push({
      severity: "error",
      file,
      message: `${fieldPath}: type "array" requires items`,
    });
  }

  if (field.type === "object" && field.fields) {
    for (const [k, v] of Object.entries(field.fields)) {
      validateField(v, `${fieldPath}.${k}`, findings, file);
    }
  }

  if (field.type === "array" && field.items) {
    validateField(field.items, `${fieldPath}[]`, findings, file);
  }

  if (
    field.type === "union" &&
    (!field.variants || field.variants.length === 0)
  ) {
    findings.push({
      severity: "error",
      file,
      message: `${fieldPath}: type "union" requires non-empty variants`,
    });
  }

  // Allowed keys on field objects
  const allowedFieldKeys = new Set([
    "type",
    "required",
    "nullable",
    "enum_values",
    "items",
    "fields",
    "variants",
    "description",
  ]);
  for (const key of Object.keys(field)) {
    if (!allowedFieldKeys.has(key)) {
      findings.push({
        severity: "error",
        file,
        message: `${fieldPath}: unknown field property "${key}"`,
      });
    }
  }
}

function validateSingleManifest(
  m: AnchorManifest,
  file: string,
  findings: Finding[]
): void {
  // Required keys
  for (const key of REQUIRED_KEYS) {
    if (m[key] === undefined || m[key] === null) {
      // status_list_slot can be null (APR)
      if (key === "status_list_slot") continue;
      findings.push({
        severity: "error",
        file,
        message: `missing required key "${key}"`,
      });
    }
  }

  // Unknown top-level keys
  for (const key of Object.keys(m)) {
    if (!ALLOWED_TOP_KEYS.has(key)) {
      findings.push({
        severity: "error",
        file,
        message: `unknown top-level key "${key}"`,
      });
    }
  }

  // id pattern
  if (m.id && !CLAIM_TYPE_RE.test(m.id)) {
    findings.push({
      severity: "error",
      file,
      message: `id "${m.id}" does not match ar.<noun>.v<N>`,
    });
  }

  // acronym pattern
  if (m.acronym && !ACRONYM_RE.test(m.acronym)) {
    findings.push({
      severity: "error",
      file,
      message: `acronym "${m.acronym}" does not match [A-Z][A-Za-z]{2,5}`,
    });
  }

  // name length
  if (m.name && m.name.length < 5) {
    findings.push({
      severity: "error",
      file,
      message: `name "${m.name}" is shorter than 5 chars`,
    });
  }

  // claim_types
  if (Array.isArray(m.claim_types)) {
    if (m.claim_types.length === 0) {
      findings.push({
        severity: "error",
        file,
        message: "claim_types must have at least 1 entry",
      });
    }
    for (const ct of m.claim_types) {
      if (!CLAIM_TYPE_RE.test(ct)) {
        findings.push({
          severity: "error",
          file,
          message: `claim_type "${ct}" does not match ar.<noun>.v<N>`,
        });
      }
    }
    // id must be in claim_types
    if (m.id && !m.claim_types.includes(m.id)) {
      findings.push({
        severity: "error",
        file,
        message: `id "${m.id}" is not in claim_types`,
      });
    }
    // uniqueness
    const cts = new Set<string>();
    for (const ct of m.claim_types) {
      if (cts.has(ct)) {
        findings.push({
          severity: "error",
          file,
          message: `duplicate claim_type "${ct}"`,
        });
      }
      cts.add(ct);
    }
  }

  // envelope
  if (m.envelope && !VALID_ENVELOPE.includes(m.envelope)) {
    findings.push({
      severity: "error",
      file,
      message: `envelope "${m.envelope}" not in [${VALID_ENVELOPE}]`,
    });
  }

  // §5 shared-envelope import: every member rides the v2 shared envelope
  // (@dekimuhq/anchors-envelope). APR is the sole sanctioned legacy v1 member;
  // any OTHER family declaring v1 has skipped the shared envelope. The
  // package-level import is linted separately by check-envelope-deps.mjs.
  if (m.envelope === "v1" && m.acronym !== "APR") {
    findings.push({
      severity: "warn",
      file,
      message: `envelope "v1" (legacy single-protocol) — only APR is grandfathered; ${m.acronym} should ride the v2 shared envelope per FAMILY-CONSISTENCY.md §5`,
    });
  }

  // sign
  if (m.sign !== undefined && !VALID_SIGN.includes(m.sign)) {
    findings.push({
      severity: "error",
      file,
      message: `sign "${m.sign}" not in [${VALID_SIGN}]`,
    });
  }

  // canonicalize
  if (
    m.canonicalize !== undefined &&
    !VALID_CANONICALIZE.includes(m.canonicalize)
  ) {
    findings.push({
      severity: "error",
      file,
      message: `canonicalize "${m.canonicalize}" not in [${VALID_CANONICALIZE}]`,
    });
  }

  // chip range
  if (m.chip !== undefined) {
    if (!Number.isInteger(m.chip) || m.chip < 1 || m.chip > 99) {
      findings.push({
        severity: "error",
        file,
        message: `chip ${m.chip} must be integer 1..99`,
      });
    }
  }

  // status_list_slot
  if (m.status_list_slot !== null && m.status_list_slot !== undefined) {
    if (!Number.isInteger(m.status_list_slot) || m.status_list_slot < 1) {
      findings.push({
        severity: "error",
        file,
        message: `status_list_slot ${m.status_list_slot} must be integer >= 1 or null`,
      });
    }
  }

  // subject_presence
  if (
    m.subject_presence &&
    !VALID_SUBJECT_PRESENCE.includes(m.subject_presence)
  ) {
    findings.push({
      severity: "error",
      file,
      message: `subject_presence "${m.subject_presence}" not in [${VALID_SUBJECT_PRESENCE}]`,
    });
  }

  // subject_presence_overrides
  if (m.subject_presence_overrides) {
    const eventTypesSet = new Set(m.event_types ?? []);
    for (const ov of m.subject_presence_overrides) {
      if (!VALID_SUBJECT_PRESENCE.includes(ov.subject_presence)) {
        findings.push({
          severity: "error",
          file,
          message: `subject_presence_override for "${ov.event_type}": invalid presence "${ov.subject_presence}"`,
        });
      }
      if (eventTypesSet.size > 0 && !eventTypesSet.has(ov.event_type)) {
        findings.push({
          severity: "warn",
          file,
          message: `subject_presence_override event_type "${ov.event_type}" not in event_types`,
        });
      }
    }
  }

  // tsa_upgrade_path
  if (
    m.tsa_upgrade_path !== undefined &&
    !VALID_TSA_UPGRADE.includes(m.tsa_upgrade_path)
  ) {
    findings.push({
      severity: "error",
      file,
      message: `tsa_upgrade_path "${m.tsa_upgrade_path}" not in [${VALID_TSA_UPGRADE}]`,
    });
  }

  // tsa_mandate values
  if (m.tsa_mandate) {
    for (const [k, v] of Object.entries(m.tsa_mandate)) {
      if (!VALID_TSA_MANDATE.includes(v)) {
        findings.push({
          severity: "error",
          file,
          message: `tsa_mandate["${k}"] = "${v}" not in [${VALID_TSA_MANDATE}]`,
        });
      }
    }
  }

  // body fields
  if (m.body && typeof m.body === "object") {
    for (const [k, v] of Object.entries(m.body)) {
      validateField(v, `body.${k}`, findings, file);
    }
  }

  // event_types vs body.event_type.enum_values
  if (m.event_types && m.body?.event_type?.enum_values) {
    const bodyEvents = new Set(m.body.event_type.enum_values);
    const manifestEvents = new Set(m.event_types);

    for (const e of m.event_types) {
      if (!bodyEvents.has(e)) {
        findings.push({
          severity: "error",
          file,
          message: `event_type "${e}" declared in event_types but missing from body.event_type.enum_values`,
        });
      }
    }
    for (const e of m.body.event_type.enum_values) {
      if (!manifestEvents.has(e)) {
        findings.push({
          severity: "error",
          file,
          message: `body.event_type.enum_values contains "${e}" but it's not in event_types`,
        });
      }
    }
  }

  // profiles vs body.profile.enum_values
  if (m.profiles && m.profiles.length > 0 && m.body?.profile?.enum_values) {
    const bodyProfiles = new Set(m.body.profile.enum_values);
    const manifestProfiles = new Set(m.profiles.map((p) => p.id));

    for (const p of m.profiles) {
      if (!bodyProfiles.has(p.id)) {
        findings.push({
          severity: "error",
          file,
          message: `profile "${p.id}" declared in profiles[] but missing from body.profile.enum_values`,
        });
      }
    }
    for (const id of m.body.profile.enum_values) {
      if (!manifestProfiles.has(id)) {
        findings.push({
          severity: "warn",
          file,
          message: `body.profile.enum_values contains "${id}" but no matching profiles[] entry`,
        });
      }
    }
  }

  // compose.links_to must be valid claim_type format
  if (m.compose?.links_to) {
    for (const link of m.compose.links_to) {
      if (!CLAIM_TYPE_RE.test(link)) {
        findings.push({
          severity: "error",
          file,
          message: `compose.links_to "${link}" does not match ar.<noun>.v<N>`,
        });
      }
    }
  }

  // status_list: false should pair with status_list_slot: null
  if (
    m.status_list === false &&
    m.status_list_slot !== null &&
    m.status_list_slot !== undefined
  ) {
    findings.push({
      severity: "warn",
      file,
      message: `status_list is false but status_list_slot is ${m.status_list_slot} (expected null)`,
    });
  }
  if (m.status_list === true && m.status_list_slot === null) {
    findings.push({
      severity: "warn",
      file,
      message: "status_list is true but status_list_slot is null",
    });
  }

  // packages.verifier should be the merged family package @dekimuhq/<acronym-lower>
  // (legacy split @dekimuhq/<acronym-lower>-verifier still accepted for families not
  // yet merged). The wire-noun slug @dekimuhq/<noun> (from ar.<noun>.v1) is also
  // accepted — used when the acronym and the wire noun diverge (e.g. AActR →
  // @dekimuhq/action, where naming after the locked wire format reads cleaner than
  // the display acronym).
  if (m.packages?.verifier && m.acronym) {
    const merged = `@dekimuhq/${m.acronym.toLowerCase()}`;
    const legacy = `${merged}-verifier`;
    const noun = typeof m.id === "string" ? m.id.split(".")[1] : undefined;
    const slug = noun ? `@dekimuhq/${noun}` : undefined;
    if (
      m.packages.verifier !== merged &&
      m.packages.verifier !== legacy &&
      m.packages.verifier !== slug
    ) {
      findings.push({
        severity: "warn",
        file,
        message: `packages.verifier "${
          m.packages.verifier
        }" — expected "${merged}" (or legacy "${legacy}", or wire-noun slug "${
          slug ?? "n/a"
        }")`,
      });
    }
  }
}

function validateCrossManifest(
  entries: Array<{ file: string; manifest: AnchorManifest }>,
  findings: Finding[]
): void {
  const chips = new Map<number, string>();
  const slots = new Map<number, string>();
  const acronyms = new Map<string, string>();
  const ids = new Map<string, string>();

  for (const { file, manifest: m } of entries) {
    // Chip uniqueness
    if (chips.has(m.chip)) {
      findings.push({
        severity: "error",
        file,
        message: `chip ${m.chip} already claimed by ${chips.get(m.chip)}`,
      });
    } else {
      chips.set(m.chip, file);
    }

    // Status list slot uniqueness (null excluded)
    if (m.status_list_slot !== null && m.status_list_slot !== undefined) {
      if (slots.has(m.status_list_slot)) {
        findings.push({
          severity: "error",
          file,
          message: `status_list_slot ${
            m.status_list_slot
          } already claimed by ${slots.get(m.status_list_slot)}`,
        });
      } else {
        slots.set(m.status_list_slot, file);
      }
    }

    // Acronym uniqueness
    if (acronyms.has(m.acronym)) {
      findings.push({
        severity: "error",
        file,
        message: `acronym "${m.acronym}" already claimed by ${acronyms.get(
          m.acronym
        )}`,
      });
    } else {
      acronyms.set(m.acronym, file);
    }

    // ID uniqueness
    if (ids.has(m.id)) {
      findings.push({
        severity: "error",
        file,
        message: `id "${m.id}" already claimed by ${ids.get(m.id)}`,
      });
    } else {
      ids.set(m.id, file);
    }

    // Cross-manifest compose.links_to must reference a known family id
    if (m.compose?.links_to) {
      const allIds = new Set(entries.map((e) => e.manifest.id));
      for (const link of m.compose.links_to) {
        if (!allIds.has(link)) {
          findings.push({
            severity: "warn",
            file,
            message: `compose.links_to "${link}" does not match any loaded manifest id`,
          });
        }
      }
    }
  }
}

function validateAgainstConsistencyTables(
  entries: Array<{ file: string; manifest: AnchorManifest }>,
  chipTable: ChipRow[],
  statusListTable: StatusListRow[],
  findings: Finding[]
): void {
  // Build lookup from consistency tables
  const chipByAcronym = new Map(chipTable.map((r) => [r.acronym, r.chip]));
  const slotByAcronym = new Map(
    statusListTable.map((r) => [r.acronym, r.order])
  );

  for (const { file, manifest: m } of entries) {
    // §1 chip check
    const expectedChip = chipByAcronym.get(m.acronym);
    if (expectedChip === undefined) {
      findings.push({
        severity: "warn",
        file,
        message: `acronym "${m.acronym}" not found in FAMILY-CONSISTENCY.md §1 chip table`,
      });
    } else if (expectedChip !== m.chip) {
      findings.push({
        severity: "error",
        file,
        message: `chip ${m.chip} does not match FAMILY-CONSISTENCY.md §1 (expected ${expectedChip} for ${m.acronym})`,
      });
    }

    // §4 status list check
    const expectedSlot = slotByAcronym.get(m.acronym);
    if (m.status_list_slot === null || m.status_list_slot === undefined) {
      // Should NOT appear in the status list table (e.g. APR)
      if (expectedSlot !== undefined) {
        findings.push({
          severity: "warn",
          file,
          message: `status_list_slot is null but ${m.acronym} appears in FAMILY-CONSISTENCY.md §4 at position ${expectedSlot}`,
        });
      }
    } else if (expectedSlot === undefined) {
      findings.push({
        severity: "warn",
        file,
        message: `${m.acronym} has status_list_slot ${m.status_list_slot} but is not in FAMILY-CONSISTENCY.md §4`,
      });
    } else if (expectedSlot !== m.status_list_slot) {
      findings.push({
        severity: "error",
        file,
        message: `status_list_slot ${m.status_list_slot} does not match FAMILY-CONSISTENCY.md §4 (expected ${expectedSlot} for ${m.acronym})`,
      });
    }
  }
}

// ── §2 + §3 matrix cross-checks ────────────────────────────────────────────
//
// These replace a per-release manual audit for the
// two matrices that ARE deterministically derivable from manifest fields:
//   §2 TSA mandate      ← manifest.tsa_mandate (mandate levels per event)
//   §3 Subject presence ← manifest.subject_presence (+ overrides)
// (§5 shared-envelope import is checked inline in validateSingleManifest via the
//  manifest.envelope field; the package-level import is linted by check-envelope-deps.mjs.)
//
// The matrices carry prose qualifiers (profile names, per-event exceptions) that
// don't map mechanically, so each check asserts ONLY where the table gives an
// unambiguous signal and warns (never errors) where the row is hedged or absent.

interface FamilyRow {
  family: string;
  event: string;
  col3: string; // mandate (§2) | subject value (§3)
  col4: string; // rationale
}

/**
 * Extract the rows of the `| Family | Event | … |` table inside section `## N.`
 * of FAMILY-CONSISTENCY.md. Anchors on the column header so the preceding
 * "Mandate levels" legend sub-table in §2 is skipped.
 */
function extractFamilyRows(md: string, sectionNum: number): FamilyRow[] {
  const sectionRe = new RegExp(
    `## ${sectionNum}\\. [\\s\\S]*?(?=\\n## [0-9]|$)`
  );
  const section = md.match(sectionRe)?.[0];
  if (!section) return [];

  const rows: FamilyRow[] = [];
  const lines = section.split("\n");
  let inFamilyTable = false;

  for (const line of lines) {
    if (/^\|\s*Family\s*\|\s*Event\s*\|/i.test(line)) {
      inFamilyTable = true;
      continue;
    }
    if (!inFamilyTable) continue;
    if (!line.trim().startsWith("|")) {
      inFamilyTable = false; // table ended
      continue;
    }
    if (/^\|\s*-+\s*\|/.test(line)) continue; // separator row
    const cells = line
      .split("|")
      .slice(1, -1)
      .map((c) => c.trim());
    if (cells.length < 3) continue;
    if (!/^[A-Z][A-Za-z]*$/.test(cells[0])) continue; // family acronym only
    rows.push({
      family: cells[0],
      event: cells[1],
      col3: cells[2],
      col4: cells[3] ?? "",
    });
  }
  return rows;
}

/** §2 → per-family { allOptional }. */
function classifyTsaMatrix(
  rows: FamilyRow[]
): Map<string, { allOptional: boolean }> {
  const out = new Map<string, { allOptional: boolean }>();
  for (const r of rows) {
    const level = /MANDATORY/i.test(r.col3)
      ? "mandatory"
      : /RECOMMENDED/i.test(r.col3)
      ? "recommended"
      : "optional";
    const prev = out.get(r.family) ?? { allOptional: true };
    out.set(r.family, {
      allOptional: prev.allOptional && level === "optional",
    });
  }
  return out;
}

type ExpectedPresence = "must-be-null" | "must-be-present" | "either";

/** §3 → per-family expected `subject_presence`. */
function classifySubjectMatrix(
  rows: FamilyRow[]
): Map<string, ExpectedPresence> {
  const acc = new Map<string, { nullSeen: boolean; presentSeen: boolean }>();
  for (const r of rows) {
    let nullSeen = /\bnull\b/.test(r.col3);
    let presentSeen = /sha256|free-form/.test(r.col3);
    // hedges that flip a single-value cell into a per-event split:
    //   §3 ANR "… OR `null` for …" (lives in the value cell, caught above)
    //   §3 AIR "… EXCEPT … MAY appear" (the exception lives in the rationale)
    if (/EXCEPT[\s\S]*?(MAY|sha256)/i.test(r.col4)) presentSeen = true;
    if (/\bOR\b\s*`?null`?/i.test(r.col3)) nullSeen = true;

    const prev = acc.get(r.family) ?? { nullSeen: false, presentSeen: false };
    acc.set(r.family, {
      nullSeen: prev.nullSeen || nullSeen,
      presentSeen: prev.presentSeen || presentSeen,
    });
  }

  const out = new Map<string, ExpectedPresence>();
  for (const [family, { nullSeen, presentSeen }] of acc) {
    if (nullSeen && presentSeen) out.set(family, "either");
    else if (nullSeen) out.set(family, "must-be-null");
    else if (presentSeen) out.set(family, "must-be-present");
    // neither → indeterminate; omitted (validator warns it's not classifiable)
  }
  return out;
}

function validateAgainstTsaMatrix(
  entries: Array<{ file: string; manifest: AnchorManifest }>,
  tsaByFamily: Map<string, { allOptional: boolean }>,
  findings: Finding[]
): void {
  for (const { file, manifest: m } of entries) {
    const row = tsaByFamily.get(m.acronym);
    if (!row) {
      findings.push({
        severity: "warn",
        file,
        message: `acronym "${m.acronym}" not found in FAMILY-CONSISTENCY.md §2 TSA mandate matrix`,
      });
      continue;
    }
    const levels = Object.values(m.tsa_mandate ?? {});
    const hasNonOptional = levels.some((v) => v !== "optional");
    if (row.allOptional && hasNonOptional) {
      findings.push({
        severity: "error",
        file,
        message: `tsa_mandate declares a non-optional level but FAMILY-CONSISTENCY.md §2 lists ${m.acronym} as OPTIONAL on every event`,
      });
    } else if (!row.allOptional && !hasNonOptional) {
      findings.push({
        severity: "warn",
        file,
        message: `FAMILY-CONSISTENCY.md §2 lists a MANDATORY/RECOMMENDED event for ${m.acronym}, but tsa_mandate has no non-optional entry`,
      });
    }
  }
}

function validateAgainstSubjectMatrix(
  entries: Array<{ file: string; manifest: AnchorManifest }>,
  presenceByFamily: Map<string, ExpectedPresence>,
  findings: Finding[]
): void {
  for (const { file, manifest: m } of entries) {
    const expected = presenceByFamily.get(m.acronym);
    if (expected === undefined) {
      findings.push({
        severity: "warn",
        file,
        message: `acronym "${m.acronym}" not classifiable from FAMILY-CONSISTENCY.md §3 subject-presence matrix`,
      });
      continue;
    }
    if (m.subject_presence !== expected) {
      findings.push({
        severity: "error",
        file,
        message: `subject_presence "${m.subject_presence}" does not match FAMILY-CONSISTENCY.md §3 (expected "${expected}" for ${m.acronym})`,
      });
    }
  }
}

// ── §2/§3 source-level cross-check (manifest ⟷ shipped src/family.ts) ──────
//
// The manifest-vs-table checks above only see the DECLARATIVE `.anchor.json`
// manifest. Every consolidated family package also carries a `src/family.ts`
// that passes the same two fields (`subject_presence`, `tsa_mandate`) into
// `defineFamily()` — the ACTUAL shipped runtime configuration. The two can
// drift independently (someone edits one and forgets the other). This section
// closes that gap by reading the real source, not just the manifest.

/** Balance-scans from the first "{" after `<key>:` to its matching "}". */
function extractBalancedBlock(src: string, key: string): string | null {
  const keyRe = new RegExp(`\\b${key}\\s*:\\s*\\{`);
  const m = keyRe.exec(src);
  if (!m) return null;
  let depth = 0;
  let start = -1;
  for (let i = m.index; i < src.length; i++) {
    if (src[i] === "{") {
      if (depth === 0) start = i;
      depth++;
    } else if (src[i] === "}") {
      depth--;
      if (depth === 0) return src.slice(start, i + 1);
    }
  }
  return null;
}

function validateFamilySourceConsistency(
  entries: Array<{ file: string; manifest: AnchorManifest }>,
  findings: Finding[]
): void {
  for (const { file, manifest: m } of entries) {
    const dir = deriveDir(m.packages?.verifier);
    if (!dir) continue;
    const familyTsPath = path.join(ANCHORS_ROOT, dir, dir, "src", "family.ts");
    if (!fs.existsSync(familyTsPath)) continue; // not yet scaffolded — nothing to cross-check
    const src = fs.readFileSync(familyTsPath, "utf-8");

    // §3: subject_presence literal must match the manifest field.
    const spMatch = src.match(
      /subject_presence:\s*"(must-be-null|must-be-present|either)"/
    );
    if (spMatch && m.subject_presence && spMatch[1] !== m.subject_presence) {
      findings.push({
        severity: "error",
        file,
        message: `${dir}/${dir}/src/family.ts declares subject_presence "${spMatch[1]}" but the manifest declares "${m.subject_presence}" — manifest and shipped family.ts have drifted`,
      });
    }

    // §2: coarse tsa_mandate consistency, same OPTIONAL/non-OPTIONAL split as
    // validateAgainstTsaMatrix but sourced from the shipped object literal
    // instead of the manifest. Only the unambiguous direction is asserted —
    // several families (e.g. ASR) intentionally OMIT tsa_mandate from
    // family.ts because their §2 row is event-keyed, not profile-keyed, and
    // is enforced elsewhere (see asr/asr/src/family.ts's own comment) — so a
    // missing/all-optional block here is never flagged as an error, only the
    // reverse (a non-optional value present while the manifest is all-optional).
    const block = extractBalancedBlock(src, "tsa_mandate");
    if (block) {
      const values = [
        ...block.matchAll(/:\s*"(optional|recommended|mandatory)"/g),
      ].map((x) => x[1]);
      const hasNonOptional = values.some((v) => v !== "optional");
      const manifestLevels = Object.values(m.tsa_mandate ?? {});
      const manifestAllOptional =
        manifestLevels.length > 0 &&
        manifestLevels.every((v) => v === "optional");
      if (manifestAllOptional && hasNonOptional) {
        findings.push({
          severity: "error",
          file,
          message: `${dir}/${dir}/src/family.ts's tsa_mandate block declares a non-optional level but the manifest's tsa_mandate is all-optional — manifest and shipped family.ts have drifted`,
        });
      }
    }
  }
}

// ── §5 shared-package import rules ──────────────────────────────────────────

interface PackageImportRule {
  pkg: string;
  /** True only for the exact "Every member's verifier + issuer-kit" phrasing (row 1,
   *  @dekimuhq/anchors-envelope). Rows 2/3 (did-web-resolver, trusted-issuers) also
   *  contain "Every member" but immediately qualify it ("...that accepts...",
   *  "...whose default trust dispatch...") — deliberately excluded so this stays
   *  conservative (no false positives on the 3 genuinely-conditional packages). */
  universal: boolean;
  /** Family this package is a documented REQUIRED exception for (e.g. AgTR ← disclosure). */
  exceptionFamily?: string;
}

function parsePackageImportRules(md: string): PackageImportRule[] {
  const section = md.match(/## 5\. [\s\S]*?(?=\n## [0-9]|$)/)?.[0];
  if (!section) return [];
  const rules: PackageImportRule[] = [];
  let inTable = false;
  for (const line of section.split("\n")) {
    if (/^\|\s*Package\s*\|/i.test(line)) {
      inTable = true;
      continue;
    }
    if (!inTable) continue;
    if (!line.trim().startsWith("|")) {
      inTable = false;
      continue;
    }
    if (/^\|\s*-+\s*\|/.test(line)) continue;
    const cells = line
      .split("|")
      .slice(1, -1)
      .map((c) => c.trim());
    if (cells.length < 3) continue;
    const pkgMatch = cells[0].match(/`(@dekimuhq\/[a-z0-9-]+)`/);
    if (!pkgMatch) continue;
    const requiredFor = cells[2];
    const universal = /Every member's verifier \+ issuer-kit/i.test(
      requiredFor
    );
    const exceptionMatch = requiredFor.match(
      /Exception:.*?\(([A-Za-z]+)\)[\s\S]*?REQUIRED import/i
    );
    rules.push({
      pkg: pkgMatch[1],
      universal,
      exceptionFamily: exceptionMatch?.[1],
    });
  }
  return rules;
}

function validatePackageImports(
  dirInfos: DirInfo[],
  rules: PackageImportRule[],
  findings: Finding[]
): void {
  for (const { acronym, dir } of dirInfos) {
    const pkgJsonPath = path.join(ANCHORS_ROOT, dir, dir, "package.json");
    if (!fs.existsSync(pkgJsonPath)) {
      findings.push({
        severity: "warn",
        file: `${dir}/${dir}/package.json`,
        message: `expected consolidated package.json not found for ${acronym} — §5 import rules not checked`,
      });
      continue;
    }
    const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, "utf-8")) as {
      dependencies?: Record<string, string>;
      peerDependencies?: Record<string, string>;
    };
    const deps = {
      ...(pkg.dependencies ?? {}),
      ...(pkg.peerDependencies ?? {}),
    };
    for (const rule of rules) {
      if (rule.universal && !deps[rule.pkg]) {
        findings.push({
          severity: "error",
          file: `${dir}/${dir}/package.json`,
          message: `missing mandatory dependency "${rule.pkg}" — FAMILY-CONSISTENCY.md §5 requires it for every family member's verifier+issuer-kit`,
        });
      }
      if (rule.exceptionFamily === acronym && !deps[rule.pkg]) {
        findings.push({
          severity: "error",
          file: `${dir}/${dir}/package.json`,
          message: `missing "${rule.pkg}" — FAMILY-CONSISTENCY.md §5 documents this as a REQUIRED import specifically for ${acronym}`,
        });
      }
    }
  }
}

// ── §6 engineering-budget / test-count floor ────────────────────────────────

interface BudgetRow {
  acronym: string;
  status: string;
  testsPromised: number | null;
}

function parseBudgetTable(md: string): Map<string, BudgetRow> {
  const out = new Map<string, BudgetRow>();
  const section = md.match(/## 6\. [\s\S]*?(?=\n## [0-9]|$)/)?.[0];
  if (!section) return out;
  let inTable = false;
  for (const line of section.split("\n")) {
    if (/^\|\s*Family\s*\|\s*Status\s*\|/i.test(line)) {
      inTable = true;
      continue;
    }
    if (!inTable) continue;
    if (!line.trim().startsWith("|")) {
      inTable = false;
      continue;
    }
    if (/^\|\s*-+\s*\|/.test(line)) continue;
    const cells = line
      .split("|")
      .slice(1, -1)
      .map((c) => c.trim());
    if (cells.length < 3) continue;
    const famMatch = cells[0].match(/^([A-Za-z]+)/);
    if (!famMatch) continue;
    const acronym = famMatch[1];
    // AgTR has 2 rows (v1 flat + v2 span-tree); keep the first (base) row — the
    // v2 row's tests live in the same trace/trace-profiles/trace-otel dirs.
    if (out.has(acronym)) continue;
    const testsMatch = cells[2].match(/^(\d+)/);
    out.set(acronym, {
      acronym,
      status: cells[1],
      testsPromised: testsMatch ? parseInt(testsMatch[1], 10) : null,
    });
  }
  return out;
}

function parseTestFloorAndExemptions(md: string): {
  floor: number;
  exempt: Set<string>;
} {
  const gateMatch = md.match(
    /Family-wide test gate:\*\*\s*≥(\d+) tests per family member\s*—\s*\*\*except ([A-Za-z]+)\*\*/
  );
  const floor = gateMatch ? parseInt(gateMatch[1], 10) : 99;
  const exempt = new Set<string>(gateMatch ? [gateMatch[2]] : []);
  // Additional documented mini-exemptions use the "**<ACRONYM> test-floor note
  // (RESOLVED ...)**" callout convention (e.g. APIIR, 2026-06-21).
  for (const m of md.matchAll(
    /\*\*([A-Z][A-Za-z]*) test-floor note[^\n]*RESOLVED/g
  )) {
    exempt.add(m[1]);
  }
  return { floor, exempt };
}

function findTestablePackageDirs(familyDir: string): string[] {
  const famPath = path.join(ANCHORS_ROOT, familyDir);
  if (!fs.existsSync(famPath)) return [];
  return fs
    .readdirSync(famPath)
    .map((name) => path.join(famPath, name))
    .filter((p) => {
      try {
        return (
          fs.statSync(p).isDirectory() &&
          fs.existsSync(path.join(p, "package.json"))
        );
      } catch {
        return false;
      }
    });
}

/** Runs the package's own `npm test` and parses the `node --test` TAP summary.
 *  Uses execFileSync (argv array, no shell) — never a shell-interpolated string;
 *  pkgDir is always a path we derived from our own filesystem listing, never
 *  external input. */
function countTestsInPackage(pkgDir: string): number | null {
  let output = "";
  try {
    output = execFileSync("npm", ["test", "--silent"], {
      cwd: pkgDir,
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 120_000,
    });
  } catch (e) {
    // node --test exits non-zero on any failing test — the TAP summary is still
    // on stdout, and a "registrations vs floor" count cares about that count,
    // not pass/fail (pass/fail is `npm test`'s job, a separate CI step).
    output = (e as { stdout?: string }).stdout ?? "";
  }
  // Node <24.18 emits the TAP summary ("# tests N"); ≥24.18's default spec
  // reporter emits "ℹ tests N" even when piped. Accept both.
  const m = output.match(/^(?:# tests|ℹ tests) (\d+)/m);
  return m ? parseInt(m[1], 10) : null;
}

function validateTestFloors(
  dirInfos: DirInfo[],
  budgetByAcronym: Map<string, BudgetRow>,
  floor: number,
  exempt: Set<string>,
  findings: Finding[]
): void {
  for (const { acronym, dir } of dirInfos) {
    const row = budgetByAcronym.get(acronym);
    if (!row) {
      findings.push({
        severity: "error",
        file: `${dir}/`,
        message: `"${acronym}" has no row in FAMILY-CONSISTENCY.md §6 engineering budget table`,
      });
      continue;
    }
    const pkgDirs = findTestablePackageDirs(dir);
    if (pkgDirs.length === 0) {
      findings.push({
        severity: "warn",
        file: `${dir}/`,
        message: `no testable sub-package found under ${dir}/ — §6 test-count not verified for ${acronym}`,
      });
      continue;
    }
    let total = 0;
    let anyUnknown = false;
    for (const p of pkgDirs) {
      const c = countTestsInPackage(p);
      if (c === null) anyUnknown = true;
      else total += c;
    }
    if (anyUnknown) {
      findings.push({
        severity: "warn",
        file: `${dir}/`,
        message: `${acronym}: at least one sub-package produced no parseable "# tests N" summary — ${total}+ is a partial lower bound`,
      });
    }
    if (total < floor && !exempt.has(acronym)) {
      findings.push({
        severity: "error",
        file: `${dir}/`,
        message: `${acronym} has ${total} actual tests across ${pkgDirs.length} package(s) — below the §6 floor of ${floor} ("Family-wide test gate", FAMILY-CONSISTENCY.md)`,
      });
    } else if (row.testsPromised !== null && total !== row.testsPromised) {
      findings.push({
        severity: "warn",
        file: `${dir}/`,
        message: `${acronym} actual test count ${total} != §6 "Tests promised" ${
          row.testsPromised
        } — table is stale (doc-drift only${
          exempt.has(acronym)
            ? ""
            : `; ${total} still clears the ≥${floor} floor`
        })`,
      });
    }
  }
}

// ── Manifest-roster coverage (every §1 acronym must have a manifest) ───────

function validateManifestCoverage(
  chipTable: ChipRow[],
  manifestAcronyms: Set<string>,
  findings: Finding[]
): void {
  for (const row of chipTable) {
    if (!manifestAcronyms.has(row.acronym)) {
      findings.push({
        severity: "error",
        file: "schema/families/",
        message: `family "${row.acronym}" (FAMILY-CONSISTENCY.md §1 chip ${row.chip}) has no schema/families/*.anchor.json manifest — §2/§3 manifest-level cross-checks cannot run for it (§5/§6 filesystem checks still run via MANIFESTLESS_FAMILIES fallback). Author the manifest with \`npm run generate\` (generate-first rule) to close this gap.`,
      });
    }
  }
}

// ── Reporter ───────────────────────────────────────────────────────────────

function report(findings: Finding[]): void {
  const errors = findings.filter((f) => f.severity === "error");
  const warnings = findings.filter((f) => f.severity === "warn");

  if (errors.length > 0) {
    console.error(`\n❌ ${errors.length} error(s):\n`);
    for (const f of errors) {
      console.error(`  ERROR  ${f.file}: ${f.message}`);
    }
  }

  if (warnings.length > 0) {
    console.error(`\n⚠️  ${warnings.length} warning(s):\n`);
    for (const w of warnings) {
      console.error(`  WARN   ${w.file}: ${w.message}`);
    }
  }

  if (errors.length === 0 && warnings.length === 0) {
    console.log("✅ All manifests valid. No errors, no warnings.");
  } else if (errors.length === 0) {
    console.log(`\n✅ No errors. ${warnings.length} warning(s).`);
  }
}

// ── Main ───────────────────────────────────────────────────────────────────

function main(): void {
  const args = process.argv.slice(2);
  const findings: Finding[] = [];

  let entries: Array<{ file: string; manifest: AnchorManifest }>;

  if (args.length > 0) {
    // Validate specific files
    entries = args.map((arg) => {
      const filePath = path.resolve(arg);
      const file = path.basename(filePath);
      return { file, manifest: loadManifest(filePath) };
    });
  } else {
    // Validate all families
    entries = loadAllManifests();
  }

  console.log(`Validating ${entries.length} manifest(s)...\n`);

  // 1. Per-manifest structural + internal consistency
  for (const entry of entries) {
    validateSingleManifest(entry.manifest, entry.file, findings);
  }

  // 2. Cross-manifest uniqueness
  if (entries.length > 1) {
    validateCrossManifest(entries, findings);
  }

  // 3. Cross-check against FAMILY-CONSISTENCY.md
  if (fs.existsSync(CONSISTENCY_PATH)) {
    const { chipTable, statusListTable } =
      parseConsistencyTables(CONSISTENCY_PATH);

    if (chipTable.length > 0 || statusListTable.length > 0) {
      console.log(
        `Cross-checking against FAMILY-CONSISTENCY.md (${chipTable.length} chip rows, ${statusListTable.length} status-list rows)\n`
      );
      validateAgainstConsistencyTables(
        entries,
        chipTable,
        statusListTable,
        findings
      );
    } else {
      console.error(
        "WARN: Could not parse any tables from FAMILY-CONSISTENCY.md\n"
      );
    }

    // §2 TSA mandate + §3 subject-presence matrices (manifest-derivable)
    const md = fs.readFileSync(CONSISTENCY_PATH, "utf-8");
    const tsaByFamily = classifyTsaMatrix(extractFamilyRows(md, 2));
    const presenceByFamily = classifySubjectMatrix(extractFamilyRows(md, 3));
    if (tsaByFamily.size > 0 || presenceByFamily.size > 0) {
      console.log(
        `Cross-checking §2/§3 matrices (${tsaByFamily.size} TSA rows, ${presenceByFamily.size} subject-presence rows)\n`
      );
      validateAgainstTsaMatrix(entries, tsaByFamily, findings);
      validateAgainstSubjectMatrix(entries, presenceByFamily, findings);
    }

    // §2/§3 source-level (manifest ⟷ shipped src/family.ts) — cheap fs+regex,
    // runs at any scope (single-manifest or full sweep).
    validateFamilySourceConsistency(entries, findings);

    // §5 package-import rules + §6 test-count floors + manifest-roster coverage.
    // Filesystem + test-execution checks — only in "validate all families" mode
    // (matches the validateCrossManifest gate below §2), so the single-manifest
    // fast path (schema/generate.ts step 2) stays cheap and doesn't need every
    // OTHER family's test suite to exist/pass.
    if (entries.length > 1) {
      const manifestAcronyms = new Set(entries.map((e) => e.manifest.acronym));
      validateManifestCoverage(chipTable, manifestAcronyms, findings);

      const dirInfos = buildDirInfos(entries);
      const importRules = parsePackageImportRules(md);
      validatePackageImports(dirInfos, importRules, findings);

      // §6 actually runs every family's `npm test` (~90s for 21 families) — skip
      // in fast unit-test iteration via ANCHORS_VALIDATE_SKIP_TEST_COUNTS=1. Full
      // `npm run validate` (CI, no env override) always runs it for real.
      if (process.env.ANCHORS_VALIDATE_SKIP_TEST_COUNTS) {
        console.log(
          "§6 test-count floors SKIPPED (ANCHORS_VALIDATE_SKIP_TEST_COUNTS set)\n"
        );
      } else {
        const budgetByAcronym = parseBudgetTable(md);
        const { floor, exempt } = parseTestFloorAndExemptions(md);
        console.log(
          `Cross-checking §5 imports (${importRules.length} rules) + §6 test floors (≥${floor}, ${dirInfos.length} families — running each family's test suite, this takes a bit)\n`
        );
        validateTestFloors(dirInfos, budgetByAcronym, floor, exempt, findings);
      }
    }
  } else {
    console.error(
      `WARN: ${CONSISTENCY_PATH} not found — skipping cross-doc checks\n`
    );
  }

  // Report
  report(findings);

  const errorCount = findings.filter((f) => f.severity === "error").length;
  process.exit(errorCount > 0 ? 1 : 0);
}

main();
