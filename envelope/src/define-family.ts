/**
 * defineFamily() — declarative family-member factory (Phase A.1).
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/envelope
 *
 * Scope of Phase A.1 (this file): manifest type + factory function. No family
 * adopts yet. Surface intentionally minimal — covers what the envelope layer
 * already owns:
 *
 *   - identity + locked cross-family invariants (meta)
 *   - body validation via a consumer-supplied validator (Zod-shaped duck-type)
 *   - claim_type ownership lookup
 *   - subject-presence rule from FAMILY-CONSISTENCY §3
 *   - profile-validator registry (paired with `dispatchProfiles`)
 *   - optional composition helpers (walkParents)
 *
 * Phase A.2 (ALR canary) will add the per-family verifier/mint surfaces.
 * Phase B.1 (ANR onward) authors new families through this factory from day one.
 */

import { CLAIM_TYPES, type ClaimType } from "./envelope-types.ts";
import type { ProfileValidator } from "./profile/types.ts";
import {
  generateKeypair,
  signCanonical,
  type Keypair,
} from "./ed25519.ts";
import {
  buildVerifyReceipt,
  type FamilyVerifyOptions,
  type FamilyVerifyResult,
} from "./family-verify-pipeline.ts";
import {
  buildMintV2,
  type FamilyMintV2Input,
} from "./family-mint-pipeline.ts";
import type { Envelope } from "./envelope-types.ts";
import {
  issueContinuityAttestation,
  verifyContinuityAttestation,
} from "./continuity.ts";
import type {
  IssueContinuityInput,
  ContinuityAttestation,
  VerifyContinuityResult,
} from "./continuity.ts";

// ── Config-level supporting types ────────────────────────────────────────────

/**
 * FAMILY-CONSISTENCY §3 subject-presence rule. Each family pins exactly one.
 * - `must-be-present` — envelope `subject` must be a non-empty string
 * - `must-be-null`    — envelope `subject` must be `null` (dataset-level)
 * - `either`          — both forms are valid (rare)
 */
export type SubjectPresence = "must-be-present" | "must-be-null" | "either";

/**
 * FAMILY-CONSISTENCY §TSA upgrade path enum. Tracks how a family acquires
 * an RFC 3161 TSA token at issue time. The factory records the value; it
 * does not perform the upgrade itself.
 */
export type TsaUpgradePath = "free" | "internal" | "external";

/**
 * Per-profile TSA mandate level. `"mandatory"` and `"recommended"` are set via
 * `FamilyDefinition.tsa_mandate`. Any profile not listed defaults to `"optional"`.
 */
export type TsaMandateLevel = "mandatory" | "recommended" | "optional";

/**
 * Duck-typed body validator. Mirrors the result shape of zod's `safeParse` so
 * a `z.ZodType<BodyType>` can be adapted with a one-line wrapper, but the
 * envelope layer takes no runtime dependency on zod.
 *
 * Implementations MUST be pure (no I/O) and total (never throw).
 */
export interface BodyValidator<BodyType> {
  validate: (body: unknown) => BodyValidateResult<BodyType>;
}

/** Result of a body validation pass. */
export type BodyValidateResult<BodyType> =
  | { ok: true; value: BodyType }
  | { ok: false; reason: string };

/** Result of a subject-presence check against an envelope. */
export type SubjectPresenceResult =
  | { ok: true }
  | { ok: false; reason: string };

/** Input to a per-event subject-presence override callback. */
export interface SubjectPresenceCheckInput {
  readonly subject: string | null | undefined;
  readonly body: unknown;
}

/**
 * Per-event subject-presence override. When supplied in `FamilyDefinition`,
 * this callback replaces the universal `subject_presence` rule entirely.
 * Must be total (never throw) — the factory wraps any throw in a
 * `{ ok: false, reason: "subject_check_threw:<msg>" }` result.
 */
export type SubjectPresenceCheck = (input: SubjectPresenceCheckInput) => SubjectPresenceResult;

/**
 * Optional composition helpers. Some families (e.g. ALR) walk parent claim
 * graphs. The factory records the function reference; it does not invoke it.
 */
export interface FamilyCompositionConfig {
  /** Return ordered parent claim IDs from a receipt body. */
  walkParents?: (body: unknown) => readonly string[];
}

// ── Compose callback types ────────────────────────────────────────────────────

/**
 * Input handed to a family's `compose` callback during `verifyReceipt`.
 * The `opts` field passes through whatever the verifier caller supplied,
 * including any resolver function (e.g. `resolveAnr`, `resolveParent`,
 * `resolveArr`, `resolveAlr`) the family-specific compose logic needs.
 *
 * `iat` is plumbed through because some compose walks need it (e.g. the ASR
 * art17 ±14-day window check against the linked ARR receipt's `iat`).
 */
export interface ComposeInput {
  readonly envelope: {
    readonly id: string;
    readonly claim_type: string;
    readonly body: unknown;
    readonly subject: string | null;
    readonly iat: string;
    readonly iss: string;
    readonly prev: string | null;
  };
  readonly opts: import("./family-verify-pipeline.ts").FamilyVerifyOptions;
}

/**
 * Result returned by a `ComposeCallback`. The optional `warnings` channel
 * carries informational diagnostics (e.g. `art19_recipient_set_incomplete`,
 * `art20_cross_border_atr_missing`) that the pipeline appends to
 * `FamilyVerifyResult.warnings` via `appendWarnings`. Warnings do NOT poison
 * `signature_valid` — they are advisory only and may accompany either
 * branch. When omitted or empty, no warnings are added.
 */
export type ComposeResult =
  | { ok: true; warnings?: readonly string[] }
  | { ok: false; reason: string; warnings?: readonly string[] };

/**
 * Optional cross-family composition callback. When declared on a
 * `FamilyDefinition`, the verify orchestrator invokes it as the final
 * pipeline step (after profile dispatch). Throw-safe: any thrown exception
 * is caught and converted to `{ ok: false, reason: "compose_threw:<msg>" }`.
 *
 * Families that perform cross-family composition (ALR↔APR parent walker,
 * ACR↔ANR notice link) will migrate their hand-rolled composition walkers
 * onto this surface in Phase 4.
 */
export type ComposeCallback = (input: ComposeInput) => Promise<ComposeResult> | ComposeResult;

// ── Input: FamilyDefinition ──────────────────────────────────────────────────

/**
 * Declarative input to `defineFamily()`. Mandatory fields cover identity,
 * cross-family invariants, and the body validator. Optional fields toggle
 * continuity / batch / predicate surfaces and supply composition hooks.
 */
export interface FamilyDefinition<BodyType = unknown> {
  // Identity
  /** Three-or-four-letter member acronym, e.g. "ALR". */
  acronym: string;
  /** Full family name, e.g. "Anchored Lineage Receipts". */
  name: string;
  /**
   * Owned claim_type discriminators. Most families: 1. ARR closure set: 8.
   * Every entry MUST be one of the `CLAIM_TYPES` literals.
   */
  claim_types: readonly ClaimType[];
  /** Path to the design spec (relative to repo root). */
  spec_path: string;

  // FAMILY-CONSISTENCY invariants
  /** Member chip number per FAMILY-CONSISTENCY §chip-table. ≥ 1. */
  chip: number;
  /**
   * Status List 2021 bitstring slot per FAMILY-CONSISTENCY §4. ≥ 1 for
   * consumers; `null` for families that intentionally do NOT consume Status
   * List 2021 (e.g. APR — provenance receipts are non-revocable by design).
   */
  status_list_slot: number | null;
  /** Envelope `subject` presence rule. */
  subject_presence: SubjectPresence;
  /**
   * Optional per-event override callback. When present, replaces the universal
   * `subject_presence` rule entirely. The callback receives both the `subject`
   * field value and the full receipt body, enabling per-event-type rules
   * (e.g. ANR's `notice.acknowledged` must be sha256, all other events may be
   * sha256 or null).
   */
  subject_presence_check?: SubjectPresenceCheck;
  /** TSA upgrade path classification. */
  tsa_upgrade_path: TsaUpgradePath;

  // Body schema
  /** Family-specific body validator (Zod-shaped duck-type). */
  body_schema: BodyValidator<BodyType>;

  // Profiles
  /**
   * Optional profile registry. Keys are profile IDs (e.g. `"gdpr.art13"`),
   * values are validators compatible with `dispatchProfiles`. Profile IDs
   * are case-sensitive and MUST be unique.
   */
  profiles?: Readonly<Record<string, ProfileValidator>>;

  /**
   * Optional per-profile TSA mandate levels. Keys must be profile IDs that
   * appear in `profiles`; values must be `"mandatory"` or `"recommended"`.
   * Any registered profile not listed defaults to `"optional"` at runtime.
   * Supplying an ID not in `profiles` throws at config time.
   */
  tsa_mandate?: Readonly<Record<string, Exclude<TsaMandateLevel, "optional">>>;

  // Optional flow flags
  /** Family emits `ar.continuity.v1` attestations. Default `false`. */
  continuity?: boolean;
  /** Family supports `ar.batch.v1` batch claim_type. Default `false`. */
  batch?: boolean;
  /** Family recommends v1.2 `predicate` field usage. Default `false`. */
  predicate_recommended?: boolean;

  /** Optional composition helpers. */
  composition?: FamilyCompositionConfig;

  /**
   * Optional cross-family composition callback. When present, the verify
   * orchestrator invokes it as the final pipeline step after profile dispatch.
   * The callback receives the envelope's `claim_type`, `body`, and `subject`,
   * plus the full `opts` passed to `verifyReceipt` (including any resolver
   * functions the callback needs). A non-function value throws at config time.
   */
  compose?: ComposeCallback;
}

// ── Output: FamilyManifest ───────────────────────────────────────────────────

/**
 * Frozen identity + invariant block. All fields are derived from the input
 * `FamilyDefinition` and are immutable after `defineFamily()` returns.
 */
export interface FamilyMeta {
  acronym: string;
  name: string;
  claim_types: readonly ClaimType[];
  spec_path: string;
  chip: number;
  /**
   * Status List 2021 slot. `null` for families that do NOT consume Status
   * List 2021 (APR is the canonical non-consumer per FAMILY-CONSISTENCY §4).
   */
  status_list_slot: number | null;
  subject_presence: SubjectPresence;
  tsa_upgrade_path: TsaUpgradePath;
  continuity: boolean;
  batch: boolean;
  predicate_recommended: boolean;
}

/**
 * The object returned by `defineFamily()`. Phase A.1 surface: meta + the
 * validation helpers the envelope can already perform. Phase A.2 will extend
 * this interface with `verifyReceipt`, `mintV2`, `mintContinuity`, etc.
 */
export interface FamilyManifest<BodyType = unknown> {
  /** Frozen identity + invariant block. */
  readonly meta: FamilyMeta;

  /** Validate a body against the family's body schema. Never throws. */
  validateBody(body: unknown): BodyValidateResult<BodyType>;

  /** Return `true` iff `claim_type` is one of the family's owned discriminators. */
  isOwnedClaimType(claim_type: string): boolean;

  /**
   * Check an envelope's `subject` field against the family's subject-presence
   * rule. `null` is treated as the explicit null form; `undefined` is treated
   * as missing (rejected unless rule is `"either"`).
   *
   * When the family supplies a `subject_presence_check` callback, that callback
   * is called with `{ subject, body }` and its result is returned directly.
   * The universal `subject_presence` rule is ignored in that case.
   */
  checkSubjectPresence(
    subject: string | null | undefined,
    body?: unknown,
  ): SubjectPresenceResult;

  /** Ordered list of registered profile validators (matches `dispatchProfiles` input). */
  readonly profileValidators: readonly ProfileValidator[];

  /** Profile IDs registered with the family, in registration order. */
  readonly profileIds: readonly string[];

  /** `true` iff a profile with this ID is registered. */
  hasProfile(profile_id: string): boolean;

  /** Return parent claim IDs for the given body, or `[]` if no walker is configured. */
  walkParents(body: unknown): readonly string[];

  /**
   * Return the TSA mandate level for the given profile ID.
   * Returns `"mandatory"` or `"recommended"` if the profile was listed in
   * `tsa_mandate`, otherwise `"optional"` (including for unknown IDs).
   */
  tsaMandateLevel(profile_id: string): TsaMandateLevel;

  /** Pass-through to envelope's Ed25519 keypair generator. */
  generateKeypair(kid: string): Keypair;
  /** Pass-through to JCS-canonicalize-and-sign helper. */
  signCanonical(body: unknown, privateKeySeed: Uint8Array): Uint8Array;

  /**
   * Pre-bound verify orchestrator. Runs the 13-step pipeline against an
   * unknown receipt, resolving the issuer key via `opts.resolveKey`. Never
   * throws — all failures are captured in the result.
   *
   * Wired by `defineFamily()` at manifest construction time.
   */
  verifyReceipt(
    receipt: unknown,
    opts: FamilyVerifyOptions,
  ): Promise<FamilyVerifyResult>;

  /**
   * Pre-bound mint orchestrator. Runs the 9-step pipeline to produce a signed
   * v=2 Envelope from the given input. Throws on validation failures (bad key
   * length, body schema reject, subject presence violation, claim_type mismatch,
   * TSA config inconsistency).
   *
   * Wired by `defineFamily()` at manifest construction time. Symmetric with
   * `verifyReceipt` — both share the same predicate bundle.
   */
  mintV2(input: FamilyMintV2Input): Promise<Envelope>;

  /**
   * Cross-family composition callback, if the family declared one. `undefined`
   * when no callback is configured. The verify orchestrator invokes this as the
   * final pipeline step after profile dispatch.
   */
  readonly compose?: ComposeCallback;

  /**
   * Optional — present iff `def.continuity === true`. Pass-through to
   * envelope's `issueContinuityAttestation`. Families that don't emit
   * `ar.continuity.v1` will not have this method defined.
   */
  readonly mintContinuity?: (input: IssueContinuityInput) => ContinuityAttestation;

  /**
   * Optional — present iff `def.continuity === true`. Pass-through to
   * envelope's `verifyContinuityAttestation`.
   */
  readonly verifyContinuity?: (
    attestation: ContinuityAttestation,
  ) => VerifyContinuityResult;
}

// ── Factory ──────────────────────────────────────────────────────────────────

const KNOWN_CLAIM_TYPES = new Set<string>(CLAIM_TYPES);
const VALID_SUBJECT_PRESENCE = new Set<SubjectPresence>([
  "must-be-present",
  "must-be-null",
  "either",
]);
const VALID_TSA_UPGRADE = new Set<TsaUpgradePath>(["free", "internal", "external"]);

/**
 * Build a `FamilyManifest` from a declarative `FamilyDefinition`.
 *
 * Validation is config-time only: invalid acronym, claim_types, chip,
 * status_list_slot, subject_presence, tsa_upgrade_path, missing body_schema,
 * or duplicate profile IDs all throw synchronously. Once the factory returns,
 * the manifest is frozen and every helper is total (never throws).
 *
 * `defineFamily` is a no-op vs. `validateBody` / `walkParents` / etc. — the
 * family supplies the predicates; this factory wires them into a stable shape.
 */
export function defineFamily<BodyType = unknown>(
  def: FamilyDefinition<BodyType>,
): FamilyManifest<BodyType> {
  // ── Identity validation ────────────────────────────────────────────────────
  if (typeof def.acronym !== "string" || def.acronym.length === 0) {
    throw new Error("defineFamily: acronym must be a non-empty string");
  }
  if (typeof def.name !== "string" || def.name.length === 0) {
    throw new Error("defineFamily: name must be a non-empty string");
  }
  if (typeof def.spec_path !== "string" || def.spec_path.length === 0) {
    throw new Error("defineFamily: spec_path must be a non-empty string");
  }

  // ── claim_types validation ────────────────────────────────────────────────
  if (!Array.isArray(def.claim_types) || def.claim_types.length === 0) {
    throw new Error("defineFamily: claim_types must be a non-empty array");
  }
  const ownedClaimTypes = new Set<string>();
  for (const ct of def.claim_types) {
    if (typeof ct !== "string" || !KNOWN_CLAIM_TYPES.has(ct)) {
      throw new Error(
        `defineFamily: unknown claim_type "${String(ct)}" — must be one of CLAIM_TYPES`,
      );
    }
    if (ownedClaimTypes.has(ct)) {
      throw new Error(`defineFamily: duplicate claim_type "${ct}"`);
    }
    ownedClaimTypes.add(ct);
  }

  // ── Invariants validation ─────────────────────────────────────────────────
  if (!Number.isInteger(def.chip) || def.chip < 1) {
    throw new Error("defineFamily: chip must be an integer ≥ 1");
  }
  if (def.status_list_slot !== null) {
    if (!Number.isInteger(def.status_list_slot) || def.status_list_slot < 1) {
      throw new Error(
        "defineFamily: status_list_slot must be an integer ≥ 1, or null for non-consumers",
      );
    }
  }
  if (!VALID_SUBJECT_PRESENCE.has(def.subject_presence)) {
    throw new Error(
      `defineFamily: subject_presence must be "must-be-present" | "must-be-null" | "either", got "${String(
        def.subject_presence,
      )}"`,
    );
  }
  if (!VALID_TSA_UPGRADE.has(def.tsa_upgrade_path)) {
    throw new Error(
      `defineFamily: tsa_upgrade_path must be "free" | "internal" | "external", got "${String(
        def.tsa_upgrade_path,
      )}"`,
    );
  }

  // ── Body schema validation ────────────────────────────────────────────────
  if (
    def.body_schema === null ||
    typeof def.body_schema !== "object" ||
    typeof def.body_schema.validate !== "function"
  ) {
    throw new Error(
      "defineFamily: body_schema must be a { validate(body): BodyValidateResult } object",
    );
  }

  // ── Profiles validation ───────────────────────────────────────────────────
  const profileIds: string[] = [];
  const profileValidators: ProfileValidator[] = [];
  const profileIdSet = new Set<string>();
  if (def.profiles !== undefined) {
    if (def.profiles === null || typeof def.profiles !== "object") {
      throw new Error("defineFamily: profiles must be a Record<string, ProfileValidator>");
    }
    for (const [id, validator] of Object.entries(def.profiles)) {
      if (typeof id !== "string" || id.length === 0) {
        throw new Error("defineFamily: profile id must be a non-empty string");
      }
      if (typeof validator !== "function") {
        throw new Error(`defineFamily: profile "${id}" validator must be a function`);
      }
      if (profileIdSet.has(id)) {
        throw new Error(`defineFamily: duplicate profile id "${id}"`);
      }
      profileIdSet.add(id);
      profileIds.push(id);
      profileValidators.push(validator);
    }
  }

  // ── tsa_mandate validation ────────────────────────────────────────────────
  const tsaMandate = new Map<string, Exclude<TsaMandateLevel, "optional">>();
  if (def.tsa_mandate !== undefined) {
    if (def.tsa_mandate === null || typeof def.tsa_mandate !== "object") {
      throw new Error(
        "defineFamily: tsa_mandate must be a Record<string, \"mandatory\" | \"recommended\">",
      );
    }
    for (const [id, level] of Object.entries(def.tsa_mandate)) {
      if (!profileIdSet.has(id)) {
        throw new Error(`defineFamily: tsa_mandate references unknown profile id "${id}"`);
      }
      if (level !== "mandatory" && level !== "recommended") {
        throw new Error(
          `defineFamily: tsa_mandate["${id}"] must be "mandatory" | "recommended"`,
        );
      }
      tsaMandate.set(id, level);
    }
  }

  // ── subject_presence_check validation ────────────────────────────────────
  if (def.subject_presence_check !== undefined && typeof def.subject_presence_check !== "function") {
    throw new Error("defineFamily: subject_presence_check must be a function");
  }

  // ── Composition validation ────────────────────────────────────────────────
  const walkParentsFn = def.composition?.walkParents;
  if (walkParentsFn !== undefined && typeof walkParentsFn !== "function") {
    throw new Error("defineFamily: composition.walkParents must be a function");
  }

  // ── Compose callback validation ───────────────────────────────────────────
  const composeCb = def.compose;
  if (composeCb !== undefined && typeof composeCb !== "function") {
    throw new Error("defineFamily: compose must be a function");
  }

  // ── Build frozen meta ─────────────────────────────────────────────────────
  const meta: FamilyMeta = Object.freeze({
    acronym: def.acronym,
    name: def.name,
    claim_types: Object.freeze([...def.claim_types]),
    spec_path: def.spec_path,
    chip: def.chip,
    status_list_slot: def.status_list_slot,
    subject_presence: def.subject_presence,
    tsa_upgrade_path: def.tsa_upgrade_path,
    continuity: def.continuity === true,
    batch: def.batch === true,
    predicate_recommended: def.predicate_recommended === true,
  });

  const frozenProfileValidators = Object.freeze([...profileValidators]);
  const frozenProfileIds = Object.freeze([...profileIds]);
  const bodySchema = def.body_schema;
  const subjectRule = def.subject_presence;

  // ── Manifest helpers ──────────────────────────────────────────────────────
  function validateBody(body: unknown): BodyValidateResult<BodyType> {
    try {
      return bodySchema.validate(body);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { ok: false, reason: `body_validator_threw:${msg}` };
    }
  }

  function isOwnedClaimType(claim_type: string): boolean {
    return ownedClaimTypes.has(claim_type);
  }

  const subjectCheck = def.subject_presence_check;
  function checkSubjectPresence(
    subject: string | null | undefined,
    body?: unknown,
  ): SubjectPresenceResult {
    if (subjectCheck !== undefined) {
      try {
        return subjectCheck({ subject, body });
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { ok: false, reason: `subject_check_threw:${msg}` };
      }
    }
    if (subjectRule === "either") {
      if (subject === undefined) return { ok: false, reason: "subject_missing" };
      return { ok: true };
    }
    if (subjectRule === "must-be-null") {
      if (subject === null) return { ok: true };
      return { ok: false, reason: "subject_must_be_null" };
    }
    // must-be-present
    if (typeof subject === "string" && subject.length > 0) return { ok: true };
    return { ok: false, reason: "subject_must_be_present" };
  }

  function hasProfile(profile_id: string): boolean {
    return profileIdSet.has(profile_id);
  }

  function walkParents(body: unknown): readonly string[] {
    if (walkParentsFn === undefined) return [];
    try {
      const parents = walkParentsFn(body);
      return Object.freeze([...parents]);
    } catch {
      return [];
    }
  }

  function tsaMandateLevel(profile_id: string): TsaMandateLevel {
    return tsaMandate.get(profile_id) ?? "optional";
  }

  // Build the verify predicate bundle (avoids circular reference to manifest).
  const verifyPredicates = {
    meta,
    validateBody,
    isOwnedClaimType,
    checkSubjectPresence,
    tsaMandateLevel,
    profileValidators: frozenProfileValidators,
    profileIds: frozenProfileIds,
    hasProfile,
    ...(composeCb !== undefined ? { compose: composeCb } : {}),
  };
  const verifyReceipt = buildVerifyReceipt(verifyPredicates);

  // Build the mint predicate bundle — shares the same predicates as verify.
  const mintPredicates = {
    meta,
    validateBody,
    checkSubjectPresence,
    isOwnedClaimType,
  };
  const mintV2 = buildMintV2(mintPredicates);

  const manifest: FamilyManifest<BodyType> = Object.freeze({
    meta,
    validateBody,
    isOwnedClaimType,
    checkSubjectPresence,
    profileValidators: frozenProfileValidators,
    profileIds: frozenProfileIds,
    hasProfile,
    walkParents,
    tsaMandateLevel,
    generateKeypair,
    signCanonical,
    verifyReceipt,
    mintV2,
    ...(composeCb !== undefined ? { compose: composeCb } : {}),
    ...(def.continuity === true
      ? {
          mintContinuity: issueContinuityAttestation,
          verifyContinuity: verifyContinuityAttestation,
        }
      : {}),
  });

  return manifest;
}
