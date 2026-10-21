/**
 * defineFamily() factory tests — Phase A.1.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/envelope
 *
 * Coverage:
 *   §1 identity validation        — acronym/name/spec_path
 *   §2 claim_types validation     — non-empty, owned-set, no dupes
 *   §3 invariants validation      — chip/status_list_slot/subject_presence/tsa_upgrade_path
 *   §4 body_schema validation     — required, must expose validate()
 *   §5 profiles validation        — optional, function values, no dupes
 *   §6 manifest meta              — fully populated, frozen
 *   §7 validateBody behaviour     — pass/fail/throw paths
 *   §8 isOwnedClaimType           — owned vs unowned
 *   §9 checkSubjectPresence       — three rules × envelope state
 *   §10 profile registry          — order preserved, hasProfile lookup
 *   §11 walkParents               — configured, absent, throwing
 *   §12 export wiring             — `defineFamily` reachable through index.ts
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";

import {
  defineFamily,
  type FamilyDefinition,
  type BodyValidator,
} from "../src/define-family.ts";
import type { ClaimType } from "../src/envelope-types.ts";
import type { ProfileValidator } from "../src/profile/types.ts";

// ── Test fixtures ───────────────────────────────────────────────────────────

interface AlrBody {
  field: string;
}

const acceptAllBody: BodyValidator<AlrBody> = {
  validate: (body): { ok: true; value: AlrBody } | { ok: false; reason: string } => {
    if (typeof body === "object" && body !== null && "field" in body) {
      return { ok: true, value: body as AlrBody };
    }
    return { ok: false, reason: "schema_invalid" };
  },
};

const okProfile: ProfileValidator = () => ({
  profile_id: "gdpr.art13",
  ok: true,
});
const noProfile: ProfileValidator = () => ({
  profile_id: "aiact.art13",
  ok: false,
  reason: "missing_field",
});

function baseAlrDef(
  overrides: Partial<FamilyDefinition<AlrBody>> = {},
): FamilyDefinition<AlrBody> {
  return {
    acronym: "ALR",
    name: "Anchored Lineage Receipts",
    claim_types: ["ar.lineage.v1"] satisfies readonly ClaimType[],
    spec_path: "https://github.com/dekimuhq/anchors-spec/tree/main/alr",
    chip: 9,
    status_list_slot: 1,
    subject_presence: "must-be-null",
    tsa_upgrade_path: "free",
    body_schema: acceptAllBody,
    ...overrides,
  };
}

// ── §1 — identity validation ─────────────────────────────────────────────────

test("§1.1 throws on empty acronym", () => {
  assert.throws(
    () => defineFamily(baseAlrDef({ acronym: "" })),
    /acronym/,
  );
});

test("§1.2 throws on empty name", () => {
  assert.throws(
    () => defineFamily(baseAlrDef({ name: "" })),
    /name/,
  );
});

test("§1.3 throws on empty spec_path", () => {
  assert.throws(
    () => defineFamily(baseAlrDef({ spec_path: "" })),
    /spec_path/,
  );
});

// ── §2 — claim_types validation ──────────────────────────────────────────────

test("§2.1 throws on empty claim_types array", () => {
  assert.throws(
    () => defineFamily(baseAlrDef({ claim_types: [] })),
    /claim_types/,
  );
});

test("§2.2 throws on unknown claim_type", () => {
  assert.throws(
    () =>
      defineFamily(
        baseAlrDef({
          claim_types: ["ar.bogus.v1" as unknown as ClaimType],
        }),
      ),
    /unknown claim_type/,
  );
});

test("§2.3 throws on duplicate claim_type", () => {
  assert.throws(
    () =>
      defineFamily(
        baseAlrDef({
          claim_types: ["ar.lineage.v1", "ar.lineage.v1"] as readonly ClaimType[],
        }),
      ),
    /duplicate claim_type/,
  );
});

test("§2.4 accepts multi-discriminator families (ARR closure-set pattern)", () => {
  const arr = defineFamily(
    baseAlrDef({
      acronym: "ARR",
      claim_types: [
        "ar.erasure.v1",
        "ar.expiry.v1",
        "ar.hold.v1",
      ] as readonly ClaimType[],
      chip: 6,
      status_list_slot: 3,
    }),
  );
  assert.strictEqual(arr.meta.claim_types.length, 3);
  assert.ok(arr.isOwnedClaimType("ar.hold.v1"));
  assert.ok(!arr.isOwnedClaimType("ar.lineage.v1"));
});

// ── §3 — invariants validation ───────────────────────────────────────────────

test("§3.1 throws on chip < 1", () => {
  assert.throws(
    () => defineFamily(baseAlrDef({ chip: 0 })),
    /chip/,
  );
});

test("§3.2 throws on non-integer chip", () => {
  assert.throws(
    () => defineFamily(baseAlrDef({ chip: 9.5 })),
    /chip/,
  );
});

test("§3.3 throws on status_list_slot < 1", () => {
  assert.throws(
    () => defineFamily(baseAlrDef({ status_list_slot: 0 })),
    /status_list_slot/,
  );
});

test("§3.3b accepts status_list_slot: null for non-consumers (APR pattern)", () => {
  const m = defineFamily(baseAlrDef({ status_list_slot: null }));
  assert.strictEqual(m.meta.status_list_slot, null);
});

test("§3.4 throws on unknown subject_presence value", () => {
  assert.throws(
    () =>
      defineFamily(
        baseAlrDef({
          subject_presence: "whatever" as unknown as "must-be-null",
        }),
      ),
    /subject_presence/,
  );
});

test("§3.5 throws on unknown tsa_upgrade_path value", () => {
  assert.throws(
    () =>
      defineFamily(
        baseAlrDef({
          tsa_upgrade_path: "premium" as unknown as "free",
        }),
      ),
    /tsa_upgrade_path/,
  );
});

// ── §4 — body_schema validation ──────────────────────────────────────────────

test("§4.1 throws when body_schema is missing", () => {
  assert.throws(
    () =>
      defineFamily(
        baseAlrDef({
          body_schema: undefined as unknown as BodyValidator<AlrBody>,
        }),
      ),
    /body_schema/,
  );
});

test("§4.2 throws when body_schema lacks validate()", () => {
  assert.throws(
    () =>
      defineFamily(
        baseAlrDef({
          body_schema: { foo: "bar" } as unknown as BodyValidator<AlrBody>,
        }),
      ),
    /body_schema/,
  );
});

// ── §5 — profiles validation ────────────────────────────────────────────────

test("§5.1 accepts a family with no profiles", () => {
  const m = defineFamily(baseAlrDef());
  assert.strictEqual(m.profileIds.length, 0);
  assert.strictEqual(m.profileValidators.length, 0);
});

test("§5.2 throws when a profile validator is not a function", () => {
  assert.throws(
    () =>
      defineFamily(
        baseAlrDef({
          profiles: {
            "gdpr.art13": "not a function" as unknown as ProfileValidator,
          },
        }),
      ),
    /profile/,
  );
});

test("§5.3 preserves profile registration order", () => {
  const m = defineFamily(
    baseAlrDef({
      profiles: {
        "gdpr.art13": okProfile,
        "aiact.art13": noProfile,
      },
    }),
  );
  assert.deepStrictEqual([...m.profileIds], ["gdpr.art13", "aiact.art13"]);
});

// ── §6 — manifest meta ───────────────────────────────────────────────────────

test("§6.1 meta is populated with every config field", () => {
  const m = defineFamily(
    baseAlrDef({
      continuity: true,
      batch: false,
      predicate_recommended: true,
    }),
  );
  assert.strictEqual(m.meta.acronym, "ALR");
  assert.strictEqual(m.meta.name, "Anchored Lineage Receipts");
  assert.deepStrictEqual([...m.meta.claim_types], ["ar.lineage.v1"]);
  assert.strictEqual(m.meta.chip, 9);
  assert.strictEqual(m.meta.status_list_slot, 1);
  assert.strictEqual(m.meta.subject_presence, "must-be-null");
  assert.strictEqual(m.meta.tsa_upgrade_path, "free");
  assert.strictEqual(m.meta.continuity, true);
  assert.strictEqual(m.meta.batch, false);
  assert.strictEqual(m.meta.predicate_recommended, true);
});

test("§6.2 meta is frozen (no runtime mutation)", () => {
  const m = defineFamily(baseAlrDef());
  assert.ok(Object.isFrozen(m.meta));
  assert.ok(Object.isFrozen(m.meta.claim_types));
  assert.throws(() => {
    (m.meta as unknown as Record<string, unknown>).acronym = "HACKED";
  });
});

test("§6.3 manifest itself is frozen", () => {
  const m = defineFamily(baseAlrDef());
  assert.ok(Object.isFrozen(m));
});

test("§6.4 flag fields default to false when omitted", () => {
  const m = defineFamily(baseAlrDef());
  assert.strictEqual(m.meta.continuity, false);
  assert.strictEqual(m.meta.batch, false);
  assert.strictEqual(m.meta.predicate_recommended, false);
});

// ── §7 — validateBody behaviour ──────────────────────────────────────────────

test("§7.1 validateBody returns ok=true on schema match", () => {
  const m = defineFamily(baseAlrDef());
  const r = m.validateBody({ field: "x" });
  assert.strictEqual(r.ok, true);
  if (r.ok) assert.deepStrictEqual(r.value, { field: "x" });
});

test("§7.2 validateBody returns ok=false on schema mismatch", () => {
  const m = defineFamily(baseAlrDef());
  const r = m.validateBody({ wrong: "shape" });
  assert.strictEqual(r.ok, false);
  if (!r.ok) assert.strictEqual(r.reason, "schema_invalid");
});

test("§7.3 validateBody never throws — surfaces validator errors", () => {
  const throwingSchema: BodyValidator<AlrBody> = {
    validate: () => {
      throw new Error("kaboom");
    },
  };
  const m = defineFamily(baseAlrDef({ body_schema: throwingSchema }));
  const r = m.validateBody({ field: "x" });
  assert.strictEqual(r.ok, false);
  if (!r.ok) assert.match(r.reason, /^body_validator_threw:kaboom$/);
});

// ── §8 — isOwnedClaimType ────────────────────────────────────────────────────

test("§8.1 isOwnedClaimType is true for owned discriminator", () => {
  const m = defineFamily(baseAlrDef());
  assert.strictEqual(m.isOwnedClaimType("ar.lineage.v1"), true);
});

test("§8.2 isOwnedClaimType is false for unowned discriminator", () => {
  const m = defineFamily(baseAlrDef());
  assert.strictEqual(m.isOwnedClaimType("ar.consent.v1"), false);
  assert.strictEqual(m.isOwnedClaimType("ar.bogus.v1"), false);
});

// ── §9 — checkSubjectPresence ────────────────────────────────────────────────

test("§9.1 must-be-null accepts null", () => {
  const m = defineFamily(baseAlrDef({ subject_presence: "must-be-null" }));
  assert.deepStrictEqual(m.checkSubjectPresence(null), { ok: true });
});

test("§9.2 must-be-null rejects a string subject", () => {
  const m = defineFamily(baseAlrDef({ subject_presence: "must-be-null" }));
  const r = m.checkSubjectPresence("did:web:example.com");
  assert.strictEqual(r.ok, false);
  if (!r.ok) assert.strictEqual(r.reason, "subject_must_be_null");
});

test("§9.3 must-be-present accepts a string subject", () => {
  const m = defineFamily(baseAlrDef({ subject_presence: "must-be-present" }));
  assert.deepStrictEqual(m.checkSubjectPresence("urn:user:42"), { ok: true });
});

test("§9.4 must-be-present rejects null", () => {
  const m = defineFamily(baseAlrDef({ subject_presence: "must-be-present" }));
  const r = m.checkSubjectPresence(null);
  assert.strictEqual(r.ok, false);
  if (!r.ok) assert.strictEqual(r.reason, "subject_must_be_present");
});

test("§9.5 must-be-present rejects empty string", () => {
  const m = defineFamily(baseAlrDef({ subject_presence: "must-be-present" }));
  const r = m.checkSubjectPresence("");
  assert.strictEqual(r.ok, false);
});

test("§9.6 either accepts both null and string", () => {
  const m = defineFamily(baseAlrDef({ subject_presence: "either" }));
  assert.deepStrictEqual(m.checkSubjectPresence(null), { ok: true });
  assert.deepStrictEqual(m.checkSubjectPresence("urn:user:1"), { ok: true });
});

test("§9.7 either rejects undefined (missing field)", () => {
  const m = defineFamily(baseAlrDef({ subject_presence: "either" }));
  const r = m.checkSubjectPresence(undefined);
  assert.strictEqual(r.ok, false);
  if (!r.ok) assert.strictEqual(r.reason, "subject_missing");
});

// ── §10 — profile registry ───────────────────────────────────────────────────

test("§10.1 hasProfile returns true for registered id", () => {
  const m = defineFamily(
    baseAlrDef({
      profiles: { "gdpr.art13": okProfile },
    }),
  );
  assert.strictEqual(m.hasProfile("gdpr.art13"), true);
});

test("§10.2 hasProfile returns false for unregistered id", () => {
  const m = defineFamily(
    baseAlrDef({
      profiles: { "gdpr.art13": okProfile },
    }),
  );
  assert.strictEqual(m.hasProfile("aiact.art13"), false);
});

test("§10.3 profileValidators integrates with dispatchProfiles (length parity)", async () => {
  const { dispatchProfiles } = await import("../src/profile/dispatch.ts");
  const m = defineFamily(
    baseAlrDef({
      profiles: {
        "gdpr.art13": okProfile,
        "aiact.art13": noProfile,
      },
    }),
  );
  const fakeEnvelope = {} as unknown as import("../src/envelope-types.ts").Envelope;
  const results = dispatchProfiles(fakeEnvelope, {}, {}, m.profileValidators);
  assert.strictEqual(results.length, 2);
  assert.strictEqual(results[0]?.profile_id, "gdpr.art13");
  assert.strictEqual(results[1]?.profile_id, "aiact.art13");
});

// ── §11 — walkParents ────────────────────────────────────────────────────────

test("§11.1 walkParents returns [] when composition omitted", () => {
  const m = defineFamily(baseAlrDef());
  assert.deepStrictEqual([...m.walkParents({})], []);
});

test("§11.2 walkParents delegates to configured walker", () => {
  const m = defineFamily(
    baseAlrDef({
      composition: {
        walkParents: (body) => {
          const b = body as { parents?: string[] };
          return b.parents ?? [];
        },
      },
    }),
  );
  assert.deepStrictEqual(
    [...m.walkParents({ parents: ["a", "b"] })],
    ["a", "b"],
  );
});

test("§11.3 walkParents returns [] when walker throws (never crashes verifier)", () => {
  const m = defineFamily(
    baseAlrDef({
      composition: {
        walkParents: () => {
          throw new Error("graph broken");
        },
      },
    }),
  );
  assert.deepStrictEqual([...m.walkParents({})], []);
});

// ── §12 — export wiring ──────────────────────────────────────────────────────

test("§12.1 defineFamily reachable through package barrel", async () => {
  const mod = await import("../src/index.ts");
  assert.strictEqual(typeof mod.defineFamily, "function");
});

// ── §13 — subject_presence_check callback ────────────────────────────────────

test("subject_presence_check callback overrides universal rule", () => {
  const fam = defineFamily({
    acronym: "TST", name: "Test", claim_types: ["ar.provenance.v1"],
    spec_path: "x", chip: 1, status_list_slot: null,
    subject_presence: "either",
    subject_presence_check: ({ subject, body }) => {
      const eventType = (body as { event_type?: string } | null)?.event_type;
      if (eventType === "ack") {
        if (typeof subject === "string" && subject.startsWith("sha256:"))
          return { ok: true };
        return { ok: false, reason: "subject_must_be_sha256" };
      }
      return { ok: true };
    },
    tsa_upgrade_path: "free",
    body_schema: { validate: (b) => ({ ok: true, value: b }) },
  });
  assert.deepEqual(
    fam.checkSubjectPresence("sha256:" + "a".repeat(64), { event_type: "ack" }),
    { ok: true },
  );
  assert.deepEqual(
    fam.checkSubjectPresence(null, { event_type: "ack" }),
    { ok: false, reason: "subject_must_be_sha256" },
  );
  assert.deepEqual(
    fam.checkSubjectPresence(null, { event_type: "presented" }),
    { ok: true },
  );

  // throw-safety: callback errors must surface as ok:false, never re-throw
  const throwingFam = defineFamily({
    acronym: "TST", name: "Test", claim_types: ["ar.provenance.v1"],
    spec_path: "x", chip: 1, status_list_slot: null,
    subject_presence: "either",
    subject_presence_check: () => { throw new Error("boom"); },
    tsa_upgrade_path: "free",
    body_schema: { validate: (b) => ({ ok: true, value: b }) },
  });
  assert.deepEqual(
    throwingFam.checkSubjectPresence("sha256:" + "a".repeat(64), {}),
    { ok: false, reason: "subject_check_threw:boom" },
  );
});

// ── §14 — subject_presence_check construction-time guard ─────────────────────

test("subject_presence_check must be a function (config-time guard)", () => {
  assert.throws(
    () =>
      defineFamily({
        acronym: "TST", name: "Test", claim_types: ["ar.provenance.v1"],
        spec_path: "x", chip: 1, status_list_slot: null,
        subject_presence: "either",
        // @ts-expect-error — testing config-time guard against bad input
        subject_presence_check: "not-a-function",
        tsa_upgrade_path: "free",
        body_schema: { validate: (b) => ({ ok: true, value: b }) },
      }),
    /subject_presence_check must be a function/,
  );
});

// ── §15 — tsa_mandate config ─────────────────────────────────────────────────

test("tsa_mandate config exposes mandate level per profile", () => {
  const fam = defineFamily({
    acronym: "TST", name: "Test", claim_types: ["ar.provenance.v1"],
    spec_path: "x", chip: 1, status_list_slot: null,
    subject_presence: "either", tsa_upgrade_path: "free",
    body_schema: { validate: (b) => ({ ok: true, value: b }) },
    profiles: {
      "p.mandatory": () => ({ profile_id: "p.mandatory", ok: true }),
      "p.rec": () => ({ profile_id: "p.rec", ok: true }),
      "p.opt": () => ({ profile_id: "p.opt", ok: true }),
    },
    tsa_mandate: { "p.mandatory": "mandatory", "p.rec": "recommended" },
  });
  assert.equal(fam.tsaMandateLevel("p.mandatory"), "mandatory");
  assert.equal(fam.tsaMandateLevel("p.rec"), "recommended");
  assert.equal(fam.tsaMandateLevel("p.opt"), "optional");
  assert.equal(fam.tsaMandateLevel("unknown-profile"), "optional");
});

test("tsa_mandate rejects entries for unknown profile ids at config time", () => {
  assert.throws(
    () =>
      defineFamily({
        acronym: "TST", name: "Test", claim_types: ["ar.provenance.v1"],
        spec_path: "x", chip: 1, status_list_slot: null,
        subject_presence: "either", tsa_upgrade_path: "free",
        body_schema: { validate: (b) => ({ ok: true, value: b }) },
        profiles: { "p.known": () => ({ profile_id: "p.known", ok: true }) },
        tsa_mandate: { "p.ghost": "mandatory" },
      }),
    /unknown profile id "p\.ghost"/,
  );
});

// ── §16 — generateKeypair + signCanonical pass-throughs ──────────────────────

test("manifest exposes generateKeypair + signCanonical as pass-throughs", () => {
  const fam = defineFamily({
    acronym: "TST", name: "Test", claim_types: ["ar.provenance.v1"],
    spec_path: "x", chip: 1, status_list_slot: null,
    subject_presence: "either", tsa_upgrade_path: "free",
    body_schema: { validate: (b) => ({ ok: true, value: b }) },
  });
  const kp = fam.generateKeypair("test-kid");
  assert.equal(kp.kid, "test-kid");
  assert.equal(kp.privateKey.length, 32);
  assert.equal(kp.publicKey.length, 32);

  const sig = fam.signCanonical({ test: true }, kp.privateKey);
  assert.ok(sig instanceof Uint8Array);
  assert.equal(sig.length, 64);
});

// ── §17 — continuity pass-throughs ───────────────────────────────────────────

test("continuity: true populates mintContinuity + verifyContinuity on manifest", () => {
  const fam = defineFamily({
    acronym: "TST", name: "Test", claim_types: ["ar.provenance.v1"],
    spec_path: "x", chip: 1, status_list_slot: null,
    subject_presence: "either", tsa_upgrade_path: "free",
    body_schema: { validate: (b) => ({ ok: true, value: b }) },
    continuity: true,
  });
  assert.equal(typeof fam.mintContinuity, "function");
  assert.equal(typeof fam.verifyContinuity, "function");
  assert.equal(fam.meta.continuity, true);
});

test("continuity: false (default) leaves mintContinuity + verifyContinuity undefined", () => {
  const fam = defineFamily({
    acronym: "TST", name: "Test", claim_types: ["ar.provenance.v1"],
    spec_path: "x", chip: 1, status_list_slot: null,
    subject_presence: "either", tsa_upgrade_path: "free",
    body_schema: { validate: (b) => ({ ok: true, value: b }) },
  });
  assert.equal(fam.mintContinuity, undefined);
  assert.equal(fam.verifyContinuity, undefined);
  assert.equal(fam.meta.continuity, false);
});

test("continuity: true binds to envelope/src/continuity.ts pass-throughs (identity check)", async () => {
  const fam = defineFamily({
    acronym: "TST", name: "Test", claim_types: ["ar.provenance.v1"],
    spec_path: "x", chip: 1, status_list_slot: null,
    subject_presence: "either", tsa_upgrade_path: "free",
    body_schema: { validate: (b) => ({ ok: true, value: b }) },
    continuity: true,
  });
  // Import the same functions and confirm reference equality — proves pass-through, not wrapping.
  const mod = await import("../src/continuity.ts");
  assert.equal(fam.mintContinuity, mod.issueContinuityAttestation);
  assert.equal(fam.verifyContinuity, mod.verifyContinuityAttestation);
});
