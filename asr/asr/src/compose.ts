/**
 * ASR — cross-family composition callback (Phase 3 §G).
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/asr
 *   §5.3   art17.erasure_request.request.fulfilled ↔ ARR (MANDATORY)
 *   §8.1   ARR composition rule
 *   §8.2   art21.objection.request.fulfilled ↔ APuR (OPTIONAL)
 *   §8.3   art20.portability.request.fulfilled ↔ ATR (OPTIONAL cross-border)
 *   §8.4   request.recipient_notified ↔ ALR cascade (MANDATORY shape)
 *
 * Wires onto the factory `compose` callback surface introduced in
 * `@dekimuhq/anchors-envelope` 0.9.0. The verify pipeline invokes this
 * callback as the final step after profile dispatch (Step 14).
 *
 * Discipline applied here:
 *
 *   1. **Resolver-undefined → skip silently.** Each cross-family resolver
 *      (`opts.resolveArr` / `opts.resolveAlr` / `opts.resolveAtr` /
 *      `opts.resolveApur`) is optional. When a resolver is not wired, the
 *      corresponding cross-walk is skipped silently and the receipt
 *      continues to verify. Matches the optional-resolver discipline of
 *      `chainResolver`, `statusListRootKey`, `fetchPolicy`. Callers that
 *      DON'T need cross-family verification (single-receipt /
 *      `verify.dekimu.com` mocks) keep working byte-equal.
 *
 *   2. **HARD-invalid + informational warnings.** A failed cross-walk
 *      flips `signature_valid` to `false` via `{ ok: false, reason: "<code>" }`.
 *      Informational warnings (`art19_recipient_set_incomplete` per
 *      spec §4.9; `art20_cross_border_atr_missing` per spec §8.3) flow
 *      via `ComposeResult.warnings` (Phase 4 — envelope 0.10.0). The
 *      pipeline appends them to `FamilyVerifyResult.warnings` without
 *      poisoning `signature_valid`.
 *
 *   3. **Profile dispatch via `opts.profile`.** Cross-walks fire on the
 *      profile/event pair the caller is actually verifying. When
 *      `opts.profile` is undefined the verifier ran in profile-less mode
 *      and we skip every profile-keyed cross-walk silently.
 *
 *   4. **Duck-typing.** Resolved envelopes come back as `unknown`
 *      because each family verifier owns its own types. We read the
 *      narrow set of fields each cross-walk needs (`claim_type`, `subject`,
 *      `body.target_kind`, `body.target_commit`, `body.event_type`, `iat`)
 *      and reject malformed shapes per spec.
 */

import type { ComposeCallback, ComposeInput, ComposeResult } from "@dekimuhq/anchors-envelope";
import type { AsrBody } from "./types.ts";

/** ±14 days in milliseconds — anti-stale-link window for art17 ARR cross-check (spec §5.3). */
const ART17_ARR_WINDOW_MS = 14 * 24 * 60 * 60 * 1000;

/** Allowed ARR claim_types on the art17 fulfilment cross-link (spec §5.3 + §8.1). */
const ART17_ARR_ALLOWED_CLAIM_TYPES: ReadonlySet<string> = new Set([
  "ar.erasure.v1",
  "ar.anonymization.v1",
]);

/** Profiles whose `request.recipient_notified` triggers the Art. 19 ALR cascade (spec §8.4). */
const ART19_PROFILES: ReadonlySet<string> = new Set([
  "subject_rights.art16.rectification",
  "subject_rights.art17.erasure_request",
  "subject_rights.art18.restriction",
]);

interface DuckEnvelope {
  readonly claim_type?: unknown;
  readonly subject?: unknown;
  readonly body?: unknown;
  readonly iat?: unknown;
}

function asDuck(v: unknown): DuckEnvelope | null {
  if (typeof v !== "object" || v === null) return null;
  return v as DuckEnvelope;
}

function parseIso(s: unknown): number | null {
  if (typeof s !== "string") return null;
  const t = Date.parse(s);
  return Number.isFinite(t) ? t : null;
}

/** Composes a `ComposeResult` failure. Local helper for readability. */
const fail = (reason: string): ComposeResult => ({ ok: false, reason });

/** Wraps an `ok` result, attaching `warnings` only when non-empty. */
const okWith = (warnings: readonly string[]): ComposeResult =>
  warnings.length > 0 ? { ok: true, warnings } : { ok: true };

/**
 * ASR cross-family composition. Returns `{ ok: true }` for every event
 * type that doesn't need a cross-walk, when the corresponding resolver
 * isn't wired, or when all cross-walks pass. May emit informational
 * warnings on the `ok` branch (Phase 4).
 */
export const composeAsr: ComposeCallback = async (
  input: ComposeInput,
): Promise<ComposeResult> => {
  const { envelope, opts } = input;
  const warnings: string[] = [];
  if (envelope.claim_type !== "ar.subject_rights.v1") return { ok: true };

  const body = envelope.body as AsrBody | undefined;
  if (!body || typeof body !== "object") return { ok: true };
  const eventType = body.event_type;
  const subject = envelope.subject;
  const asrIatMs = parseIso(envelope.iat);

  // ── Art. 17 ARR cross-walk (spec §5.3, §8.1 — MANDATORY) ────────────────────
  if (
    opts.profile === "subject_rights.art17.erasure_request" &&
    eventType === "request.fulfilled"
  ) {
    const arrId = (body as { arr_receipt_id?: unknown }).arr_receipt_id;
    if (typeof arrId !== "string" || arrId.length === 0) {
      // body schema doesn't enforce this MANDATORY (profile-level field);
      // profile validator surfaces the same gap advisorily. Cross-walk
      // upgrades it to HARD invalid per spec D10-ASR-3.
      return fail("art17_arr_link_missing");
    }
    if (opts.resolveArr !== undefined) {
      const arr = await opts.resolveArr(arrId);
      if (arr === null || arr === undefined) {
        return fail("art17_arr_link_unresolvable");
      }
      const arrDuck = asDuck(arr);
      if (arrDuck === null) {
        return fail("art17_arr_link_unresolvable");
      }
      if (
        typeof arrDuck.claim_type !== "string" ||
        !ART17_ARR_ALLOWED_CLAIM_TYPES.has(arrDuck.claim_type)
      ) {
        return fail("art17_arr_wrong_claim_type");
      }
      const arrBody = arrDuck.body as { target_kind?: unknown; target_commit?: unknown } | null | undefined;
      if (
        !arrBody ||
        typeof arrBody !== "object" ||
        arrBody.target_kind !== "subject" ||
        typeof arrBody.target_commit !== "string" ||
        subject === null ||
        arrBody.target_commit !== subject
      ) {
        return fail("art17_arr_subject_mismatch");
      }
      const arrIatMs = parseIso(arrDuck.iat);
      if (asrIatMs === null || arrIatMs === null) {
        // Both iats are envelope-mandated ISO strings — if either parses as
        // non-finite, the chain is malformed. Surface as stale-link to keep
        // the error namespace small.
        return fail("art17_arr_stale_link");
      }
      if (Math.abs(arrIatMs - asrIatMs) > ART17_ARR_WINDOW_MS) {
        return fail("art17_arr_stale_link");
      }
    }
  }

  // ── Art. 19 ALR cascade (spec §4.9, §8.4 — MANDATORY shape) ─────────────────
  if (
    opts.profile !== undefined &&
    ART19_PROFILES.has(opts.profile) &&
    eventType === "request.recipient_notified"
  ) {
    const alrIds = (body as { recipient_set_alr_ids?: unknown }).recipient_set_alr_ids;
    if (!Array.isArray(alrIds) || alrIds.length === 0) {
      // body schema enforces non-empty string array on this event, so this
      // should never trigger. Defensive — if it does, fail HARD.
      return fail("art19_recipient_set_invalid");
    }
    if (opts.resolveAlr !== undefined) {
      for (const alrId of alrIds) {
        if (typeof alrId !== "string" || alrId.length === 0) {
          return fail("art19_recipient_set_invalid");
        }
        const alr = await opts.resolveAlr(alrId);
        if (alr === null || alr === undefined) {
          return fail("art19_alr_link_unresolvable");
        }
        const alrDuck = asDuck(alr);
        if (alrDuck === null) {
          return fail("art19_alr_link_unresolvable");
        }
        if (alrDuck.claim_type !== "ar.lineage.v1") {
          return fail("art19_alr_wrong_claim_type");
        }
        const alrBody = alrDuck.body as { event_type?: unknown } | null | undefined;
        if (!alrBody || typeof alrBody !== "object" || alrBody.event_type !== "disclosed") {
          return fail("art19_alr_wrong_event_type");
        }
        if (subject === null || alrDuck.subject !== subject) {
          return fail("art19_alr_subject_mismatch");
        }
      }
    }
    // Informational completeness check (spec §4.9). When the caller wires
    // `findDisclosedAlrsForSubject`, compare the body's set against the
    // authoritative ledger and warn if a strict subset. Resolver-undefined
    // → skip silently per the optional-resolver discipline.
    if (opts.findDisclosedAlrsForSubject !== undefined && subject !== null) {
      const complete = await opts.findDisclosedAlrsForSubject(subject);
      const bodySet = new Set<string>();
      for (const id of alrIds) {
        if (typeof id === "string") bodySet.add(id);
      }
      let missing = false;
      for (const expected of complete) {
        if (typeof expected === "string" && !bodySet.has(expected)) {
          missing = true;
          break;
        }
      }
      if (missing) warnings.push("art19_recipient_set_incomplete");
    }
  }

  // ── Art. 20 ATR cross-walk (spec §8.3 — OPTIONAL, parity-check only) ────────
  if (
    opts.profile === "subject_rights.art20.portability" &&
    eventType === "request.fulfilled"
  ) {
    const atrId = (body as { atr_receipt_id?: unknown }).atr_receipt_id;
    const recipientDid = (body as { portability_recipient_did?: unknown }).portability_recipient_did;
    // Informational cross-border check (spec §8.3, §5.5). When the issuer
    // anchored a subject-directed transfer (`portability_recipient_did` set)
    // without pairing it with an ATR receipt, surface an advisory warning.
    // The verifier cannot determine EU vs non-EU recipient status from byte
    // data alone, so the trigger is conservative — issuers can disambiguate
    // EU-only transfers off-chain.
    if (
      typeof recipientDid === "string" &&
      recipientDid.length > 0 &&
      (typeof atrId !== "string" || atrId.length === 0)
    ) {
      warnings.push("art20_cross_border_atr_missing");
    }
    if (typeof atrId === "string" && atrId.length > 0 && opts.resolveAtr !== undefined) {
      const atr = await opts.resolveAtr(atrId);
      if (atr === null || atr === undefined) {
        return fail("art20_atr_link_unresolvable");
      }
      const atrDuck = asDuck(atr);
      if (atrDuck === null) {
        return fail("art20_atr_link_unresolvable");
      }
      if (atrDuck.claim_type !== "ar.transfer.v1") {
        return fail("art20_atr_wrong_claim_type");
      }
      if (subject === null || atrDuck.subject !== subject) {
        return fail("art20_atr_subject_mismatch");
      }
    }
  }

  // ── Art. 21 APuR back-ref (spec §8.2 — OPTIONAL, parity-check only) ─────────
  if (
    opts.profile === "subject_rights.art21.objection" &&
    eventType === "request.fulfilled"
  ) {
    const apurId = (body as { apur_receipt_id?: unknown }).apur_receipt_id;
    if (typeof apurId === "string" && apurId.length > 0 && opts.resolveApur !== undefined) {
      const apur = await opts.resolveApur(apurId);
      if (apur === null || apur === undefined) {
        return fail("art21_apur_link_unresolvable");
      }
      const apurDuck = asDuck(apur);
      if (apurDuck === null) {
        return fail("art21_apur_link_unresolvable");
      }
      if (apurDuck.claim_type !== "ar.purpose.v1") {
        return fail("art21_apur_wrong_claim_type");
      }
      const apurBody = apurDuck.body as { event_type?: unknown } | null | undefined;
      if (!apurBody || typeof apurBody !== "object" || apurBody.event_type !== "unbinding") {
        return fail("art21_apur_wrong_event_type");
      }
      if (subject === null || apurDuck.subject !== subject) {
        return fail("art21_apur_subject_mismatch");
      }
    }
  }

  return okWith(warnings);
};
