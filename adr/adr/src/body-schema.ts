/**
 * ADR — runtime body validator wired into `adrFamily.body_schema`.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/adr §4.2 + §5.
 *
 * Pipeline contract (per `@dekimuhq/anchors-envelope` `BodyValidator<T>`):
 * pure, total (never throws), returns `{ ok: true, value }` or
 * `{ ok: false, reason }`.
 *
 * Scope: per-event MANDATORY / PROHIBITED fields from spec §4.2. Profile-specific
 * extensions are enforced by the per-profile validators in `@dekimuhq/adr-profiles`.
 */

import type { BodyValidator } from "@dekimuhq/anchors-envelope";
import {
  ADR_EVENT_TYPES,
  ADR_PROFILES,
  type AdrBody,
  type AdrEventType,
  type AdrProfile,
} from "./types.ts";

// ── Helpers ───────────────────────────────────────────────────────────────────

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

const isNonEmptyString = (v: unknown): v is string =>
  typeof v === "string" && v.length > 0;

const isNonEmptyStringArray = (v: unknown): v is readonly string[] =>
  Array.isArray(v) && v.length > 0 && v.every((x) => typeof x === "string" && x.length > 0);

const isAdrEventType = (v: unknown): v is AdrEventType =>
  typeof v === "string" && (ADR_EVENT_TYPES as readonly string[]).includes(v);

const isAdrProfile = (v: unknown): v is AdrProfile =>
  typeof v === "string" && (ADR_PROFILES as readonly string[]).includes(v);

const fail = (reason: string) => ({ ok: false as const, reason });

// ── Grant-only fields — prohibited on non-grant events ────────────────────────

const GRANT_ONLY_FIELDS = [
  "agent",
  "scope",
  "delegable",
  "expiry",
  "rationale_uri",
  "rationale_hash",
  "authorizing_credential",
] as const;

// Fields that are prohibited specifically on revoke/narrow/renew/suspend/resume
// (each event has its own subset — checked per-event below)

// ── Scope validation ──────────────────────────────────────────────────────────

function validateScope(
  body: Record<string, unknown>,
): { ok: false; reason: string } | null {
  const scope = body["scope"];
  if (!isObject(scope)) return fail("adr_missing_scope");
  if (!isNonEmptyStringArray(scope["actions"])) return fail("adr_scope_invalid_actions");
  if (!isNonEmptyStringArray(scope["resources"])) return fail("adr_scope_invalid_resources");
  if (!isObject(scope["constraints"])) return fail("adr_scope_invalid_constraints");
  return null;
}

// ── Agent validation ──────────────────────────────────────────────────────────

function validateAgent(
  body: Record<string, unknown>,
): { ok: false; reason: string } | null {
  const agent = body["agent"];
  if (!isObject(agent)) return fail("adr_missing_agent");
  if (!isNonEmptyString(agent["agent_id"])) return fail("adr_agent_invalid_agent_id");
  if (
    agent["agent_pubkey"] !== null &&
    agent["agent_pubkey"] !== undefined &&
    typeof agent["agent_pubkey"] !== "string"
  ) {
    return fail("adr_agent_invalid_agent_pubkey");
  }
  if (agent["agent_descriptor"] !== null && agent["agent_descriptor"] !== undefined) {
    const desc = agent["agent_descriptor"];
    if (!isObject(desc)) return fail("adr_agent_invalid_descriptor");
    if (!isNonEmptyString(desc["model"])) return fail("adr_agent_descriptor_missing_model");
    if (!isNonEmptyString(desc["model_version"])) return fail("adr_agent_descriptor_missing_model_version");
    if (!isNonEmptyString(desc["tool_set_hash"])) return fail("adr_agent_descriptor_missing_tool_set_hash");
  }
  return null;
}

// ── Authorizing-credential validation (grant-only, optional) ─────────────────
// Reference to an external authorizing artifact (e.g. an AP2 mandate), by id —
// receipt-*of*, never is-a. Shape-check only when present; absent or explicit
// null are both the graceful-degrade path. Mirrors AActR's optional
// `credential_id` handling (FAMILY-CONSISTENCY §1 chip 15).

function validateAuthorizingCredential(
  body: Record<string, unknown>,
): { ok: false; reason: string } | null {
  if (!("authorizing_credential" in body)) return null;
  const ac = body["authorizing_credential"];
  if (ac === null) return null;
  if (!isObject(ac)) return fail("adr_invalid_authorizing_credential");
  if (!isNonEmptyString(ac["scheme"])) return fail("adr_authorizing_credential_invalid_scheme");
  if (!isNonEmptyString(ac["id"])) return fail("adr_authorizing_credential_invalid_id");
  if (!isNonEmptyString(ac["type"])) return fail("adr_authorizing_credential_invalid_type");
  return null;
}

// ── Main validator ────────────────────────────────────────────────────────────

export const AdrBodySchema: BodyValidator<AdrBody> = {
  validate(body) {
    if (!isObject(body)) return fail("adr_body_not_object");
    if (!isAdrEventType(body["event"])) return fail("adr_unknown_event");
    if (!isAdrProfile(body["profile"])) return fail("adr_unknown_profile");

    const event = body["event"];

    switch (event) {
      case "grant": {
        const agentErr = validateAgent(body);
        if (agentErr) return agentErr;

        const scopeErr = validateScope(body);
        if (scopeErr) return scopeErr;

        if (typeof body["delegable"] !== "boolean") return fail("adr_missing_delegable");

        // expiry: number > 0 or null
        const expiry = body["expiry"];
        if (expiry !== null) {
          if (typeof expiry !== "number" || expiry <= 0) return fail("adr_grant_invalid_expiry");
        }

        if (!isNonEmptyString(body["rationale_uri"])) return fail("adr_missing_rationale_uri");
        if (!isNonEmptyString(body["rationale_hash"])) return fail("adr_missing_rationale_hash");

        // authorizing_credential: optional external-mandate reference (AP2 etc.)
        const acErr = validateAuthorizingCredential(body);
        if (acErr) return acErr;

        // reason_uri / reason_hash prohibited on grant
        if ("reason_uri" in body) return fail("adr_prohibited_field_reason_uri");
        if ("reason_hash" in body) return fail("adr_prohibited_field_reason_hash");
        if ("cascade" in body) return fail("adr_prohibited_field_cascade");
        break;
      }

      case "revoke": {
        // Prohibited: all grant-only fields
        for (const field of GRANT_ONLY_FIELDS) {
          if (field in body) return fail(`adr_prohibited_field_${field}`);
        }
        if ("cascade" in body) return fail("adr_prohibited_field_cascade");
        // reason_uri / reason_hash are optional — no validation needed
        break;
      }

      case "narrow": {
        // Prohibited: agent, delegable, expiry, rationale_uri, rationale_hash
        if ("agent" in body) return fail("adr_prohibited_field_agent");
        if ("delegable" in body) return fail("adr_prohibited_field_delegable");
        if ("expiry" in body) return fail("adr_prohibited_field_expiry");
        if ("rationale_uri" in body) return fail("adr_prohibited_field_rationale_uri");
        if ("rationale_hash" in body) return fail("adr_prohibited_field_rationale_hash");
        if ("authorizing_credential" in body) return fail("adr_prohibited_field_authorizing_credential");
        if ("reason_uri" in body) return fail("adr_prohibited_field_reason_uri");
        if ("reason_hash" in body) return fail("adr_prohibited_field_reason_hash");
        if ("cascade" in body) return fail("adr_prohibited_field_cascade");

        const scopeErr = validateScope(body);
        if (scopeErr) return scopeErr;
        break;
      }

      case "renew": {
        // Prohibited: agent, scope, delegable, rationale_uri, rationale_hash
        if ("agent" in body) return fail("adr_prohibited_field_agent");
        if ("scope" in body) return fail("adr_prohibited_field_scope");
        if ("delegable" in body) return fail("adr_prohibited_field_delegable");
        if ("rationale_uri" in body) return fail("adr_prohibited_field_rationale_uri");
        if ("rationale_hash" in body) return fail("adr_prohibited_field_rationale_hash");
        if ("authorizing_credential" in body) return fail("adr_prohibited_field_authorizing_credential");
        if ("reason_uri" in body) return fail("adr_prohibited_field_reason_uri");
        if ("reason_hash" in body) return fail("adr_prohibited_field_reason_hash");
        if ("cascade" in body) return fail("adr_prohibited_field_cascade");

        // expiry required, must be number > 0 (null NOT allowed)
        const expiry = body["expiry"];
        if (typeof expiry !== "number" || expiry <= 0) return fail("adr_renew_missing_expiry");
        break;
      }

      case "suspend": {
        // Prohibited: agent, scope, delegable, expiry, rationale_uri, rationale_hash
        if ("agent" in body) return fail("adr_prohibited_field_agent");
        if ("scope" in body) return fail("adr_prohibited_field_scope");
        if ("delegable" in body) return fail("adr_prohibited_field_delegable");
        if ("expiry" in body) return fail("adr_prohibited_field_expiry");
        if ("rationale_uri" in body) return fail("adr_prohibited_field_rationale_uri");
        if ("rationale_hash" in body) return fail("adr_prohibited_field_rationale_hash");
        if ("authorizing_credential" in body) return fail("adr_prohibited_field_authorizing_credential");

        // cascade optional but must be boolean if present
        if ("cascade" in body && typeof body["cascade"] !== "boolean") {
          return fail("adr_suspend_invalid_cascade");
        }
        // reason_uri / reason_hash optional — no validation needed
        break;
      }

      case "resume": {
        // Prohibited: all grant-only fields + reason_uri + reason_hash + cascade
        for (const field of GRANT_ONLY_FIELDS) {
          if (field in body) return fail(`adr_prohibited_field_${field}`);
        }
        if ("reason_uri" in body) return fail("adr_prohibited_field_reason_uri");
        if ("reason_hash" in body) return fail("adr_prohibited_field_reason_hash");
        if ("cascade" in body) return fail("adr_prohibited_field_cascade");
        break;
      }
    }

    return { ok: true, value: body as unknown as AdrBody };
  },
};
