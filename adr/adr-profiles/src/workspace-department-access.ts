/**
 * `workspace.department-access` profile validator — ADR spec section 5.
 *
 * Hook: a workspace owner or admin (or a department admin) changes what one
 * workspace member may do inside one named department of that workspace —
 * `none`, `read`, `write` or `admin`. Each change is one point-in-time record
 * of the transition `previous_level -> new_level`.
 *
 * WHAT THIS IS NOT. This is an access-control record. It states that an
 * application's permission check was told to behave differently for a member;
 * it is NOT cryptographic separation. A receipt under this profile says nothing
 * about whether a member who bypasses the application could still read the
 * department's data. It is also not one of the AI-agent profiles (the delegate
 * is a person, not an autonomous agent), not a corporate-officer authority
 * (no monetary limit), and not a GDPR mandate.
 *
 * PRIVACY. The body carries opaque ids only: the workspace, the delegator, the
 * delegate and the department key. It MUST NOT carry names or email addresses.
 * The validator enforces what a machine can: every id must match a restrictive
 * opaque-id shape (no `@`, no whitespace, no dots), and `scope.constraints` is
 * closed — any key outside the list below is rejected, so a name cannot ride
 * along in a stray field. A shape check is not a PII detector: an issuer that
 * uses a person's name as an id defeats it, so ids SHOULD be random identifiers.
 *
 * SHAPE. Every record is a standalone `grant` event (`prev` is null): the
 * ADR `revoke` / `narrow` bodies cannot carry the transition fields, and a
 * per-member chain would force the issuer to track receipt ids. A change to
 * `none` is therefore a `grant` whose `new_level` is `none`, not a `revoke`.
 * Non-grant events are rejected under this profile.
 *
 * v1 invariants enforced here:
 *   - `body.event` MUST be `grant`.
 *   - `body.delegable` MUST be `false`; `body.expiry` MUST be `null` (a level
 *     holds until the next record changes it).
 *   - `body.agent.agent_id` MUST be an opaque id (the delegate member);
 *     `agent_pubkey` and `agent_descriptor` MUST be `null` (a member is not a
 *     key holder or an AI agent).
 *   - `body.scope.actions` MUST be exactly `["department-access.<new_level>"]`
 *     and `body.scope.resources` exactly `["department:<department_key>"]`,
 *     consistent with the constraints below.
 *   - `body.scope.constraints` MUST contain exactly these keys, no others:
 *       `workspace_id`    opaque id
 *       `department_key`  lowercase slug, `^[a-z0-9]+(-[a-z0-9]+)*$`, <= 64
 *                         chars. Deliberately NOT a closed enum: departments
 *                         are added by the issuer without a profile release.
 *       `delegator_id`    opaque id of who made the change, or `system` for an
 *                         automatic cleanup no person asked for
 *       `delegator_role`  `owner | admin | member | system` (`member` = a
 *                         department admin acting inside their department)
 *       `delegate_role`   `owner | admin | member | viewer`: the delegate's
 *                         workspace role at the time; `null` only when
 *                         `reason` is `member-removed` (the role is gone)
 *       `previous_level`  `none | read | write | admin`
 *       `new_level`       `none | read | write | admin`, MUST differ from
 *                         `previous_level` (a no-op mints nothing)
 *       `reason`          `set | member-removed | role-changed`
 *       `effective_at`    UTC timestamp `YYYY-MM-DDTHH:MM:SS(.fff)?Z`
 *   - Semantic rules, taken from the department-access model:
 *       * `delegate_role` of `owner` or `admin` has full access and no
 *         per-department rows, so `new_level` MUST be `none`.
 *       * `delegate_role` of `viewer` is capped: `new_level` MUST be `none` or
 *         `read` (the workspace role is the ceiling, never exceeded).
 *       * `reason` `member-removed` MUST end at `none`.
 *       * `reason` `set` MUST NOT have `delegator_role` `system`.
 *       * `delegator_role` `system` MUST carry `delegator_id` `system`, and
 *         `delegator_id` `system` MUST carry `delegator_role` `system`.
 *       * A department admin (`delegator_role` `member`) MUST NOT set
 *         `new_level` `admin`; only an owner or admin can.
 *
 * The envelope `subject` (a `sha256:` commit, required by the ADR family) is
 * outside the body and not checked here; issuers SHOULD derive it from the
 * workspace and delegate ids so a delegate's records can be listed together
 * without revealing either id.
 */

import type { AdrBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const WORKSPACE_DEPARTMENT_ACCESS_PROFILE_ID =
  "workspace.department-access" as const;

/** Opaque id: no `@`, no whitespace, no dots. Random identifiers fit. */
const OPAQUE_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;

/** Lowercase slug, hyphen-separated segments, at most 64 chars. */
const DEPARTMENT_KEY_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const DEPARTMENT_KEY_MAX = 64;

/** UTC instant, second or millisecond precision. */
const EFFECTIVE_AT_RE =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,3})?Z$/;

const LEVELS = ["none", "read", "write", "admin"] as const;
const REASONS = ["set", "member-removed", "role-changed"] as const;
const DELEGATOR_ROLES = ["owner", "admin", "member", "system"] as const;
const DELEGATE_ROLES = ["owner", "admin", "member", "viewer"] as const;

/** The only keys `scope.constraints` may carry. */
const CONSTRAINT_KEYS = [
  "workspace_id",
  "department_key",
  "delegator_id",
  "delegator_role",
  "delegate_role",
  "previous_level",
  "new_level",
  "reason",
  "effective_at",
] as const;

const P = WORKSPACE_DEPARTMENT_ACCESS_PROFILE_ID;

function isOneOf<T extends string>(
  list: readonly T[],
  v: unknown,
): v is T {
  return typeof v === "string" && (list as readonly string[]).includes(v);
}

function isOpaqueId(v: unknown): v is string {
  return typeof v === "string" && OPAQUE_ID_RE.test(v);
}

function isValidInstant(v: unknown): boolean {
  if (typeof v !== "string") return false;
  const m = EFFECTIVE_AT_RE.exec(v);
  if (!m) return false;
  const [y, mo, d, h, mi, s] = m.slice(1, 7).map(Number) as [
    number, number, number, number, number, number,
  ];
  if (mo < 1 || mo > 12 || h > 23 || mi > 59 || s > 59) return false;
  const dt = new Date(Date.UTC(y, mo - 1, d));
  return dt.getUTCFullYear() === y && dt.getUTCMonth() === mo - 1 && dt.getUTCDate() === d;
}

export function validateWorkspaceDepartmentAccess(
  body: AdrBody,
): ProfileValidationResult {
  const errors: string[] = [];

  if (body.event !== "grant") {
    errors.push(`${P}.event_must_be_grant`);
    return { errors };
  }

  const b = body as unknown as Record<string, unknown>;

  if (b["delegable"] !== false) errors.push(`${P}.delegable_must_be_false`);
  if (b["expiry"] !== null) errors.push(`${P}.expiry_must_be_null`);

  // The delegate is a member, identified only by an opaque id.
  const agent = b["agent"] as Record<string, unknown> | undefined;
  if (!isOpaqueId(agent?.["agent_id"])) {
    errors.push(`${P}.delegate_id_invalid`);
  }
  if (agent?.["agent_pubkey"] !== null) {
    errors.push(`${P}.agent_pubkey_must_be_null`);
  }
  if (agent?.["agent_descriptor"] !== null) {
    errors.push(`${P}.agent_descriptor_must_be_null`);
  }

  const scope = b["scope"] as Record<string, unknown> | undefined;
  const c = scope?.["constraints"] as Record<string, unknown> | undefined;

  if (c === undefined || c === null || typeof c !== "object" || Array.isArray(c)) {
    errors.push(`${P}.constraints_missing`);
    return { errors };
  }

  // Closed key set: nothing outside the list (no names, no emails) rides along.
  for (const k of Object.keys(c)) {
    if (!(CONSTRAINT_KEYS as readonly string[]).includes(k)) {
      errors.push(`${P}.constraints_unknown_key`);
      break;
    }
  }

  const workspaceId = c["workspace_id"];
  if (!isOpaqueId(workspaceId)) errors.push(`${P}.workspace_id_invalid`);

  const department = c["department_key"];
  const departmentOk =
    typeof department === "string" &&
    department.length <= DEPARTMENT_KEY_MAX &&
    DEPARTMENT_KEY_RE.test(department);
  if (!departmentOk) errors.push(`${P}.department_key_invalid`);

  const delegatorId = c["delegator_id"];
  if (!isOpaqueId(delegatorId)) errors.push(`${P}.delegator_id_invalid`);

  const delegatorRole = c["delegator_role"];
  if (!isOneOf(DELEGATOR_ROLES, delegatorRole)) {
    errors.push(`${P}.delegator_role_invalid`);
  }

  const previous = c["previous_level"];
  const next = c["new_level"];
  const reason = c["reason"];
  if (!isOneOf(LEVELS, previous)) errors.push(`${P}.previous_level_invalid`);
  if (!isOneOf(LEVELS, next)) errors.push(`${P}.new_level_invalid`);
  if (!isOneOf(REASONS, reason)) errors.push(`${P}.reason_invalid`);

  // delegate_role: a workspace role, or null only once the member is gone.
  const delegateRole = c["delegate_role"];
  if (delegateRole === null) {
    if (reason !== "member-removed") errors.push(`${P}.delegate_role_required`);
  } else if (!isOneOf(DELEGATE_ROLES, delegateRole)) {
    errors.push(`${P}.delegate_role_invalid`);
  }

  if (!isValidInstant(c["effective_at"])) errors.push(`${P}.effective_at_invalid`);

  // Actions / resources restate the constraints; they must agree.
  const actions = scope?.["actions"];
  if (
    isOneOf(LEVELS, next) &&
    !(
      Array.isArray(actions) &&
      actions.length === 1 &&
      actions[0] === `department-access.${next}`
    )
  ) {
    errors.push(`${P}.actions_mismatch`);
  }
  const resources = scope?.["resources"];
  if (
    departmentOk &&
    !(
      Array.isArray(resources) &&
      resources.length === 1 &&
      resources[0] === `department:${department as string}`
    )
  ) {
    errors.push(`${P}.resources_mismatch`);
  }

  // Semantic rules (only when the inputs they read are themselves valid).
  if (isOneOf(LEVELS, previous) && isOneOf(LEVELS, next) && previous === next) {
    errors.push(`${P}.level_unchanged`);
  }
  if (
    isOneOf(LEVELS, next) &&
    (delegateRole === "owner" || delegateRole === "admin") &&
    next !== "none"
  ) {
    errors.push(`${P}.full_access_role_has_no_level`);
  }
  if (
    isOneOf(LEVELS, next) &&
    delegateRole === "viewer" &&
    next !== "none" &&
    next !== "read"
  ) {
    errors.push(`${P}.level_exceeds_role_ceiling`);
  }
  if (reason === "member-removed" && isOneOf(LEVELS, next) && next !== "none") {
    errors.push(`${P}.removal_must_end_at_none`);
  }
  if (reason === "set" && delegatorRole === "system") {
    errors.push(`${P}.set_requires_person_delegator`);
  }
  if (
    isOneOf(DELEGATOR_ROLES, delegatorRole) &&
    typeof delegatorId === "string" &&
    (delegatorRole === "system") !== (delegatorId === "system")
  ) {
    errors.push(`${P}.system_delegator_inconsistent`);
  }
  if (delegatorRole === "member" && next === "admin") {
    errors.push(`${P}.department_admin_cannot_grant_admin`);
  }

  return { errors };
}

export const validateWorkspaceDepartmentAccessProfile = makeProfileAdapter(
  WORKSPACE_DEPARTMENT_ACCESS_PROFILE_ID,
  (body) => validateWorkspaceDepartmentAccess(body as AdrBody),
);
