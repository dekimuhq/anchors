/**
 * ADR (Anchored Delegation Receipts) body-type definitions.
 *
 * Body shape — what goes in `Envelope.body` — plus the discriminated union
 * keyed on `event` that the verifier's per-event body validator dispatches
 * on, and the profile-id union the profile validators are keyed by.
 *
 * These types live in `@dekimuhq/adr-profiles` (not the verifier) so the
 * profile validators can import the body shape without depending on the
 * verifier package — the verifier imports profile *values* (`family.ts`), so a
 * profiles→verifier type edge would form an import cycle that blocks the
 * topological built-`dist` publish. `@dekimuhq/adr` re-exports every
 * symbol here, so its public API is unchanged for downstream consumers.
 *
 * Envelope-level fields (`v`, `id`, `claim_type`, `iss`, `iss_key`, `iat`,
 * `iat_ms`, `subject`, `policy_uri`, `policy_hash`, `policy_version`,
 * `field_root`, `prev`, `credentialStatus`, `tsa`, `anchor`, `sig`,
 * `countersig`, `countersig_key`, `kind`, `cause`, `predicate`) are provided by
 * `@dekimuhq/anchors-envelope` and are NOT repeated here.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/adr.
 */

// ── Claim type ────────────────────────────────────────────────────────────────

export type AdrClaimType = "ar.delegation.v1";

// ── Event types (spec §4.2, D11-ADR) ──────────────────────────────────────────

export type AdrEventType =
  | "grant"
  | "revoke"
  | "narrow"
  | "renew"
  | "suspend"
  | "resume";

// ── Profiles (spec §5, D15-ADR) ──────────────────────────────────────────────

export type AdrProfile =
  | "aiact.art26.deployer"
  | "aiact.art14.oversight"
  | "agentops.scoped-delegation"
  | "gdpr.art28.processor"
  | "gdpr.dsr.authorised-agent"
  | "corporate.officer";

// ── Scope (spec §4.2 + §7.3, D13-ADR) ──────────────────────────────────────

export interface AdrScope {
  readonly actions: readonly string[];
  readonly resources: readonly string[];
  readonly constraints: Readonly<Record<string, unknown>>;
}

// ── Agent (spec §4.2, D14-ADR) ──────────────────────────────────────────────

export interface AdrAgentDescriptor {
  readonly model: string;
  readonly model_version: string;
  readonly tool_set_hash: string;
}

export interface AdrAgent {
  readonly agent_id: string;
  readonly agent_pubkey: string | null;
  readonly agent_descriptor: AdrAgentDescriptor | null;
}

// ── Authorizing credential (spec §4.2, AP2 interop — additive, optional) ──────

/**
 * OPTIONAL reference to the external credential that authorized this delegation.
 *
 * This is a *reference by identifier* to an authorizing artifact issued by
 * another ecosystem — NOT an embedded credential and NOT a claim of
 * shape-equivalence. The canonical example is an AP2 mandate (SD-JWT-VC): the
 * ADR records the *receipt-of* obligations around an AP2-authorized action; it
 * is never itself an AP2 mandate. See `meta/STANDARDS-BRIDGE.md` §2d.
 *
 * `scheme` names the external system (e.g. `"ap2"`), `type` names the artifact
 * within it (e.g. `"payment-mandate"`), and `id` is the opaque identifier that
 * artifact travels under (e.g. AP2's `payment_mandate_id` / SD-JWT `jti`). No
 * field carries shape or crypto — this is a pointer, resolved and verified
 * out-of-band against the authorizing system.
 *
 * Additive + optional: pre-existing grant receipts omit the key entirely and
 * verify byte-equal. Grant-only — prohibited on non-grant events.
 */
export interface AdrAuthorizingCredential {
  readonly scheme: string;
  readonly id: string;
  readonly type: string;
}

// ── Body variants (discriminated union on event) ────────────────────────────

export interface AdrGrantBody {
  readonly event: "grant";
  readonly profile: AdrProfile;
  readonly agent: AdrAgent;
  readonly scope: AdrScope;
  readonly delegable: boolean;
  readonly expiry: number | null;
  readonly rationale_uri: string;
  readonly rationale_hash: string;
  /** SHA-256 hash of an AAR receipt attesting QTS posture. `null` when absent. */
  readonly qts_attestation_hash: string | null;
  /**
   * OPTIONAL reference to the external credential that authorized this
   * delegation (e.g. an AP2 mandate, referenced by id — receipt-*of*, never
   * is-a). Absent on receipts that record no external authorization; `null` is
   * also accepted as an explicit "no authorizing credential." Grant-only.
   * See `AdrAuthorizingCredential` + `meta/STANDARDS-BRIDGE.md` §2d.
   */
  readonly authorizing_credential?: AdrAuthorizingCredential | null;
}

export interface AdrRevokeBody {
  readonly event: "revoke";
  readonly profile: AdrProfile;
  readonly reason_uri?: string;
  readonly reason_hash?: string;
  /** SHA-256 hash of an AAR receipt attesting QTS posture. `null` when absent. */
  readonly qts_attestation_hash: string | null;
}

export interface AdrNarrowBody {
  readonly event: "narrow";
  readonly profile: AdrProfile;
  readonly scope: AdrScope;
  /** SHA-256 hash of an AAR receipt attesting QTS posture. `null` when absent. */
  readonly qts_attestation_hash: string | null;
}

export interface AdrRenewBody {
  readonly event: "renew";
  readonly profile: AdrProfile;
  readonly expiry: number;
  /** SHA-256 hash of an AAR receipt attesting QTS posture. `null` when absent. */
  readonly qts_attestation_hash: string | null;
}

export interface AdrSuspendBody {
  readonly event: "suspend";
  readonly profile: AdrProfile;
  readonly reason_uri?: string;
  readonly reason_hash?: string;
  readonly cascade?: boolean;
  /** SHA-256 hash of an AAR receipt attesting QTS posture. `null` when absent. */
  readonly qts_attestation_hash: string | null;
}

export interface AdrResumeBody {
  readonly event: "resume";
  readonly profile: AdrProfile;
  /** SHA-256 hash of an AAR receipt attesting QTS posture. `null` when absent. */
  readonly qts_attestation_hash: string | null;
}

export type AdrBody =
  | AdrGrantBody
  | AdrRevokeBody
  | AdrNarrowBody
  | AdrRenewBody
  | AdrSuspendBody
  | AdrResumeBody;
