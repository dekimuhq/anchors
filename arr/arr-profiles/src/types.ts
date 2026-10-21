/**
 * Shared descriptor types for ARR v1 profile mandate enforcement.
 * Phase D Task 21.
 */

/**
 * Declarative descriptor attached to each regulation profile.
 * TSA mandate fields added in Task 21 — other descriptor fields (id, name, etc.)
 * can be added additively in future tasks without breaking existing profiles.
 */
export interface ProfileDescriptor {
  /** If true, a TSA block must be present in the receipt. */
  requires_tsa?: boolean;
  /** If true, the TSA must appear in the EUTL (EU Trusted List). */
  requires_tsa_listed?: boolean;
  /** If set, the TSA's policy OID must match exactly. */
  requires_tsa_policy_oid?: string;
}
