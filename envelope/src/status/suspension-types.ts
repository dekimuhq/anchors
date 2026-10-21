/**
 * SuspensionCheck — discriminated result type for suspension status verification.
 *
 * Wave 3. Mirrors StatusCheck but with suspension-specific terminal states.
 * bit=1 → suspended. bit=0 → not_suspended.
 */

export type SuspensionCheck =
  | { state: "not_attempted" }
  | { state: "no_suspension_pointer" }
  | { state: "invalid_pointer"; reason: string }
  | { state: "unreachable"; reason: string }
  | { state: "list_signature_invalid" }
  | { state: "list_mismatch"; reason: string }
  | { state: "not_suspended"; fresh_until: number; status_list_id: string }
  | {
      state: "not_suspended_stale";
      fresh_until: number;
      status_list_id: string;
      cached_age_sec: number;
      warnings: ["status_stale"];
    }
  | { state: "suspended"; fresh_until: number; status_list_id: string }
  | {
      state: "suspended_stale";
      fresh_until: number;
      status_list_id: string;
      cached_age_sec: number;
      warnings: readonly ["status_stale", ...string[]];
    };
