/**
 * TSA mandate matrix for ATR (FAMILY-CONSISTENCY.md §2).
 *
 * - arrangement → RECOMMENDED
 * - suspension → RECOMMENDED
 * - transfer → OPTIONAL
 * - tia → OPTIONAL
 */

export type TsaMandate = "mandatory" | "recommended" | "optional";

const ATR_TSA_MANDATE: Record<string, TsaMandate> = {
  arrangement: "recommended",
  suspension: "recommended",
  transfer: "optional",
  tia: "optional",
};

export function getAtrTsaMandate(eventType: string): TsaMandate {
  return ATR_TSA_MANDATE[eventType] ?? "optional";
}
