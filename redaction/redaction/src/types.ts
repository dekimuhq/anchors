export type {
  APIIRBody, APIIRClaimType, RedactionProfile,
  RedactionCategory, RedactionCounts,
} from "@dekimuhq/redaction-profiles";
import type { APIIRBody } from "@dekimuhq/redaction-profiles";
export interface VerifyBodyResult { valid: boolean; errors: string[]; body: APIIRBody | null; }
