// ar.compliance.v1 body verifier (spec §4). SHAPE ONLY — records references;
// never re-derives compliance or re-verifies constituents (that is the consumer's job).
import type {
  ComplianceBundleBody, BundleRef, GapDecl, NotApplicableDecl, ControllerIdentity, VerifyBodyResult,
} from "./types.ts";

const SHA256_RE = /^sha256:[0-9a-f]{64}$/;
const RFC3339_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

const isStr = (v: unknown): v is string => typeof v === "string" && v.length > 0;
const isSha = (v: unknown): v is string => typeof v === "string" && SHA256_RE.test(v);
const isNonNegInt = (v: unknown): v is number => typeof v === "number" && Number.isInteger(v) && v >= 0;
const isRatio = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v) && v >= 0 && v <= 1;
const isStrArr = (v: unknown): v is string[] => Array.isArray(v) && v.every((x) => typeof x === "string");

function controllerOk(v: unknown): v is ControllerIdentity {
  if (typeof v !== "object" || v === null) return false;
  const c = v as Record<string, unknown>;
  return isStr(c.entityName)
    && (c.registeredAddress === null || isStr(c.registeredAddress))
    && (c.contactEmail === null || isStr(c.contactEmail));
}

function refErrors(prefix: string, v: unknown, errors: string[]): void {
  if (typeof v !== "object" || v === null) { errors.push(`${prefix}.not_object`); return; }
  const r = v as Record<string, unknown>;
  if (!isStr(r.ref)) errors.push(`${prefix}.ref`);
  if (!isSha(r.contentHash)) errors.push(`${prefix}.contentHash`);
  if (!isStrArr(r.satisfiedObligations)) errors.push(`${prefix}.satisfiedObligations`);
  if (r.claimType !== undefined && !isStr(r.claimType)) errors.push(`${prefix}.claimType`);
}

const isGap = (v: unknown): v is GapDecl =>
  typeof v === "object" && v !== null && (v as Record<string, unknown>).status === "gap"
  && isStr((v as Record<string, unknown>).reason);
const isNA = (v: unknown): v is NotApplicableDecl =>
  typeof v === "object" && v !== null && (v as Record<string, unknown>).status === "not_applicable"
  && isStr((v as Record<string, unknown>).reason) && isStr((v as Record<string, unknown>).basis);

export function verifyComplianceBundleBody(body: unknown): VerifyBodyResult {
  const errors: string[] = [];
  if (typeof body !== "object" || body === null) return { valid: false, errors: ["body.not_object"], body: null };
  const b = body as Record<string, unknown>;

  if (b.profile !== "compliance.bundle") errors.push("profile.invalid");
  if (!isStr(b.workspaceId)) errors.push("workspaceId.missing");
  if (!controllerOk(b.controller)) errors.push("controller.invalid");

  const reg = b.regulation as Record<string, unknown> | undefined;
  if (typeof reg !== "object" || reg === null) errors.push("regulation.missing");
  else {
    if (reg.manifestId !== "gdpr") errors.push("regulation.manifestId");
    if (!isStr(reg.manifestVersion)) errors.push("regulation.manifestVersion");
    if (!isSha(reg.manifestHash)) errors.push("regulation.manifestHash");
  }

  const cov = b.coverage as Record<string, unknown> | undefined;
  if (typeof cov !== "object" || cov === null) errors.push("coverage.missing");
  else {
    if (!isNonNegInt(cov.applicable)) errors.push("coverage.applicable");
    if (!isNonNegInt(cov.satisfied)) errors.push("coverage.satisfied");
    if (!isRatio(cov.ratio)) errors.push("coverage.ratio");
    if (isNonNegInt(cov.applicable) && isNonNegInt(cov.satisfied) && (cov.satisfied as number) > (cov.applicable as number)) {
      errors.push("coverage.satisfied_exceeds_applicable");
    }
  }

  const con = b.constituents as Record<string, unknown> | undefined;
  if (typeof con !== "object" || con === null) errors.push("constituents.missing");
  else {
    if (isGap(con.ropa)) { /* ok */ } else refErrors("constituents.ropa", con.ropa, errors);
    if (isNA(con.dpia)) { /* ok */ }
    else if (Array.isArray(con.dpia)) con.dpia.forEach((d, i) => refErrors(`constituents.dpia[${i}]`, d, errors));
    else errors.push("constituents.dpia.invalid");
    refErrors("constituents.obligations", con.obligations, errors);
  }

  if (!isStr(b.generated_at)) errors.push("generated_at.missing");
  else if (!RFC3339_RE.test(b.generated_at) || Number.isNaN(Date.parse(b.generated_at))) errors.push("generated_at.invalid");

  if (errors.length > 0) return { valid: false, errors, body: null };
  return { valid: true, errors: [], body: b as unknown as ComplianceBundleBody };
}
