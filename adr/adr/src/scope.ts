/**
 * ADR scope-subset engine (spec §7.3).
 *
 * Used by: chain walker (narrow validation) and tree walker (sub-delegation).
 */

import type { AdrScope, ScopeSubsetResult } from "./types.ts";

/**
 * Match a concrete value against a pattern with `*` wildcard segments.
 * `separator` splits into segments (`.` for actions, `:` for resources).
 *
 * - `*` at a position matches exactly one segment.
 * - Trailing `*` matches all remaining segments.
 * - Exact string equality when no wildcards.
 */
export function segmentMatch(
  pattern: string,
  value: string,
  separator: string,
): boolean {
  if (pattern === value) return true;
  const pParts = pattern.split(separator);
  const vParts = value.split(separator);

  for (let i = 0; i < pParts.length; i++) {
    if (pParts[i] === "*") {
      if (i === pParts.length - 1) return true; // trailing wildcard
      if (i >= vParts.length) return false;
      continue;
    }
    if (i >= vParts.length || pParts[i] !== vParts[i]) return false;
  }
  return pParts.length === vParts.length;
}

function actionsSubset(child: readonly string[], parent: readonly string[]): string[] {
  const reasons: string[] = [];
  for (const action of child) {
    const covered = parent.some((p) => segmentMatch(p, action, "."));
    if (!covered) reasons.push(`adr.action_not_covered:${action}`);
  }
  return reasons;
}

function resourcesSubset(child: readonly string[], parent: readonly string[]): string[] {
  const reasons: string[] = [];
  for (const resource of child) {
    const covered = parent.some((p) => segmentMatch(p, resource, ":"));
    if (!covered) reasons.push(`adr.resource_not_covered:${resource}`);
  }
  return reasons;
}

function constraintsSubset(
  child: Readonly<Record<string, unknown>>,
  parent: Readonly<Record<string, unknown>>,
): string[] {
  const reasons: string[] = [];
  for (const key of Object.keys(child)) {
    const childVal = child[key];
    const parentVal = parent[key];
    if (parentVal === undefined) continue; // child adds new constraint = narrowing, OK
    if (typeof childVal === "number" && typeof parentVal === "number") {
      if (childVal > parentVal) reasons.push(`adr.constraint_exceeded:${key}`);
      continue;
    }
    if (typeof childVal === "boolean" && typeof parentVal === "boolean") {
      if (childVal && !parentVal) reasons.push(`adr.constraint_widened:${key}`);
      continue;
    }
    if (typeof childVal === "string" && typeof parentVal === "string") {
      if (childVal !== parentVal) reasons.push(`adr.constraint_mismatch:${key}`);
      continue;
    }
    if (Array.isArray(childVal) && Array.isArray(parentVal)) {
      const parentSet = new Set(parentVal.map(String));
      for (const item of childVal) {
        if (!parentSet.has(String(item))) reasons.push(`adr.constraint_not_subset:${key}:${String(item)}`);
      }
      continue;
    }
    reasons.push(`adr.constraint_type_mismatch:${key}`);
  }
  return reasons;
}

export function isScopeSubset(child: AdrScope, parent: AdrScope): ScopeSubsetResult {
  const reasons: string[] = [
    ...actionsSubset(child.actions, parent.actions),
    ...resourcesSubset(child.resources, parent.resources),
    ...constraintsSubset(child.constraints, parent.constraints),
  ];
  return { ok: reasons.length === 0, reasons };
}
