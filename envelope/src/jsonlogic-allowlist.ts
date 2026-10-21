/**
 * Pinned JSON Logic operator allowlist for v1.2 envelope predicates.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/envelope §5.1
 * Lock: L5 (operators outside this set make the receipt invalid) +
 *       L7 (pinned + exported; member specs reference by version, never re-list).
 *
 * Total: 22 operators across equality (4), boolean (4), ordering (4),
 * arithmetic (5), conditional (1), set/membership (4), data access (3),
 * bounds (2). Standard JSON Logic operators only — no custom or extension
 * operators (L8).
 */

export const JSON_LOGIC_ALLOWLIST_V1_2 = [
  // Equality (4)
  "==",
  "===",
  "!=",
  "!==",
  // Boolean (4)
  "!",
  "!!",
  "and",
  "or",
  // Ordering (4)
  ">",
  ">=",
  "<",
  "<=",
  // Arithmetic (5)
  "+",
  "-",
  "*",
  "/",
  "%",
  // Conditional (1)
  "if",
  // Set / membership (4)
  "in",
  "all",
  "none",
  "some",
  // Data access (3)
  "var",
  "missing",
  "missing_some",
  // Bounds (2)
  "min",
  "max",
] as const satisfies readonly string[];

/** Operator string-literal union derived from the allowlist. */
export type JsonLogicOperator = (typeof JSON_LOGIC_ALLOWLIST_V1_2)[number];
