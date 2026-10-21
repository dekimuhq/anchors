export type GuardCategory =
  | "instruction_override"
  | "system_prompt_leak"
  | "delimiter_injection"
  | "encoding_obfuscation"
  | "tool_hijack"
  | "jailbreak_template";

export type GuardSeverity = "info" | "warn" | "critical";
export type GuardDecision = "pass" | "flagged" | "blocked";

export const GUARD_CATEGORIES: readonly GuardCategory[] = [
  "instruction_override", "system_prompt_leak", "delimiter_injection",
  "encoding_obfuscation", "tool_hijack", "jailbreak_template",
] as const;
