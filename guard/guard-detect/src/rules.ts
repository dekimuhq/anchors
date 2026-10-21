import type { GuardCategory, GuardSeverity, GuardDecision } from "./categories.ts";

export interface GuardRule {
  id: string;
  category: GuardCategory;
  severity: GuardSeverity;
  pattern: string;   // regex source, serialised into ruleset_hash
  flags?: string;    // default "i"
}

export const RULESET_ID = "dekimu/prompt-guard";
export const RULESET_VERSION = "1.0.0";

export const DECISION_POLICY: Record<GuardSeverity, GuardDecision> = {
  info: "pass",
  warn: "flagged",
  critical: "blocked",
};

export const RULES: readonly GuardRule[] = [
  { id: "io.ignore-previous.v1", category: "instruction_override", severity: "critical",
    pattern: "ignore\\s+(all\\s+|the\\s+)?(previous|prior|above)\\s+(instructions?|prompts?|rules?)" },
  { id: "io.disregard.v1", category: "instruction_override", severity: "critical",
    pattern: "disregard\\s+(the\\s+)?(system|previous|above)\\s+(prompt|instructions?)" },
  { id: "io.you-are-now.v1", category: "instruction_override", severity: "warn",
    pattern: "you\\s+are\\s+now\\s+(a|an|in)\\s+" },
  { id: "spl.reveal-prompt.v1", category: "system_prompt_leak", severity: "critical",
    pattern: "(reveal|print|repeat|show)\\s+(me\\s+)?(your|the)\\s+(system\\s+)?(prompt|instructions?)" },
  { id: "spl.what-instructions.v1", category: "system_prompt_leak", severity: "warn",
    pattern: "what\\s+(are|were)\\s+your\\s+(initial|original|system)\\s+instructions?" },
  { id: "di.role-marker.v1", category: "delimiter_injection", severity: "warn",
    pattern: "<\\|?(system|assistant|user)\\|?>|\\[/?(INST|SYS)\\]" },
  { id: "di.end-of-prompt.v1", category: "delimiter_injection", severity: "warn",
    pattern: "(###\\s+)?(end\\s+of|begin)\\s+(system\\s+)?prompt" },
  { id: "eo.base64-blob.v1", category: "encoding_obfuscation", severity: "info",
    pattern: "(?:[A-Za-z0-9+/]{40,}={0,2})", flags: "" },
  { id: "eo.zero-width.v1", category: "encoding_obfuscation", severity: "warn",
    pattern: "[\\u200b\\u200c\\u200d\\ufeff]", flags: "" },
  { id: "th.call-tool.v1", category: "tool_hijack", severity: "warn",
    pattern: "(call|invoke|execute)\\s+(the\\s+)?(function|tool|api)\\s+" },
  { id: "th.exfiltrate.v1", category: "tool_hijack", severity: "critical",
    pattern: "(send|post|exfiltrate|leak)\\s+(all\\s+)?(data|secrets|keys|env)\\s+to\\s+(https?://|\\S+@|\\S+\\.[a-z]{2,})" },
  { id: "jt.dan.v1", category: "jailbreak_template", severity: "critical",
    pattern: "\\bDAN\\b", flags: "" },
  { id: "jt.jailbreak-mode.v1", category: "jailbreak_template", severity: "critical",
    pattern: "do anything now|developer mode" },
  { id: "jt.hypothetical.v1", category: "jailbreak_template", severity: "warn",
    pattern: "hypothetically,?\\s+(if\\s+)?you\\s+(had\\s+no|were\\s+not\\s+bound\\s+by)\\s+(rules|restrictions|guidelines)" },
];
