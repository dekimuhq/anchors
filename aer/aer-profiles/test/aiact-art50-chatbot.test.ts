import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { validateAiactArt50Chatbot } from "../src/aiact-art50-chatbot.ts";

function makeTransparency(overrides?: Record<string, unknown>) {
  return {
    event_type: "transparency",
    profile: "aiact.art50.chatbot",
    system_id_commit: "sha256:abc",
    system_apr_kid: null,
    conformity_receipt_hash: "sha256:conf",
    subject_commit: "sha256:subj",
    disclosure_scope: "single",
    disclosure_type: "chatbot",
    disclosure_text_hash: "sha256:text",
    disclosure_locale: "en",
    interaction_window_start: "2026-08-02T10:00:00Z",
    interaction_window_end: "2026-08-02T10:30:00Z",
    artifact_apr_hash: null,
    oversight_acr_hash: null,
    watermark_scheme: "none",
    watermark_sample_commit: null,
    ...overrides,
  };
}

describe("validateAiactArt50Chatbot", () => {
  it("accepts a valid chatbot transparency receipt", () => {
    const result = validateAiactArt50Chatbot(makeTransparency() as never);
    assert.deepEqual(result.errors, []);
  });

  it("rejects wrong event_type", () => {
    const result = validateAiactArt50Chatbot(makeTransparency({ event_type: "conformity" }) as never);
    assert.ok(result.errors.includes("aiact.art50.chatbot.wrong_event_type"));
  });

  it("rejects wrong disclosure_type", () => {
    const result = validateAiactArt50Chatbot(makeTransparency({ disclosure_type: "synthetic_audio" }) as never);
    assert.ok(result.errors.includes("aiact.art50.chatbot.wrong_disclosure_type"));
  });

  it("rejects empty disclosure_text_hash", () => {
    const result = validateAiactArt50Chatbot(makeTransparency({ disclosure_text_hash: "" }) as never);
    assert.ok(result.errors.includes("aiact.art50.chatbot.disclosure_text_hash_missing"));
  });

  it("rejects empty disclosure_locale", () => {
    const result = validateAiactArt50Chatbot(makeTransparency({ disclosure_locale: "" }) as never);
    assert.ok(result.errors.includes("aiact.art50.chatbot.disclosure_locale_missing"));
  });

  it("rejects non-none watermark_scheme", () => {
    const result = validateAiactArt50Chatbot(makeTransparency({ watermark_scheme: "c2pa" }) as never);
    assert.ok(result.errors.includes("aiact.art50.chatbot.watermark_scheme_must_be_none"));
  });
});
