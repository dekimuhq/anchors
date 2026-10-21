import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { validateAiactArt50PublicText } from "../src/aiact-art50-public-text.ts";

function makeTransparency(overrides?: Record<string, unknown>) {
  return {
    event_type: "transparency",
    profile: "aiact.art50.public_text",
    system_id_commit: "sha256:abc",
    system_apr_kid: null,
    conformity_receipt_hash: "sha256:conf",
    subject_commit: "sha256:subj",
    disclosure_scope: "batch",
    disclosure_type: "ai_generated_text_public_interest",
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

describe("validateAiactArt50PublicText", () => {
  it("accepts a valid public-interest text transparency receipt", () => {
    const result = validateAiactArt50PublicText(makeTransparency() as never);
    assert.deepEqual(result.errors, []);
  });

  it("rejects wrong event_type", () => {
    const result = validateAiactArt50PublicText(makeTransparency({ event_type: "conformity" }) as never);
    assert.ok(result.errors.includes("aiact.art50.public_text.wrong_event_type"));
  });

  it("rejects wrong disclosure_type", () => {
    const result = validateAiactArt50PublicText(makeTransparency({ disclosure_type: "chatbot" }) as never);
    assert.ok(result.errors.includes("aiact.art50.public_text.wrong_disclosure_type"));
  });

  it("rejects empty disclosure_text_hash", () => {
    const result = validateAiactArt50PublicText(makeTransparency({ disclosure_text_hash: "" }) as never);
    assert.ok(result.errors.includes("aiact.art50.public_text.disclosure_text_hash_missing"));
  });
});
