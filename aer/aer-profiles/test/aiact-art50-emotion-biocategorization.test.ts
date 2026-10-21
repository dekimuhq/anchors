import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { validateAiactArt50EmotionBiocategorization } from "../src/aiact-art50-emotion-biocategorization.ts";

function makeTransparency(overrides?: Record<string, unknown>) {
  return {
    event_type: "transparency",
    profile: "aiact.art50.emotion_biocategorization",
    system_id_commit: "sha256:abc",
    system_apr_kid: null,
    conformity_receipt_hash: "sha256:conf",
    subject_commit: "sha256:subj",
    disclosure_scope: "single",
    disclosure_type: "emotion_recognition",
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

describe("validateAiactArt50EmotionBiocategorization", () => {
  it("accepts emotion_recognition disclosure", () => {
    const result = validateAiactArt50EmotionBiocategorization(makeTransparency() as never);
    assert.deepEqual(result.errors, []);
  });

  it("accepts biometric_categorisation disclosure", () => {
    const result = validateAiactArt50EmotionBiocategorization(
      makeTransparency({ disclosure_type: "biometric_categorisation" }) as never,
    );
    assert.deepEqual(result.errors, []);
  });

  it("rejects wrong event_type", () => {
    const result = validateAiactArt50EmotionBiocategorization(makeTransparency({ event_type: "conformity" }) as never);
    assert.ok(result.errors.includes("aiact.art50.emotion_biocategorization.wrong_event_type"));
  });

  it("rejects chatbot disclosure_type (wrong category)", () => {
    const result = validateAiactArt50EmotionBiocategorization(makeTransparency({ disclosure_type: "chatbot" }) as never);
    assert.ok(result.errors.includes("aiact.art50.emotion_biocategorization.wrong_disclosure_type"));
  });

  it("rejects synthetic_image disclosure_type (different profile's concern)", () => {
    const result = validateAiactArt50EmotionBiocategorization(makeTransparency({ disclosure_type: "synthetic_image" }) as never);
    assert.ok(result.errors.includes("aiact.art50.emotion_biocategorization.wrong_disclosure_type"));
  });
});
