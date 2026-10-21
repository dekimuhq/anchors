import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { validateAiactArt50SyntheticMedia } from "../src/aiact-art50-synthetic-media.ts";

function makeTransparency(overrides?: Record<string, unknown>) {
  return {
    event_type: "transparency",
    profile: "aiact.art50.synthetic_media",
    system_id_commit: "sha256:abc",
    system_apr_kid: null,
    conformity_receipt_hash: "sha256:conf",
    subject_commit: "sha256:subj",
    disclosure_scope: "batch",
    disclosure_type: "synthetic_image",
    disclosure_text_hash: "sha256:text",
    disclosure_locale: "en",
    interaction_window_start: "2026-08-02T10:00:00Z",
    interaction_window_end: "2026-08-02T10:30:00Z",
    artifact_apr_hash: "sha256:artifact",
    oversight_acr_hash: null,
    watermark_scheme: "c2pa",
    watermark_sample_commit: "sha256:wmark",
    ...overrides,
  };
}

describe("validateAiactArt50SyntheticMedia", () => {
  it("accepts a valid synthetic media transparency receipt", () => {
    const result = validateAiactArt50SyntheticMedia(makeTransparency() as never);
    assert.deepEqual(result.errors, []);
  });

  it("accepts all valid synthetic media disclosure types", () => {
    const types = ["synthetic_audio", "synthetic_image", "synthetic_video", "deepfake_recognisable_person", "deepfake_artistic"];
    for (const disclosure_type of types) {
      const result = validateAiactArt50SyntheticMedia(makeTransparency({ disclosure_type }) as never);
      assert.deepEqual(result.errors, [], `disclosure_type=${disclosure_type} should be valid`);
    }
  });

  it("rejects wrong event_type", () => {
    const result = validateAiactArt50SyntheticMedia(makeTransparency({ event_type: "conformity" }) as never);
    assert.ok(result.errors.includes("aiact.art50.synthetic_media.wrong_event_type"));
  });

  it("rejects chatbot disclosure_type (wrong category)", () => {
    const result = validateAiactArt50SyntheticMedia(makeTransparency({ disclosure_type: "chatbot" }) as never);
    assert.ok(result.errors.includes("aiact.art50.synthetic_media.wrong_disclosure_type"));
  });

  it("rejects watermark_scheme=none", () => {
    const result = validateAiactArt50SyntheticMedia(makeTransparency({ watermark_scheme: "none" }) as never);
    assert.ok(result.errors.includes("aiact.art50.synthetic_media.watermark_scheme_required"));
  });

  it("rejects missing watermark_sample_commit", () => {
    const result = validateAiactArt50SyntheticMedia(makeTransparency({ watermark_sample_commit: null }) as never);
    assert.ok(result.errors.includes("aiact.art50.synthetic_media.watermark_sample_commit_missing"));
  });
});
