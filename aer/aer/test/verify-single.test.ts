import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { verifyAerBody } from "../src/verify-single.ts";
import { makeConformityBody, makeTransparencyBody } from "./_helpers/fixtures.ts";

describe("verifyAerBody", () => {
  describe("conformity", () => {
    it("accepts a valid conformity body", () => {
      const body = makeConformityBody();
      const r = verifyAerBody(body);
      assert.ok(r.valid);
      assert.deepStrictEqual(r.errors, []);
      assert.ok(r.body !== null);
    });

    it("rejects non-object body", () => {
      const r = verifyAerBody(null);
      assert.ok(!r.valid);
      assert.ok(r.errors.includes("body.not_object"));
    });

    it("rejects unknown event_type", () => {
      const r = verifyAerBody({ event_type: "bogus" });
      assert.ok(!r.valid);
      assert.ok(r.errors.includes("event_type.unknown"));
    });

    it("rejects missing system_id_commit", () => {
      const body = makeConformityBody();
      (body as unknown as Record<string, unknown>).system_id_commit = "";
      const r = verifyAerBody(body);
      assert.ok(!r.valid);
      assert.ok(r.errors.includes("system_id_commit.missing"));
    });

    it("rejects missing system_version", () => {
      const body = makeConformityBody();
      (body as unknown as Record<string, unknown>).system_version = "";
      const r = verifyAerBody(body);
      assert.ok(!r.valid);
      assert.ok(r.errors.includes("system_version.missing"));
    });

    it("rejects invalid risk_class", () => {
      const body = makeConformityBody();
      (body as unknown as Record<string, unknown>).risk_class = "invalid";
      const r = verifyAerBody(body);
      assert.ok(!r.valid);
      assert.ok(r.errors.includes("risk_class.invalid"));
    });

    it("rejects invalid assessment_route", () => {
      const body = makeConformityBody();
      (body as unknown as Record<string, unknown>).assessment_route = "invalid";
      const r = verifyAerBody(body);
      assert.ok(!r.valid);
      assert.ok(r.errors.includes("assessment_route.invalid"));
    });

    it("requires annex_iii_categories when risk_class=high", () => {
      const body = makeConformityBody({ risk_class: "high", annex_iii_categories: null });
      const r = verifyAerBody(body);
      assert.ok(!r.valid);
      assert.ok(r.errors.includes("annex_iii_categories.required_when_high_risk"));
    });

    it("allows null annex_iii_categories when risk_class is not high", () => {
      const body = makeConformityBody({ risk_class: "gpai", annex_iii_categories: null });
      const r = verifyAerBody(body);
      assert.ok(r.valid);
    });

    it("requires notified_body_id when assessment_route=thirdparty_notified_body", () => {
      const body = makeConformityBody({
        assessment_route: "thirdparty_notified_body",
        notified_body_id: null,
      });
      const r = verifyAerBody(body);
      assert.ok(!r.valid);
      assert.ok(r.errors.includes("notified_body_id.required_when_thirdparty"));
    });

    it("requires fundamental_rights_hash when assessment_route=fundamental_rights", () => {
      const body = makeConformityBody({
        assessment_route: "fundamental_rights",
        fundamental_rights_hash: null,
      });
      const r = verifyAerBody(body);
      assert.ok(!r.valid);
      assert.ok(r.errors.includes("fundamental_rights_hash.required_when_fr"));
    });

    it("rejects missing tech_doc_hash", () => {
      const body = makeConformityBody();
      (body as unknown as Record<string, unknown>).tech_doc_hash = "";
      const r = verifyAerBody(body);
      assert.ok(!r.valid);
      assert.ok(r.errors.includes("tech_doc_hash.missing"));
    });

    it("rejects missing valid_from", () => {
      const body = makeConformityBody();
      (body as unknown as Record<string, unknown>).valid_from = "";
      const r = verifyAerBody(body);
      assert.ok(!r.valid);
      assert.ok(r.errors.includes("valid_from.missing"));
    });
  });

  describe("transparency", () => {
    it("accepts a valid transparency body", () => {
      const body = makeTransparencyBody();
      const r = verifyAerBody(body);
      assert.ok(r.valid);
      assert.deepStrictEqual(r.errors, []);
    });

    it("rejects missing conformity_receipt_hash", () => {
      const body = makeTransparencyBody();
      (body as unknown as Record<string, unknown>).conformity_receipt_hash = "";
      const r = verifyAerBody(body);
      assert.ok(!r.valid);
      assert.ok(r.errors.includes("conformity_receipt_hash.missing"));
    });

    it("rejects invalid disclosure_scope", () => {
      const body = makeTransparencyBody();
      (body as unknown as Record<string, unknown>).disclosure_scope = "weekly";
      const r = verifyAerBody(body);
      assert.ok(!r.valid);
      assert.ok(r.errors.includes("disclosure_scope.invalid"));
    });

    it("rejects invalid disclosure_type", () => {
      const body = makeTransparencyBody();
      (body as unknown as Record<string, unknown>).disclosure_type = "fake_type";
      const r = verifyAerBody(body);
      assert.ok(!r.valid);
      assert.ok(r.errors.includes("disclosure_type.invalid"));
    });

    it("rejects missing disclosure_text_hash", () => {
      const body = makeTransparencyBody();
      (body as unknown as Record<string, unknown>).disclosure_text_hash = "";
      const r = verifyAerBody(body);
      assert.ok(!r.valid);
      assert.ok(r.errors.includes("disclosure_text_hash.missing"));
    });

    it("rejects missing disclosure_locale", () => {
      const body = makeTransparencyBody();
      (body as unknown as Record<string, unknown>).disclosure_locale = "";
      const r = verifyAerBody(body);
      assert.ok(!r.valid);
      assert.ok(r.errors.includes("disclosure_locale.missing"));
    });

    it("rejects missing interaction_window_start", () => {
      const body = makeTransparencyBody();
      (body as unknown as Record<string, unknown>).interaction_window_start = "";
      const r = verifyAerBody(body);
      assert.ok(!r.valid);
      assert.ok(r.errors.includes("interaction_window_start.missing"));
    });

    it("requires watermark_sample_commit when watermark_scheme != none", () => {
      const body = makeTransparencyBody({
        watermark_scheme: "c2pa",
        watermark_sample_commit: null,
      });
      const r = verifyAerBody(body);
      assert.ok(!r.valid);
      assert.ok(r.errors.includes("watermark_sample_commit.required_when_watermarked"));
    });

    it("accepts null watermark_sample_commit when watermark_scheme = none", () => {
      const body = makeTransparencyBody({
        watermark_scheme: "none",
        watermark_sample_commit: null,
      });
      const r = verifyAerBody(body);
      assert.ok(r.valid);
    });

    it("rejects invalid watermark_scheme", () => {
      const body = makeTransparencyBody();
      (body as unknown as Record<string, unknown>).watermark_scheme = "invalid";
      const r = verifyAerBody(body);
      assert.ok(!r.valid);
      assert.ok(r.errors.includes("watermark_scheme.invalid"));
    });
  });
});
