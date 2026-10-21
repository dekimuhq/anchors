/**
 * Tests for the tokenization.pci.dss_v4 profile validator (ATokR §5.3).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import type { AtokrBody } from "@dekimuhq/atokr";
import {
  PCI_DSS_V4_PROFILE_ID,
  validatePciDssV4,
  validatePciDssV4Profile,
} from "../src/pci-dss-v4.ts";

function makeBody(overrides?: Record<string, unknown>): AtokrBody {
  return {
    event_type: "token.issued",
    token_id: "tok_123",
    format_class: "pan",
    scope: {
      audience: "a",
      purpose: "p",
      valid_from: "2026-01-01T00:00:00Z",
      valid_until: null,
      single_use: false,
    },
    rotation_of: null,
    redemption_audit_ref: null,
    asr_ref: null,
    arr_ref: null,
    alr_ref: null,
    apur_ref: null,
    pci_environment: "cde",
    ...overrides,
  } as AtokrBody;
}

test("pci-dss-v4: valid pan body with cde environment passes", () => {
  const out = validatePciDssV4(makeBody());
  assert.deepEqual(out.errors, []);
});

test("pci-dss-v4: valid pan body with connected environment passes", () => {
  const out = validatePciDssV4(makeBody({ pci_environment: "connected" }));
  assert.deepEqual(out.errors, []);
});

test("pci-dss-v4: valid pan body with out_of_scope environment passes", () => {
  const out = validatePciDssV4(makeBody({ pci_environment: "out_of_scope" }));
  assert.deepEqual(out.errors, []);
});

test("pci-dss-v4: non-pan format_class produces format_class_mismatch", () => {
  const out = validatePciDssV4(makeBody({ format_class: "email" }));
  assert.ok(
    out.errors.includes("tokenization.pci.dss_v4.format_class_mismatch"),
  );
});

test("pci-dss-v4: invalid pci_environment value produces .invalid error", () => {
  const out = validatePciDssV4(
    makeBody({ pci_environment: "unknown_env" }),
  );
  assert.ok(
    out.errors.includes("tokenization.pci.dss_v4.pci_environment.invalid"),
  );
});

test("pci-dss-v4: missing pci_environment produces .invalid error", () => {
  const body = makeBody();
  const b = body as unknown as Record<string, unknown>;
  delete b["pci_environment"];
  const out = validatePciDssV4(body);
  assert.ok(
    out.errors.includes("tokenization.pci.dss_v4.pci_environment.invalid"),
  );
});

// ── Adapter ──────────────────────────────────────────────────────────────────

test("pci-dss-v4 adapter: ok=true on valid body", () => {
  const out = validatePciDssV4Profile({} as never, makeBody(), {});
  assert.equal(out.profile_id, PCI_DSS_V4_PROFILE_ID);
  assert.equal(out.ok, true);
  assert.equal(out.reason, undefined);
});

test("pci-dss-v4 adapter: ok=false with reason on format_class_mismatch", () => {
  const out = validatePciDssV4Profile(
    {} as never,
    makeBody({ format_class: "email" }),
    {},
  );
  assert.equal(out.ok, false);
  assert.equal(out.reason, "tokenization.pci.dss_v4.format_class_mismatch");
});
