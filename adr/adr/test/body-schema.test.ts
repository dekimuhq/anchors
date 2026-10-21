/**
 * Tests for `AdrBodySchema` — per-event required/prohibited field validation.
 *
 * Covers all 6 event types: grant, revoke, narrow, renew, suspend, resume.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { AdrBodySchema } from "../src/body-schema.ts";

// ── Fixtures ──────────────────────────────────────────────────────────────────

const VALID_SCOPE = {
  actions: ["read", "write"],
  resources: ["doc:*"],
  constraints: { max_calls: 100 },
};

const VALID_AGENT = {
  agent_id: "agent-abc-123",
  agent_pubkey: null,
  agent_descriptor: null,
};

const VALID_AGENT_WITH_DESCRIPTOR = {
  agent_id: "agent-abc-123",
  agent_pubkey: "pubkey-base64==",
  agent_descriptor: {
    model: "claude-opus-4",
    model_version: "2026-05-01",
    tool_set_hash: "sha256:abcdef0123456789",
  },
};

function grantBody(overrides: Record<string, unknown> = {}) {
  return {
    event: "grant",
    profile: "agentops.scoped-delegation",
    agent: VALID_AGENT,
    scope: VALID_SCOPE,
    delegable: false,
    expiry: 1800000,
    rationale_uri: "https://example.com/rationale",
    rationale_hash: "sha256:deadbeef",
    ...overrides,
  };
}

function revokeBody(overrides: Record<string, unknown> = {}) {
  return {
    event: "revoke",
    profile: "agentops.scoped-delegation",
    ...overrides,
  };
}

function narrowBody(overrides: Record<string, unknown> = {}) {
  return {
    event: "narrow",
    profile: "agentops.scoped-delegation",
    scope: VALID_SCOPE,
    ...overrides,
  };
}

function renewBody(overrides: Record<string, unknown> = {}) {
  return {
    event: "renew",
    profile: "agentops.scoped-delegation",
    expiry: 3600000,
    ...overrides,
  };
}

function suspendBody(overrides: Record<string, unknown> = {}) {
  return {
    event: "suspend",
    profile: "agentops.scoped-delegation",
    ...overrides,
  };
}

function resumeBody(overrides: Record<string, unknown> = {}) {
  return {
    event: "resume",
    profile: "agentops.scoped-delegation",
    ...overrides,
  };
}

// ── Common rejects ────────────────────────────────────────────────────────────

describe("common", () => {
  it("rejects non-object body", () => {
    for (const body of [null, undefined, "x", 42, [], true]) {
      const r = AdrBodySchema.validate(body);
      assert.equal(r.ok, false);
      if (!r.ok) assert.equal(r.reason, "adr_body_not_object");
    }
  });

  it("rejects unknown event", () => {
    const r = AdrBodySchema.validate({ event: "delegate", profile: "agentops.scoped-delegation" });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_unknown_event");
  });

  it("rejects missing event", () => {
    const r = AdrBodySchema.validate({ profile: "agentops.scoped-delegation" });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_unknown_event");
  });

  it("rejects unknown profile", () => {
    const r = AdrBodySchema.validate({ event: "revoke", profile: "made_up.profile" });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_unknown_profile");
  });

  it("rejects missing profile", () => {
    const r = AdrBodySchema.validate({ event: "revoke" });
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_unknown_profile");
  });

  it("ok-value is the same body object reference", () => {
    const body = revokeBody();
    const r = AdrBodySchema.validate(body);
    assert.equal(r.ok, true);
    if (r.ok) assert.equal(r.value, body);
  });
});

// ── grant ─────────────────────────────────────────────────────────────────────

describe("grant", () => {
  it("accepts valid grant body", () => {
    const r = AdrBodySchema.validate(grantBody());
    assert.equal(r.ok, true);
  });

  it("accepts grant with null expiry", () => {
    const r = AdrBodySchema.validate(grantBody({ expiry: null }));
    assert.equal(r.ok, true);
  });

  it("accepts grant with agent_descriptor", () => {
    const r = AdrBodySchema.validate(grantBody({ agent: VALID_AGENT_WITH_DESCRIPTOR }));
    assert.equal(r.ok, true);
  });

  it("accepts grant with delegable=true", () => {
    const r = AdrBodySchema.validate(grantBody({ delegable: true }));
    assert.equal(r.ok, true);
  });

  it("rejects missing agent", () => {
    const { agent: _a, ...body } = grantBody() as Record<string, unknown> & { agent: unknown };
    const r = AdrBodySchema.validate(body);
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_missing_agent");
  });

  it("rejects non-object agent", () => {
    const r = AdrBodySchema.validate(grantBody({ agent: "not-an-object" }));
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_missing_agent");
  });

  it("rejects agent with missing agent_id", () => {
    const r = AdrBodySchema.validate(grantBody({ agent: { ...VALID_AGENT, agent_id: "" } }));
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_agent_invalid_agent_id");
  });

  it("rejects missing scope", () => {
    const { scope: _s, ...body } = grantBody() as Record<string, unknown> & { scope: unknown };
    const r = AdrBodySchema.validate(body);
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_missing_scope");
  });

  it("rejects scope with empty actions array", () => {
    const r = AdrBodySchema.validate(grantBody({ scope: { ...VALID_SCOPE, actions: [] } }));
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_scope_invalid_actions");
  });

  it("rejects scope with non-string in actions", () => {
    const r = AdrBodySchema.validate(grantBody({ scope: { ...VALID_SCOPE, actions: [42] } }));
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_scope_invalid_actions");
  });

  it("rejects non-boolean delegable", () => {
    const r = AdrBodySchema.validate(grantBody({ delegable: "yes" }));
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_missing_delegable");
  });

  it("rejects negative expiry", () => {
    const r = AdrBodySchema.validate(grantBody({ expiry: -1 }));
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_grant_invalid_expiry");
  });

  it("rejects zero expiry", () => {
    const r = AdrBodySchema.validate(grantBody({ expiry: 0 }));
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_grant_invalid_expiry");
  });

  it("rejects missing rationale_uri", () => {
    const { rationale_uri: _ru, ...body } = grantBody() as Record<string, unknown> & { rationale_uri: unknown };
    const r = AdrBodySchema.validate(body);
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_missing_rationale_uri");
  });

  it("rejects empty rationale_uri", () => {
    const r = AdrBodySchema.validate(grantBody({ rationale_uri: "" }));
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_missing_rationale_uri");
  });

  it("rejects missing rationale_hash", () => {
    const { rationale_hash: _rh, ...body } = grantBody() as Record<string, unknown> & { rationale_hash: unknown };
    const r = AdrBodySchema.validate(body);
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_missing_rationale_hash");
  });

  it("rejects grant carrying prohibited reason_uri", () => {
    const r = AdrBodySchema.validate(grantBody({ reason_uri: "https://example.com/reason" }));
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_prohibited_field_reason_uri");
  });

  it("rejects grant carrying prohibited cascade", () => {
    const r = AdrBodySchema.validate(grantBody({ cascade: true }));
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_prohibited_field_cascade");
  });
});

// ── grant: authorizing_credential (AP2 interop, additive, optional) ───────────

const VALID_AUTHORIZING_CREDENTIAL = {
  scheme: "ap2",
  id: "payment_mandate_id:abc-123",
  type: "payment-mandate",
};

describe("grant authorizing_credential", () => {
  it("accepts grant without authorizing_credential (graceful degrade — key absent)", () => {
    const r = AdrBodySchema.validate(grantBody());
    assert.equal(r.ok, true);
  });

  it("accepts grant with a well-formed authorizing_credential", () => {
    const r = AdrBodySchema.validate(grantBody({ authorizing_credential: VALID_AUTHORIZING_CREDENTIAL }));
    assert.equal(r.ok, true);
  });

  it("accepts grant with explicit null authorizing_credential", () => {
    const r = AdrBodySchema.validate(grantBody({ authorizing_credential: null }));
    assert.equal(r.ok, true);
  });

  it("rejects non-object authorizing_credential", () => {
    const r = AdrBodySchema.validate(grantBody({ authorizing_credential: "ap2:abc" }));
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_invalid_authorizing_credential");
  });

  it("rejects authorizing_credential missing scheme", () => {
    const { scheme: _s, ...ac } = VALID_AUTHORIZING_CREDENTIAL;
    const r = AdrBodySchema.validate(grantBody({ authorizing_credential: ac }));
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_authorizing_credential_invalid_scheme");
  });

  it("rejects authorizing_credential with empty id", () => {
    const r = AdrBodySchema.validate(
      grantBody({ authorizing_credential: { ...VALID_AUTHORIZING_CREDENTIAL, id: "" } }),
    );
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_authorizing_credential_invalid_id");
  });

  it("rejects authorizing_credential missing type", () => {
    const { type: _t, ...ac } = VALID_AUTHORIZING_CREDENTIAL;
    const r = AdrBodySchema.validate(grantBody({ authorizing_credential: ac }));
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_authorizing_credential_invalid_type");
  });
});

// ── authorizing_credential prohibited on every non-grant event ────────────────

describe("authorizing_credential prohibited on non-grant events", () => {
  const nonGrant: ReadonlyArray<[string, (o?: Record<string, unknown>) => Record<string, unknown>]> = [
    ["revoke", revokeBody],
    ["narrow", narrowBody],
    ["renew", renewBody],
    ["suspend", suspendBody],
    ["resume", resumeBody],
  ];

  for (const [name, make] of nonGrant) {
    it(`rejects ${name} carrying authorizing_credential`, () => {
      const r = AdrBodySchema.validate(make({ authorizing_credential: VALID_AUTHORIZING_CREDENTIAL }));
      assert.equal(r.ok, false);
      if (!r.ok) assert.equal(r.reason, "adr_prohibited_field_authorizing_credential");
    });
  }
});

// ── revoke ────────────────────────────────────────────────────────────────────

describe("revoke", () => {
  it("accepts valid minimal revoke", () => {
    const r = AdrBodySchema.validate(revokeBody());
    assert.equal(r.ok, true);
  });

  it("accepts revoke with optional reason fields", () => {
    const r = AdrBodySchema.validate(revokeBody({
      reason_uri: "https://example.com/reason",
      reason_hash: "sha256:cafebabe",
    }));
    assert.equal(r.ok, true);
  });

  it("rejects revoke carrying prohibited scope", () => {
    const r = AdrBodySchema.validate(revokeBody({ scope: VALID_SCOPE }));
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_prohibited_field_scope");
  });

  it("rejects revoke carrying prohibited agent", () => {
    const r = AdrBodySchema.validate(revokeBody({ agent: VALID_AGENT }));
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_prohibited_field_agent");
  });

  it("rejects revoke carrying prohibited expiry", () => {
    const r = AdrBodySchema.validate(revokeBody({ expiry: 1000 }));
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_prohibited_field_expiry");
  });

  it("rejects revoke carrying prohibited rationale_uri", () => {
    const r = AdrBodySchema.validate(revokeBody({ rationale_uri: "https://example.com/rationale" }));
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_prohibited_field_rationale_uri");
  });
});

// ── narrow ────────────────────────────────────────────────────────────────────

describe("narrow", () => {
  it("accepts valid narrow body", () => {
    const r = AdrBodySchema.validate(narrowBody());
    assert.equal(r.ok, true);
  });

  it("rejects narrow with missing scope", () => {
    const { scope: _s, ...body } = narrowBody() as Record<string, unknown> & { scope: unknown };
    const r = AdrBodySchema.validate(body);
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_missing_scope");
  });

  it("rejects narrow carrying prohibited agent", () => {
    const r = AdrBodySchema.validate(narrowBody({ agent: VALID_AGENT }));
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_prohibited_field_agent");
  });

  it("rejects narrow carrying prohibited delegable", () => {
    const r = AdrBodySchema.validate(narrowBody({ delegable: true }));
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_prohibited_field_delegable");
  });

  it("rejects narrow carrying prohibited rationale_uri", () => {
    const r = AdrBodySchema.validate(narrowBody({ rationale_uri: "https://example.com" }));
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_prohibited_field_rationale_uri");
  });
});

// ── renew ─────────────────────────────────────────────────────────────────────

describe("renew", () => {
  it("accepts valid renew body", () => {
    const r = AdrBodySchema.validate(renewBody());
    assert.equal(r.ok, true);
  });

  it("rejects renew with missing expiry", () => {
    const { expiry: _e, ...body } = renewBody() as Record<string, unknown> & { expiry: unknown };
    const r = AdrBodySchema.validate(body);
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_renew_missing_expiry");
  });

  it("rejects renew with null expiry (null not OK for renew)", () => {
    const r = AdrBodySchema.validate(renewBody({ expiry: null }));
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_renew_missing_expiry");
  });

  it("rejects renew with negative expiry", () => {
    const r = AdrBodySchema.validate(renewBody({ expiry: -5 }));
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_renew_missing_expiry");
  });

  it("rejects renew carrying prohibited agent", () => {
    const r = AdrBodySchema.validate(renewBody({ agent: VALID_AGENT }));
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_prohibited_field_agent");
  });

  it("rejects renew carrying prohibited scope", () => {
    const r = AdrBodySchema.validate(renewBody({ scope: VALID_SCOPE }));
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_prohibited_field_scope");
  });
});

// ── suspend ───────────────────────────────────────────────────────────────────

describe("suspend", () => {
  it("accepts valid minimal suspend", () => {
    const r = AdrBodySchema.validate(suspendBody());
    assert.equal(r.ok, true);
  });

  it("accepts suspend with optional cascade=true", () => {
    const r = AdrBodySchema.validate(suspendBody({ cascade: true }));
    assert.equal(r.ok, true);
  });

  it("accepts suspend with optional cascade=false", () => {
    const r = AdrBodySchema.validate(suspendBody({ cascade: false }));
    assert.equal(r.ok, true);
  });

  it("accepts suspend with optional reason fields", () => {
    const r = AdrBodySchema.validate(suspendBody({
      reason_uri: "https://example.com/reason",
      reason_hash: "sha256:cafebabe",
    }));
    assert.equal(r.ok, true);
  });

  it("rejects suspend with non-boolean cascade", () => {
    const r = AdrBodySchema.validate(suspendBody({ cascade: "yes" }));
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_suspend_invalid_cascade");
  });

  it("rejects suspend carrying prohibited agent", () => {
    const r = AdrBodySchema.validate(suspendBody({ agent: VALID_AGENT }));
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_prohibited_field_agent");
  });

  it("rejects suspend carrying prohibited expiry", () => {
    const r = AdrBodySchema.validate(suspendBody({ expiry: 1000 }));
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_prohibited_field_expiry");
  });
});

// ── resume ────────────────────────────────────────────────────────────────────

describe("resume", () => {
  it("accepts valid minimal resume", () => {
    const r = AdrBodySchema.validate(resumeBody());
    assert.equal(r.ok, true);
  });

  it("rejects resume carrying prohibited expiry", () => {
    const r = AdrBodySchema.validate(resumeBody({ expiry: 3600 }));
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_prohibited_field_expiry");
  });

  it("rejects resume carrying prohibited agent", () => {
    const r = AdrBodySchema.validate(resumeBody({ agent: VALID_AGENT }));
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_prohibited_field_agent");
  });

  it("rejects resume carrying prohibited scope", () => {
    const r = AdrBodySchema.validate(resumeBody({ scope: VALID_SCOPE }));
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_prohibited_field_scope");
  });

  it("rejects resume carrying prohibited rationale_uri", () => {
    const r = AdrBodySchema.validate(resumeBody({ rationale_uri: "https://example.com/rationale" }));
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_prohibited_field_rationale_uri");
  });

  it("rejects resume carrying prohibited reason_uri", () => {
    const r = AdrBodySchema.validate(resumeBody({ reason_uri: "https://example.com/reason" }));
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "adr_prohibited_field_reason_uri");
  });
});
