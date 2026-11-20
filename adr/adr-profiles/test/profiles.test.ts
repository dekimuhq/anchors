/**
 * Tests for ADR v1 profile validators (spec section 5).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import type { AdrBody } from "@dekimuhq/adr";
import type { AdrAuthorizingCredential, AdrGrantBody } from "../src/body.ts";
import {
  AIACT_ART26_DEPLOYER_PROFILE_ID,
  validateAiactArt26Deployer,
  validateAiactArt26DeployerProfile,
  AIACT_ART14_OVERSIGHT_PROFILE_ID,
  validateAiactArt14Oversight,
  validateAiactArt14OversightProfile,
  AGENTOPS_SCOPED_DELEGATION_PROFILE_ID,
  validateAgentopsScopedDelegation,
  validateAgentopsScopedDelegationProfile,
  GDPR_ART28_PROCESSOR_PROFILE_ID,
  validateGdprArt28Processor,
  validateGdprArt28ProcessorProfile,
  GDPR_DSR_AUTHORISED_AGENT_PROFILE_ID,
  validateGdprDsrAuthorisedAgent,
  validateGdprDsrAuthorisedAgentProfile,
  CORPORATE_OFFICER_PROFILE_ID,
  validateCorporateOfficer,
  validateCorporateOfficerProfile,
  WORKSPACE_DEPARTMENT_ACCESS_PROFILE_ID,
  validateWorkspaceDepartmentAccess,
  validateWorkspaceDepartmentAccessProfile,
} from "../src/index.ts";

// ── Helpers ──────────────────────────────────────────────────────────────────

function makeGrant(overrides?: Record<string, unknown>): AdrBody {
  return {
    event: "grant",
    profile: "aiact.art26.deployer",
    agent: {
      agent_id: "agent-1",
      agent_pubkey: null,
      agent_descriptor: {
        model: "gpt-4",
        model_version: "2025-01",
        tool_set_hash: "sha256:abc123",
      },
    },
    scope: {
      actions: ["invoke"],
      resources: ["*"],
      constraints: {
        human_oversight_uri: "https://example.com/oversight",
        incident_reporting_uri: "https://example.com/incidents",
      },
    },
    delegable: false,
    expiry: null,
    rationale_uri: "https://example.com/rationale",
    rationale_hash: "sha256:def456",
    qts_attestation_hash: null,
    ...overrides,
  } as AdrBody;
}

function makeRevoke(): AdrBody {
  return {
    event: "revoke",
    profile: "aiact.art26.deployer",
    qts_attestation_hash: null,
  } as AdrBody;
}

// ── aiact.art26.deployer ─────────────────────────────────────────────────────

test("aiact.art26.deployer: valid grant passes", () => {
  const out = validateAiactArt26Deployer(makeGrant());
  assert.deepEqual(out.errors, []);
});

test("aiact.art26.deployer: non-grant event returns empty errors", () => {
  const out = validateAiactArt26Deployer(makeRevoke());
  assert.deepEqual(out.errors, []);
});

test("aiact.art26.deployer: missing agent_descriptor produces error", () => {
  const out = validateAiactArt26Deployer(
    makeGrant({ agent: { agent_id: "a", agent_pubkey: null, agent_descriptor: null } }),
  );
  assert.ok(out.errors.includes("aiact.art26.deployer.agent_descriptor_missing"));
});

test("aiact.art26.deployer: missing human_oversight_uri produces error", () => {
  const out = validateAiactArt26Deployer(
    makeGrant({
      scope: {
        actions: ["invoke"],
        resources: ["*"],
        constraints: { incident_reporting_uri: "https://example.com/incidents" },
      },
    }),
  );
  assert.ok(out.errors.includes("aiact.art26.deployer.human_oversight_uri_missing"));
});

test("aiact.art26.deployer: missing incident_reporting_uri produces error", () => {
  const out = validateAiactArt26Deployer(
    makeGrant({
      scope: {
        actions: ["invoke"],
        resources: ["*"],
        constraints: { human_oversight_uri: "https://example.com/oversight" },
      },
    }),
  );
  assert.ok(out.errors.includes("aiact.art26.deployer.incident_reporting_uri_missing"));
});

test("aiact.art26.deployer adapter: ok=true on valid grant", () => {
  const out = validateAiactArt26DeployerProfile({} as never, makeGrant(), {});
  assert.equal(out.profile_id, AIACT_ART26_DEPLOYER_PROFILE_ID);
  assert.equal(out.ok, true);
  assert.equal(out.reason, undefined);
});

// ── aiact.art14.oversight ────────────────────────────────────────────────────

test("aiact.art14.oversight: valid grant passes", () => {
  const body = makeGrant({
    profile: "aiact.art14.oversight",
    delegable: false,
    scope: {
      actions: ["approve"],
      resources: ["*"],
      constraints: {
        oversight_scope: "continuous",
        escalation_uri: "https://example.com/escalate",
      },
    },
  });
  const out = validateAiactArt14Oversight(body);
  assert.deepEqual(out.errors, []);
});

test("aiact.art14.oversight: non-grant event returns empty errors", () => {
  const out = validateAiactArt14Oversight(makeRevoke());
  assert.deepEqual(out.errors, []);
});

test("aiact.art14.oversight: invalid oversight_scope produces error", () => {
  const body = makeGrant({
    scope: {
      actions: ["approve"],
      resources: ["*"],
      constraints: {
        oversight_scope: "invalid-scope",
        escalation_uri: "https://example.com/escalate",
      },
    },
    delegable: false,
  });
  const out = validateAiactArt14Oversight(body);
  assert.ok(out.errors.includes("aiact.art14.oversight.oversight_scope_invalid"));
});

test("aiact.art14.oversight: delegable=true produces error", () => {
  const body = makeGrant({
    delegable: true,
    scope: {
      actions: ["approve"],
      resources: ["*"],
      constraints: {
        oversight_scope: "continuous",
        escalation_uri: "https://example.com/escalate",
      },
    },
  });
  const out = validateAiactArt14Oversight(body);
  assert.ok(out.errors.includes("aiact.art14.oversight.delegable_must_be_false"));
});

test("aiact.art14.oversight: missing escalation_uri produces error", () => {
  const body = makeGrant({
    delegable: false,
    scope: {
      actions: ["approve"],
      resources: ["*"],
      constraints: { oversight_scope: "pre-approval" },
    },
  });
  const out = validateAiactArt14Oversight(body);
  assert.ok(out.errors.includes("aiact.art14.oversight.escalation_uri_missing"));
});

test("aiact.art14.oversight adapter: ok=false on delegable=true", () => {
  const body = makeGrant({
    delegable: true,
    scope: {
      actions: ["approve"],
      resources: ["*"],
      constraints: {
        oversight_scope: "continuous",
        escalation_uri: "https://example.com/escalate",
      },
    },
  });
  const out = validateAiactArt14OversightProfile({} as never, body, {});
  assert.equal(out.profile_id, AIACT_ART14_OVERSIGHT_PROFILE_ID);
  assert.equal(out.ok, false);
  assert.equal(out.reason, "aiact.art14.oversight.delegable_must_be_false");
});

// ── agentops.scoped-delegation ───────────────────────────────────────────────

test("agentops.scoped-delegation: always returns empty errors", () => {
  const out = validateAgentopsScopedDelegation(makeGrant());
  assert.deepEqual(out.errors, []);
});

test("agentops.scoped-delegation: non-grant also returns empty errors", () => {
  const out = validateAgentopsScopedDelegation(makeRevoke());
  assert.deepEqual(out.errors, []);
});

test("agentops.scoped-delegation adapter: ok=true always", () => {
  const out = validateAgentopsScopedDelegationProfile({} as never, makeGrant(), {});
  assert.equal(out.profile_id, AGENTOPS_SCOPED_DELEGATION_PROFILE_ID);
  assert.equal(out.ok, true);
});

// ── gdpr.art28.processor ─────────────────────────────────────────────────────

test("gdpr.art28.processor: valid grant passes", () => {
  const body = makeGrant({
    profile: "gdpr.art28.processor",
    scope: {
      actions: ["process"],
      resources: ["user-data"],
      constraints: {
        dpa_uri: "https://example.com/dpa",
        dpa_hash: "sha256:dpa123",
        sub_processing_allowed: false,
        transfer_basis: "scc",
      },
    },
  });
  const out = validateGdprArt28Processor(body);
  assert.deepEqual(out.errors, []);
});

test("gdpr.art28.processor: non-grant event returns empty errors", () => {
  const out = validateGdprArt28Processor(makeRevoke());
  assert.deepEqual(out.errors, []);
});

test("gdpr.art28.processor: missing dpa_uri produces error", () => {
  const body = makeGrant({
    scope: {
      actions: ["process"],
      resources: ["user-data"],
      constraints: {
        dpa_hash: "sha256:dpa123",
        sub_processing_allowed: false,
        transfer_basis: "scc",
      },
    },
  });
  const out = validateGdprArt28Processor(body);
  assert.ok(out.errors.includes("gdpr.art28.processor.dpa_uri_missing"));
});

test("gdpr.art28.processor: invalid transfer_basis produces error", () => {
  const body = makeGrant({
    scope: {
      actions: ["process"],
      resources: ["user-data"],
      constraints: {
        dpa_uri: "https://example.com/dpa",
        dpa_hash: "sha256:dpa123",
        sub_processing_allowed: true,
        transfer_basis: "invalid",
      },
    },
  });
  const out = validateGdprArt28Processor(body);
  assert.ok(out.errors.includes("gdpr.art28.processor.transfer_basis_invalid"));
});

test("gdpr.art28.processor: missing sub_processing_allowed produces error", () => {
  const body = makeGrant({
    scope: {
      actions: ["process"],
      resources: ["user-data"],
      constraints: {
        dpa_uri: "https://example.com/dpa",
        dpa_hash: "sha256:dpa123",
        transfer_basis: "adequacy",
      },
    },
  });
  const out = validateGdprArt28Processor(body);
  assert.ok(out.errors.includes("gdpr.art28.processor.sub_processing_allowed_missing"));
});

test("gdpr.art28.processor adapter: ok=true on valid grant", () => {
  const body = makeGrant({
    scope: {
      actions: ["process"],
      resources: ["user-data"],
      constraints: {
        dpa_uri: "https://example.com/dpa",
        dpa_hash: "sha256:dpa123",
        sub_processing_allowed: false,
        transfer_basis: "bcr",
      },
    },
  });
  const out = validateGdprArt28ProcessorProfile({} as never, body, {});
  assert.equal(out.profile_id, GDPR_ART28_PROCESSOR_PROFILE_ID);
  assert.equal(out.ok, true);
});

// ── gdpr.dsr.authorised-agent ────────────────────────────────────────────────

const REP_HASH =
  "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/** A representative-shaped grant: identity agent (no descriptor), single controller. */
function makeAgentGrant(overrides?: Record<string, unknown>): AdrBody {
  return makeGrant({
    profile: "gdpr.dsr.authorised-agent",
    agent: {
      agent_id: "did:web:agent.example",
      agent_pubkey: "MCowBQYDK2VwAyEA-spki-here",
      agent_descriptor: null,
    },
    delegable: false,
    scope: {
      actions: ["gdpr-art-17", "gdpr-art-21"],
      resources: ["broker:acme"],
      constraints: {
        letter_hash: REP_HASH,
        representative: "Example Representative Ltd",
        mandate_basis:
          "National civil-law mandate; GDPR Art. 12(2)/(6), Recital 59",
      },
    },
    ...overrides,
  });
}

test("gdpr.dsr.authorised-agent: valid grant passes", () => {
  const out = validateGdprDsrAuthorisedAgent(makeAgentGrant());
  assert.deepEqual(out.errors, []);
});

test("gdpr.dsr.authorised-agent: non-grant event returns empty errors", () => {
  const out = validateGdprDsrAuthorisedAgent(makeRevoke());
  assert.deepEqual(out.errors, []);
});

test("gdpr.dsr.authorised-agent: delegable=true produces error", () => {
  const out = validateGdprDsrAuthorisedAgent(makeAgentGrant({ delegable: true }));
  assert.ok(
    out.errors.includes("gdpr.dsr.authorised-agent.delegable_must_be_false"),
  );
});

test("gdpr.dsr.authorised-agent: agent_descriptor present produces error", () => {
  const out = validateGdprDsrAuthorisedAgent(
    makeAgentGrant({
      agent: {
        agent_id: "did:web:agent.example",
        agent_pubkey: "spki",
        agent_descriptor: {
          model: "gpt-4",
          model_version: "2025-01",
          tool_set_hash: "sha256:abc",
        },
      },
    }),
  );
  assert.ok(
    out.errors.includes(
      "gdpr.dsr.authorised-agent.agent_descriptor_must_be_null",
    ),
  );
});

test("gdpr.dsr.authorised-agent: missing agent_pubkey produces error", () => {
  const out = validateGdprDsrAuthorisedAgent(
    makeAgentGrant({
      agent: {
        agent_id: "did:web:agent.example",
        agent_pubkey: null,
        agent_descriptor: null,
      },
    }),
  );
  assert.ok(
    out.errors.includes("gdpr.dsr.authorised-agent.agent_pubkey_missing"),
  );
});

test("gdpr.dsr.authorised-agent: non-DSR action produces error", () => {
  const out = validateGdprDsrAuthorisedAgent(
    makeAgentGrant({
      scope: {
        actions: ["gdpr-art-17", "invoke"],
        resources: ["broker:acme"],
        constraints: {
          letter_hash: REP_HASH,
          representative: "Example Representative Ltd",
          mandate_basis: "mandate",
        },
      },
    }),
  );
  assert.ok(out.errors.includes("gdpr.dsr.authorised-agent.actions_invalid"));
});

test("gdpr.dsr.authorised-agent: empty actions produces error", () => {
  const out = validateGdprDsrAuthorisedAgent(
    makeAgentGrant({
      scope: {
        actions: [],
        resources: ["broker:acme"],
        constraints: {
          letter_hash: REP_HASH,
          representative: "Example Representative Ltd",
          mandate_basis: "mandate",
        },
      },
    }),
  );
  assert.ok(out.errors.includes("gdpr.dsr.authorised-agent.actions_invalid"));
});

test("gdpr.dsr.authorised-agent: multiple resources produce error", () => {
  const out = validateGdprDsrAuthorisedAgent(
    makeAgentGrant({
      scope: {
        actions: ["gdpr-art-17"],
        resources: ["broker:acme", "broker:crif"],
        constraints: {
          letter_hash: REP_HASH,
          representative: "Example Representative Ltd",
          mandate_basis: "mandate",
        },
      },
    }),
  );
  assert.ok(
    out.errors.includes(
      "gdpr.dsr.authorised-agent.resources_must_name_single_controller",
    ),
  );
});

test("gdpr.dsr.authorised-agent: malformed letter_hash produces error", () => {
  const out = validateGdprDsrAuthorisedAgent(
    makeAgentGrant({
      scope: {
        actions: ["gdpr-art-17"],
        resources: ["broker:acme"],
        constraints: {
          letter_hash: "not-a-hash",
          representative: "Example Representative Ltd",
          mandate_basis: "mandate",
        },
      },
    }),
  );
  assert.ok(
    out.errors.includes("gdpr.dsr.authorised-agent.letter_hash_invalid"),
  );
});

test("gdpr.dsr.authorised-agent: missing representative produces error", () => {
  const out = validateGdprDsrAuthorisedAgent(
    makeAgentGrant({
      scope: {
        actions: ["gdpr-art-17"],
        resources: ["broker:acme"],
        constraints: { letter_hash: REP_HASH, mandate_basis: "mandate" },
      },
    }),
  );
  assert.ok(
    out.errors.includes("gdpr.dsr.authorised-agent.representative_missing"),
  );
});

test("gdpr.dsr.authorised-agent: missing mandate_basis produces error", () => {
  const out = validateGdprDsrAuthorisedAgent(
    makeAgentGrant({
      scope: {
        actions: ["gdpr-art-17"],
        resources: ["broker:acme"],
        constraints: { letter_hash: REP_HASH, representative: "Example Representative Ltd" },
      },
    }),
  );
  assert.ok(
    out.errors.includes("gdpr.dsr.authorised-agent.mandate_basis_missing"),
  );
});

test("gdpr.dsr.authorised-agent adapter: ok=true on valid grant", () => {
  const out = validateGdprDsrAuthorisedAgentProfile(
    {} as never,
    makeAgentGrant(),
    {},
  );
  assert.equal(out.profile_id, GDPR_DSR_AUTHORISED_AGENT_PROFILE_ID);
  assert.equal(out.ok, true);
  assert.equal(out.reason, undefined);
});

test("gdpr.dsr.authorised-agent adapter: ok=false on delegable=true", () => {
  const out = validateGdprDsrAuthorisedAgentProfile(
    {} as never,
    makeAgentGrant({ delegable: true }),
    {},
  );
  assert.equal(out.profile_id, GDPR_DSR_AUTHORISED_AGENT_PROFILE_ID);
  assert.equal(out.ok, false);
});

// ── corporate.officer ────────────────────────────────────────────────────────

test("corporate.officer: valid grant passes", () => {
  const body = makeGrant({
    profile: "corporate.officer",
    delegable: false,
    scope: {
      actions: ["approve-payment"],
      resources: ["treasury"],
      constraints: {
        monetary_limit: { currency: "EUR", amount: 50000 },
        transaction_categories: ["payroll", "vendor-payment"],
      },
    },
    rationale_uri: "https://example.com/board-resolution",
  });
  const out = validateCorporateOfficer(body);
  assert.deepEqual(out.errors, []);
});

test("corporate.officer: non-grant event returns empty errors", () => {
  const out = validateCorporateOfficer(makeRevoke());
  assert.deepEqual(out.errors, []);
});

test("corporate.officer: missing monetary_limit produces error", () => {
  const body = makeGrant({
    profile: "corporate.officer",
    scope: {
      actions: ["approve-payment"],
      resources: ["treasury"],
      constraints: {
        transaction_categories: ["payroll"],
      },
    },
  });
  const out = validateCorporateOfficer(body);
  assert.ok(out.errors.includes("corporate.officer.monetary_limit_missing"));
});

test("corporate.officer: invalid currency produces error", () => {
  const body = makeGrant({
    profile: "corporate.officer",
    scope: {
      actions: ["approve-payment"],
      resources: ["treasury"],
      constraints: {
        monetary_limit: { currency: "eu", amount: 100 },
        transaction_categories: ["payroll"],
      },
    },
  });
  const out = validateCorporateOfficer(body);
  assert.ok(out.errors.includes("corporate.officer.monetary_limit_currency_invalid"));
});

test("corporate.officer: zero amount produces error", () => {
  const body = makeGrant({
    profile: "corporate.officer",
    scope: {
      actions: ["approve-payment"],
      resources: ["treasury"],
      constraints: {
        monetary_limit: { currency: "EUR", amount: 0 },
        transaction_categories: ["payroll"],
      },
    },
  });
  const out = validateCorporateOfficer(body);
  assert.ok(out.errors.includes("corporate.officer.monetary_limit_amount_invalid"));
});

test("corporate.officer: empty transaction_categories produces error", () => {
  const body = makeGrant({
    profile: "corporate.officer",
    scope: {
      actions: ["approve-payment"],
      resources: ["treasury"],
      constraints: {
        monetary_limit: { currency: "EUR", amount: 100 },
        transaction_categories: [],
      },
    },
  });
  const out = validateCorporateOfficer(body);
  assert.ok(out.errors.includes("corporate.officer.transaction_categories_missing"));
});

test("corporate.officer: delegable=true without sub_delegation_authority_uri produces error", () => {
  const body = makeGrant({
    profile: "corporate.officer",
    delegable: true,
    scope: {
      actions: ["approve-payment"],
      resources: ["treasury"],
      constraints: {
        monetary_limit: { currency: "EUR", amount: 5000 },
        transaction_categories: ["payroll"],
      },
    },
  });
  const out = validateCorporateOfficer(body);
  assert.ok(out.errors.includes("corporate.officer.sub_delegation_authority_uri_missing"));
});

test("corporate.officer: delegable=true with sub_delegation_authority_uri passes", () => {
  const body = makeGrant({
    profile: "corporate.officer",
    delegable: true,
    scope: {
      actions: ["approve-payment"],
      resources: ["treasury"],
      constraints: {
        monetary_limit: { currency: "USD", amount: 10000 },
        transaction_categories: ["payroll", "expenses"],
        sub_delegation_authority_uri: "https://example.com/sub-auth",
      },
    },
  });
  const out = validateCorporateOfficer(body);
  assert.deepEqual(out.errors, []);
});

test("corporate.officer adapter: ok=false on missing rationale_uri", () => {
  const body = makeGrant({
    profile: "corporate.officer",
    rationale_uri: "",
    scope: {
      actions: ["approve-payment"],
      resources: ["treasury"],
      constraints: {
        monetary_limit: { currency: "EUR", amount: 100 },
        transaction_categories: ["payroll"],
      },
    },
  });
  const out = validateCorporateOfficerProfile({} as never, body, {});
  assert.equal(out.profile_id, CORPORATE_OFFICER_PROFILE_ID);
  assert.equal(out.ok, false);
  assert.equal(out.reason, "corporate.officer.rationale_uri_missing");
});

// ── authorizing_credential (AP2 interop — additive optional grant field) ──────
//
// The field is a typed member of AdrGrantBody carried in this package. Profile
// validators are orthogonal to it (it references an *external* authorizing
// artifact — an AP2 mandate — not a profile-scoped obligation), so a grant that
// carries it must still pass every profile that would pass without it.

const AP2_MANDATE_REF: AdrAuthorizingCredential = {
  scheme: "ap2",
  id: "payment_mandate_id:abc-123",
  type: "payment-mandate",
};

test("authorizing_credential: typed field is assignable on AdrGrantBody", () => {
  const grant = makeGrant({ authorizing_credential: AP2_MANDATE_REF }) as AdrGrantBody;
  assert.deepEqual(grant.authorizing_credential, AP2_MANDATE_REF);
  // type carries scheme/id/type only — a pointer, never an embedded credential.
  assert.deepEqual(Object.keys(AP2_MANDATE_REF).sort(), ["id", "scheme", "type"]);
});

test("agentops.scoped-delegation: valid grant still passes WITH authorizing_credential", () => {
  const withField = validateAgentopsScopedDelegation(
    makeGrant({ profile: "agentops.scoped-delegation", authorizing_credential: AP2_MANDATE_REF }),
  );
  const withoutField = validateAgentopsScopedDelegation(
    makeGrant({ profile: "agentops.scoped-delegation" }),
  );
  // The external-mandate reference is orthogonal to profile validation.
  assert.deepEqual(withField.errors, withoutField.errors);
});

// ── workspace.department-access ──────────────────────────────────────────────

const WDA = "workspace.department-access";

function makeDeptGrant(
  constraintOverrides?: Record<string, unknown>,
  overrides?: Record<string, unknown>,
): AdrBody {
  const constraints: Record<string, unknown> = {
    workspace_id: "ws_1",
    department_key: "legal",
    delegator_id: "0b6f3c1e-1111-4222-8333-444455556666",
    delegator_role: "admin",
    delegate_role: "member",
    previous_level: "none",
    new_level: "write",
    reason: "set",
    effective_at: "2026-11-20T10:15:30Z",
    ...constraintOverrides,
  };
  const nl = constraints["new_level"];
  const dk = constraints["department_key"];
  return {
    event: "grant",
    profile: WDA,
    agent: {
      agent_id: "7c9e6679-7425-40de-944b-e07fc1f90ae7",
      agent_pubkey: null,
      agent_descriptor: null,
    },
    scope: {
      actions: [`department-access.${String(nl)}`],
      resources: [`department:${String(dk)}`],
      constraints,
    },
    delegable: false,
    expiry: null,
    rationale_uri: "https://example.com/department-access",
    rationale_hash: "sha256:" + "a".repeat(64),
    qts_attestation_hash: null,
    ...overrides,
  } as AdrBody;
}

function deptConstraints(): Record<string, unknown> {
  return (makeDeptGrant() as unknown as { scope: { constraints: Record<string, unknown> } }).scope.constraints;
}

function wdaErrors(c?: Record<string, unknown>, o?: Record<string, unknown>): string[] {
  return validateWorkspaceDepartmentAccess(makeDeptGrant(c, o)).errors;
}

test("workspace.department-access: valid grant passes", () => {
  assert.deepEqual(wdaErrors(), []);
});

test("workspace.department-access: every level pairing in the model passes", () => {
  assert.deepEqual(wdaErrors({ previous_level: "write", new_level: "none", delegate_role: "member" }), []);
  assert.deepEqual(wdaErrors({ previous_level: "none", new_level: "admin", delegator_role: "owner" }), []);
  assert.deepEqual(wdaErrors({ previous_level: "none", new_level: "read", delegate_role: "viewer" }), []);
  assert.deepEqual(
    wdaErrors({ previous_level: "write", new_level: "read", delegate_role: "viewer", reason: "role-changed", delegator_id: "system", delegator_role: "system" }),
    [],
  );
  // Promotion to admin clears per-department levels.
  assert.deepEqual(
    wdaErrors({ previous_level: "read", new_level: "none", delegate_role: "admin", reason: "role-changed" }),
    [],
  );
});

test("workspace.department-access: removal with unknown role and system actor passes", () => {
  assert.deepEqual(
    wdaErrors({
      previous_level: "write",
      new_level: "none",
      delegate_role: null,
      reason: "member-removed",
      delegator_id: "system",
      delegator_role: "system",
    }),
    [],
  );
});

test("workspace.department-access: department key is an open slug, not an enum", () => {
  assert.deepEqual(wdaErrors({ department_key: "customer-success-2" }), []);
});

test("workspace.department-access: bad department keys produce error", () => {
  for (const k of ["Legal", "legal ", "a_b", "-x", "x-", "a--b", "", "x".repeat(65), 5]) {
    assert.ok(wdaErrors({ department_key: k }).includes(`${WDA}.department_key_invalid`), String(k));
  }
});

test("workspace.department-access: non-grant event is rejected", () => {
  const out = validateWorkspaceDepartmentAccess({
    event: "revoke",
    profile: WDA,
    qts_attestation_hash: null,
  } as AdrBody);
  assert.deepEqual(out.errors, [`${WDA}.event_must_be_grant`]);
});

test("workspace.department-access: delegable / expiry / agent shape", () => {
  assert.ok(wdaErrors({}, { delegable: true }).includes(`${WDA}.delegable_must_be_false`));
  assert.ok(wdaErrors({}, { expiry: 1893456000 }).includes(`${WDA}.expiry_must_be_null`));
  const agent = (a: Record<string, unknown>) => ({ agent: { agent_id: "m1", agent_pubkey: null, agent_descriptor: null, ...a } });
  assert.ok(wdaErrors({}, agent({ agent_pubkey: "abc" })).includes(`${WDA}.agent_pubkey_must_be_null`));
  assert.ok(
    wdaErrors({}, agent({ agent_descriptor: { model: "m", model_version: "1", tool_set_hash: "sha256:x" } })).includes(
      `${WDA}.agent_descriptor_must_be_null`,
    ),
  );
});

test("workspace.department-access: ids reject emails, names with spaces and dots", () => {
  for (const bad of ["jane@example.com", "Jane Doe", "jane.doe", "", ".x", "x".repeat(129)]) {
    assert.ok(wdaErrors({ workspace_id: bad }).includes(`${WDA}.workspace_id_invalid`), bad);
    assert.ok(wdaErrors({ delegator_id: bad }).includes(`${WDA}.delegator_id_invalid`), bad);
    assert.ok(
      wdaErrors({}, { agent: { agent_id: bad, agent_pubkey: null, agent_descriptor: null } }).includes(`${WDA}.delegate_id_invalid`),
      bad,
    );
  }
});

test("workspace.department-access: constraints is a closed key set", () => {
  assert.ok(wdaErrors({ delegate_email: "jane@example.com" }).includes(`${WDA}.constraints_unknown_key`));
  assert.ok(wdaErrors({ delegate_name: "Jane" }).includes(`${WDA}.constraints_unknown_key`));
});

test("workspace.department-access: missing constraints produce error", () => {
  const out = validateWorkspaceDepartmentAccess(
    makeDeptGrant({}, { scope: { actions: ["x"], resources: ["y"] } }),
  );
  assert.deepEqual(out.errors.filter((e) => e.endsWith("constraints_missing")), [`${WDA}.constraints_missing`]);
});

test("workspace.department-access: enum fields reject unknown values", () => {
  assert.ok(wdaErrors({ previous_level: "owner" }).includes(`${WDA}.previous_level_invalid`));
  assert.ok(wdaErrors({ new_level: "superuser" }).includes(`${WDA}.new_level_invalid`));
  assert.ok(wdaErrors({ reason: "because" }).includes(`${WDA}.reason_invalid`));
  assert.ok(wdaErrors({ delegator_role: "viewer" }).includes(`${WDA}.delegator_role_invalid`));
  assert.ok(wdaErrors({ delegate_role: "guest" }).includes(`${WDA}.delegate_role_invalid`));
});

test("workspace.department-access: delegate_role null only on member-removed", () => {
  assert.ok(wdaErrors({ delegate_role: null }).includes(`${WDA}.delegate_role_required`));
});

test("workspace.department-access: effective_at must be a real UTC instant", () => {
  for (const bad of ["2026-11-20", "2026-11-20T10:15:30", "2026-11-20T10:15:30+01:00", "2026-02-30T10:15:30Z", "2026-13-01T00:00:00Z", "2026-11-20T24:00:00Z", 1763633730]) {
    assert.ok(wdaErrors({ effective_at: bad }).includes(`${WDA}.effective_at_invalid`), String(bad));
  }
  assert.deepEqual(wdaErrors({ effective_at: "2026-11-20T10:15:30.123Z" }), []);
});

test("workspace.department-access: actions and resources must restate the constraints", () => {
  assert.ok(
    wdaErrors({}, { scope: { actions: ["department-access.read"], resources: ["department:legal"], constraints: deptConstraints() } }).includes(
      `${WDA}.actions_mismatch`,
    ),
  );
  assert.ok(
    wdaErrors({}, { scope: { actions: ["department-access.write"], resources: ["department:hr"], constraints: deptConstraints() } }).includes(
      `${WDA}.resources_mismatch`,
    ),
  );
});

test("workspace.department-access: unchanged level produces error", () => {
  assert.ok(wdaErrors({ previous_level: "write", new_level: "write" }).includes(`${WDA}.level_unchanged`));
});

test("workspace.department-access: owner/admin delegate cannot carry a level", () => {
  for (const role of ["owner", "admin"]) {
    assert.ok(wdaErrors({ delegate_role: role, new_level: "read" }).includes(`${WDA}.full_access_role_has_no_level`), role);
  }
});

test("workspace.department-access: viewer is capped at read", () => {
  for (const lvl of ["write", "admin"]) {
    assert.ok(wdaErrors({ delegate_role: "viewer", new_level: lvl }).includes(`${WDA}.level_exceeds_role_ceiling`), lvl);
  }
});

test("workspace.department-access: removal must end at none", () => {
  assert.ok(
    wdaErrors({ reason: "member-removed", delegate_role: null, new_level: "read" }).includes(`${WDA}.removal_must_end_at_none`),
  );
});

test("workspace.department-access: reason set needs a person; system id/role agree", () => {
  assert.ok(
    wdaErrors({ delegator_id: "system", delegator_role: "system" }).includes(`${WDA}.set_requires_person_delegator`),
  );
  assert.ok(
    wdaErrors({ reason: "role-changed", delegator_role: "system" }).includes(`${WDA}.system_delegator_inconsistent`),
  );
  assert.ok(
    wdaErrors({ reason: "role-changed", delegator_id: "system", delegator_role: "admin" }).includes(`${WDA}.system_delegator_inconsistent`),
  );
});

test("workspace.department-access: department admin cannot grant admin", () => {
  assert.ok(
    wdaErrors({ delegator_role: "member", new_level: "admin" }).includes(`${WDA}.department_admin_cannot_grant_admin`),
  );
  assert.deepEqual(wdaErrors({ delegator_role: "member", new_level: "write" }), []);
});

test("workspace.department-access adapter: ok=true on valid grant", () => {
  const out = validateWorkspaceDepartmentAccessProfile({} as never, makeDeptGrant(), {});
  assert.equal(out.profile_id, WORKSPACE_DEPARTMENT_ACCESS_PROFILE_ID);
  assert.equal(out.ok, true);
  assert.equal(out.reason, undefined);
});

test("workspace.department-access adapter: ok=false with stable first reason", () => {
  const out = validateWorkspaceDepartmentAccessProfile({} as never, makeDeptGrant({ reason: "nope" }), {});
  assert.equal(out.ok, false);
  assert.equal(out.reason, `${WDA}.reason_invalid`);
});
