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
