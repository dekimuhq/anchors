/**
 * Tests for the disclosure.recipients profile validator (ALR §5.5).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import type { AlrBody } from "@dekimuhq/alr-profiles/body-types";
import {
  validateDisclosureRecipients,
  validateDisclosureRecipientsProfile,
  DISCLOSURE_RECIPIENTS_PROFILE_ID,
} from "../src/disclosure-recipients.ts";

const H = (b: string) => `sha256:${b.repeat(64)}`;

function disclosedBody(
  recipient_role: string,
  profile: string = DISCLOSURE_RECIPIENTS_PROFILE_ID,
): AlrBody {
  return {
    profile: profile as AlrBody["profile"],
    event_type: "disclosed",
    artifact_hash: H("c"),
    event_at: "2026-05-16T14:23:00Z",
    qts_attestation_hash: null,
    parents: [],
    successor: null,
    transform_claim: null,
    disclosure: {
      recipient: "did:web:auditor.example",
      recipient_role,
      scope_hash: H("d"),
      basis: "gdpr.art6.1.c",
    },
  };
}

const ALLOWED_ROLES = [
  "controller",
  "processor",
  "joint-controller",
  "recipient",
  "third-country-recipient",
];

for (const role of ALLOWED_ROLES) {
  test(`disclosure.recipients: recipient_role=${role} passes`, () => {
    const out = validateDisclosureRecipients(disclosedBody(role));
    assert.deepEqual(out.errors, []);
  });
}

test("disclosure.recipients: recipient_role 'auditor' rejected (not in allowlist)", () => {
  const out = validateDisclosureRecipients(disclosedBody("auditor"));
  assert.ok(
    out.errors.includes("disclosure.recipients.recipient_role.disallowed"),
  );
});

test("disclosure.recipients: derived_from rejected (event_type allowlist)", () => {
  const body: AlrBody = {
    profile: DISCLOSURE_RECIPIENTS_PROFILE_ID,
    event_type: "derived_from",
    artifact_hash: H("c"),
    event_at: "2026-05-16T14:23:00Z",
    qts_attestation_hash: null,
    parents: [
      { artifact_hash: H("a"), parent_apr_id: null, parent_alr_id: null, uri: null },
    ],
    successor: null,
    transform_claim: { summary: "x", uri: null },
    disclosure: null,
  };
  const out = validateDisclosureRecipients(body);
  assert.deepEqual(
    out.errors,
    ["disclosure.recipients.event_type.disallowed"],
  );
});

test("disclosure.recipients: profile mismatch short-circuits", () => {
  const out = validateDisclosureRecipients(disclosedBody("controller", "gdpr.art13.transparency"));
  assert.deepEqual(out.errors, ["disclosure.recipients.profile.mismatch"]);
});

// ── Adapter ──────────────────────────────────────────────────────────────────

test("disclosure.recipients adapter: ok=true on valid", () => {
  const out = validateDisclosureRecipientsProfile(
    {} as never,
    disclosedBody("processor"),
    {},
  );
  assert.equal(out.profile_id, DISCLOSURE_RECIPIENTS_PROFILE_ID);
  assert.equal(out.ok, true);
});

test("disclosure.recipients adapter: surfaces role mismatch reason", () => {
  const out = validateDisclosureRecipientsProfile(
    {} as never,
    disclosedBody("intern"),
    {},
  );
  assert.equal(out.ok, false);
  assert.equal(out.reason, "disclosure.recipients.recipient_role.disallowed");
});
