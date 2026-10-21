/**
 * Shared test fixtures for ADR chain walker tests.
 *
 * Provides thin AdrChainReceipt builders — no envelope crypto needed since
 * the walker treats receipts as already body-verified.
 */

import type {
  AdrAgent,
  AdrBody,
  AdrChainReceipt,
  AdrProfile,
  AdrScope,
} from "../../src/types.ts";

/** Produce `sha256:<hex>` from a single character repeated 64 times. */
export function H(b: string): string {
  return "sha256:" + b.repeat(64);
}

export const defaultProfile: AdrProfile = "aiact.art26.deployer";

export const defaultAgent: AdrAgent = {
  agent_id: "agent-001",
  agent_pubkey: null,
  agent_descriptor: null,
};

export const defaultScope: AdrScope = {
  actions: ["inference.run", "inference.explain"],
  resources: ["model:gpt-4:*", "dataset:training:v1"],
  constraints: { max_requests: 1000, region: "eu-west" },
};

const ONE_YEAR_S = 365 * 24 * 60 * 60;

/**
 * Build a grant (root) receipt with sensible defaults.
 * `overrides.body` merges into the body; other overrides merge at envelope level.
 */
export function makeGrant(
  overrides?: Partial<Omit<AdrChainReceipt, "body">> & {
    body?: Partial<AdrChainReceipt["body"] & { expiry?: number | null }>;
  },
): AdrChainReceipt {
  const now = Math.floor(Date.now() / 1000);
  const bodyOverrides = overrides?.body ?? {};
  const { body: _body, ...envelopeOverrides } = overrides ?? {};

  return {
    id: "grant-001",
    iss: "did:web:acme.example",
    subject: H("s"),
    iat: "2026-01-01T00:00:00Z",
    prev: null,
    ...envelopeOverrides,
    body: {
      event: "grant",
      profile: defaultProfile,
      agent: defaultAgent,
      scope: defaultScope,
      delegable: false,
      expiry: now + ONE_YEAR_S,
      rationale_uri: "https://acme.example/delegation/rationale-001",
      rationale_hash: H("r"),
      ...bodyOverrides,
    } as AdrBody,
  };
}

/**
 * Build a non-grant chain receipt (revoke, narrow, renew, suspend, resume).
 *
 * - `narrow` auto-adds a narrowed scope (fewer actions) when none provided.
 * - `renew` auto-adds a future expiry when none provided.
 */
export function makeEvent(
  event: Exclude<AdrBody["event"], "grant">,
  prevId: string,
  overrides?: Partial<Omit<AdrChainReceipt, "body">> & {
    body?: Record<string, unknown>;
  },
): AdrChainReceipt {
  const bodyOverrides = overrides?.body ?? {};
  const { body: _body, ...envelopeOverrides } = overrides ?? {};

  let body: AdrBody;

  switch (event) {
    case "revoke":
      body = {
        event: "revoke",
        profile: defaultProfile,
        ...bodyOverrides,
      } as AdrBody;
      break;

    case "narrow": {
      const narrowedScope: AdrScope = (bodyOverrides.scope as AdrScope) ?? {
        actions: ["inference.run"],
        resources: ["model:gpt-4:*"],
        constraints: { max_requests: 500, region: "eu-west" },
      };
      body = {
        event: "narrow",
        profile: defaultProfile,
        scope: narrowedScope,
        ...bodyOverrides,
      } as AdrBody;
      break;
    }

    case "renew": {
      const now = Math.floor(Date.now() / 1000);
      const expiry = (bodyOverrides.expiry as number) ?? now + 2 * ONE_YEAR_S;
      body = {
        event: "renew",
        profile: defaultProfile,
        expiry,
        ...bodyOverrides,
      } as AdrBody;
      break;
    }

    case "suspend":
      body = {
        event: "suspend",
        profile: defaultProfile,
        ...bodyOverrides,
      } as AdrBody;
      break;

    case "resume":
      body = {
        event: "resume",
        profile: defaultProfile,
        ...bodyOverrides,
      } as AdrBody;
      break;
  }

  return {
    id: `${event}-${prevId}`,
    iss: "did:web:acme.example",
    subject: H("s"),
    iat: "2026-06-01T00:00:00Z",
    prev: prevId,
    ...envelopeOverrides,
    body,
  };
}
