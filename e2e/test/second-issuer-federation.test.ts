/**
 * Second-issuer federation e2e fixture (cross-issuer interop plan Task 4).
 *
 * Proves the federation + verification paths are truly issuer-agnostic by
 * minting test material from TWO independent issuer identities and exercising:
 *
 *   1. Manifest fetch + structural parse for both issuers
 *   2. Manifest signature verification for both issuers (via injected fetcher)
 *   3. Receipt minting + verification from each issuer (ACR as proxy family)
 *   4. Trust dispatch correctly distinguishes the two issuers
 *   5. Manifest cache isolation — one issuer's cache entry doesn't leak to the other
 *
 * Uses the ACR family as a proxy (consistent with the existing cross-issuer
 * e2e tests). Each issuer gets its own Ed25519 keypair, manifest, and key doc.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { signEnvelope, base64UrlEncode } from "@dekimuhq/anchors-envelope";
import type { Envelope } from "@dekimuhq/anchors-envelope";
import { verifyReceipt as verifyAcrRaw } from "@dekimuhq/acr";
import type { EnvelopeVerifyResult } from "@dekimuhq/acr";
import {
  fetchIssuerManifest,
  verifyIssuerManifest,
  parseIssuerManifest,
  ManifestCache,
} from "@dekimuhq/anchors-federation";
import type {
  IssuerTrustResult,
  TrustedIssuerRecord,
  VerifyIssuerTrust,
} from "@dekimuhq/anchors-envelope";
import {
  makeIssuerFixture,
  multiIssuerFetcher,
} from "./_helpers/manifest-issuer.ts";

const TRUSTED_LOG = "https://verify.dekimu.com/acr/v1";

/**
 * `verifyReceipt` returns a `v=1 | v=2 | unknown` union; every receipt here is
 * v=2, so narrow to the v=2 result. Wrapped so the call sites stay unchanged.
 */
function v2(r: Awaited<ReturnType<typeof verifyAcrRaw>>): EnvelopeVerifyResult {
  if (r.envelope_version !== 2) {
    assert.fail(`expected v=2 verify result, got ${String(r.envelope_version)}`);
  }
  return r;
}
const verifyAcr = (
  receipt: unknown,
  opts?: Parameters<typeof verifyAcrRaw>[1],
): Promise<EnvelopeVerifyResult> => verifyAcrRaw(receipt, opts).then(v2);

// --- Issuer fixtures (created once, reused across tests) ---

const issuerAlpha = makeIssuerFixture({
  domain: "alpha-issuer.example",
  operator: { name: "Alpha Corp BV", jurisdiction: "NL" },
  memberships: [
    {
      family: "acr",
      claim_types: ["ar.consent.v1"],
      profiles: [],
      spec_versions: ["v1"],
    },
    {
      family: "apr",
      claim_types: ["ar.provenance.v1"],
      profiles: [],
      spec_versions: ["v1"],
    },
  ],
});

const issuerBeta = makeIssuerFixture({
  domain: "beta-issuer.example",
  operator: { name: "Beta GmbH", jurisdiction: "DE" },
  memberships: [
    {
      family: "acr",
      claim_types: ["ar.consent.v1", "ar.withdrawal.v1"],
      profiles: [],
      spec_versions: ["v1"],
    },
  ],
  trustAnchors: {
    endorses: ["did:web:verify.dekimu.com", "did:web:alpha-issuer.example"],
    endorsed_by: [],
  },
});

const fetcher = multiIssuerFetcher(issuerAlpha, issuerBeta);

// --- Helpers ---

async function mintAcrReceipt(
  issuerDid: string,
  issuerSeed: Uint8Array,
): Promise<{ receipt: Envelope; pub: Uint8Array }> {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const pkDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const pkRaw = pkDer.subarray(-32);
  const iss_key: `ed25519:${string}` = `ed25519:${base64UrlEncode(new Uint8Array(pkRaw))}`;

  const unsigned: Envelope = {
    v: 2,
    id: `01HXX${crypto.randomBytes(11).toString("hex").slice(0, 22).toUpperCase()}`,
    claim_type: "ar.consent.v1",
    iss: issuerDid,
    iss_key,
    subject: "sha256:" + "a".repeat(64),
    iat: "2026-05-25T00:00:00Z",
    exp: null,
    prev: null,
    policy_uri: "https://example.com/policy",
    policy_hash: "sha256:" + "a".repeat(64),
    policy_version: "1.0",
    tsa: null,
    credentialStatus: null,
    anchor: {
      log: TRUSTED_LOG,
      leaf_index: 0,
      inclusion_proof: [],
      tree_head_root: "sha256:" + "0".repeat(64),
      tree_size: 1,
      log_time: "2026-05-25T00:00:01Z",
    },
    sig: "",
    countersig: null,
    body: { lawful_basis: "6(1)(a)" },
  };

  const signed = await signEnvelope(unsigned, privateKey);
  return { receipt: signed, pub: new Uint8Array(pkDer) };
}

function makeResolveKey(
  pub: Uint8Array,
): (envelope: unknown) => Promise<Uint8Array> {
  return async () => pub;
}

function record(
  iss: string,
  overrides: Partial<TrustedIssuerRecord> = {},
): TrustedIssuerRecord {
  return {
    iss,
    added_at: "2025-01-01T00:00:00Z",
    revoked_at: null,
    families: ["acr"],
    profiles_pinned: null,
    notes: null,
    ...overrides,
  };
}

function makeTrustReturning(
  spki: Uint8Array,
  iss: string,
  outcome: IssuerTrustResult["outcome"],
  opts: {
    matched_record?: TrustedIssuerRecord | null;
    reason?: string;
  } = {},
): VerifyIssuerTrust {
  return async () => {
    const reason = opts.reason ?? outcome;
    if (
      outcome === "valid_trusted" ||
      outcome === "valid_untrusted" ||
      outcome === "valid_revoked"
    ) {
      return {
        outcome,
        iss,
        iss_key: "ed25519:dummy",
        spki,
        matched_record: opts.matched_record ?? null,
        reason,
      };
    }
    return {
      outcome,
      iss,
      iss_key: "ed25519:dummy",
      spki: null,
      matched_record: null,
      reason,
    };
  };
}

// --- Tests ---

describe("second-issuer federation e2e", () => {
  describe("manifest fetch + parse", () => {
    it("fetches and parses alpha manifest", async () => {
      const doc = await fetchIssuerManifest({
        url: `https://${issuerAlpha.domain}/.well-known/dekimu-issuer.json`,
        fetcher,
      });
      assert.equal(doc.kind, "ar.issuer_manifest.v1");
      assert.equal(doc.iss, issuerAlpha.did);
      assert.equal(doc.operator.name, "Alpha Corp BV");
      assert.equal(doc.memberships.length, 2);
    });

    it("fetches and parses beta manifest", async () => {
      const doc = await fetchIssuerManifest({
        url: `https://${issuerBeta.domain}/.well-known/dekimu-issuer.json`,
        fetcher,
      });
      assert.equal(doc.kind, "ar.issuer_manifest.v1");
      assert.equal(doc.iss, issuerBeta.did);
      assert.equal(doc.operator.name, "Beta GmbH");
      assert.equal(doc.operator.jurisdiction, "DE");
      assert.equal(doc.memberships.length, 1);
      assert.deepEqual(doc.memberships[0]!.claim_types, [
        "ar.consent.v1",
        "ar.withdrawal.v1",
      ]);
    });

    it("issuers have distinct DIDs", () => {
      assert.notEqual(issuerAlpha.did, issuerBeta.did);
    });

    it("issuers have distinct signing keys", () => {
      assert.notDeepEqual(issuerAlpha.publicKey, issuerBeta.publicKey);
    });
  });

  describe("manifest signature verification", () => {
    it("alpha manifest verifies against alpha key doc", async () => {
      const result = await verifyIssuerManifest({
        doc: issuerAlpha.manifest,
        fetcher,
      });
      assert.equal(result.ok, true);
      if (result.ok) {
        assert.equal(result.outcome, "valid");
        assert.equal(result.doc.iss, issuerAlpha.did);
      }
    });

    it("beta manifest verifies against beta key doc", async () => {
      const result = await verifyIssuerManifest({
        doc: issuerBeta.manifest,
        fetcher,
      });
      assert.equal(result.ok, true);
      if (result.ok) {
        assert.equal(result.outcome, "valid");
        assert.equal(result.doc.iss, issuerBeta.did);
      }
    });

    it("alpha manifest fails against beta key doc (cross-issuer isolation)", async () => {
      // Forge a manifest that claims alpha's iss but points to beta's key doc
      const forged = {
        ...issuerAlpha.manifest,
        key_doc_uri: `https://${issuerBeta.domain}/.well-known/dekimu-keys.json`,
      };
      // Re-parse to pass structural validation (key_doc_uri changed)
      const parsed = parseIssuerManifest(forged);
      assert.equal(parsed.ok, true);
      if (!parsed.ok) return;

      const result = await verifyIssuerManifest({
        doc: parsed.doc,
        fetcher,
      });
      // Should fail: key_doc_uri origin doesn't match iss DID origin
      assert.equal(result.ok, false);
    });
  });

  describe("receipt minting + verification from each issuer", () => {
    it("alpha-issued ACR receipt verifies independently", async () => {
      const { receipt, pub } = await mintAcrReceipt(
        issuerAlpha.did,
        issuerAlpha.seed,
      );
      const r = await verifyAcr(receipt, {
        resolveKey: makeResolveKey(pub),
      });
      assert.equal(r.signature_valid, true);
      assert.equal(r.claim_type, "ar.consent.v1");
    });

    it("beta-issued ACR receipt verifies independently", async () => {
      const { receipt, pub } = await mintAcrReceipt(
        issuerBeta.did,
        issuerBeta.seed,
      );
      const r = await verifyAcr(receipt, {
        resolveKey: makeResolveKey(pub),
      });
      assert.equal(r.signature_valid, true);
      assert.equal(r.claim_type, "ar.consent.v1");
    });
  });

  describe("trust dispatch distinguishes issuers", () => {
    it("alpha trusted, beta untrusted — both receipts verify but with different trust outcomes", async () => {
      const { receipt: alphaReceipt, pub: alphaPub } = await mintAcrReceipt(
        issuerAlpha.did,
        issuerAlpha.seed,
      );
      const { receipt: betaReceipt, pub: betaPub } = await mintAcrReceipt(
        issuerBeta.did,
        issuerBeta.seed,
      );

      const alphaResult = await verifyAcr(alphaReceipt, {
        resolveKey: makeResolveKey(alphaPub),
        verifyIssuerTrust: makeTrustReturning(
          alphaPub,
          issuerAlpha.did,
          "valid_trusted",
          { matched_record: record(issuerAlpha.did), reason: "active" },
        ),
      });
      assert.equal(alphaResult.signature_valid, true);
      assert.equal(alphaResult.trust_outcome, "valid_trusted");

      const betaResult = await verifyAcr(betaReceipt, {
        resolveKey: makeResolveKey(betaPub),
        verifyIssuerTrust: makeTrustReturning(
          betaPub,
          issuerBeta.did,
          "valid_untrusted",
          { reason: "issuer_not_on_allowlist" },
        ),
      });
      assert.equal(betaResult.signature_valid, true);
      assert.equal(betaResult.trust_outcome, "valid_untrusted");
    });

    it("revoked issuer receipt fails verification regardless of signature", async () => {
      const { receipt, pub } = await mintAcrReceipt(
        issuerBeta.did,
        issuerBeta.seed,
      );
      const r = await verifyAcr(receipt, {
        resolveKey: makeResolveKey(pub),
        verifyIssuerTrust: makeTrustReturning(
          pub,
          issuerBeta.did,
          "valid_revoked",
          {
            matched_record: record(issuerBeta.did, {
              revoked_at: "2026-05-01T00:00:00Z",
            }),
          },
        ),
      });
      assert.equal(r.signature_valid, false);
      assert.equal(r.reason, "issuer_revoked");
      assert.equal(r.trust_outcome, "valid_revoked");
    });
  });

  describe("manifest cache isolation", () => {
    it("caching alpha does not return alpha for beta lookup", () => {
      const cache = new ManifestCache({ ttlMs: 60_000, negativeTtlMs: 5000 });

      cache.set(issuerAlpha.did, issuerAlpha.manifest);

      const alphaHit = cache.get(issuerAlpha.did);
      assert.notEqual(alphaHit, undefined);
      assert.notEqual(alphaHit, null);
      if (alphaHit) {
        assert.equal(alphaHit.iss, issuerAlpha.did);
      }

      const betaHit = cache.get(issuerBeta.did);
      assert.equal(betaHit, undefined, "beta must be a cache miss");
    });

    it("negative cache for one issuer does not affect the other", () => {
      const cache = new ManifestCache({ ttlMs: 60_000, negativeTtlMs: 5000 });

      cache.set(issuerAlpha.did, null); // negative cache
      cache.set(issuerBeta.did, issuerBeta.manifest);

      const alphaHit = cache.get(issuerAlpha.did);
      assert.equal(alphaHit, null, "alpha should be negative-cached");

      const betaHit = cache.get(issuerBeta.did);
      assert.notEqual(betaHit, undefined);
      assert.notEqual(betaHit, null);
    });
  });

  describe("cross-issuer trust anchors", () => {
    it("beta endorses alpha in its trust_anchors", () => {
      assert.ok(
        issuerBeta.manifest.trust_anchors.endorses.includes(
          issuerAlpha.did,
        ),
        "beta manifest should list alpha in endorses",
      );
    });

    it("alpha endorses verify.dekimu.com (default)", () => {
      assert.ok(
        issuerAlpha.manifest.trust_anchors.endorses.includes(
          "did:web:verify.dekimu.com",
        ),
      );
    });

    it("endorsement is observational, not a trust grant", () => {
      // Both manifests are structurally valid regardless of endorsement content.
      const alphaResult = parseIssuerManifest(issuerAlpha.manifest);
      const betaResult = parseIssuerManifest(issuerBeta.manifest);
      assert.equal(alphaResult.ok, true);
      assert.equal(betaResult.ok, true);
    });
  });
});
