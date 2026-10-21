import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { runHandshake } from "../src/handshake.ts";
import {
  makeSignedManifest,
  makeKeyDoc,
  dualFetcher,
  defaultMembership,
  toUrlStr,
} from "./fixtures.ts";

describe("runHandshake", () => {
  // --- Happy path ---

  it("completes a successful handshake", async () => {
    const { doc, keypair } = makeSignedManifest({
      iss: "did:web:test-issuer.example",
    });
    const keyDoc = makeKeyDoc(keypair);
    const fetcher = dualFetcher(doc, keyDoc);

    const report = await runHandshake({
      iss: "did:web:test-issuer.example",
      fetcher,
    });
    assert.equal(report.overall, "pass");
    assert.equal(report.iss, "did:web:test-issuer.example");
    assert.equal(report.steps.length, 4); // discovery, verification, test_vectors, endorsement
    assert.ok(report.steps.every((s) => s.ok));
    assert.ok(report.manifest);
  });

  it("includes manifest in report on success", async () => {
    const { doc, keypair } = makeSignedManifest({
      iss: "did:web:test-issuer.example",
    });
    const keyDoc = makeKeyDoc(keypair);
    const fetcher = dualFetcher(doc, keyDoc);

    const report = await runHandshake({
      iss: "did:web:test-issuer.example",
      fetcher,
    });
    assert.equal(report.manifest?.kind, "ar.issuer_manifest.v1");
    assert.equal(report.manifest?.iss, "did:web:test-issuer.example");
  });

  it("records timestamps", async () => {
    const { doc, keypair } = makeSignedManifest({
      iss: "did:web:test-issuer.example",
    });
    const keyDoc = makeKeyDoc(keypair);
    const fetcher = dualFetcher(doc, keyDoc);

    const report = await runHandshake({
      iss: "did:web:test-issuer.example",
      fetcher,
    });
    assert.ok(report.started_at);
    assert.ok(report.completed_at);
  });

  // --- Discovery failures ---

  it("fails on discovery when manifest fetch fails", async () => {
    const fetcher = async () => new Response("Not found", { status: 404 });

    const report = await runHandshake({
      iss: "did:web:missing.example",
      fetcher,
    });
    assert.equal(report.overall, "fail");
    assert.equal(report.steps[0]!.step, "discovery");
    assert.equal(report.steps[0]!.ok, false);
    assert.equal(report.steps.length, 1); // stops after discovery
  });

  it("fails on discovery when network error", async () => {
    const fetcher = async () => { throw new Error("ECONNREFUSED"); };

    const report = await runHandshake({
      iss: "did:web:unreachable.example",
      fetcher,
    });
    assert.equal(report.overall, "fail");
    assert.equal(report.steps[0]!.ok, false);
  });

  // --- Verification failures ---

  it("fails when manifest iss does not match handshake target", async () => {
    const { doc, keypair } = makeSignedManifest({
      iss: "did:web:wrong-issuer.example",
    });
    const keyDoc = makeKeyDoc(keypair);
    // The fetcher responds with a manifest for a different iss
    const fetcher = async (url: string | URL | Request) => {
      if (toUrlStr(url).includes("dekimu-keys")) {
        return new Response(JSON.stringify(keyDoc), { status: 200 });
      }
      return new Response(JSON.stringify(doc), { status: 200 });
    };

    const report = await runHandshake({
      iss: "did:web:expected-issuer.example",
      fetcher,
    });
    assert.equal(report.overall, "fail");
    const verifyStep = report.steps.find((s) => s.step === "verification");
    assert.ok(verifyStep);
    assert.equal(verifyStep.ok, false);
    assert.match(verifyStep.detail, /does not match/);
  });

  it("fails when manifest signature is invalid", async () => {
    const { doc, keypair } = makeSignedManifest({
      iss: "did:web:test-issuer.example",
    });
    // Tamper with the manifest after signing
    const tampered = { ...doc, version: 999 };
    const keyDoc = makeKeyDoc(keypair);
    const fetcher = async (url: string | URL | Request) => {
      if (toUrlStr(url).includes("dekimu-keys")) {
        return new Response(JSON.stringify(keyDoc), { status: 200 });
      }
      return new Response(JSON.stringify(tampered), { status: 200 });
    };

    const report = await runHandshake({
      iss: "did:web:test-issuer.example",
      fetcher,
    });
    assert.equal(report.overall, "fail");
  });

  // --- Test vector exchange ---

  it("passes test vectors when all verify", async () => {
    const { doc, keypair } = makeSignedManifest({
      iss: "did:web:test-issuer.example",
      memberships: [
        defaultMembership({ family: "apr" }),
        defaultMembership({ family: "acr", claim_types: ["ar.consent.v1"] }),
      ],
    });
    const keyDoc = makeKeyDoc(keypair);
    const fetcher = dualFetcher(doc, keyDoc);

    const report = await runHandshake({
      iss: "did:web:test-issuer.example",
      fetcher,
      testVectors: { apr: { mock: "receipt" }, acr: { mock: "receipt" } },
      verifyReceipt: async () => ({ ok: true }),
    });
    assert.equal(report.overall, "pass");
    assert.equal(report.test_vectors.filter((r) => r.status === "pass").length, 2);
  });

  it("fails when a test vector fails verification", async () => {
    const { doc, keypair } = makeSignedManifest({
      iss: "did:web:test-issuer.example",
      memberships: [defaultMembership({ family: "apr" })],
    });
    const keyDoc = makeKeyDoc(keypair);
    const fetcher = dualFetcher(doc, keyDoc);

    const report = await runHandshake({
      iss: "did:web:test-issuer.example",
      fetcher,
      testVectors: { apr: { mock: "bad-receipt" } },
      verifyReceipt: async () => ({ ok: false, code: "invalid_sig", reason: "test failure" }),
    });
    assert.equal(report.overall, "fail");
    assert.equal(report.test_vectors[0]!.status, "fail");
  });

  it("skips test vectors for families without vectors", async () => {
    const { doc, keypair } = makeSignedManifest({
      iss: "did:web:test-issuer.example",
      memberships: [
        defaultMembership({ family: "apr" }),
        defaultMembership({ family: "acr", claim_types: ["ar.consent.v1"] }),
      ],
    });
    const keyDoc = makeKeyDoc(keypair);
    const fetcher = dualFetcher(doc, keyDoc);

    const report = await runHandshake({
      iss: "did:web:test-issuer.example",
      fetcher,
      testVectors: { apr: { mock: "receipt" } }, // no acr vector
      verifyReceipt: async () => ({ ok: true }),
    });
    assert.equal(report.overall, "pass");
    const aprResult = report.test_vectors.find((r) => r.family === "apr");
    const acrResult = report.test_vectors.find((r) => r.family === "acr");
    assert.equal(aprResult?.status, "pass");
    assert.equal(acrResult?.status, "skipped");
  });

  it("skips all test vectors when no verifyReceipt provided", async () => {
    const { doc, keypair } = makeSignedManifest({
      iss: "did:web:test-issuer.example",
    });
    const keyDoc = makeKeyDoc(keypair);
    const fetcher = dualFetcher(doc, keyDoc);

    const report = await runHandshake({
      iss: "did:web:test-issuer.example",
      fetcher,
      // no verifyReceipt
    });
    assert.equal(report.overall, "pass");
    assert.ok(report.test_vectors.every((r) => r.status === "skipped"));
  });

  it("handles verifier that throws", async () => {
    const { doc, keypair } = makeSignedManifest({
      iss: "did:web:test-issuer.example",
      memberships: [defaultMembership({ family: "apr" })],
    });
    const keyDoc = makeKeyDoc(keypair);
    const fetcher = dualFetcher(doc, keyDoc);

    const report = await runHandshake({
      iss: "did:web:test-issuer.example",
      fetcher,
      testVectors: { apr: {} },
      verifyReceipt: async () => { throw new Error("verifier crashed"); },
    });
    assert.equal(report.overall, "fail");
    assert.equal(report.test_vectors[0]!.status, "fail");
    assert.match(report.test_vectors[0]!.detail, /verifier crashed/);
  });

  // --- Endorsement step ---

  it("records endorsement of verify.dekimu.com", async () => {
    const { doc, keypair } = makeSignedManifest({
      iss: "did:web:test-issuer.example",
      trust_anchors: { endorses: ["did:web:verify.dekimu.com"], endorsed_by: [] },
    });
    const keyDoc = makeKeyDoc(keypair);
    const fetcher = dualFetcher(doc, keyDoc);

    const report = await runHandshake({
      iss: "did:web:test-issuer.example",
      fetcher,
    });
    const endorseStep = report.steps.find((s) => s.step === "endorsement");
    assert.ok(endorseStep);
    assert.match(endorseStep.detail, /endorses did:web:verify\.dekimu\.com/);
  });

  it("notes when issuer does not endorse verify.dekimu.com", async () => {
    const { doc, keypair } = makeSignedManifest({
      iss: "did:web:test-issuer.example",
      trust_anchors: { endorses: [], endorsed_by: [] },
    });
    const keyDoc = makeKeyDoc(keypair);
    const fetcher = dualFetcher(doc, keyDoc);

    const report = await runHandshake({
      iss: "did:web:test-issuer.example",
      fetcher,
    });
    const endorseStep = report.steps.find((s) => s.step === "endorsement");
    assert.ok(endorseStep);
    assert.match(endorseStep.detail, /does not endorse/);
  });

  // --- Custom manifest URL ---

  it("uses custom manifestUrl when provided", async () => {
    const { doc, keypair } = makeSignedManifest({
      iss: "did:web:test-issuer.example",
    });
    const keyDoc = makeKeyDoc(keypair);

    const customUrl = "https://test-issuer.example/custom/manifest.json";
    const fetcher = async (url: string | URL | Request) => {
      if (toUrlStr(url) === customUrl) {
        return new Response(JSON.stringify(doc), { status: 200 });
      }
      if (toUrlStr(url).includes("dekimu-keys")) {
        return new Response(JSON.stringify(keyDoc), { status: 200 });
      }
      return new Response("Not found", { status: 404 });
    };

    const report = await runHandshake({
      iss: "did:web:test-issuer.example",
      manifestUrl: customUrl,
      fetcher,
    });
    assert.equal(report.overall, "pass");
    assert.equal(report.manifest_url, customUrl);
  });

  // --- Warnings propagation ---

  it("propagates staleness warnings", async () => {
    const { doc, keypair } = makeSignedManifest({
      iss: "did:web:test-issuer.example",
      issued_at: "2025-01-01T00:00:00Z",
      valid_until: "2025-03-01T00:00:00Z",
    });
    const keyDoc = makeKeyDoc(keypair);
    const fetcher = dualFetcher(doc, keyDoc);

    const report = await runHandshake({
      iss: "did:web:test-issuer.example",
      fetcher,
      now: () => new Date("2026-01-01T00:00:00Z"),
    });
    assert.equal(report.overall, "pass"); // stale is not a failure
    assert.ok(report.warnings.length > 0);
    assert.match(report.warnings[0]!, /stale/);
  });

  // --- Clock override ---

  it("uses now() override", async () => {
    // Explicit window around the pinned instant: this test pins `now`, so it must
    // not lean on the fixture's clock-relative default (see fixtures.ts).
    const { doc, keypair } = makeSignedManifest({
      iss: "did:web:test-issuer.example",
      issued_at: "2026-06-01T00:00:00Z",
      valid_until: "2026-07-01T00:00:00Z",
    });
    const keyDoc = makeKeyDoc(keypair);
    const fetcher = dualFetcher(doc, keyDoc);
    const fixedDate = new Date("2026-06-15T00:00:00Z");

    const report = await runHandshake({
      iss: "did:web:test-issuer.example",
      fetcher,
      now: () => fixedDate,
    });
    assert.equal(report.started_at, fixedDate.toISOString());
  });

  // --- Report shape ---

  it("report has all required fields", async () => {
    const { doc, keypair } = makeSignedManifest({
      iss: "did:web:test-issuer.example",
    });
    const keyDoc = makeKeyDoc(keypair);
    const fetcher = dualFetcher(doc, keyDoc);

    const report = await runHandshake({
      iss: "did:web:test-issuer.example",
      fetcher,
    });
    assert.ok("iss" in report);
    assert.ok("manifest_url" in report);
    assert.ok("started_at" in report);
    assert.ok("completed_at" in report);
    assert.ok("overall" in report);
    assert.ok("steps" in report);
    assert.ok("test_vectors" in report);
    assert.ok("manifest" in report);
    assert.ok("warnings" in report);
  });

  // --- Null manifest on failure ---

  it("report has null manifest on discovery failure", async () => {
    const fetcher = async () => new Response("Not found", { status: 404 });

    const report = await runHandshake({
      iss: "did:web:missing.example",
      fetcher,
    });
    assert.equal(report.manifest, null);
  });
});
