/**
 * Cross-issuer handshake orchestrator.
 *
 * Implements the 4-step onboarding flow from the cross-issuer interop plan §3.3:
 *   1. Discovery — fetch issuer manifest + key doc.
 *   2. Verification — verify manifest signature, self-consistency.
 *   3. Test-vector exchange — verify representative receipts per claimed family.
 *   4. Mutual endorsement (optional) — record endorsement metadata.
 *
 * Returns a `HandshakeReport` — a structured object summarising each step.
 */

import { fetchIssuerManifest, manifestUrlFromDid } from "./fetch.ts";
import { verifyIssuerManifest } from "./verify.ts";
import type { IssuerManifestV1 } from "./types.ts";
import type { KeyCache } from "@dekimuhq/did-web-resolver";

export interface HandshakeOptions {
  /** The issuer DID to handshake with (e.g. `did:web:competitor.com`). */
  iss: string;
  /** Optional: explicit manifest URL (overrides derivation from DID). */
  manifestUrl?: string;
  /** Injectable HTTP fetcher. */
  fetcher?: typeof fetch;
  /** Key cache for did:web resolver. */
  cache?: KeyCache;
  /** Clock override. */
  now?: () => Date;
  /**
   * Test vectors — one representative receipt per family the issuer claims.
   * Key = family slug, value = raw receipt JSON (as-is from the issuer).
   * Omitting a family that the manifest advertises produces a `skipped` result.
   */
  testVectors?: Record<string, unknown>;
  /**
   * Per-family receipt verifier. Given a raw receipt and the issuer DID,
   * returns { ok, code?, reason? }. The handshake orchestrator calls this
   * for each test vector.
   */
  verifyReceipt?: (receipt: unknown, iss: string, family: string) => Promise<ReceiptVerifyResult>;
}

export interface ReceiptVerifyResult {
  ok: boolean;
  code?: string;
  reason?: string;
}

export interface HandshakeStepResult {
  step: string;
  ok: boolean;
  detail: string;
}

export interface TestVectorResult {
  family: string;
  status: "pass" | "fail" | "skipped";
  detail: string;
}

export interface HandshakeReport {
  iss: string;
  manifest_url: string;
  started_at: string;
  completed_at: string;
  overall: "pass" | "fail";
  steps: HandshakeStepResult[];
  test_vectors: TestVectorResult[];
  manifest: IssuerManifestV1 | null;
  warnings: string[];
}

export async function runHandshake(
  opts: HandshakeOptions,
): Promise<HandshakeReport> {
  const startedAt = (opts.now ?? (() => new Date()))().toISOString();
  const manifestUrl = opts.manifestUrl ?? manifestUrlFromDid(opts.iss);
  const steps: HandshakeStepResult[] = [];
  const testVectorResults: TestVectorResult[] = [];
  const warnings: string[] = [];
  let manifest: IssuerManifestV1 | null = null;

  // --- Step 1: Discovery ---
  try {
    const fetchOpts: Parameters<typeof fetchIssuerManifest>[0] = { url: manifestUrl };
    if (opts.fetcher) fetchOpts.fetcher = opts.fetcher;
    manifest = await fetchIssuerManifest(fetchOpts);
    steps.push({
      step: "discovery",
      ok: true,
      detail: `fetched manifest from ${manifestUrl}`,
    });
  } catch (err) {
    steps.push({
      step: "discovery",
      ok: false,
      detail: `fetch failed: ${stringifyErr(err)}`,
    });
    return finalise("fail");
  }

  // --- Step 2: Verification ---
  // 2a. iss consistency: manifest iss must match the handshake target DID.
  if (manifest.iss !== opts.iss) {
    steps.push({
      step: "verification",
      ok: false,
      detail: `manifest iss=${manifest.iss} does not match handshake target ${opts.iss}`,
    });
    return finalise("fail");
  }

  // 2b. Signature verification via did:web key resolution.
  const verifyOpts: Parameters<typeof verifyIssuerManifest>[0] = { doc: manifest };
  if (opts.fetcher) verifyOpts.fetcher = opts.fetcher;
  if (opts.cache) verifyOpts.cache = opts.cache;
  if (opts.now) verifyOpts.now = opts.now;
  const verifyResult = await verifyIssuerManifest(verifyOpts);

  if (!verifyResult.ok) {
    steps.push({
      step: "verification",
      ok: false,
      detail: `${verifyResult.outcome}: ${verifyResult.reason}`,
    });
    return finalise("fail");
  }

  if (verifyResult.warnings.length > 0) {
    warnings.push(...verifyResult.warnings);
  }

  // 2c. Claim-type taxonomy check: all memberships must reference locked families.
  // (Already validated by schema.ts — this step confirms it passed.)
  steps.push({
    step: "verification",
    ok: true,
    detail: `signature valid (${verifyResult.outcome}); ${manifest.memberships.length} family membership(s) declared`,
  });

  // --- Step 3: Test-vector exchange ---
  const advertisedFamilies = manifest.memberships.map((m) => m.family);

  if (!opts.verifyReceipt) {
    // No verifier provided — skip all test vectors.
    for (const family of advertisedFamilies) {
      testVectorResults.push({
        family,
        status: "skipped",
        detail: "no verifyReceipt callback provided",
      });
    }
    steps.push({
      step: "test_vectors",
      ok: true,
      detail: `skipped — no verifyReceipt callback (${advertisedFamilies.length} families)`,
    });
  } else {
    let allPass = true;
    for (const family of advertisedFamilies) {
      const vector = opts.testVectors?.[family];
      if (vector === undefined) {
        testVectorResults.push({
          family,
          status: "skipped",
          detail: "no test vector supplied for this family",
        });
        continue;
      }

      try {
        const result = await opts.verifyReceipt(vector, opts.iss, family);
        if (result.ok) {
          testVectorResults.push({
            family,
            status: "pass",
            detail: "receipt verified end-to-end",
          });
        } else {
          allPass = false;
          testVectorResults.push({
            family,
            status: "fail",
            detail: `verification failed: ${result.code ?? "unknown"} — ${result.reason ?? ""}`,
          });
        }
      } catch (err) {
        allPass = false;
        testVectorResults.push({
          family,
          status: "fail",
          detail: `verifier threw: ${stringifyErr(err)}`,
        });
      }
    }

    const passCount = testVectorResults.filter((r) => r.status === "pass").length;
    const failCount = testVectorResults.filter((r) => r.status === "fail").length;
    const skipCount = testVectorResults.filter((r) => r.status === "skipped").length;

    steps.push({
      step: "test_vectors",
      ok: allPass,
      detail: `${passCount} pass, ${failCount} fail, ${skipCount} skipped`,
    });

    if (!allPass) {
      return finalise("fail");
    }
  }

  // --- Step 4: Mutual endorsement (informational) ---
  const endorsesDekimu = manifest.trust_anchors.endorses.some(
    (d) => d === "did:web:verify.dekimu.com",
  );
  steps.push({
    step: "endorsement",
    ok: true,
    detail: endorsesDekimu
      ? "issuer endorses did:web:verify.dekimu.com"
      : "issuer does not endorse did:web:verify.dekimu.com (optional)",
  });

  return finalise("pass");

  function finalise(overall: "pass" | "fail"): HandshakeReport {
    return {
      iss: opts.iss,
      manifest_url: manifestUrl,
      started_at: startedAt,
      completed_at: (opts.now ?? (() => new Date()))().toISOString(),
      overall,
      steps,
      test_vectors: testVectorResults,
      manifest,
      warnings,
    };
  }
}

function stringifyErr(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
