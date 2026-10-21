/**
 * attachTsaBlock — shared TSA block attachment helper.
 *
 * Phase B Task 12a. Building block called by apr/acr/arr issuer-kits
 * (Tasks 12b/c/d) to attach an RFC 3161 TSA block to a signed envelope.
 *
 * Imprint = SHA-256 of the JCS-canonicalised envelope with `anchor`,
 * `countersig`, and `tsa` zeroed to null. `sig` and `credentialStatus`
 * are signed-in and therefore included in the imprint.
 */

import { createHash, X509Certificate } from "node:crypto";
import { buildTimeStampReq } from "./request.ts";
import { parseTimeStampResp } from "./response.ts";
import { base64UrlEncode } from "../base64url.ts";
import { computeTsaImprint } from "./imprint.ts";
import type { Envelope, TsaBlock } from "../envelope-types.ts";
import type { TsaConfig } from "./types.ts";

// ── Public types ──────────────────────────────────────────────────────────────

/**
 * Async function that sends a DER-encoded TimeStampReq to a TSA and returns
 * the raw DER-encoded TimeStampResp bytes.
 *
 * The caller provides this so tests can inject a mock without touching the
 * network. Production implementations use a plain `fetch`-based wrapper.
 */
export type TsaFetcher = (req: Uint8Array, url: string) => Promise<Uint8Array>;

// ── Error ─────────────────────────────────────────────────────────────────────

/**
 * Thrown by `attachTsaBlock` on any TSP-level failure:
 * network error, timeout, status ≠ 0, or imprint mismatch.
 */
export class TsaMintError extends Error {
  override readonly cause: unknown;
  constructor(message: string, cause: unknown) {
    super(message);
    this.name = "TsaMintError";
    this.cause = cause;
  }
}

// ── Core helper ───────────────────────────────────────────────────────────────

/**
 * Build a TSA block for a signed envelope and return the envelope with `tsa`
 * populated.
 *
 * Imprint: SHA-256 of the JCS-canonicalised envelope with `anchor`,
 * `countersig`, and `tsa` zeroed to null. `sig` and `credentialStatus` are
 * included because they are signed-in fields.
 *
 * Throws `TsaMintError` on:
 * - unsupported hashAlg
 * - network error or TSP timeout
 * - TSP status ≠ 0
 * - imprint mismatch between sent request and returned TSR
 *
 * @param signed - Signed envelope (sig populated; tsa null at call time)
 * @param cfg    - TSA configuration (url, hashAlg, policyOid, timeoutMs, …)
 * @param fetcher - Caller-provided async TSP transport; injectable for testing
 * @returns The envelope with `tsa` populated
 */
export async function attachTsaBlock(
  signed: Envelope,
  cfg: TsaConfig,
  fetcher: TsaFetcher,
): Promise<Envelope> {
  if (cfg.hashAlg !== "sha-256") {
    throw new TsaMintError(`tsa: unsupported hashAlg ${cfg.hashAlg}`, null);
  }

  // Compute imprint via the shared helper — identical to what the verifier computes.
  const imprint = computeTsaImprint(signed);

  const req = buildTimeStampReq(new Uint8Array(imprint), cfg.hashAlg, {
    // certReq MUST be true: RFC 3161 defaults it to FALSE, in which case TSAs
    // (e.g. FreeTSA) return a token with NO embedded certificates. verifyTsa
    // matches the trust anchor against certs embedded in the token, so without
    // this the signer chain is empty and every timestamp fails as
    // `tsa_unrecognised_anchor` — even against the bundled FreeTSA root. With
    // certReq=true FreeTSA embeds [TSA leaf, Root CA]; the Root's SHA-256 DER
    // matches the `freetsa-root-ca` anchor → `tsa_verified`.
    certReq: true,
    ...(cfg.policyOid !== undefined ? { policyOid: cfg.policyOid } : {}),
  });

  // ── TSP call with timeout ─────────────────────────────────────────────────

  let tsrBytes: Uint8Array;
  try {
    const timer = new Promise<never>((_, reject) => {
      const t = setTimeout(
        () => reject(new Error(`tsa: timeout after ${cfg.timeoutMs}ms`)),
        cfg.timeoutMs,
      );
      // Avoid keeping the Node.js event loop alive during tests.
      if (typeof t === "object" && t !== null && "unref" in t) {
        (t as { unref(): void }).unref();
      }
    });
    tsrBytes = await Promise.race([fetcher(req, cfg.url), timer]);
  } catch (err) {
    throw new TsaMintError("tsa: TSP call failed", err);
  }

  // ── Defence-in-depth: validate TSR before persisting ─────────────────────

  const parsed = parseTimeStampResp(tsrBytes);
  if (!parsed.granted) {
    throw new TsaMintError(`tsa: TSP returned non-zero status ${parsed.status}`, null);
  }

  // Imprint round-trip: the returned hashedMessage must equal what we sent.
  if (Buffer.compare(Buffer.from(parsed.tstInfo.hashedMessage), imprint) !== 0) {
    throw new TsaMintError("tsa: returned imprint does not match sent imprint", null);
  }

  // ── Build TsaBlock ────────────────────────────────────────────────────────

  const chainSha256: string[] = parsed.signerInfo.certChainDer.map((certDer) => {
    const cert = new X509Certificate(Buffer.from(certDer));
    return "sha256:" + createHash("sha256").update(cert.raw).digest("hex");
  });

  const block: TsaBlock = {
    v: 1,
    tsr: base64UrlEncode(tsrBytes),
    alg: "sha-256",
    tsa_url: cfg.url,
    tsa_cert_chain_sha256: chainSha256,
    issued_at: new Date().toISOString(),
  };

  return { ...signed, tsa: block };
}
