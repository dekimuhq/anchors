/**
 * Test fixtures + helpers shared across the trusted-issuers test suite.
 * No `*.test.ts` suffix → not picked up by the test runner.
 */

import {
  generateKeypair,
  signCanonical,
  base64UrlEncode,
  generateMlDsaKeypair,
  signMlDsaCanonical,
  encodeMlDsaIssKey,
  type Keypair,
  type MlDsaKeypair,
} from "@dekimuhq/anchors-envelope";
import type { TrustedIssuerListV1, TrustedIssuerRecord } from "../src/types.ts";

const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/** Wrap a 32-byte raw Ed25519 public key as SPKI DER (44 bytes). */
export function rawToSpkiDer(rawPubKey32: Uint8Array): Uint8Array {
  return new Uint8Array(Buffer.concat([SPKI_ED25519_PREFIX, Buffer.from(rawPubKey32)]));
}

/** `ed25519:<base64url-encoded raw 32-byte pubkey>`. */
export function publisherKeyFingerprint(rawPubKey32: Uint8Array): string {
  return `ed25519:${base64UrlEncode(rawPubKey32)}`;
}

export interface MakeSignedDocOpts {
  keypair?: Keypair;
  publisher?: string;
  publisher_key?: string;
  issued_at?: string;
  valid_until?: string;
  version?: number;
  previous_sha256?: string | null;
  issuers?: TrustedIssuerRecord[];
}

export function defaultIssuerRecord(
  overrides: Partial<TrustedIssuerRecord> = {},
): TrustedIssuerRecord {
  return {
    iss: "did:web:issuer.example",
    added_at: "2026-05-01T00:00:00Z",
    revoked_at: null,
    families: ["apr", "acr"],
    profiles_pinned: null,
    notes: null,
    ...overrides,
  };
}

/**
 * Build a signed `ar.trusted_issuers.v1` document. Returns the doc + the
 * SPKI DER bytes for the publisher key (so callers can wire a fake resolver
 * or bootstrap pin).
 */
export function makeSignedDoc(opts: MakeSignedDocOpts = {}): {
  doc: TrustedIssuerListV1;
  spki_der: Uint8Array;
  keypair: Keypair;
} {
  const keypair = opts.keypair ?? generateKeypair("test-kid");
  const publisher_key = opts.publisher_key ?? publisherKeyFingerprint(keypair.publicKey);

  const unsigned = {
    kind: "ar.trusted_issuers.v1" as const,
    version: opts.version ?? 1,
    issued_at: opts.issued_at ?? "2026-05-19T00:00:00Z",
    valid_until: opts.valid_until ?? "2026-06-19T00:00:00Z",
    publisher: opts.publisher ?? "did:web:dekimu.com",
    publisher_key,
    previous_sha256: opts.previous_sha256 ?? null,
    issuers: opts.issuers ?? [defaultIssuerRecord()],
    sig: null,
  };

  const sigBytes = signCanonical(unsigned, keypair.privateKey);
  const sig = base64UrlEncode(sigBytes);

  return {
    doc: { ...unsigned, sig },
    spki_der: rawToSpkiDer(keypair.publicKey),
    keypair,
  };
}

/**
 * Build an `ar.trusted_issuers.v1` document signed with ML-DSA-65 (v1.3 PQC).
 * Returns the doc + the 1952-byte raw public key (the resolver/bootstrap form
 * for ml-dsa — node:crypto has no SPKI DER framing for ML-DSA). Needs Node ≥24.6.
 */
export function makeMlDsaSignedDoc(opts: MakeSignedDocOpts = {}): {
  doc: TrustedIssuerListV1;
  raw_pub: Uint8Array;
  keypair: MlDsaKeypair;
} {
  const keypair = generateMlDsaKeypair("test-mldsa-kid");
  const publisher_key = opts.publisher_key ?? encodeMlDsaIssKey(keypair.publicKeyRaw);

  const unsigned = {
    kind: "ar.trusted_issuers.v1" as const,
    version: opts.version ?? 1,
    issued_at: opts.issued_at ?? "2026-05-19T00:00:00Z",
    valid_until: opts.valid_until ?? "2026-06-19T00:00:00Z",
    publisher: opts.publisher ?? "did:web:dekimu.com",
    publisher_key,
    previous_sha256: opts.previous_sha256 ?? null,
    issuers: opts.issuers ?? [defaultIssuerRecord()],
    sig: null,
  };

  const sigBytes = signMlDsaCanonical(unsigned, keypair.privateKey);
  const sig = base64UrlEncode(sigBytes);

  return {
    doc: { ...unsigned, sig },
    raw_pub: keypair.publicKeyRaw,
    keypair,
  };
}

/**
 * Build a Response-returning fetcher for `fetchTrustedIssuers` tests.
 */
export function jsonFetcher(
  body: unknown,
  status = 200,
  init: ResponseInit = {},
): (url: string, opt?: { signal?: AbortSignal }) => Promise<Response> {
  return async () =>
    new Response(typeof body === "string" ? body : JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
      ...init,
    });
}
