/**
 * Test fixtures + helpers shared across the federation test suite.
 * No `*.test.ts` suffix → not picked up by the test runner.
 */

import {
  generateKeypair,
  signCanonical,
  base64UrlEncode,
  type Keypair,
} from "@dekimuhq/anchors-envelope";
import type {
  IssuerManifestV1,
  IssuerMembership,
  OperatorInfo,
  TrustAnchors,
} from "../src/types.ts";

/** Convert a fetch input (string | URL | Request) to a plain URL string. */
export function toUrlStr(url: string | URL | Request): string {
  if (typeof url === "string") return url;
  if (url instanceof URL) return url.href;
  return url.url;
}

const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/** Wrap a 32-byte raw Ed25519 public key as SPKI DER (44 bytes). */
export function rawToSpkiDer(rawPubKey32: Uint8Array): Uint8Array {
  return new Uint8Array(Buffer.concat([SPKI_ED25519_PREFIX, Buffer.from(rawPubKey32)]));
}

/** `ed25519:<base64url-encoded raw 32-byte pubkey>`. */
export function issuerKeyFingerprint(rawPubKey32: Uint8Array): string {
  return `ed25519:${base64UrlEncode(rawPubKey32)}`;
}

/** Standard base64 of SPKI DER (for key doc `public_key_der_base64`). */
export function spkiToBase64(rawPubKey32: Uint8Array): string {
  return Buffer.from(rawToSpkiDer(rawPubKey32)).toString("base64");
}

export function defaultOperator(overrides: Partial<OperatorInfo> = {}): OperatorInfo {
  return {
    name: "Test Issuer BV",
    jurisdiction: "NL",
    contact_uri: "mailto:trust@test-issuer.example",
    ...overrides,
  };
}

export function defaultMembership(overrides: Partial<IssuerMembership> = {}): IssuerMembership {
  return {
    family: "apr",
    claim_types: ["ar.provenance.v1"],
    profiles: [],
    spec_versions: ["v1"],
    ...overrides,
  };
}

export function defaultTrustAnchors(overrides: Partial<TrustAnchors> = {}): TrustAnchors {
  return {
    endorses: ["did:web:verify.dekimu.com"],
    endorsed_by: [],
    ...overrides,
  };
}

export interface MakeSignedManifestOpts {
  keypair?: Keypair;
  iss?: string;
  version?: number;
  issued_at?: string;
  valid_until?: string;
  operator?: OperatorInfo;
  key_doc_uri?: string;
  memberships?: IssuerMembership[];
  trust_anchors?: TrustAnchors;
}

const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * Default validity window for a fixture manifest — CLOCK-RELATIVE, deliberately.
 *
 * These were the literals `2026-06-01` → `2026-08-01`. Every happy-path test that
 * did not pin `now` compared them against the real clock, so on 2026-08-01 the
 * default fixture silently went stale and `verifyIssuerManifest` started returning
 * `valid_stale` where the tests expected `valid`. anchors-cohesion-audit has been
 * red every night since, on a defect that is entirely in the fixture: the library
 * is correct, the manifest really had expired.
 *
 * A test that asserts "this manifest is currently valid" has to express that
 * relative to now, or it is really asserting "…until this hardcoded date", which
 * is a time bomb with a fuse measured in months. Tests that care about a SPECIFIC
 * instant pass explicit `issued_at`/`valid_until` AND pin `now` — those stay fully
 * deterministic and are unaffected by this.
 */
const DEFAULT_ISSUED_AT = () => new Date(Date.now() - 30 * DAY_MS).toISOString();
const DEFAULT_VALID_UNTIL = () => new Date(Date.now() + 30 * DAY_MS).toISOString();

/**
 * Build a signed `ar.issuer_manifest.v1` document. Returns the doc + the
 * SPKI DER bytes + keypair for wiring test resolvers.
 */
export function makeSignedManifest(opts: MakeSignedManifestOpts = {}): {
  doc: IssuerManifestV1;
  spki_der: Uint8Array;
  keypair: Keypair;
} {
  const keypair = opts.keypair ?? generateKeypair("test-kid");
  const iss = opts.iss ?? "did:web:test-issuer.example";

  const unsigned = {
    kind: "ar.issuer_manifest.v1" as const,
    version: opts.version ?? 1,
    issued_at: opts.issued_at ?? DEFAULT_ISSUED_AT(),
    valid_until: opts.valid_until ?? DEFAULT_VALID_UNTIL(),
    iss,
    operator: opts.operator ?? defaultOperator(),
    key_doc_uri: opts.key_doc_uri ?? `https://test-issuer.example/.well-known/dekimu-keys.json`,
    memberships: opts.memberships ?? [defaultMembership()],
    trust_anchors: opts.trust_anchors ?? defaultTrustAnchors(),
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
 * Build a Response-returning fetcher for test injection.
 */
export function jsonFetcher(
  body: unknown,
  status = 200,
): typeof fetch {
  return (async () =>
    new Response(typeof body === "string" ? body : JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    })) as typeof fetch;
}

/**
 * Build a key doc JSON for a keypair (matches did-web-resolver KeyDocV1 shape).
 */
export function makeKeyDoc(keypair: Keypair, iss_key?: string) {
  return {
    version: 1,
    keys: [
      {
        iss_key: iss_key ?? issuerKeyFingerprint(keypair.publicKey),
        public_key_der_base64: spkiToBase64(keypair.publicKey),
        valid_from: "2026-01-01T00:00:00Z",
        valid_until: null,
      },
    ],
  };
}

/**
 * Build a fetcher that serves both the manifest and key doc at their
 * expected well-known URLs. Used for end-to-end verify + handshake tests.
 */
export function dualFetcher(
  manifest: IssuerManifestV1,
  keyDoc: ReturnType<typeof makeKeyDoc>,
  domain = "test-issuer.example",
): typeof fetch {
  const manifestUrl = `https://${domain}/.well-known/dekimu-issuer.json`;
  const keyDocUrl = `https://${domain}/.well-known/dekimu-keys.json`;

  return (async (url: string | URL | Request) => {
    // resolveDidWebKey passes a URL object; fetchIssuerManifest passes a string.
    const urlStr = typeof url === "string" ? url : url instanceof URL ? url.href : url.url;
    if (urlStr === manifestUrl) {
      return new Response(JSON.stringify(manifest), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    if (urlStr === keyDocUrl) {
      return new Response(JSON.stringify(keyDoc), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    return new Response("Not found", { status: 404 });
  }) as typeof fetch;
}
