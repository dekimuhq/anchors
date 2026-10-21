/**
 * e2e cross-issuer manifest helpers — builds signed issuer manifests and
 * key docs for dual-issuer federation tests.
 *
 * Copied (not imported) from federation/test/fixtures.ts — per plan §Risk
 * acceptance, near-identical helpers beat exporting private test fixtures
 * across workspace boundaries.
 */

import * as crypto from "node:crypto";
import {
  signCanonical,
  base64UrlEncode,
} from "@dekimuhq/anchors-envelope";
import type {
  IssuerManifestV1,
  IssuerMembership,
  OperatorInfo,
  TrustAnchors,
} from "@dekimuhq/anchors-federation";

const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export interface IssuerFixture {
  domain: string;
  did: string;
  manifest: IssuerManifestV1;
  keyDoc: KeyDocV1;
  seed: Uint8Array;
  publicKey: Uint8Array;
  issKeyFingerprint: string;
}

interface KeyDocV1 {
  version: 1;
  keys: Array<{
    iss_key: string;
    public_key_der_base64: string;
    valid_from: string;
    valid_until: string | null;
  }>;
}

export interface MakeIssuerOpts {
  domain: string;
  operator?: Partial<OperatorInfo>;
  memberships?: IssuerMembership[];
  trustAnchors?: Partial<TrustAnchors>;
  issuedAt?: string;
  validUntil?: string;
}

/**
 * Build a complete issuer fixture: keypair + key doc + signed manifest.
 */
const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * Default manifest validity window — CLOCK-RELATIVE, deliberately.
 *
 * These were the literals `2026-06-01` → `2026-08-01`, and on 2026-08-01 they
 * simply expired: `verifyIssuerManifest` started returning `valid_stale` where
 * `second-issuer-federation.test.ts` expects `valid`, and anchors-cohesion-audit
 * has been red every night since. The library was correct — the fixture manifest
 * really had passed its own `valid_until`.
 *
 * A test asserting "this manifest is currently valid" has to say so relative to
 * now. A hardcoded window is really asserting "…until August", which is a time
 * bomb with a fuse measured in months. Same fix as
 * `anchors/federation/test/fixtures.ts`; callers that care about a specific
 * instant pass `issuedAt`/`validUntil` explicitly and are unaffected.
 */
const defaultIssuedAt = () => new Date(Date.now() - 30 * DAY_MS).toISOString();
const defaultValidUntil = () => new Date(Date.now() + 30 * DAY_MS).toISOString();

export function makeIssuerFixture(opts: MakeIssuerOpts): IssuerFixture {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const skDer = privateKey.export({ format: "der", type: "pkcs8" }) as Buffer;
  const seed = new Uint8Array(skDer.subarray(-32));
  const pkDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const pkRaw = new Uint8Array(pkDer.subarray(-32));

  const issKeyFingerprint = `ed25519:${base64UrlEncode(pkRaw)}`;
  const spkiDer = Buffer.concat([SPKI_ED25519_PREFIX, Buffer.from(pkRaw)]);

  const did = `did:web:${opts.domain}`;

  const keyDoc: KeyDocV1 = {
    version: 1,
    keys: [
      {
        iss_key: issKeyFingerprint,
        public_key_der_base64: spkiDer.toString("base64"),
        valid_from: "2026-01-01T00:00:00Z",
        valid_until: null,
      },
    ],
  };

  const operator: OperatorInfo = {
    name: opts.operator?.name ?? `${opts.domain} BV`,
    jurisdiction: opts.operator?.jurisdiction ?? "NL",
    contact_uri:
      opts.operator?.contact_uri ?? `mailto:trust@${opts.domain}`,
  };

  const memberships: IssuerMembership[] = opts.memberships ?? [
    {
      family: "acr",
      claim_types: ["ar.consent.v1"],
      profiles: [],
      spec_versions: ["v1"],
    },
  ];

  const trustAnchors: TrustAnchors = {
    endorses: opts.trustAnchors?.endorses ?? ["did:web:verify.dekimu.com"],
    endorsed_by: opts.trustAnchors?.endorsed_by ?? [],
  };

  const unsigned = {
    kind: "ar.issuer_manifest.v1" as const,
    version: 1,
    issued_at: opts.issuedAt ?? defaultIssuedAt(),
    valid_until: opts.validUntil ?? defaultValidUntil(),
    iss: did,
    operator,
    key_doc_uri: `https://${opts.domain}/.well-known/dekimu-keys.json`,
    memberships,
    trust_anchors: trustAnchors,
    sig: null,
  };

  const sigBytes = signCanonical(unsigned, seed);
  const manifest: IssuerManifestV1 = {
    ...unsigned,
    sig: base64UrlEncode(sigBytes),
  };

  return {
    domain: opts.domain,
    did,
    manifest,
    keyDoc,
    seed,
    publicKey: pkRaw,
    issKeyFingerprint,
  };
}

/**
 * Build a fetch interceptor that serves manifests and key docs for multiple
 * issuers. Unrecognized URLs return 404.
 */
export function multiIssuerFetcher(
  ...issuers: IssuerFixture[]
): typeof fetch {
  const routes = new Map<string, unknown>();
  for (const iss of issuers) {
    routes.set(
      `https://${iss.domain}/.well-known/dekimu-issuer.json`,
      iss.manifest,
    );
    routes.set(
      `https://${iss.domain}/.well-known/dekimu-keys.json`,
      iss.keyDoc,
    );
  }

  return (async (url: string | URL | Request) => {
    const urlStr =
      typeof url === "string"
        ? url
        : url instanceof URL
          ? url.href
          : url.url;
    const body = routes.get(urlStr);
    if (body !== undefined) {
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    return new Response("Not found", { status: 404 });
  }) as typeof fetch;
}
