/**
 * Reference issuer for APR v1. Pure, in-process: takes a body + signing key,
 * returns a serialised APR claim. The hosted verifier at verify.dekimu.com
 * (or any other v1-conforming verifier) will accept the output.
 *
 * Pairs with `@dekimuhq/apr` (the verifier at the root export) for the symmetric verify path.
 */

import * as crypto from "node:crypto";
import { canonicalize } from "../canonicalize.ts";
import { base64UrlEncode } from "../base64url.ts";
import type { APRBody, APRClaim } from "../types.ts";

const PKCS8_ED25519_PREFIX = Buffer.from(
  "302e020100300506032b657004220420",
  "hex",
);

import type { SigningKey } from "@dekimuhq/anchors-envelope/issuer";
export type { SigningKey };

export interface MintInput {
  /** Short issuer identifier, e.g. "my-app". Must match the catalog entry for `kid`. */
  issuer: string;
  /** Free-form subject (typically an artifact id or a stable URL). */
  subject: string;
  /** Required body — see apr-spec §3. */
  body: APRBody;
  /** Signing key (kid + 32-byte seed). */
  signingKey: SigningKey;
  /** Optional `holder` identifier. */
  holder?: string;
  /** Optional `audience` list. */
  audience?: string[];
  /** Optional unix-seconds expiry. */
  exp?: number;
  /** Optional parent claim id. */
  parent?: string;
  /** Override clock for testability (defaults to system clock). */
  now?: () => number;
  /** Override id generator for testability (defaults to ULID). */
  newId?: () => string;
}

export function mint(input: MintInput): APRClaim {
  if (!input.issuer) throw new Error("mint: issuer required");
  if (!input.subject) throw new Error("mint: subject required");
  if (!input.body) throw new Error("mint: body required");
  if (!input.signingKey || !input.signingKey.kid) {
    throw new Error("mint: signingKey.kid required");
  }
  if (input.signingKey.privateKey.length !== 32) {
    throw new Error("mint: signingKey.privateKey must be 32 bytes");
  }

  const iat = (input.now ?? defaultNow)();
  const id = (input.newId ?? newUlid)();

  const unsigned = {
    v: 1 as const,
    id,
    kind: "ar.provenance.v1" as const,
    issuer: input.issuer,
    subject: input.subject,
    iat,
    kid: input.signingKey.kid,
    body: input.body,
    ...(input.holder !== undefined ? { holder: input.holder } : {}),
    ...(input.audience !== undefined ? { audience: input.audience } : {}),
    ...(input.exp !== undefined ? { exp: input.exp } : {}),
    ...(input.parent !== undefined ? { parent: input.parent } : {}),
  };

  const bytes = new TextEncoder().encode(canonicalize(unsigned));
  const sk = privKeyFromSeed(input.signingKey.privateKey);
  const sig = crypto.sign(null, bytes, sk);

  return { ...unsigned, sig: base64UrlEncode(new Uint8Array(sig)) };
}

function privKeyFromSeed(seed: Uint8Array): crypto.KeyObject {
  const der = Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(seed)]);
  return crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

function defaultNow(): number {
  return Math.floor(Date.now() / 1000);
}

/**
 * Crockford-Base32 ULID. Time-prefixed (10 chars), random suffix (16 chars).
 * Implementation is deliberately small — issuers SHOULD bring their own ULID
 * library in production for collision-resistance guarantees they trust.
 */
const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

function newUlid(): string {
  const now = Date.now();
  let timeStr = "";
  let t = now;
  for (let i = 0; i < 10; i++) {
    timeStr = CROCKFORD[t % 32] + timeStr;
    t = Math.floor(t / 32);
  }
  const randBytes = crypto.randomBytes(16);
  let randStr = "";
  for (let i = 0; i < 16; i++) {
    randStr += CROCKFORD[randBytes[i]! % 32];
  }
  return timeStr + randStr;
}
