/**
 * In-memory signed Status List 2021 Credential helper for verifier tests.
 *
 * Phase D Task 19. The committed fixture
 * `envelope/test/status/fixtures/status-list-signed.json` covers the all-zero
 * bitstring case. For per-test scenarios that need a specific bit set, build
 * the credential inline with this helper — no fixture file changes required.
 *
 * Cycle:
 *   1. Caller passes `bitIndex` + `bitValue` + a signing keypair.
 *   2. Helper builds a 131072-bit bitstring (W3C minimum), sets the bit,
 *      gzip+base64url-encodes it, fills the credential body, and signs it
 *      Ed25519Signature2020 over the RFC 8785-canonical unsigned form.
 *   3. Caller threads the matching public key into `RootKeyMaterial`.
 *
 * NEVER imports the on-disk fixtures. NEVER writes to disk.
 */

import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { canonicalize } from "../../src/index.ts";
import { base64UrlEncode } from "../../src/base64url.ts";
import { encodedListFromBitstring } from "../../src/status/decode.ts";
import type {
  StatusListCredential,
  RootKeyMaterial,
} from "../../src/status/types.ts";

export interface SignedListOpts {
  /** Bit index to flip (0 = first bit of byte 0; W3C MSB-first). */
  bitIndex: number;
  /** 0 = active, 1 = revoked. */
  bitValue: 0 | 1;
  /** DID identifier embedded in the credential proof.verificationMethod. */
  kid?: string;
  /** ID URL embedded in the credential (and the URL the verifier fetches). */
  credentialUrl?: string;
  /** statusPurpose for the credential — "revocation" by default. */
  statusPurpose?: string;
  /** Bitstring length in bits — 131072 (W3C minimum) by default. */
  bitstringLengthBits?: number;
}

export interface SignedListResult {
  credential: StatusListCredential;
  rootKey: RootKeyMaterial;
}

const DEFAULT_KID = "did:web:verify.dekimu.com#root";
const DEFAULT_URL = "https://verify.dekimu.com/test/status/2026/05";
const DEFAULT_LENGTH_BITS = 131072;

export function makeSignedStatusList(opts: SignedListOpts): SignedListResult {
  const lenBits = opts.bitstringLengthBits ?? DEFAULT_LENGTH_BITS;
  if (opts.bitIndex < 0 || opts.bitIndex >= lenBits) {
    throw new Error(
      `makeSignedStatusList: bitIndex ${opts.bitIndex} out of range (0..${lenBits - 1})`,
    );
  }

  const bits = new Uint8Array(lenBits / 8);
  if (opts.bitValue === 1) {
    const byteIdx = opts.bitIndex >>> 3;
    const bitOff = 7 - (opts.bitIndex & 7); // MSB-first
    bits[byteIdx] = (bits[byteIdx] ?? 0) | (1 << bitOff);
  }
  const encodedList = encodedListFromBitstring(bits);

  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicKeyDer = publicKey.export({ format: "der", type: "spki" });
  const publicKeyDerB64u = base64UrlEncode(new Uint8Array(publicKeyDer));

  const kid = opts.kid ?? DEFAULT_KID;
  const credentialUrl = opts.credentialUrl ?? DEFAULT_URL;
  const statusPurpose = opts.statusPurpose ?? "revocation";

  const unsigned = {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://w3id.org/vc/status-list/2021/v1",
    ],
    id: credentialUrl,
    type: ["VerifiableCredential", "StatusList2021Credential"],
    issuer: "did:web:verify.dekimu.com",
    validFrom: "2026-05-01T00:00:00Z",
    credentialSubject: {
      id: `${credentialUrl}#list`,
      type: "StatusList2021" as const,
      statusPurpose,
      encodedList,
    },
  };

  const canonical = canonicalize(unsigned);
  const sigBytes = edSign(null, Buffer.from(canonical, "utf8"), privateKey);

  const credential: StatusListCredential = {
    ...unsigned,
    proof: {
      type: "Ed25519Signature2020",
      created: "2026-05-17T00:00:00Z",
      verificationMethod: kid,
      proofPurpose: "assertionMethod",
      proofValue: base64UrlEncode(new Uint8Array(sigBytes)),
    },
  };

  return {
    credential,
    rootKey: { kid, publicKeyDer: publicKeyDerB64u },
  };
}
