/**
 * TSA response verifier — Phase B Task 10.
 *
 * Implements the trust-chain verification for a parsed RFC 3161 TimeStampResp:
 *   1. Status must be 0 (granted).
 *   2. TSTInfo.messageImprint must match the caller-supplied imprint.
 *   3. At least one cert in the embedded chain matches a pinned trust anchor.
 *   4. The matched anchor must not be expired at referenceTime.
 *   5. Each link in the cert chain is verified against the next issuer's key.
 *   6. The CMS SignerInfo signature is verified over the TSTInfo eContent
 *      (RFC 5652 §5.4/§5.6): signedAttrs content-type + message-digest are
 *      checked, then the signature bytes against the signer cert's key.
 *   7. The TST genTime must be within driftToleranceSec of referenceTime.
 */

import { constants, createHash, verify as cryptoVerify, X509Certificate } from "node:crypto";
import { parseTimeStampResp } from "./response.ts";
import { readTLV, decodeOID, readInteger } from "./asn1.ts";
import type { SignerInfo } from "./types.ts";
import type { TrustAnchor } from "./anchors.ts";

// ── Types ─────────────────────────────────────────────────────────────────────

export type TsaReason =
  | "tsa_verified"
  | "tsa_unrecognised_anchor"
  | "tsa_imprint_mismatch"
  | "tsa_signature_invalid"
  | "tsa_signed_attrs_invalid"
  | "tsa_cms_signature_invalid"
  | "tsa_anchor_expired"
  | "tsa_anchor_not_timestamping"
  | "tsa_drift_exceeded"
  | "tsa_status_not_granted";

/**
 * Full TSA state surfaced on a verify result — a superset of `TsaReason` (the
 * outcomes of verifying a present TSA block) plus the no-block and per-event
 * mandate states:
 *   - `"tsa_absent"`      — receipt carries no TSA block.
 *   - `"tsa_required"`    — a MANDATORY mandate found no TSA block (hard fail).
 *   - `"tsa_recommended"` — a RECOMMENDED mandate found no TSA block (advisory).
 *
 * Mandate states are assigned by the per-family TSA-mandate post-steps
 * (ABR/AIR/ARR/AAR/…), which run after the shared pipeline's TSA dispatch.
 */
export type TsaState =
  | "tsa_absent"
  | "tsa_required"
  | "tsa_recommended"
  | TsaReason;

export interface TsaVerifyResult {
  verified: boolean;
  reason: TsaReason;
  anchorName?: string;
  listed: boolean;
  genTime?: string;
  /**
   * TSA policy OID extracted from the parsed TSTInfo. Populated on every code
   * path past the `tsa_status_not_granted` early-return — i.e. wherever the
   * TST itself was successfully parsed, regardless of imprint/anchor/drift
   * outcome. Consumed by profile validators (e.g. ACR `esig.accept@qes`,
   * which requires the eIDAS BTSP policy OID `0.4.0.2023.1.1`).
   */
  policy_oid?: string;
}

export interface TsaVerifyOpts {
  anchors: TrustAnchor[];
  driftToleranceSec: number;
  referenceTime: Date;
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Verify a DER-encoded TimeStampResp against a caller-supplied imprint and
 * a set of trusted anchors. Returns a structured TsaVerifyResult — never throws.
 *
 * @param tsr     Raw DER bytes of the full TimeStampResp.
 * @param imprint The SHA-256 hash of the datum that was time-stamped.
 * @param opts    Anchors, drift tolerance, and reference clock.
 */
export function verifyTsa(
  tsr: Uint8Array,
  imprint: Uint8Array,
  opts: TsaVerifyOpts,
): TsaVerifyResult {
  const parsed = parseTimeStampResp(tsr);
  if (!parsed.granted) {
    return { verified: false, reason: "tsa_status_not_granted", listed: false };
  }

  // From here on, the TST was successfully parsed — surface its policy OID on
  // every return path. Profile validators (e.g. ACR `esig.accept@qes`) require
  // this regardless of whether the trust-chain check ultimately succeeded.
  const policyOid = parsed.tstInfo.policy;

  // Step 1 — imprint must match TSTInfo.messageImprint
  // `imprint` is already a SHA-256 hash (32 bytes); compare directly. Do NOT re-hash — plan body's template had a double-hash bug.
  if (Buffer.compare(Buffer.from(parsed.tstInfo.hashedMessage), Buffer.from(imprint)) !== 0) {
    return { verified: false, reason: "tsa_imprint_mismatch", listed: false, policy_oid: policyOid };
  }

  // Step 2 — find a trust anchor matching any cert in the embedded chain
  const certChain = parsed.signerInfo.certChainDer.map((d) => new X509Certificate(Buffer.from(d)));
  if (certChain.length === 0) {
    return { verified: false, reason: "tsa_unrecognised_anchor", listed: false, policy_oid: policyOid };
  }

  let matchedAnchor: TrustAnchor | undefined;
  for (const cert of certChain) {
    const sha = "sha256:" + createHash("sha256").update(cert.raw).digest("hex");
    matchedAnchor = opts.anchors.find((a) => a.cert_sha256_der === sha);
    if (matchedAnchor) break;
  }
  if (!matchedAnchor) {
    return { verified: false, reason: "tsa_unrecognised_anchor", listed: false, policy_oid: policyOid };
  }

  // Step 3 — anchor must not be expired
  if (new Date(matchedAnchor.valid_until) < opts.referenceTime) {
    return {
      verified: false,
      reason: "tsa_anchor_expired",
      listed: matchedAnchor.eutl_listed,
      policy_oid: policyOid,
    };
  }

  // Step 3b — anchor must advertise timeStamping key usage
  if (!matchedAnchor.key_usage.includes("timeStamping")) {
    return {
      verified: false,
      reason: "tsa_anchor_not_timestamping",
      listed: matchedAnchor.eutl_listed,
      policy_oid: policyOid,
    };
  }

  // Step 4 — verify each link in the chain against the next issuer's public key
  // Note: if certChain has only 1 cert (self-signed root), the loop is a no-op —
  // that is intentional: a pinned self-signed root requires no additional issuer check.
  for (let i = 0; i + 1 < certChain.length; i++) {
    const issuerPub = certChain[i + 1]!.publicKey;
    if (!certChain[i]!.verify(issuerPub)) {
      return {
        verified: false,
        reason: "tsa_signature_invalid",
        listed: matchedAnchor.eutl_listed,
        policy_oid: policyOid,
      };
    }
  }

  // Step 5 — CMS SignerInfo signature over the TSTInfo eContent (RFC 5652
  // §5.4/§5.6 + RFC 3161 §2.4.2). Without this, a genuine TSA cert chain
  // paired with a fabricated TSTInfo would verify true.
  const cmsFailure = verifyCmsSignerInfo(parsed.signerInfo, parsed.tstInfoDer, certChain);
  if (cmsFailure !== null) {
    return {
      verified: false,
      reason: cmsFailure,
      listed: matchedAnchor.eutl_listed,
      policy_oid: policyOid,
    };
  }

  // Step 6 — drift check between TST genTime and caller's reference clock
  const gen = new Date(parsed.tstInfo.genTime);
  const driftSec = Math.abs(gen.getTime() - opts.referenceTime.getTime()) / 1000;
  if (driftSec > opts.driftToleranceSec) {
    return {
      verified: false,
      reason: "tsa_drift_exceeded",
      listed: matchedAnchor.eutl_listed,
      genTime: parsed.tstInfo.genTime,
      policy_oid: policyOid,
    };
  }

  return {
    verified: true,
    reason: "tsa_verified",
    anchorName: matchedAnchor.name,
    listed: matchedAnchor.eutl_listed,
    genTime: parsed.tstInfo.genTime,
    policy_oid: policyOid,
  };
}

// ── CMS SignerInfo signature verification (RFC 5652 §5.4/§5.6) ───────────────

const OID_CONTENT_TYPE = "1.2.840.113549.1.9.3";
const OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
const OID_TST_INFO = "1.2.840.113549.1.9.16.1.4";

/** CMS/X.509 digest-algorithm OID → node:crypto hash name. */
const DIGEST_OID_TO_HASH: Record<string, string> = {
  "1.3.14.3.2.26": "sha1",
  "2.16.840.1.101.3.4.2.4": "sha224",
  "2.16.840.1.101.3.4.2.1": "sha256",
  "2.16.840.1.101.3.4.2.2": "sha384",
  "2.16.840.1.101.3.4.2.3": "sha512",
};

const OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1";
const OID_RSASSA_PSS = "1.2.840.113549.1.1.10";
const OID_ED25519 = "1.3.101.112";

/** signature-algorithm OIDs that pin their own hash (RSA PKCS#1 v1.5 / ECDSA). */
const SIG_OID_TO_HASH: Record<string, { hash: string; kind: "rsa" | "ecdsa" }> = {
  "1.2.840.113549.1.1.5": { hash: "sha1", kind: "rsa" },
  "1.2.840.113549.1.1.14": { hash: "sha224", kind: "rsa" },
  "1.2.840.113549.1.1.11": { hash: "sha256", kind: "rsa" },
  "1.2.840.113549.1.1.12": { hash: "sha384", kind: "rsa" },
  "1.2.840.113549.1.1.13": { hash: "sha512", kind: "rsa" },
  "1.2.840.10045.4.1": { hash: "sha1", kind: "ecdsa" },
  "1.2.840.10045.4.3.1": { hash: "sha224", kind: "ecdsa" },
  "1.2.840.10045.4.3.2": { hash: "sha256", kind: "ecdsa" },
  "1.2.840.10045.4.3.3": { hash: "sha384", kind: "ecdsa" },
  "1.2.840.10045.4.3.4": { hash: "sha512", kind: "ecdsa" },
};

/**
 * Extract issuer Name DER + serial from a raw X.509 certificate.
 *
 *   Certificate ::= SEQUENCE {
 *     tbsCertificate SEQUENCE {
 *       version [0] EXPLICIT OPTIONAL, serialNumber INTEGER,
 *       signature AlgorithmIdentifier, issuer Name, ... }, ... }
 */
function certIssuerAndSerial(certDer: Uint8Array): { issuerDer: Uint8Array; serial: bigint } {
  const cert = readTLV(certDer, 0);
  const tbs = readTLV(certDer, cert.contentStart);
  let off = tbs.contentStart;
  const first = readTLV(certDer, off);
  if (first.tag === 0xa0) {
    off = first.contentStart + first.length; // skip [0] version
  }
  const serial = readInteger(certDer, off);
  const serialTlv = readTLV(certDer, off);
  const sigAlgTlv = readTLV(certDer, serialTlv.contentStart + serialTlv.length);
  const issuerStart = sigAlgTlv.contentStart + sigAlgTlv.length;
  const issuerTlv = readTLV(certDer, issuerStart);
  return {
    issuerDer: certDer.subarray(issuerStart, issuerTlv.contentStart + issuerTlv.length),
    serial,
  };
}

/**
 * Validate the mandatory signed attributes (RFC 5652 §11.1/§11.2):
 *   - content-type must be id-ct-TSTInfo,
 *   - message-digest must equal hash(TSTInfo eContent) under `hashName`.
 * Returns true only when BOTH attributes are present and correct.
 */
function checkSignedAttrs(
  signedAttrsDer: Uint8Array,
  tstInfoDer: Uint8Array,
  hashName: string,
): boolean {
  const outer = readTLV(signedAttrsDer, 0);
  const end = outer.contentStart + outer.length;
  let off = outer.contentStart;
  let contentTypeOk = false;
  let messageDigestOk = false;
  let sawContentType = false;
  let sawMessageDigest = false;

  while (off < end) {
    // Attribute ::= SEQUENCE { attrType OID, attrValues SET OF AttributeValue }
    const attr = readTLV(signedAttrsDer, off);
    if (attr.tag !== 0x30) return false;
    const typeTlv = readTLV(signedAttrsDer, attr.contentStart);
    if (typeTlv.tag !== 0x06) return false;
    const attrType = decodeOID(signedAttrsDer, typeTlv.contentStart, typeTlv.length);
    const valuesTlv = readTLV(signedAttrsDer, typeTlv.contentStart + typeTlv.length);
    if (valuesTlv.tag !== 0x31) return false;

    if (attrType === OID_CONTENT_TYPE) {
      if (sawContentType) return false; // RFC 5652 §5.3: only one instance
      sawContentType = true;
      const valueTlv = readTLV(signedAttrsDer, valuesTlv.contentStart);
      contentTypeOk =
        valueTlv.tag === 0x06 &&
        decodeOID(signedAttrsDer, valueTlv.contentStart, valueTlv.length) === OID_TST_INFO;
    } else if (attrType === OID_MESSAGE_DIGEST) {
      if (sawMessageDigest) return false;
      sawMessageDigest = true;
      const valueTlv = readTLV(signedAttrsDer, valuesTlv.contentStart);
      if (valueTlv.tag !== 0x04) return false;
      const claimed = signedAttrsDer.subarray(
        valueTlv.contentStart,
        valueTlv.contentStart + valueTlv.length,
      );
      const actual = createHash(hashName).update(tstInfoDer).digest();
      messageDigestOk = Buffer.compare(Buffer.from(claimed), actual) === 0;
    }

    off = attr.contentStart + attr.length;
  }

  return contentTypeOk && messageDigestOk;
}

/**
 * Verify raw signature bytes against one certificate's public key, per the
 * SignerInfo signatureAlgorithm OID. node:crypto only.
 */
function verifySignatureBytes(
  cert: X509Certificate,
  signatureAlgOid: string,
  digestHash: string | undefined,
  data: Uint8Array,
  signature: Uint8Array,
): boolean {
  const pinned = SIG_OID_TO_HASH[signatureAlgOid];
  if (pinned !== undefined) {
    return cryptoVerify(pinned.hash, data, cert.publicKey, signature);
  }
  if (signatureAlgOid === OID_RSA_ENCRYPTION) {
    // Bare rsaEncryption: hash comes from the SignerInfo digestAlgorithm.
    if (digestHash === undefined) return false;
    return cryptoVerify(digestHash, data, cert.publicKey, signature);
  }
  if (signatureAlgOid === OID_RSASSA_PSS) {
    // RSASSA-PSS: hash from the SignerInfo digestAlgorithm; salt length
    // recovered from the signature (RSA_PSS_SALTLEN_AUTO).
    if (digestHash === undefined) return false;
    return cryptoVerify(
      digestHash,
      data,
      {
        key: cert.publicKey,
        padding: constants.RSA_PKCS1_PSS_PADDING,
        saltLength: constants.RSA_PSS_SALTLEN_AUTO,
      },
      signature,
    );
  }
  if (signatureAlgOid === OID_ED25519) {
    return cryptoVerify(null, data, cert.publicKey, signature);
  }
  return false; // unknown algorithm — fail closed
}

/**
 * Verify the CMS SignerInfo signature over the TSTInfo eContent.
 *
 * Returns `null` on success, or the fail-closed reason:
 *   - `"tsa_signed_attrs_invalid"` — signedAttrs malformed, or content-type /
 *     message-digest attributes missing or not matching the eContent.
 *   - `"tsa_cms_signature_invalid"` — signer cert not identifiable, algorithm
 *     unsupported, or the signature bytes do not verify.
 *
 * Signature input per RFC 5652 §5.4: when signedAttrs are present (the normal
 * RFC 3161 case), the DER of SignedAttributes with the IMPLICIT [0] tag byte
 * replaced by EXPLICIT SET OF (0x31); otherwise the eContent bytes directly.
 *
 * Signer cert selection: `issuerAndSerialNumber` is matched against each
 * chain cert's issuer DER + serial. For `subjectKeyIdentifier` the parser
 * does not extract the SKI extension from certs, so every chain cert is
 * tried — sound, because the signature check itself is the binding.
 */
function verifyCmsSignerInfo(
  signerInfo: SignerInfo,
  tstInfoDer: Uint8Array,
  certChain: X509Certificate[],
): "tsa_signed_attrs_invalid" | "tsa_cms_signature_invalid" | null {
  try {
    const digestHash = DIGEST_OID_TO_HASH[signerInfo.digestAlg];

    // Signed bytes per RFC 5652 §5.4
    let signedBytes: Uint8Array;
    if (signerInfo.signedAttrsDer !== undefined) {
      if (digestHash === undefined) return "tsa_signed_attrs_invalid";
      if (!checkSignedAttrs(signerInfo.signedAttrsDer, tstInfoDer, digestHash)) {
        return "tsa_signed_attrs_invalid";
      }
      signedBytes = Uint8Array.from(signerInfo.signedAttrsDer);
      signedBytes[0] = 0x31; // IMPLICIT [0] → EXPLICIT SET OF
    } else {
      signedBytes = tstInfoDer;
    }

    // Candidate signer certs
    let candidates: X509Certificate[];
    if (signerInfo.sid.kind === "issuerAndSerialNumber") {
      const { issuerDer, serial } = signerInfo.sid;
      candidates = certChain.filter((cert) => {
        try {
          const info = certIssuerAndSerial(new Uint8Array(cert.raw));
          return (
            info.serial === serial &&
            Buffer.compare(Buffer.from(info.issuerDer), Buffer.from(issuerDer)) === 0
          );
        } catch {
          return false;
        }
      });
    } else {
      candidates = certChain;
    }
    if (candidates.length === 0) return "tsa_cms_signature_invalid";

    for (const cert of candidates) {
      if (
        verifySignatureBytes(
          cert,
          signerInfo.signatureAlg,
          digestHash,
          signedBytes,
          signerInfo.signature,
        )
      ) {
        return null;
      }
    }
    return "tsa_cms_signature_invalid";
  } catch {
    return "tsa_cms_signature_invalid"; // any parse/verify throw — fail closed
  }
}
