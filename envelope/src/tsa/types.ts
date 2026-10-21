/**
 * TSA-related types — Phase B Task 9.
 *
 * TsaBlock re-exported from the envelope-types canonical location.
 * Internal types for RFC 3161 request/response handling.
 */

export type { TsaBlock } from "../envelope-types.ts";

// ── TSA configuration ─────────────────────────────────────────────────────────

export interface TsaConfig {
  url: string;
  trustAnchorIds: string[];
  hashAlg: "sha-256";
  driftToleranceSec: number;
  policyOid?: string;
  timeoutMs: number;
}

// ── Parsed TST structures ─────────────────────────────────────────────────────

/** Parsed TSTInfo from a TimeStampToken (RFC 3161 §2.4.2). */
export interface TstInfo {
  /** OID string of the TSA's time-stamping policy. */
  policy: string;
  /** OID of the hash algorithm used for messageImprint. SHA-256 = 2.16.840.1.101.3.4.2.1 */
  hashAlg: string;
  /** The imprint (hash) value that was time-stamped. */
  hashedMessage: Uint8Array;
  /** Serial number assigned by the TSA to this timestamp. */
  serialNumber: bigint;
  /** RFC 3339 UTC string derived from GeneralizedTime, e.g. "2026-05-17T14:30:00Z". */
  genTime: string;
}

/**
 * SignerIdentifier (RFC 5652 §5.3) — identifies which certificate in the
 * SignedData chain holds the key that produced the SignerInfo signature.
 */
export type SignerId =
  | {
      kind: "issuerAndSerialNumber";
      /** Raw DER bytes of the issuer Name (full TLV incl. SEQUENCE header). */
      issuerDer: Uint8Array;
      /** CertificateSerialNumber as an unsigned bigint. */
      serial: bigint;
    }
  | {
      kind: "subjectKeyIdentifier";
      /** Raw SubjectKeyIdentifier bytes ([0] IMPLICIT OCTET STRING content). */
      ski: Uint8Array;
    };

/** Parsed SignerInfo from the CMS SignedData wrapping the TimeStampToken. */
export interface SignerInfo {
  /** The signature bytes from the SignerInfo. */
  signature: Uint8Array;
  /** OID of the digest algorithm used by the signer. */
  digestAlg: string;
  /** Full DER blobs for each certificate in the SignedData certificates field. */
  certChainDer: Uint8Array[];
  /** OID of the signature algorithm from SignerInfo (RFC 5652 §5.3). */
  signatureAlg: string;
  /** SignerIdentifier — which cert in the chain signed this SignerInfo. */
  sid: SignerId;
  /**
   * Raw DER of signedAttrs when present — the FULL TLV including the
   * `[0]` IMPLICIT tag byte. Per RFC 5652 §5.4 the signature input is this
   * encoding with the first byte replaced by an EXPLICIT SET OF tag (0x31).
   */
  signedAttrsDer?: Uint8Array;
}

/** Result of parsing a full TimeStampResp (RFC 3161 §2.4.2). */
export type ParsedTsr =
  | {
      granted: true;
      status: 0;
      tstInfo: TstInfo;
      signerInfo: SignerInfo;
      /** Raw DER bytes of the TSTInfo eContent (the CMS signed content). */
      tstInfoDer: Uint8Array;
    }
  | { granted: false; status: number; tstInfo: null; signerInfo: null };
