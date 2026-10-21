/**
 * RFC 3161 TimeStampResp parser — Phase B Task 9.
 *
 * Parses a DER-encoded TimeStampResp (RFC 3161 §2.4.2):
 *
 *   TimeStampResp ::= SEQUENCE {
 *     status         PKIStatusInfo,
 *     timeStampToken ContentInfo OPTIONAL   -- absent when status ≠ 0
 *   }
 *
 * The ContentInfo wraps a CMS SignedData (RFC 5652 §5) whose encapContentInfo
 * holds the DER-encoded TSTInfo.
 *
 * Only the subset of fields needed by the TSA integration are extracted.
 * Full cert-chain trust validation is Task 10.
 */

import {
  readTLV,
  decodeOID,
  readInteger,
  readGeneralizedTime,
  readOctetString,
} from "./asn1.ts";
import type { ParsedTsr, TstInfo, SignerInfo, SignerId } from "./types.ts";

// ── OID constants ─────────────────────────────────────────────────────────────

const OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
const OID_TST_INFO = "1.2.840.113549.1.9.16.1.4";

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Walk ContentInfo → [0] EXPLICIT → SignedData and return the SignedData TLV
 * plus the offset of its first body byte. Used by both findTstInfoOctets and
 * parseFirstSignerInfo to avoid duplicating the walk.
 */
function walkToSignedData(
  der: Uint8Array,
  ci: ReturnType<typeof readTLV>,
): { sd: ReturnType<typeof readTLV>; sdBodyOffset: number } {
  // ContentInfo: SEQUENCE { contentType OID, [0] EXPLICIT content }
  const ctOidTlv = readTLV(der, ci.contentStart);
  if (ctOidTlv.tag !== 0x06) {
    throw new Error("tsr: ContentInfo contentType is not OID");
  }
  const ctOidStr = decodeOID(der, ctOidTlv.contentStart, ctOidTlv.length);
  if (ctOidStr !== OID_SIGNED_DATA) {
    throw new Error(`tsr: unexpected contentType OID ${ctOidStr}`);
  }

  // [0] EXPLICIT SignedData
  const expl0 = readTLV(der, ctOidTlv.contentStart + ctOidTlv.length);
  if (expl0.tag !== 0xa0) {
    throw new Error(`tsr: expected [0] EXPLICIT (0xA0), got 0x${expl0.tag.toString(16)}`);
  }

  // SignedData SEQUENCE
  const sd = readTLV(der, expl0.contentStart);
  if (sd.tag !== 0x30) {
    throw new Error("tsr: SignedData is not a SEQUENCE");
  }

  return { sd, sdBodyOffset: sd.contentStart };
}

/**
 * Walk a ContentInfo → SignedData → encapContentInfo → eContent and return the
 * raw TSTInfo DER bytes (the inner OCTET STRING content).
 */
function findTstInfoOctets(der: Uint8Array, ci: ReturnType<typeof readTLV>): Uint8Array {
  const { sd } = walkToSignedData(der, ci);

  // version INTEGER
  const sdVer = readTLV(der, sd.contentStart);
  // digestAlgorithms SET
  const dAlgs = readTLV(der, sdVer.contentStart + sdVer.length);
  // encapContentInfo SEQUENCE
  const eci = readTLV(der, dAlgs.contentStart + dAlgs.length);
  if (eci.tag !== 0x30) {
    throw new Error("tsr: encapContentInfo is not a SEQUENCE");
  }

  // eContentType OID
  const eCtOid = readTLV(der, eci.contentStart);
  if (eCtOid.tag !== 0x06) {
    throw new Error("tsr: eContentType is not OID");
  }
  const eCtOidStr = decodeOID(der, eCtOid.contentStart, eCtOid.length);
  if (eCtOidStr !== OID_TST_INFO) {
    throw new Error(`tsr: unexpected eContentType OID ${eCtOidStr}`);
  }

  // [0] EXPLICIT eContent
  const expl0ec = readTLV(der, eCtOid.contentStart + eCtOid.length);
  if (expl0ec.tag !== 0xa0) {
    throw new Error("tsr: eContent [0] EXPLICIT tag missing");
  }

  // OCTET STRING containing TSTInfo DER
  const octetStr = readTLV(der, expl0ec.contentStart);
  if (octetStr.tag !== 0x04) {
    throw new Error("tsr: eContent is not an OCTET STRING");
  }
  return der.subarray(octetStr.contentStart, octetStr.contentStart + octetStr.length);
}

/**
 * Parse a DER-encoded TSTInfo SEQUENCE into a TstInfo object.
 *
 *   TSTInfo ::= SEQUENCE {
 *     version      INTEGER { v1(1) },
 *     policy       TSAPolicyId (OID),
 *     messageImprint MessageImprint {
 *       hashAlgorithm AlgorithmIdentifier,
 *       hashedMessage OCTET STRING
 *     },
 *     serialNumber  INTEGER,
 *     genTime       GeneralizedTime,
 *     ...            (accuracy, ordering, nonce, tsa, extensions — ignored)
 *   }
 */
function parseTstInfo(octets: Uint8Array): TstInfo {
  const seq = readTLV(octets, 0);
  if (seq.tag !== 0x30) {
    throw new Error("tsr: TSTInfo is not a SEQUENCE");
  }

  // version INTEGER
  const ver = readTLV(octets, seq.contentStart);
  // policy OID
  const policyTlv = readTLV(octets, ver.contentStart + ver.length);
  if (policyTlv.tag !== 0x06) {
    throw new Error("tsr: TSTInfo policy is not OID");
  }
  const policy = decodeOID(octets, policyTlv.contentStart, policyTlv.length);

  // messageImprint SEQUENCE
  const mi = readTLV(octets, policyTlv.contentStart + policyTlv.length);
  if (mi.tag !== 0x30) {
    throw new Error("tsr: messageImprint is not a SEQUENCE");
  }
  // AlgorithmIdentifier SEQUENCE
  const algId = readTLV(octets, mi.contentStart);
  if (algId.tag !== 0x30) {
    throw new Error("tsr: AlgorithmIdentifier is not a SEQUENCE");
  }
  const algOid = readTLV(octets, algId.contentStart);
  if (algOid.tag !== 0x06) {
    throw new Error("tsr: AlgorithmIdentifier OID missing");
  }
  const hashAlg = decodeOID(octets, algOid.contentStart, algOid.length);

  // hashedMessage OCTET STRING — immediately after full algId TLV inside mi
  const algIdEnd = algId.contentStart + algId.length;
  const hmOs = readOctetString(octets, algIdEnd);

  // serialNumber INTEGER — after full messageImprint TLV
  const miEnd = mi.contentStart + mi.length;
  const serialNumber = readInteger(octets, miEnd);

  // genTime GeneralizedTime — after serialNumber TLV
  const snTlv = readTLV(octets, miEnd);
  const gtOff = snTlv.contentStart + snTlv.length;
  const genTime = readGeneralizedTime(octets, gtOff);

  return { policy, hashAlg, hashedMessage: hmOs, serialNumber, genTime };
}

/**
 * Extract certificates and first SignerInfo from SignedData.
 *
 * Walks ContentInfo → SignedData → certificates [0] IMPLICIT (optional) →
 * signerInfos SET → first SignerInfo.
 */
function parseFirstSignerInfo(der: Uint8Array, ci: ReturnType<typeof readTLV>): SignerInfo {
  const { sd } = walkToSignedData(der, ci);
  const sdVer = readTLV(der, sd.contentStart);
  const dAlgs = readTLV(der, sdVer.contentStart + sdVer.length);
  const eci = readTLV(der, dAlgs.contentStart + dAlgs.length);
  const eciEnd = eci.contentStart + eci.length;

  // certificates [0] IMPLICIT OPTIONAL — tag 0xA0
  const certChainDer: Uint8Array[] = [];
  let signerInfosOff = eciEnd;

  const maybeIter = readTLV(der, eciEnd);
  if (maybeIter.tag === 0xa0) {
    // Collect each certificate (each is a top-level X.509 SEQUENCE)
    let certOff = maybeIter.contentStart;
    const certsEnd = maybeIter.contentStart + maybeIter.length;
    while (certOff < certsEnd) {
      const certTlv = readTLV(der, certOff);
      if (certTlv.tag !== 0x30) break; // non-cert entry — stop
      const certDerEnd = certTlv.contentStart + certTlv.length;
      // Include the outer SEQUENCE TL bytes in the DER blob
      certChainDer.push(der.subarray(certOff, certDerEnd));
      certOff = certDerEnd;
    }
    signerInfosOff = maybeIter.contentStart + maybeIter.length;
  }

  // crls [1] IMPLICIT OPTIONAL — tag 0xA1 (skip if present)
  const maybeCrls = readTLV(der, signerInfosOff);
  if (maybeCrls.tag === 0xa1) {
    signerInfosOff = maybeCrls.contentStart + maybeCrls.length;
  }

  // signerInfos SET OF SignerInfo
  const siSet = readTLV(der, signerInfosOff);
  if (siSet.tag !== 0x31) {
    throw new Error(`tsr: signerInfos is not a SET (0x31), got 0x${siSet.tag.toString(16)}`);
  }

  // First SignerInfo SEQUENCE
  const si = readTLV(der, siSet.contentStart);
  if (si.tag !== 0x30) {
    throw new Error("tsr: SignerInfo is not a SEQUENCE");
  }

  // version INTEGER
  const siVer = readTLV(der, si.contentStart);
  // sid (IssuerAndSerialNumber SEQUENCE or [0] IMPLICIT SubjectKeyIdentifier)
  const sidTlv = readTLV(der, siVer.contentStart + siVer.length);
  let sid: SignerId;
  if (sidTlv.tag === 0x30) {
    // IssuerAndSerialNumber ::= SEQUENCE { issuer Name, serialNumber INTEGER }
    const issuerTlv = readTLV(der, sidTlv.contentStart);
    if (issuerTlv.tag !== 0x30) {
      throw new Error("tsr: SignerInfo sid issuer Name is not a SEQUENCE");
    }
    const issuerEnd = issuerTlv.contentStart + issuerTlv.length;
    sid = {
      kind: "issuerAndSerialNumber",
      issuerDer: der.subarray(sidTlv.contentStart, issuerEnd),
      serial: readInteger(der, issuerEnd),
    };
  } else if (sidTlv.tag === 0x80) {
    // [0] IMPLICIT SubjectKeyIdentifier (OCTET STRING content)
    sid = {
      kind: "subjectKeyIdentifier",
      ski: der.subarray(sidTlv.contentStart, sidTlv.contentStart + sidTlv.length),
    };
  } else {
    throw new Error(`tsr: unrecognised SignerIdentifier tag 0x${sidTlv.tag.toString(16)}`);
  }

  // digestAlgorithm SEQUENCE
  const dAlg = readTLV(der, sidTlv.contentStart + sidTlv.length);
  if (dAlg.tag !== 0x30) {
    throw new Error("tsr: SignerInfo digestAlgorithm is not a SEQUENCE");
  }
  const dAlgOidTlv = readTLV(der, dAlg.contentStart);
  if (dAlgOidTlv.tag !== 0x06) {
    throw new Error("tsr: SignerInfo digestAlgorithm OID missing");
  }
  const digestAlg = decodeOID(der, dAlgOidTlv.contentStart, dAlgOidTlv.length);

  // signedAttrs [0] IMPLICIT OPTIONAL — tag 0xA0. Keep the FULL TLV bytes
  // (tag + length + content): RFC 5652 §5.4 defines the signature input as
  // this encoding with the IMPLICIT [0] tag replaced by EXPLICIT SET OF (0x31).
  let cursor = dAlg.contentStart + dAlg.length;
  let signedAttrsDer: Uint8Array | undefined;
  const maybeSignedAttrs = readTLV(der, cursor);
  if (maybeSignedAttrs.tag === 0xa0) {
    const attrsEnd = maybeSignedAttrs.contentStart + maybeSignedAttrs.length;
    signedAttrsDer = der.subarray(cursor, attrsEnd);
    cursor = attrsEnd;
  }

  // signatureAlgorithm SEQUENCE
  const sigAlg = readTLV(der, cursor);
  if (sigAlg.tag !== 0x30) {
    throw new Error("tsr: SignerInfo signatureAlgorithm is not a SEQUENCE");
  }
  const sigAlgOidTlv = readTLV(der, sigAlg.contentStart);
  if (sigAlgOidTlv.tag !== 0x06) {
    throw new Error("tsr: SignerInfo signatureAlgorithm OID missing");
  }
  const signatureAlg = decodeOID(der, sigAlgOidTlv.contentStart, sigAlgOidTlv.length);
  const sigAlgEnd = sigAlg.contentStart + sigAlg.length;

  // signature OCTET STRING
  const sig = readOctetString(der, sigAlgEnd);

  return {
    signature: sig,
    digestAlg,
    certChainDer,
    signatureAlg,
    sid,
    ...(signedAttrsDer !== undefined ? { signedAttrsDer } : {}),
  };
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Parse a DER-encoded TimeStampResp into a ParsedTsr.
 *
 * On status ≠ 0, returns `{ status, tstInfo: null, signerInfo: null }` —
 * the caller must check `status === 0` before using tstInfo / signerInfo.
 */
export function parseTimeStampResp(der: Uint8Array): ParsedTsr {
  const outer = readTLV(der, 0);
  if (outer.tag !== 0x30) {
    throw new Error("tsr: not a SEQUENCE — input is not a TimeStampResp");
  }

  // PKIStatusInfo SEQUENCE
  const statusSeq = readTLV(der, outer.contentStart);
  if (statusSeq.tag !== 0x30) {
    throw new Error("tsr: PKIStatusInfo is not a SEQUENCE");
  }

  // status INTEGER (first field of PKIStatusInfo)
  const status = Number(readInteger(der, statusSeq.contentStart));

  if (status !== 0) {
    return { granted: false, status, tstInfo: null, signerInfo: null };
  }

  // TimeStampToken ContentInfo — immediately after PKIStatusInfo TLV
  const tokenStart = statusSeq.contentStart + statusSeq.length;
  const ci = readTLV(der, tokenStart);
  if (ci.tag !== 0x30) {
    throw new Error("tsr: TimeStampToken ContentInfo is not a SEQUENCE");
  }

  const tstInfoOctets = findTstInfoOctets(der, ci);
  const tstInfo = parseTstInfo(tstInfoOctets);
  const signerInfo = parseFirstSignerInfo(der, ci);

  return { granted: true, status: 0, tstInfo, signerInfo, tstInfoDer: tstInfoOctets };
}
