/**
 * attachSuspensionStatus — mint a W3C Bitstring Status List 2021 suspension
 * pointer and embed it in a v=2 envelope BEFORE signing.
 *
 * Wave 3 addition. Mirrors attach.ts but writes to `suspensionStatus` field
 * with statusPurpose "suspension".
 */

import type { Envelope, SuspensionStatus } from "../envelope-types.ts";

export interface SuspensionListConfig {
  baseUrl: string;
  getNextStatusIndex: (bucket: string) => Promise<number>;
  now?: () => Date;
}

export const MAX_STATUS_INDEX = 131_071;

export async function attachSuspensionStatus(
  envelope: Envelope,
  cfg: SuspensionListConfig,
): Promise<Envelope> {
  if (!cfg.baseUrl.startsWith("https://")) {
    throw new Error(
      `attachSuspensionStatus: baseUrl must start with https:// (got "${cfg.baseUrl}")`,
    );
  }
  const now = cfg.now ? cfg.now() : new Date();
  const bucket = `${now.getUTCFullYear()}/${String(now.getUTCMonth() + 1).padStart(2, "0")}`;
  const idx = await cfg.getNextStatusIndex(bucket);
  if (!Number.isInteger(idx) || idx < 0 || idx > MAX_STATUS_INDEX) {
    throw new Error(
      `attachSuspensionStatus: status index ${idx} out of range [0, ${MAX_STATUS_INDEX}]`,
    );
  }
  const listUrl = `${cfg.baseUrl}/${bucket}`;
  const ss: SuspensionStatus = {
    id: `${listUrl}#${idx}`,
    type: "StatusList2021Entry",
    statusPurpose: "suspension",
    statusListIndex: String(idx),
    statusListCredential: listUrl,
  };
  return { ...envelope, suspensionStatus: ss };
}
