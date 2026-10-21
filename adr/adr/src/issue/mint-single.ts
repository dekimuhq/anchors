/**
 * Per-event convenience wrappers around `mintAdrV2`.
 *
 * ADR is v=2 only — there is no v=1 single-receipt path. These six functions
 * are thin adapters that narrow the discriminated input so call sites can
 * skip the `event: "..."` literal.
 */

import type { Envelope } from "@dekimuhq/anchors-envelope";
import {
  mintAdrV2,
  type MintGrantInput,
  type MintRevokeInput,
  type MintNarrowInput,
  type MintRenewInput,
  type MintSuspendInput,
  type MintResumeInput,
} from "./mint-v2.ts";

export type MintAdrGrantInput = Omit<MintGrantInput, "event">;
export type MintAdrRevokeInput = Omit<MintRevokeInput, "event">;
export type MintAdrNarrowInput = Omit<MintNarrowInput, "event">;
export type MintAdrRenewInput = Omit<MintRenewInput, "event">;
export type MintAdrSuspendInput = Omit<MintSuspendInput, "event">;
export type MintAdrResumeInput = Omit<MintResumeInput, "event">;

export function mintGrant(input: MintAdrGrantInput): Promise<Envelope> {
  return mintAdrV2({ ...input, event: "grant" });
}

export function mintRevoke(input: MintAdrRevokeInput): Promise<Envelope> {
  return mintAdrV2({ ...input, event: "revoke" });
}

export function mintNarrow(input: MintAdrNarrowInput): Promise<Envelope> {
  return mintAdrV2({ ...input, event: "narrow" });
}

export function mintRenew(input: MintAdrRenewInput): Promise<Envelope> {
  return mintAdrV2({ ...input, event: "renew" });
}

export function mintSuspend(input: MintAdrSuspendInput): Promise<Envelope> {
  return mintAdrV2({ ...input, event: "suspend" });
}

export function mintResume(input: MintAdrResumeInput): Promise<Envelope> {
  return mintAdrV2({ ...input, event: "resume" });
}
