/**
 * Local helper — mint a deterministic v=2 AIR envelope plus its public key.
 *
 * Parameterised over `event_type` so per-event tests (e.g. tsa-mandate matrix
 * coverage) can mint each variant without copy-pasting the fixture.
 *
 * Deliberately NOT shared with APR/ACR/ARR/ALR/ANR/ABR (per the same risk-
 * tradeoff recorded in the sibling helpers: per-family helpers beat a
 * premature abstraction — bodies diverge sharply by family).
 *
 * Bodies are reused from `./bodies.ts` rather than duplicated. The minted
 * envelope has every POLICY_BOUND envelope field populated so the §D
 * `ar.impact.v1` POLICY_BOUND check (added in `@dekimuhq/anchors-envelope
 * 0.7.1`) passes without callers needing to override per receipt.
 */

import * as crypto from "node:crypto";
import { signEnvelope, base64UrlEncode } from "@dekimuhq/anchors-envelope";
import type { Envelope } from "@dekimuhq/anchors-envelope";
import type { AirBody, AirEventType } from "../../src/types.ts";
import {
  completed,
  dpoAdvised,
  priorConsultationInitiated,
  priorConsultationResolved,
  processingAuthorised,
  processingBlocked,
  reviewed,
  scopeLocked,
  stakeholdersConsulted,
  terminated,
  thresholdTriggered,
} from "./bodies.ts";

const HASH = (b: string) => `sha256:${b.repeat(64)}`;

function bodyForEvent(event_type: AirEventType): AirBody {
  switch (event_type) {
    case "dpia.threshold_triggered":
      return thresholdTriggered();
    case "dpia.scope_locked":
      return scopeLocked();
    case "dpia.dpo_advised":
      return dpoAdvised();
    case "dpia.stakeholders_consulted":
      return stakeholdersConsulted();
    case "dpia.completed":
      return completed();
    case "dpia.reviewed":
      return reviewed();
    case "dpia.prior_consultation_initiated":
      return priorConsultationInitiated();
    case "dpia.prior_consultation_resolved":
      return priorConsultationResolved();
    case "dpia.processing_authorised":
      return processingAuthorised();
    case "dpia.processing_blocked":
      return processingBlocked();
    case "dpia.terminated":
      return terminated();
  }
}

export interface MintedAir {
  envelope: Envelope;
  publicKey: Uint8Array;
}

export async function mintValidAir(
  event_type: AirEventType = "dpia.completed",
): Promise<MintedAir> {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const pkDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const pkRaw = pkDer.subarray(-32);
  const iss_key = `ed25519:${base64UrlEncode(new Uint8Array(pkRaw))}` as const;

  const body = bodyForEvent(event_type);

  // FAMILY-CONSISTENCY §3 / D10-AIR-6: subject is null on every event EXCEPT
  // OPTIONALLY on `dpia.stakeholders_consulted` (and only when method is
  // `representative_org` / `ngo_review`). The helper bakes the safe default —
  // every minted receipt has `subject: null`. §E tests that exercise the
  // representative-org carve-out mutate envelope.subject and re-sign post-hoc.
  const unsigned: Envelope = {
    v: 2,
    id: "01HXX0000000000000000AIRTEST",
    claim_type: "ar.impact.v1",
    iss: "did:web:controller.example",
    iss_key,
    subject: null as unknown as string,
    iat: "2026-05-19T08:00:00Z",
    exp: null,
    prev: null,
    policy_uri: "https://controller.example/dpia-methodology/v1",
    policy_hash: HASH("c"),
    policy_version: "1.0.0",
    tsa: null,
    credentialStatus: null,
    anchor: null as unknown as Envelope["anchor"],
    sig: "",
    countersig: null,
    body,
  };

  const signed = await signEnvelope(unsigned, privateKey);
  return { envelope: signed, publicKey: new Uint8Array(pkDer) };
}

export function makeResolveKey(
  pub: Uint8Array,
): (envelope: unknown) => Promise<Uint8Array> {
  return async () => pub;
}
