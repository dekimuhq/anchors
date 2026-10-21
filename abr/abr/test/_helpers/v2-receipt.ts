/**
 * Local helper — mint a deterministic v=2 ABR envelope plus its public key.
 *
 * Parameterised over `event_type` so per-event tests (e.g. tsa-mandate matrix
 * coverage) can mint each variant without copy-pasting the fixture.
 *
 * Deliberately NOT shared with APR/ACR/ARR/ALR/ANR (per the same risk-tradeoff
 * recorded in the ALR/ANR helpers: per-family helpers beat a premature
 * abstraction — bodies diverge sharply by family).
 */

import * as crypto from "node:crypto";
import { signEnvelope, base64UrlEncode } from "@dekimuhq/anchors-envelope";
import type { Envelope } from "@dekimuhq/anchors-envelope";
import type { AbrBody, AbrEventType, AbrProfile } from "../../src/types.ts";

const INCIDENT_ID = "incident-2026-05-19-tsa-mandate-test";
const HASH = (b: string) => `sha256:${b.repeat(64)}`;

const BASE = {
  profile: "breach.gdpr.art33" as AbrProfile,
  incident_correlation_id: INCIDENT_ID,
  qts_attestation_hash: null,
};

/** Every cross-event-pinned field set to null. */
const ALL_PINS_NULL = {
  detected_at: null,
  severity_class: null,
  affected_data_categories: null,
  affected_data_hash: null,
  affected_count: null,
  jurisdiction: null,
  assessment_method_hash: null,
  notification_uri: null,
  notification_hash: null,
  dpa_reference_id: null,
  notification_phase: null,
  delay_reason_hash: null,
  delay_until_at: null,
  subject_batch_root: null,
  subject_batch_size: null,
  exemption_ground: null,
  justification_hash: null,
  public_communication_uri: null,
  containment_at: null,
  containment_summary_hash: null,
  containment_attestation: null,
  closed_at: null,
  closure_dpa_reference_id: null,
  affected_aer_ids: null,
  containment_remediation_arr_ids: null,
  transfer_suspension_atr_ids: null,
  post_breach_anr_id: null,
  qes_aar_id: null,
};

function bodyForEvent(event_type: AbrEventType): AbrBody {
  switch (event_type) {
    case "breach.detected":
      return {
        ...BASE,
        ...ALL_PINS_NULL,
        event_type: "breach.detected",
        detected_at: "2026-05-19T08:00:00Z",
        severity_class: "high_risk",
        affected_data_categories: ["email", "ip_address"],
        affected_data_hash: HASH("a"),
        affected_count: 1024,
        jurisdiction: "EU",
      } as AbrBody;
    case "breach.assessed":
      return {
        ...BASE,
        ...ALL_PINS_NULL,
        event_type: "breach.assessed",
        severity_class: "risk",
        assessment_method_hash: HASH("b"),
      } as AbrBody;
    case "breach.dpa_notified":
      return {
        ...BASE,
        ...ALL_PINS_NULL,
        event_type: "breach.dpa_notified",
        notification_uri: "https://dpa.example/case/2026-001",
        notification_hash: HASH("c"),
        dpa_reference_id: "AEPD-2026-001",
      } as AbrBody;
    case "breach.dpa_delayed":
      return {
        ...BASE,
        ...ALL_PINS_NULL,
        event_type: "breach.dpa_delayed",
        delay_reason_hash: HASH("d"),
        delay_until_at: "2026-05-22T08:00:00Z",
      } as AbrBody;
    case "breach.subject_notified":
      return {
        ...BASE,
        ...ALL_PINS_NULL,
        event_type: "breach.subject_notified",
        subject_batch_root: HASH("e"),
        subject_batch_size: 256,
        notification_uri: "https://controller.example/notify/2026-001",
        notification_hash: HASH("f"),
      } as AbrBody;
    case "breach.subject_notification_exempted":
      return {
        ...BASE,
        ...ALL_PINS_NULL,
        event_type: "breach.subject_notification_exempted",
        exemption_ground: "art34_3_a_encrypted",
        justification_hash: HASH("9"),
      } as AbrBody;
    case "breach.contained":
      return {
        ...BASE,
        ...ALL_PINS_NULL,
        event_type: "breach.contained",
        containment_at: "2026-05-20T08:00:00Z",
        containment_summary_hash: HASH("7"),
      } as AbrBody;
    case "breach.closed":
      return {
        ...BASE,
        ...ALL_PINS_NULL,
        event_type: "breach.closed",
        closed_at: "2026-05-25T08:00:00Z",
      } as AbrBody;
  }
}

export interface MintedAbr {
  envelope: Envelope;
  publicKey: Uint8Array;
}

export async function mintValidAbr(
  event_type: AbrEventType = "breach.detected",
): Promise<MintedAbr> {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const pkDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const pkRaw = pkDer.subarray(-32);
  const iss_key = `ed25519:${base64UrlEncode(new Uint8Array(pkRaw))}` as const;

  const body = bodyForEvent(event_type);

  // FAMILY-CONSISTENCY §3 / D10-ABR-4: subject MUST be `subject_batch_root`
  // on `breach.subject_notified` and MUST be null on every other event.
  // Helper bakes the rule in so every minted receipt is §E-valid by default;
  // tests that deliberately violate the rule mutate `envelope.subject` and
  // re-sign post-hoc.
  const subject =
    body.event_type === "breach.subject_notified"
      ? body.subject_batch_root
      : (null as unknown as string);

  const unsigned: Envelope = {
    v: 2,
    id: "01HXX0000000000000000ABRTEST",
    claim_type: "ar.breach.v1",
    iss: "did:web:controller.example",
    iss_key,
    subject,
    iat: "2026-05-19T08:00:00Z",
    exp: null,
    prev: null,
    policy_uri: "https://controller.example/incident-response/v1",
    policy_hash: HASH("e"),
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
