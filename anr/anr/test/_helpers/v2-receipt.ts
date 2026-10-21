/**
 * Local helper — mint a deterministic v=2 ANR envelope plus its public key.
 *
 * Parameterised over `profile` so per-profile tests (e.g. tsa-mandate matrix
 * coverage) can mint each variant without copy-pasting the fixture.
 *
 * Deliberately NOT shared with APR/ACR/ARR/ALR (per the same risk-tradeoff
 * recorded in the ALR helper: per-family helpers beat a premature abstraction
 * — bodies diverge sharply by family).
 */

import * as crypto from "node:crypto";
import { signEnvelope, base64UrlEncode } from "@dekimuhq/anchors-envelope";
import type { Envelope } from "@dekimuhq/anchors-envelope";
import type { AnrBody, AnrProfile } from "../../src/types.ts";

const H = (b: string) => `sha256:${b.repeat(64)}`;

interface PresentedBaseOverride {
  profile: AnrProfile;
  subject_age_band?: "adult" | "13_to_15" | "under_13";
  data_source?: string;
  collection_horizon?: "one_month" | "first_communication" | "disclosure_to_third_party";
  data_acquired_at?: string;
  layer_uris?: readonly { layer: "summary" | "full" | "jit"; uri: string; hash: string }[];
  ai_system_kind?:
    | "interaction"
    | "synthetic_content"
    | "emotion_recognition"
    | "biometric_categorisation"
    | "deepfake";
  ai_system_provider_did?: string;
}

function presentedBody(over: PresentedBaseOverride): AnrBody {
  return {
    profile: over.profile,
    lang_tag: "en-GB",
    lang_inferred: null,
    qts_attestation_hash: null,
    event_type: "notice.presented",
    jurisdiction: "EU",
    delivery_channel: "web",
    render_uri: "https://example.test/notice/v1",
    rights_surface: ["art15", "art16", "art17", "art18", "art20", "art21"],
    subject_age_band: over.subject_age_band ?? null,
    data_source: over.data_source ?? null,
    collection_horizon: over.collection_horizon ?? null,
    data_acquired_at: over.data_acquired_at ?? null,
    layer_uris: over.layer_uris ?? null,
    ai_system_kind: over.ai_system_kind ?? null,
    ai_system_provider_did: over.ai_system_provider_did ?? null,
    aer_id: null,
    supersedes_anr_id: null,
    base_anr_id: null,
    ack_method: null,
    joint_controllers: null,
    cessation_reason: null,
    translation_provenance_alr_id: null,
  };
}

function bodyForProfile(profile: AnrProfile): AnrBody {
  switch (profile) {
    case "notice.art13.collected_direct":
      return presentedBody({ profile, subject_age_band: "adult" });
    case "notice.art14.collected_indirect":
      return presentedBody({
        profile,
        data_source: "broker:example",
        collection_horizon: "one_month",
        data_acquired_at: "2026-05-15T00:00:00Z",
      });
    case "notice.layered_transparency":
      return presentedBody({
        profile,
        layer_uris: [
          { layer: "summary", uri: "https://example.test/notice/summary", hash: H("d") },
          { layer: "full", uri: "https://example.test/notice/full", hash: H("e") },
        ],
      });
    case "notice.aiact.art50_transparency":
      return presentedBody({
        profile,
        ai_system_kind: "interaction",
        ai_system_provider_did: "did:web:ai-provider.example",
      });
    case "notice.art26.joint_controller_essence":
      return {
        profile,
        lang_tag: "en-GB",
        lang_inferred: null,
        qts_attestation_hash: null,
        event_type: "notice.joint_controller_essence",
        jurisdiction: "EU",
        joint_controllers: [
          {
            did: "did:web:co-controller-a.example",
            role: "marketing analytics",
            contact_point_uri: "https://co-controller-a.example/privacy",
            adr_id: null,
          },
          {
            did: "did:web:co-controller-b.example",
            role: "ad delivery",
            contact_point_uri: "https://co-controller-b.example/privacy",
            adr_id: null,
          },
        ],
        delivery_channel: null,
        render_uri: null,
        rights_surface: null,
        subject_age_band: null,
        data_source: null,
        collection_horizon: null,
        data_acquired_at: null,
        layer_uris: null,
        ai_system_kind: null,
        ai_system_provider_did: null,
        aer_id: null,
        supersedes_anr_id: null,
        base_anr_id: null,
        ack_method: null,
        cessation_reason: null,
        translation_provenance_alr_id: null,
      };
  }
}

export interface MintedAnr {
  envelope: Envelope;
  publicKey: Uint8Array;
}

export async function mintValidAnr(
  profile: AnrProfile = "notice.art13.collected_direct",
): Promise<MintedAnr> {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const pkDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const pkRaw = pkDer.subarray(-32);
  const iss_key = `ed25519:${base64UrlEncode(new Uint8Array(pkRaw))}` as const;

  const unsigned: Envelope = {
    v: 2,
    id: "01HXX0000000000000000ANRTEST",
    claim_type: "ar.notice.v1",
    iss: "did:web:controller.example",
    iss_key,
    subject: null as unknown as string,
    iat: "2026-05-17T00:00:00Z",
    exp: null,
    prev: null,
    policy_uri: "https://controller.example/notice/v1",
    policy_hash: "sha256:" + "e".repeat(64),
    policy_version: "1.0.0",
    tsa: null,
    credentialStatus: null,
    anchor: null as unknown as Envelope["anchor"],
    sig: "",
    countersig: null,
    body: bodyForProfile(profile),
  };

  const signed = await signEnvelope(unsigned, privateKey);
  return { envelope: signed, publicKey: new Uint8Array(pkDer) };
}

export function makeResolveKey(
  pub: Uint8Array,
): (_envelope: unknown) => Promise<Uint8Array> {
  return async () => pub;
}
