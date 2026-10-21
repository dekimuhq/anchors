/**
 * Body-fixture helpers for ANR profile-validator tests.
 *
 * Each helper builds a minimal valid `AnrBody` of a given event_type, with
 * profile-conditional optional fields populated. Tests override individual
 * fields by spreading.
 */

import type {
  AnrAcknowledgedBody,
  AnrBody,
  AnrJointControllerEssenceBody,
  AnrPresentedBody,
  AnrProfile,
  AnrRePresentedBody,
  AnrTranslatedBody,
  AnrWithdrawnBody,
} from "@dekimuhq/anr-profiles/body-types";

const ART13_RIGHTS: readonly string[] = [
  "art15",
  "art16",
  "art17",
  "art18",
  "art20",
  "art21",
];

export function H(seed: string): string {
  return `sha256:${seed.repeat(64).slice(0, 64)}`;
}

export function presented(
  profile: AnrProfile,
  overrides: Partial<AnrPresentedBody> = {},
): AnrPresentedBody {
  return {
    event_type: "notice.presented",
    profile,
    lang_tag: "en-GB",
    lang_inferred: null,
    qts_attestation_hash: null,
    jurisdiction: "GB",
    delivery_channel: "web",
    render_uri: "https://example.com/notice/v1",
    rights_surface: ART13_RIGHTS,
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
    joint_controllers: null,
    cessation_reason: null,
    translation_provenance_alr_id: null,
    ...overrides,
  };
}

export function rePresented(
  profile: AnrProfile,
  overrides: Partial<AnrRePresentedBody> = {},
): AnrRePresentedBody {
  return {
    event_type: "notice.re_presented",
    profile,
    lang_tag: "en-GB",
    lang_inferred: null,
    qts_attestation_hash: null,
    jurisdiction: "GB",
    delivery_channel: "web",
    render_uri: "https://example.com/notice/v2",
    rights_surface: ART13_RIGHTS,
    supersedes_anr_id: "01HABCDEFGHJKMNPQRSTUVWXYZ",
    subject_age_band: null,
    data_source: null,
    collection_horizon: null,
    data_acquired_at: null,
    layer_uris: null,
    ai_system_kind: null,
    ai_system_provider_did: null,
    aer_id: null,
    base_anr_id: null,
    ack_method: null,
    joint_controllers: null,
    cessation_reason: null,
    translation_provenance_alr_id: null,
    ...overrides,
  };
}

export function acknowledged(
  profile: AnrProfile,
  overrides: Partial<AnrAcknowledgedBody> = {},
): AnrAcknowledgedBody {
  return {
    event_type: "notice.acknowledged",
    profile,
    lang_tag: "en-GB",
    lang_inferred: null,
    qts_attestation_hash: null,
    jurisdiction: "GB",
    ack_method: "checkbox",
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
    joint_controllers: null,
    cessation_reason: null,
    translation_provenance_alr_id: null,
    ...overrides,
  };
}

export function withdrawn(
  profile: AnrProfile,
  overrides: Partial<AnrWithdrawnBody> = {},
): AnrWithdrawnBody {
  return {
    event_type: "notice.withdrawn",
    profile,
    lang_tag: "en-GB",
    lang_inferred: null,
    qts_attestation_hash: null,
    jurisdiction: "GB",
    supersedes_anr_id: null,
    cessation_reason: "processing_ceased",
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
    base_anr_id: null,
    ack_method: null,
    joint_controllers: null,
    translation_provenance_alr_id: null,
    ...overrides,
  };
}

export function translated(
  profile: AnrProfile,
  overrides: Partial<AnrTranslatedBody> = {},
): AnrTranslatedBody {
  return {
    event_type: "notice.translated",
    profile,
    lang_tag: "de-DE",
    lang_inferred: null,
    qts_attestation_hash: null,
    base_anr_id: "01HBASEAAAAAAAAAAAAAAAAAAA",
    jurisdiction: null,
    translation_provenance_alr_id: null,
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
    ack_method: null,
    joint_controllers: null,
    cessation_reason: null,
    ...overrides,
  };
}

export function jointControllerEssence(
  profile: AnrProfile,
  overrides: Partial<AnrJointControllerEssenceBody> = {},
): AnrJointControllerEssenceBody {
  return {
    event_type: "notice.joint_controller_essence",
    profile,
    lang_tag: "en-GB",
    lang_inferred: null,
    qts_attestation_hash: null,
    jurisdiction: "GB",
    joint_controllers: [
      {
        did: "did:web:example.com",
        role: "co-controller",
        contact_point_uri: "https://example.com/dpo",
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
    ...overrides,
  };
}

export type AnyAnrBody = AnrBody;
