/**
 * AUTO-GENERATED from ar.transfer.v1.anchor.json
 * Generated: [TIMESTAMP]
 *
 * Do not edit manually — re-run `npm run generate` to regenerate.
 * Manual edits will be lost on next generation.
 */

/** Claim type discriminators for ATR. */
export type ATRClaimType =
  | "ar.transfer.v1";

/** Event types for ATR. */
export type ATREventType =
  | "arrangement"
  | "transfer"
  | "tia"
  | "suspension";

/** Regulation profiles for ATR. */
export type ATRProfile =
  | "gdpr.art45.adequacy"
  | "gdpr.art46.scc"
  | "gdpr.art46.bcr"
  | "gdpr.art46.idta"
  | "gdpr.art47.bcr_authorised"
  | "gdpr.art49.derogation"
  | "gdpr.dpf"
  | "schremsii.tia";

/** Body for ATR "arrangement" events. */
export interface ATRArrangementBody {
  event_type: "arrangement";
  profile: "gdpr.art45.adequacy" | "gdpr.art46.scc" | "gdpr.art46.bcr" | "gdpr.art46.idta" | "gdpr.art47.bcr_authorised" | "gdpr.art49.derogation" | "gdpr.dpf" | "schremsii.tia";
  /** `sha256:<hex>` */
  exporter_commit: string;
  /** `sha256:<hex>` */
  importer_commit: string;
  /** ISO 3166-1 alpha-2. */
  destination_country: string;
  mechanism_version: string;
  data_categories: readonly string[];
  subject_count_bucket?: "1" | "2_9" | "10_99" | "100_999" | "1k_9k" | "10k_99k" | "100k_plus";
  /** `sha256:<hex>` */
  qts_attestation_hash: string | null;
}

/** Body for ATR "transfer" events. */
export interface ATRTransferBody {
  event_type: "transfer";
  profile: "gdpr.art45.adequacy" | "gdpr.art46.scc" | "gdpr.art46.bcr" | "gdpr.art46.idta" | "gdpr.art47.bcr_authorised" | "gdpr.art49.derogation" | "gdpr.dpf" | "schremsii.tia";
  /** `sha256:<hex>` */
  exporter_commit: string;
  /** `sha256:<hex>` */
  importer_commit: string;
  /** ISO 3166-1 alpha-2. */
  destination_country: string;
  mechanism_version: string;
  data_categories: readonly string[];
  subject_count_bucket?: "1" | "2_9" | "10_99" | "100_999" | "1k_9k" | "10k_99k" | "100k_plus";
  /** `sha256:<hex>` */
  qts_attestation_hash: string | null;
}

/** Body for ATR "tia" events. */
export interface ATRTiaBody {
  event_type: "tia";
  profile: "gdpr.art45.adequacy" | "gdpr.art46.scc" | "gdpr.art46.bcr" | "gdpr.art46.idta" | "gdpr.art47.bcr_authorised" | "gdpr.art49.derogation" | "gdpr.dpf" | "schremsii.tia";
  /** `sha256:<hex>` */
  exporter_commit: string;
  /** `sha256:<hex>` */
  importer_commit: string;
  /** ISO 3166-1 alpha-2. */
  destination_country: string;
  mechanism_version: string;
  data_categories: readonly string[];
  subject_count_bucket?: "1" | "2_9" | "10_99" | "100_999" | "1k_9k" | "10k_99k" | "100k_plus";
  /** `sha256:<hex>` */
  qts_attestation_hash: string | null;
}

/** Body for ATR "suspension" events. */
export interface ATRSuspensionBody {
  event_type: "suspension";
  profile: "gdpr.art45.adequacy" | "gdpr.art46.scc" | "gdpr.art46.bcr" | "gdpr.art46.idta" | "gdpr.art47.bcr_authorised" | "gdpr.art49.derogation" | "gdpr.dpf" | "schremsii.tia";
  /** `sha256:<hex>` */
  exporter_commit: string;
  /** `sha256:<hex>` */
  importer_commit: string;
  /** ISO 3166-1 alpha-2. */
  destination_country: string;
  mechanism_version: string;
  data_categories: readonly string[];
  subject_count_bucket?: "1" | "2_9" | "10_99" | "100_999" | "1k_9k" | "10k_99k" | "100k_plus";
  /** `sha256:<hex>` */
  qts_attestation_hash: string | null;
}

/** Discriminated union of all ATR body variants. */
export type ATRBody =
  | ATRArrangementBody
  | ATRTransferBody
  | ATRTiaBody
  | ATRSuspensionBody;
