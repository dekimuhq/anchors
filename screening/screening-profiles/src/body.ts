/**
 * AScR (Anchored Screening Receipts) body types. Asserts WHICH list file was
 * screened against, WHEN, by WHICH matcher, with WHAT result. Never asserts
 * sanctions status. Envelope-level fields come from @dekimuhq/anchors-envelope;
 * field_root is added issuer-side by mintScreeningV1.
 */
export type ScreeningResult = "none_at_threshold" | "candidate";
export type ScreeningTrigger = "manual" | "scheduled";

export interface ScreeningList {
  id: string;
  file_name: string;
  file_date: string;
  file_sha256: string;
  parsed_sha256: string;
  entry_count: number;
  fetched_at: string;
}

export interface ScreeningMatcher {
  name: string;
  version: string;
  threshold: number;
}

export interface ScreeningCandidate {
  entry_ref: string;
  score: number;
}

export interface ScreeningListBody {
  profile: "screening.list";
  screen_id: string;
  list: ScreeningList;
  matcher: ScreeningMatcher;
  subject_commit: string;
  result: ScreeningResult;
  candidates: ScreeningCandidate[];
  trigger: ScreeningTrigger;
  screened_at: string;
}

export type AScRBody = ScreeningListBody;
export type AScRProfile = "screening.list";
