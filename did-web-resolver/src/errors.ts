export type DidWebResolveErrorCode =
  | "unsupported_did_method"
  | "invalid_did"
  | "fetch_failed"
  | "non_200"
  | "json_parse"
  | "key_doc_invalid"
  | "no_matching_key"
  | "key_not_yet_valid"
  | "key_no_longer_valid"
  | "invalid_public_key_encoding"
  | "iss_key_fingerprint_mismatch"
  | "iss_scheme_unsupported"
  | "issuer_revoked"
  | "negative_cached";

export class DidWebResolveError extends Error {
  readonly code: DidWebResolveErrorCode;
  constructor(code: DidWebResolveErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "DidWebResolveError";
    this.code = code;
  }
}
