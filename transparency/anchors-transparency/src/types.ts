export interface InclusionPromise {
  timestamp: string;            // ISO 8601
  sig: string;                  // base64url ed25519 over (log_id‖leaf‖timestamp)
}

export interface InclusionProof {
  index: number;                // 0-based leaf index
  tree_size: number;
  path: string[];               // RFC 6962 audit path, each "sha256:<hex>"
  checkpoint: string;           // the C2SP checkpoint note text this proof is against
}

export interface InclBlock {
  log_id: string;               // C2SP checkpoint origin string
  leaf: string;                 // "sha256:<hex>" per leafHash
  promise?: InclusionPromise;   // exactly one of promise|proof
  proof?: InclusionProof;
}

export interface CheckpointNote {
  origin: string;               // log_id
  size: number;                 // tree size
  rootHashB64: string;          // base64 root hash
  signatures: { keyHint: string; sigB64: string }[];   // operator first; witnesses (phase 1.5) after
}

export type LogStatus =
  | "logged_proven"             // valid inclusion proof against a verified checkpoint
  | "logged_promised"           // valid promise, proof not yet available
  | "not_logged"                // no incl block
  | "incl_invalid";             // present but failed verification — HARD failure
