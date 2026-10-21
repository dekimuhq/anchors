// ar.compliance.v1 body — workspace-level Proof-of-Compliance bundle.
// References only; the envelope (iss/iat/sig/anchor) is handled by anchors-envelope.

export type ComplianceClaimType = "ar.compliance.v1";

export interface ControllerIdentity {
  entityName: string;
  registeredAddress: string | null;
  contactEmail: string | null;
}

export interface BundleRef {
  ref: string;                    // verify claim ID (AIR) | "ropa:<registerHash>"
  contentHash: string;            // "sha256:<64hex>"
  claimType?: string;             // e.g. "ar.impact.v1"
  satisfiedObligations: string[]; // gdpr.* obligation ids this evidences
  embedded?: unknown;             // self-contained re-verify payload (RoPA receipt / public passport)
}

export interface GapDecl { status: "gap"; reason: string; }
export interface NotApplicableDecl { status: "not_applicable"; reason: string; basis: string; }

export interface ComplianceBundleBody {
  profile: "compliance.bundle";
  workspaceId: string;
  controller: ControllerIdentity;
  regulation: { manifestId: "gdpr"; manifestVersion: string; manifestHash: string };
  coverage: { applicable: number; satisfied: number; ratio: number };
  constituents: {
    ropa: BundleRef | GapDecl;
    dpia: BundleRef[] | NotApplicableDecl;
    obligations: BundleRef;
  };
  generated_at: string;           // RFC3339; reproducible (injected clock)
}

export interface VerifyBodyResult { valid: boolean; errors: string[]; body: ComplianceBundleBody | null; }
