// @dekimuhq/<member>-profiles — type definitions

export interface ProfileDescriptor {
  name: string; // e.g. "<member>.<profile>.v1"
  regulator_anchor: string; // human-readable e.g. "GDPR Art. 17"
  required_body_fields: string[]; // dotted paths into body
  requires_tsa?: boolean;
  requires_tsa_listed?: boolean; // EU LOTL membership required
  requires_tsa_policy_oid?: string; // ETSI QTS policy OID
  composition_refs?: { field: string; target_claim_type: string; required: boolean }[];
  status_list_flip_on?: string[]; // successor claim_types that flip this profile's Status List bit
  notes?: string;
}
