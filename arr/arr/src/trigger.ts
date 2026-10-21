export interface ResolvedTriggerReceipt {
  kind: string;
  iss: string;
  granted_at?: string;
  [k: string]: unknown;
}

export type TriggerReceiptResolver = (
  hash: string,
) => Promise<ResolvedTriggerReceipt | null>;

export interface ResolveTriggerInput {
  triggerReceiptHash: string;
  expectedIssuer: string;
  expectedKinds?: string[];
  resolver: TriggerReceiptResolver;
}

export interface TriggerResolutionResult {
  valid: boolean;
  errors: string[];
  resolved: ResolvedTriggerReceipt | null;
}

export async function resolveTriggerReceipt(
  input: ResolveTriggerInput,
): Promise<TriggerResolutionResult> {
  const errors: string[] = [];
  const resolved = await input.resolver(input.triggerReceiptHash);
  if (!resolved) {
    errors.push("trigger_receipt.not_found");
    return { valid: false, errors, resolved: null };
  }
  if (resolved.iss !== input.expectedIssuer) {
    errors.push("trigger_receipt.issuer_mismatch");
  }
  if (input.expectedKinds && !input.expectedKinds.includes(resolved.kind)) {
    errors.push("trigger_receipt.kind_unexpected");
  }
  return { valid: errors.length === 0, errors, resolved };
}
