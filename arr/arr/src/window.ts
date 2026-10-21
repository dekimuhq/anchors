export interface Verify30DayInput {
  erasureEventAt: string;
  acrWithdrawalGrantedAt: string;
}

export interface Window30Result {
  valid: boolean;
  errors: string[];
  daysElapsed: number;
}

const DAY_MS = 86_400_000;
const LIMIT_DAYS = 30;

export function verify30DayWindow(input: Verify30DayInput): Window30Result {
  const errors: string[] = [];
  const event = Date.parse(input.erasureEventAt);
  const withdrawal = Date.parse(input.acrWithdrawalGrantedAt);
  const deltaMs = event - withdrawal;
  const daysElapsed = Math.floor(deltaMs / DAY_MS);
  if (deltaMs < 0) errors.push("event_before_withdrawal");
  if (daysElapsed > LIMIT_DAYS) errors.push("gdpr.art12.timeout");
  return { valid: errors.length === 0, errors, daysElapsed };
}
