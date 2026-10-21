/**
 * Cross-profile event-type coverage tests.
 *
 * Each of the 5 v1 profile validators is exercised against every one of the
 * 8 ABR event types. Three classes:
 *
 *   - "permissive event types" pass unconditionally (assessed, dpa_delayed,
 *     subject_notification_exempted, contained, closed) — they carry no
 *     profile-specific invariant beyond profile match + correlation-id
 *     non-empty.
 *   - "event-specific invariant" types (detected for art33; subject_notified
 *     for art34; dpa_notified for all 5 profiles' phase rule) are tested in
 *     their per-profile files.
 *   - The 5 cross-validator dispatch tests assert exactly-one passes.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { validateBreachGdprArt33 } from "../src/gdpr-art33.ts";
import { validateBreachGdprArt34 } from "../src/gdpr-art34.ts";
import { validateBreachNis2Art23 } from "../src/nis2-art23.ts";
import { validateBreachDoraArt19 } from "../src/dora-art19.ts";
import { validateBreachUsStateAttorneyGeneral } from "../src/us-state-attorney-general.ts";
import {
  BREACH_GDPR_ART33_PROFILE_ID,
} from "../src/gdpr-art33.ts";
import {
  BREACH_GDPR_ART34_PROFILE_ID,
} from "../src/gdpr-art34.ts";
import {
  BREACH_NIS2_ART23_PROFILE_ID,
} from "../src/nis2-art23.ts";
import {
  BREACH_DORA_ART19_PROFILE_ID,
} from "../src/dora-art19.ts";
import {
  BREACH_US_STATE_ATTORNEY_GENERAL_PROFILE_ID,
} from "../src/us-state-attorney-general.ts";
import {
  assessed,
  closed,
  contained,
  detected,
  dpaDelayed,
  dpaNotified,
  subjectNotificationExempted,
  subjectNotified,
} from "./_helpers/bodies.ts";
import type { AbrProfile } from "@dekimuhq/abr-profiles";

const PROFILES: readonly AbrProfile[] = [
  BREACH_GDPR_ART33_PROFILE_ID,
  BREACH_GDPR_ART34_PROFILE_ID,
  BREACH_NIS2_ART23_PROFILE_ID,
  BREACH_DORA_ART19_PROFILE_ID,
  BREACH_US_STATE_ATTORNEY_GENERAL_PROFILE_ID,
];

function validatorFor(p: AbrProfile) {
  switch (p) {
    case BREACH_GDPR_ART33_PROFILE_ID:
      return validateBreachGdprArt33;
    case BREACH_GDPR_ART34_PROFILE_ID:
      return validateBreachGdprArt34;
    case BREACH_NIS2_ART23_PROFILE_ID:
      return validateBreachNis2Art23;
    case BREACH_DORA_ART19_PROFILE_ID:
      return validateBreachDoraArt19;
    case BREACH_US_STATE_ATTORNEY_GENERAL_PROFILE_ID:
      return validateBreachUsStateAttorneyGeneral;
    default:
      throw new Error(`unknown profile: ${String(p)}`);
  }
}

// ── Permissive event types pass under every profile ──────────────────────────

for (const p of PROFILES) {
  test(`${p}: assessed passes`, () => {
    const out = validatorFor(p)(assessed(p));
    assert.deepEqual(out.errors, []);
  });
  test(`${p}: dpa_delayed passes`, () => {
    const out = validatorFor(p)(dpaDelayed(p));
    assert.deepEqual(out.errors, []);
  });
  test(`${p}: subject_notification_exempted passes`, () => {
    const out = validatorFor(p)(subjectNotificationExempted(p));
    assert.deepEqual(out.errors, []);
  });
  test(`${p}: contained passes`, () => {
    const out = validatorFor(p)(contained(p));
    assert.deepEqual(out.errors, []);
  });
  test(`${p}: closed passes`, () => {
    const out = validatorFor(p)(closed(p));
    assert.deepEqual(out.errors, []);
  });
}

// ── Empty correlation_id flags on every permissive event under every profile ──

for (const p of PROFILES) {
  test(`${p}: assessed with empty correlation_id flagged`, () => {
    const out = validatorFor(p)(assessed(p, { incident_correlation_id: "" }));
    assert.ok(out.errors.some((e) => e.endsWith(".incident_correlation_id.empty")));
  });
  test(`${p}: closed with empty correlation_id flagged`, () => {
    const out = validatorFor(p)(closed(p, { incident_correlation_id: "" }));
    assert.ok(out.errors.some((e) => e.endsWith(".incident_correlation_id.empty")));
  });
}

// ── Cross-validator dispatch: exactly-one passes per body ────────────────────

for (const p of PROFILES) {
  test(`cross-dispatch: only the matching validator accepts a body with profile=${p}`, () => {
    const body = dpaNotified(
      p,
      // NIS2 needs notification_phase; everyone else needs it null.
      p === BREACH_NIS2_ART23_PROFILE_ID
        ? { notification_phase: "full_notification" }
        : {},
    );
    const matchOk = validatorFor(p)(body).errors.length === 0;
    assert.equal(matchOk, true, `${p} validator must accept its own body`);

    for (const other of PROFILES) {
      if (other === p) continue;
      const otherOk = validatorFor(other)(body).errors.length === 0;
      assert.equal(
        otherOk,
        false,
        `${other} validator must REJECT a body tagged ${p}`,
      );
    }
  });
}

// ── Sanity: detected event passes under every non-art33 profile ─────────────

for (const p of PROFILES) {
  if (p === BREACH_GDPR_ART33_PROFILE_ID) continue;
  test(`${p}: detected passes (jurisdiction/categories invariants are art33-only)`, () => {
    const out = validatorFor(p)(
      detected(p, { jurisdiction: "", affected_data_categories: [] }),
    );
    assert.deepEqual(out.errors, []);
  });
}

// ── Sanity: subject_notified passes under every non-art34 profile ───────────

for (const p of PROFILES) {
  if (p === BREACH_GDPR_ART34_PROFILE_ID) continue;
  test(`${p}: subject_notified passes with batch_size>0 (batch invariant is art34-only)`, () => {
    const out = validatorFor(p)(subjectNotified(p, { subject_batch_size: 1 }));
    assert.deepEqual(out.errors, []);
  });
}
