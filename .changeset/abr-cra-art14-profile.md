---
"@dekimuhq/abr-profiles": minor
"@dekimuhq/abr": minor
---

Add the `breach.cra.art14` profile (Regulation (EU) 2024/2847, Cyber Resilience Act Art. 14(2)/(4)): phased reporting of actively exploited vulnerabilities and severe incidents (early warning 24h, notification 72h, final report). Same invariants as `breach.nis2.art23`: profile match, non-empty `incident_correlation_id`, non-null `notification_phase` on `breach.dpa_notified`. Registered in the ABR family manifest, verifier profile set and `ar.breach.v1` schema; no new family or claim type.
