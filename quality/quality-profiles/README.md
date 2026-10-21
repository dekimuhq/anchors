# @dekimuhq/quality-profiles

Body types + profile validators for **Anchored Quality Receipts (AQR)** v1
(`ar.quality.v1`).

AQR proves an AI/agent output (or a named version/release) was scored against a
named eval suite. The receipt asserts evaluation **PROVENANCE, not truth** —
distinct from AER (`ar.evaluation.v1`, AI Act conformity); never conflate them.

Body types live here (not in `@dekimuhq/quality`) so the profile validators can
import the body shape without depending on the verifier package — a
profiles→verifier type edge would form an import cycle that blocks the
topological built-`dist` publish. `@dekimuhq/quality` re-exports every symbol
here, so its public API carries the full body surface.

## Exports

- `AQRBody`, `AQROutputBody`, `AQRReleaseBody`, `AQRProfile`, `AQRClaimType` — body types.
- `QualityScorer`, `QualityResult`, `QualityVerdict`, `QualityScorerKind`, `AQRCaveatsConsumed` — sub-shapes.
- `validateQualityOutput`, `validateQualityOutputProfile`, `validateQualityCommon`, `QUALITY_OUTPUT_PROFILE_ID` — the `quality.output` profile validator.
- `validateQualityRelease`, `validateQualityReleaseProfile`, `QUALITY_RELEASE_PROFILE_ID` — the `quality.release` profile validator.
- `ProfileValidationResult` — shared validator result type.

## License

Apache-2.0
