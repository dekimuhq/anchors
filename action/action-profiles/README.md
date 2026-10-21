# @dekimuhq/action-profiles

Body types + profile validators for **Anchored Action Receipts (AActR)** v1
(`ar.action.v1`).

Body types live here (not in `@dekimuhq/action`) so the profile validators can
import the body shape without depending on the verifier package — a
profiles→verifier type edge would form an import cycle that blocks the
topological built-`dist` publish. `@dekimuhq/action` re-exports every symbol
here, so its public API carries the full body surface.

## Exports

- `AActRBody`, `AActRProfile`, `AActROutcome`, `AActRClaimType` — body types.
- `validateHubAutomationProfile`, `validateHubAutomation` — the `hub.automation` profile validator.
- `ProfileValidationResult` — shared validator result type.

## License

Apache-2.0
