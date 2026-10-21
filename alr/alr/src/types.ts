/**
 * ALR body types — re-export shim.
 *
 * The body-type leaf (`AlrBody`, `AlrEventType`, `AlrParentRef`, `AlrProfile`,
 * depth-limit constants, …) physically lives in `@dekimuhq/alr-profiles` so the
 * profile validators can import it without depending on this verifier — which
 * itself depends on the profiles package for dispatch. Relocating the leaf
 * breaks the verifier↔profiles dependency cycle while keeping every type
 * importable from `@dekimuhq/alr` exactly as before (public API
 * unchanged). See `docs/suggestions/2026-06-04-build-all-undeclared-sibling-deps.md`.
 */

export * from "@dekimuhq/alr-profiles/body-types";
