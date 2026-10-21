/**
 * ARR body types — re-export shim.
 *
 * The body-type leaf physically lives in `@dekimuhq/arr-profiles` so the profile
 * validators can import it without depending on this verifier — which itself
 * depends on the profiles package for dispatch. Relocating the leaf breaks the
 * verifier↔profiles dependency cycle while keeping every type importable from
 * `@dekimuhq/arr` exactly as before (public API unchanged).
 * See `docs/suggestions/2026-06-04-build-all-undeclared-sibling-deps.md`.
 */

export * from "@dekimuhq/arr-profiles/body-types";
