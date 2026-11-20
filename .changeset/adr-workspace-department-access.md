---
"@dekimuhq/adr": minor
"@dekimuhq/adr-profiles": minor
---

New ADR profile `workspace.department-access` — additive 7th v1 profile.

Records that a workspace owner, admin or department admin set one member's access level (`none | read | write | admin`) for one named department. It is an access-control record, not cryptographic separation, and carries opaque ids only (no names or emails).

- `@dekimuhq/adr-profiles`: new `workspace.department-access` id on the `AdrProfile` union + `validateWorkspaceDepartmentAccess` / `validateWorkspaceDepartmentAccessProfile`.
- `@dekimuhq/adr`: id registered in `ADR_PROFILES` + the family `profiles` map, so `isAdrProfile` accepts it.

Grant-only. Constraints are a closed key set: `workspace_id`, `department_key` (lowercase slug, not a closed enum), `delegator_id`, `delegator_role`, `delegate_role`, `previous_level`, `new_level`, `reason` (`set | member-removed | role-changed`), `effective_at`. Additive: every existing ADR receipt verifies byte-equal.
