# `@dekimuhq/adr-profiles`

[![Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Profile validators for ADR v1 — 7 profiles: `aiact.art26.deployer`, `aiact.art14.oversight`, `agentops.scoped-delegation`, `gdpr.art28.processor`, `gdpr.dsr.authorised-agent`, `corporate.officer`, `workspace.department-access`.

## `workspace.department-access`

Records that a workspace owner, admin or department admin set one member's access level (`none | read | write | admin`) for one department. Each record is a standalone `grant` event carrying `previous_level`, `new_level`, `reason` (`set | member-removed | role-changed`), the delegator and delegate (opaque ids plus workspace roles), a lowercase-slug `department_key` (an open set, not an enum) and `effective_at`, all inside `scope.constraints`.

- **Access-control record only.** A receipt says an application's permission check was configured a certain way. It is not cryptographic separation: it does not show that data for a department cannot be read by a member who bypasses the application.
- **Opaque ids only, no names or emails.** The validator rejects any id containing `@`, whitespace or dots, and `scope.constraints` is a closed key set. This is a shape check, not a PII detector: use random identifiers, never a person's name.
- Level changes to `none` are `grant` records with `new_level: "none"` (not `revoke`), because `revoke` bodies cannot carry the transition fields. Non-grant events are rejected under this profile.

## Install

```bash
npm install @dekimuhq/adr-profiles
```

## Usage

See the [ADR spec](../../meta/FAMILY-CONSISTENCY.md) for the full profile definitions.

## License

Apache-2.0. See [LICENSE](LICENSE).

