# Anchored Receipts — Template Scaffolding

Templates for adding a new claim_type to the Anchored Receipts family. Use these whenever a new family member (ADR / ATR / APuR / AER / AAR / ALR / ANR / ASR / ABR / AIR / any future member) graduates from spec to code.

## Contents

| Template | Purpose | Output package name |
|---|---|---|
| [`spec-template.md`](spec-template.md) | Spec document scaffold. Drop in https://github.com/dekimuhq/anchors-spec. | n/a — spec is a doc, not a package |
| [`verifier-package-template/`](verifier-package-template/) | Verifier package scaffold (stateless, edge-runtime compatible). | `@dekimuhq/<member>-verifier` |
| [`issuer-kit-template/`](issuer-kit-template/) | Issuer kit scaffold (Node-only, keys + mint + disclose). | `@dekimuhq/<member>-issuer-kit` |
| [`profile-pack-template/`](profile-pack-template/) | Profile pack scaffold (regulator-anchored profile descriptors). | `@dekimuhq/<member>-profiles` |

## Naming convention

Placeholder tokens use `<MEMBER>` and `<member>` (case-sensitive). Find-and-replace before committing.

- `<MEMBER>` → 3-letter family member shorthand (e.g. `ADR`, `ATR`, `APUR`). Used in display contexts only.
- `<member>` → lowercase 3-letter shorthand (e.g. `adr`, `atr`, `apur`). Used in package names + filesystem paths.
- `<noun>` → the claim_type noun (e.g. `delegation`, `transfer`, `purpose`). Used inside `claim_type` strings.
- `<full-name>` → full member name (e.g. `Anchored Delegation Receipts`). Used in README headers.

Wire format `claim_type` is `ar.<noun>.v<N>` per [REGISTRY.md](../meta/REGISTRY.md). The `ar.` namespace is the wire-level family identifier; member acronyms appear in package names + filesystem paths, never in the wire format. This eliminates external acronym collisions (ADR ↔ Architecture Decision Record, ABR ↔ Adaptive Bitrate, ASR ↔ Automatic Speech Recognition) at the protocol layer.

## Workflow when adding a new member

1. **Spec first.** Copy `spec-template.md` into a new `<member>/` directory of [`dekimuhq/anchors-spec`](https://github.com/dekimuhq/anchors-spec) and fill in all sections. PR + maintainer approval before code.
2. **Update [REGISTRY.md](../meta/REGISTRY.md)** with the new row (status: `specced`).
3. **Update [CROSS-REFERENCES.md](../meta/CROSS-REFERENCES.md)** with any chain `prev` rules and cross-family composition refs the spec introduces.
4. **Update `@dekimuhq/anchors-envelope`** to extend the `ClaimType` union with the new discriminator.
5. **Scaffold packages** by copying `verifier-package-template/`, `issuer-kit-template/`, and `profile-pack-template/` (if profile-bound) under `<member>/`.
6. **Implement.** Verifier first (TDD), then issuer-kit, then profiles. v=2 envelope handling delegates to `@dekimuhq/anchors-envelope`.
7. **Update [REGISTRY.md](../meta/REGISTRY.md)** row status: `specced` → `shipped`.

## Inheritance from v1.1 envelope

Every new family member inherits the v1.1 shared envelope verbatim — `v: 2`, `id: ULID`, `iss`, `iss_key`, `subject`, `iat: ISO 8601 string`, `exp`, `prev`, `policy_uri`, `policy_hash`, `policy_version`, `tsa`, `credentialStatus`, `anchor`, `sig`, `countersig`. Member-specific schema lives in `body` only. Verifier dispatch by `claim_type` is in `@dekimuhq/anchors-envelope`.

A new member that needs to extend the envelope (not just `body`) is a v1.2 conversation — escalate to maintainer, don't patch.
