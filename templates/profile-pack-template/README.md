# @dekimuhq/<member>-profiles

Regulator-anchored profile descriptors for **Anchored <Noun> Receipts** (<MEMBER>) v1.

Profiles bind a `ar.<noun>.v1` receipt to a specific legal regime (GDPR Art. X, AI Act Art. Y, HIPAA §Z, etc.). Each profile pins:

- Required `body` fields beyond the envelope baseline.
- TSA mandate flags (`requires_tsa`, `requires_tsa_listed`, `requires_tsa_policy_oid`).
- Status List 2021 flip semantics specific to the profile.
- Cross-family composition refs required by the regulator.

## Install

```bash
npm install @dekimuhq/<member>-profiles
```

## Usage

```ts
import { profiles } from "@dekimuhq/<member>-profiles";

const profile = profiles["<member>.<profile-name>.v1"];

if (profile.requires_tsa) {
  // mint with TSA opt-in
}
```

## Profile inventory (v1)

| Profile name | Regulator anchor | TSA mandate | Notes |
|---|---|---|---|
| `<member>.<profile1>.v1` | GDPR Art. X | optional | … |
| `<member>.<profile2>.v1` | AI Act Art. Y | `requires_tsa = true` | … |
| … | … | … | … |

See [v1 design spec](TODO: link) §5 for the full descriptor schema.

## License

Apache-2.0
