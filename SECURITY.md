# Security policy — Anchored Receipts

This is the security policy for every package in this repository: `@dekimuhq/anchors-envelope`, `@dekimuhq/anchors` (meta), each family package `@dekimuhq/<family>` and `@dekimuhq/<family>-profiles`, and the supporting packages (`did-web-resolver`, `anchors-trusted-issuers`, `anchors-federation`, `anchors-transparency`, `anchors-disclosure`, `anchors-vc`, `anchors-cli`). Per-package `SECURITY.md` files point here.

## Reporting a vulnerability

If you believe you have found a security vulnerability — an implementation bug, a spec contradiction, a canonicalisation drift, a code path that lets a tampered envelope verify, a valid envelope that fails incorrectly, a private-seed leak, a downgrade attack, or anything analogous — please **do not open a public GitHub issue**.

Email **security@dekimu.com** with:

- A clear description of the issue.
- The affected package and source file(s), with a minimal reproducer.
- Your assessment of impact (false-verified, false-tampered, info leak, denial of verify, key exposure, signature forgery, downgrade, status-list bypass, profile-mandate bypass, etc.).
- Whether you intend to publish your own write-up, and on what timeline.

You can also report privately through GitHub: **Security → Report a vulnerability** on [`dekimuhq/anchors`](https://github.com/dekimuhq/anchors/security/advisories/new).

You should receive a human acknowledgement within **3 business days**.

## How fixes are prepared

A fix for a vulnerability that is not yet public is never developed in the open. It is prepared in a GitHub security advisory's temporary private fork, reviewed there, and kept off `main` until a patched release is ready. The advisory, the fix commit and the patched release are then published together. Dekimu's own products that depend on the affected package are updated to the patched version before the advisory is published, inside the disclosure window below.

## Disclosure window

This project follows a **90-day responsible-disclosure window**, starting from the day we acknowledge your report.

- Within 90 days we investigate, agree on impact, ship a fix or a spec clarification, coordinate disclosure with you, and publish a security advisory.
- After 90 days you are free to publish your findings whether or not a fix has shipped. If we need an extension we will ask before day 75; we will not extend unilaterally.
- For trivial issues (cosmetic, not exploitable) we may publish sooner, in coordination with you.

## Scope

| Package | In scope |
|---|---|
| `@dekimuhq/anchors-envelope` | `src/`: canonicalisation, signature verify (Ed25519 and ML-DSA), TSA helpers (`src/tsa/`), W3C status lists (`src/status/`), policy validation, profile dispatch, the shared mint/verify pipeline. Any code path that could mis-verify an envelope for any family. |
| `@dekimuhq/<family>` | The verifier on the package root (dispatch, policy, status and profile enforcement) and the issuer helpers on `./issue` (`mint*()`, key helpers, status-pointer helpers, quickstart examples when a copied pattern creates a hole). |
| `@dekimuhq/<family>-profiles` | Profile descriptors and validators, and their mandate-enforcement logic. |
| `@dekimuhq/anchors` (meta) | The re-export surface: issues that let a consumer reach an unsafe path through the namespace exports. |
| Supporting packages | `did-web-resolver` key resolution, `anchors-trusted-issuers` allowlist verification, `anchors-federation`, `anchors-transparency`, `anchors-disclosure`, `anchors-vc`, `anchors-cli`. |
| Spec text | Lives in [`dekimuhq/anchors-spec`](https://github.com/dekimuhq/anchors-spec). Any normative statement that turns out to be false or unsafe in practice; report it here as well. |

Out of scope (please use the matching channel instead):

- Operational issues with `verify.dekimu.com` (the hosted reference verifier): also **security@dekimu.com**, but name the hosted verifier so the report routes correctly.
- Product feedback, feature requests, UX issues: open a public GitHub issue.
- Vulnerabilities in third-party dependencies: report upstream; we track and bump.

## Supported versions

Anchors v1 is supported for at least 36 months from the first public release, with security fixes backported throughout that window. Fixes land on `main` and ship as a patch release of each affected package; see each package's `CHANGELOG.md`.

## Coordinated disclosure

All family members share the envelope, the policy matrix and the status-list machinery, so a finding often affects more than one package. Please flag any cross-package impact in your first report. When a finding affects several packages or a known downstream implementer, we coordinate disclosure with every affected party before publication.

## Acknowledgements

We credit reporters in the affected packages' changelogs. Tell us in your first email whether you want to be credited, and how.

## Companion documents

- Contribution guide: [CONTRIBUTING.md](CONTRIBUTING.md).
- Code of Conduct: [Contributor Covenant 2.1](https://github.com/dekimuhq/anchors-spec/blob/main/CODE_OF_CONDUCT.md). Reports go to **conduct@dekimu.com**.
- Threat models and privacy reviews live with the specs in `dekimuhq/anchors-spec` (`security/threat-model.md`, `apr/THREAT-MODEL.md`, `acr/THREAT-MODEL.md`, `apr/PRIVACY-REVIEW.md`, `acr/PRIVACY-REVIEW.md`).
