/**
 * `@dekimuhq/anchors-cli` — programmatic surface.
 *
 * The package's primary use is the `anchors verify` command (see `cli.ts`,
 * wired as the `bin`). This module re-exports the reusable pieces for callers
 * embedding offline verification in their own tooling.
 */

export {
  verifyAnchor,
  supportedClaimTypes,
  ALL_FAMILIES,
  type AnchorVerifyOutcome,
} from "./dispatch.ts";

export {
  selfCertifyingResolveKey,
  makeTrustedKeysResolveKey,
  derFromFingerprint,
} from "./resolve-key.ts";

export { runCli, type CliResult, type CliDeps } from "./cli.ts";
