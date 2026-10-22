# Changelog

## 0.1.3

### Patch Changes

- 2b31383: Installed as a bin (`npx @dekimuhq/anchors-cli`, `node_modules/.bin/anchors`), the CLI exited 0 without doing anything: its entry check compared the symlinked `argv[1]` to its own file URL. It now compares real paths, and a test runs the built CLI through a symlink.

## 0.1.2

### Patch Changes

- First release from the public `dekimuhq/anchors` repository: package metadata now points at it (`repository`, `homepage`, `bugs`), `publishConfig.access` is `public`, `engines.node` is declared as `>=24.6.0`, and every tarball ships a README and the Apache-2.0 LICENSE. No API changes.
- Updated dependencies
  - @dekimuhq/anchors-envelope@0.26.2
  - @dekimuhq/anchors@0.12.3

## 0.1.1

### Patch Changes

- 28c64ff: Re-sync internal dependency ranges so npm links the workspace instead of fetching stale published copies.

  Five internal 0.x carets could not admit their own workspace version (`^0.6.6` cannot match `0.7.0`), so npm resolved those packages from the registry, and those older tarballs pinned `@dekimuhq/anchors-envelope@^0.18.1` — materialising envelope 0.18.x in nested `node_modules` where `cli` then compiled against it. Every `anchors-envelope` range is now `^0.26.1` (the published version, matching the workspace source), and the five broken internal pins admit their workspace versions.

  This removes the root cause of the nesting, so the root `postinstall` rm -rf and the explicit `npm run postinstall` step in `anchors-ci.yml` are both deleted — the workaround was masking the drift that created it.

- Updated dependencies [28c64ff]
  - @dekimuhq/anchors@0.12.2

## 0.1.0

- Initial release: `anchors verify <file>` offline verifier dispatching by claim_type across all 14 Anchored Receipts families; self-certifying + trusted-keys modes; JSON output.
