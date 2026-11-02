---
"@dekimuhq/anchors-envelope": patch
---

fix(tsa): ship the default FreeTSA trust-anchor catalog in the package.

`defaultTrustAnchorPath()` resolved to the workspace-root `data/` directory,
which is not in the published tarball, so any consumer that verified a
`tsa`-bearing receipt without passing `tsaAnchors` got an ENOENT throw instead
of a result. The catalog now ships at `<package>/data/freetsa-trust-anchor.json`
(added to `files`) and is kept byte-equal to the workspace copy by a test.
