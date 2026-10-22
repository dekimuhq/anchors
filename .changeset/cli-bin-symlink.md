---
"@dekimuhq/anchors-cli": patch
---

Installed as a bin (`npx @dekimuhq/anchors-cli`, `node_modules/.bin/anchors`), the CLI exited 0 without doing anything: its entry check compared the symlinked `argv[1]` to its own file URL. It now compares real paths, and a test runs the built CLI through a symlink.
