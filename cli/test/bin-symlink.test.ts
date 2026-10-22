/**
 * Regression: run the BUILT cli through a symlink, the way npm installs a bin
 * (node_modules/.bin/anchors -> ../@dekimuhq/anchors-cli/dist/cli.js). The entry
 * guard once compared argv[1] to import.meta.url, which a symlink defeats, so
 * the installed CLI exited 0 having printed nothing. Needs dist (build-all).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, symlinkSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const dist = resolve(fileURLToPath(new URL("../dist/cli.js", import.meta.url)));

test("the installed bin (a symlink to dist/cli.js) actually runs", { skip: !existsSync(dist) && "dist not built" }, () => {
  const dir = mkdtempSync(join(tmpdir(), "anchors-bin-"));
  try {
    const bin = join(dir, "anchors");
    symlinkSync(dist, bin);
    const r = spawnSync(process.execPath, [bin], { encoding: "utf8" });
    assert.ok(
      (r.stdout + r.stderr).trim().length > 0,
      `bin printed nothing (exit ${r.status}) — the entry guard did not recognise the symlinked bin`,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
