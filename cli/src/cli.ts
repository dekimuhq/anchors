#!/usr/bin/env node
/**
 * `anchors verify` — offline / third-party verifier CLI for Anchored Receipts.
 *
 * Reads one or more receipt JSON files (each a single envelope OR a JSON array
 * of envelopes), routes every receipt to its family verifier by `claim_type`,
 * and reports a per-receipt verdict. No network, no trust in the Dekimu SaaS:
 * by default the issuer key is taken from the receipt's embedded `iss_key`
 * (self-certifying). Pass `--trusted-keys <file>` (a JSON array of
 * `ed25519:<base64url>` fingerprints) to require a known issuer.
 *
 * The work is split so it is testable without spawning a process:
 *   - `runCli(argv, deps)` is pure-ish — `deps.readFile` is injected and it
 *     returns `{ exitCode, stdout, stderr }` instead of writing/exiting.
 *   - The `#!` entry at the bottom wires real fs + process and runs it.
 *
 * Exit codes: 0 = every receipt valid · 1 = at least one invalid/undispatched ·
 * 2 = usage error or unreadable/invalid input file.
 */

import { readFile as fsReadFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import type { FamilyVerifyOptions } from "@dekimuhq/anchors-envelope";
import {
  verifyAnchor,
  supportedClaimTypes,
  type AnchorVerifyOutcome,
} from "./dispatch.ts";
import {
  selfCertifyingResolveKey,
  makeTrustedKeysResolveKey,
} from "./resolve-key.ts";

export interface CliResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export interface CliDeps {
  /** Read a UTF-8 file. Throws on missing/unreadable file. */
  readFile: (path: string) => Promise<string>;
}

interface ParsedArgs {
  files: string[];
  json: boolean;
  trustedKeysFile: string | null;
  help: boolean;
}

const USAGE = `anchors verify — offline verifier for Anchored Receipts

Usage:
  anchors verify <file...> [--json] [--trusted-keys <file>]

Options:
  --json                  Emit machine-readable JSON instead of human lines.
  --trusted-keys <file>   JSON array of ed25519:<base64url> issuer fingerprints.
                          Receipts signed by any other key fail verification.
                          Omit for self-certifying mode (embedded iss_key).
  -h, --help              Show this help.

Each file is a single receipt envelope or a JSON array of envelopes.
Exit: 0 all valid · 1 any invalid · 2 usage/IO error.`;

function parseArgs(argv: readonly string[]): ParsedArgs | { error: string } {
  const files: string[] = [];
  let json = false;
  let trustedKeysFile: string | null = null;
  let help = false;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === undefined) continue;
    if (arg === "--json") json = true;
    else if (arg === "-h" || arg === "--help") help = true;
    else if (arg === "--trusted-keys") {
      const next = argv[i + 1];
      if (next === undefined || next.startsWith("-")) {
        return { error: "--trusted-keys requires a file path" };
      }
      trustedKeysFile = next;
      i++;
    } else if (arg.startsWith("-")) {
      return { error: `unknown option: ${arg}` };
    } else {
      files.push(arg);
    }
  }
  return { files, json, trustedKeysFile, help };
}

/** Parse a receipts file into a list of envelopes (single object or array). */
function parseReceipts(raw: string): unknown[] {
  const parsed: unknown = JSON.parse(raw);
  return Array.isArray(parsed) ? parsed : [parsed];
}

function loadTrustedFingerprints(raw: string): ReadonlySet<string> {
  const parsed: unknown = JSON.parse(raw);
  if (!Array.isArray(parsed) || parsed.some((x) => typeof x !== "string")) {
    throw new Error(
      "trusted-keys file must be a JSON array of fingerprint strings"
    );
  }
  return new Set(parsed as string[]);
}

interface FileReport {
  file: string;
  outcomes: AnchorVerifyOutcome[];
}

function humanLine(
  file: string,
  index: number,
  total: number,
  o: AnchorVerifyOutcome
): string {
  const mark = o.ok ? "PASS" : "FAIL";
  const label = total > 1 ? `${file}[${index}]` : file;
  const fam = o.family ?? "?";
  const ct = o.claim_type ?? "(no claim_type)";
  const reason = o.ok
    ? ""
    : `  reason=${o.result?.reason ?? o.reason ?? "unknown"}`;
  return `${mark}  ${label}  ${fam}  ${ct}${reason}`;
}

export async function runCli(
  argv: readonly string[],
  deps: CliDeps
): Promise<CliResult> {
  // Peel the subcommand. `verify` is the only command today; a bare
  // `--help`/`-h` (or no args) prints usage.
  const [command, ...rest] = argv;
  if (command === undefined || command === "-h" || command === "--help") {
    return {
      exitCode: command === undefined ? 2 : 0,
      stdout: command === undefined ? "" : `${USAGE}\n`,
      stderr: command === undefined ? `error: no command\n\n${USAGE}\n` : "",
    };
  }
  if (command !== "verify") {
    return {
      exitCode: 2,
      stdout: "",
      stderr: `error: unknown command "${command}"\n\n${USAGE}\n`,
    };
  }

  const parsed = parseArgs(rest);
  if ("error" in parsed) {
    return {
      exitCode: 2,
      stdout: "",
      stderr: `error: ${parsed.error}\n\n${USAGE}\n`,
    };
  }
  if (parsed.help) {
    return { exitCode: 0, stdout: `${USAGE}\n`, stderr: "" };
  }
  if (parsed.files.length === 0) {
    return {
      exitCode: 2,
      stdout: "",
      stderr: `error: no input files\n\n${USAGE}\n`,
    };
  }

  // Build the issuer-key resolver (self-certifying or allowlist).
  let resolveKey: FamilyVerifyOptions["resolveKey"];
  if (parsed.trustedKeysFile !== null) {
    let trusted: ReadonlySet<string>;
    try {
      trusted = loadTrustedFingerprints(
        await deps.readFile(parsed.trustedKeysFile)
      );
    } catch (err) {
      return {
        exitCode: 2,
        stdout: "",
        stderr: `error: cannot read --trusted-keys ${
          parsed.trustedKeysFile
        }: ${errMsg(err)}\n`,
      };
    }
    resolveKey = makeTrustedKeysResolveKey(trusted);
  } else {
    resolveKey = selfCertifyingResolveKey;
  }
  const opts: FamilyVerifyOptions = { resolveKey };

  const reports: FileReport[] = [];
  for (const file of parsed.files) {
    let receipts: unknown[];
    try {
      receipts = parseReceipts(await deps.readFile(file));
    } catch (err) {
      return {
        exitCode: 2,
        stdout: "",
        stderr: `error: cannot read ${file}: ${errMsg(err)}\n`,
      };
    }
    const outcomes: AnchorVerifyOutcome[] = [];
    for (const receipt of receipts) {
      outcomes.push(await verifyAnchor(receipt, opts));
    }
    reports.push({ file, outcomes });
  }

  const allOk = reports.every((r) => r.outcomes.every((o) => o.ok));
  const exitCode = allOk ? 0 : 1;

  if (parsed.json) {
    const payload = {
      ok: allOk,
      mode:
        parsed.trustedKeysFile !== null ? "trusted-keys" : "self-certifying",
      files: reports,
    };
    return {
      exitCode,
      stdout: `${JSON.stringify(payload, null, 2)}\n`,
      stderr: "",
    };
  }

  const lines: string[] = [];
  if (parsed.trustedKeysFile === null) {
    lines.push(
      "mode: self-certifying (embedded iss_key — proves signature, NOT issuer identity)"
    );
  } else {
    lines.push(`mode: trusted-keys (${parsed.trustedKeysFile})`);
  }
  for (const r of reports) {
    r.outcomes.forEach((o, i) =>
      lines.push(humanLine(r.file, i, r.outcomes.length, o))
    );
  }
  return { exitCode, stdout: `${lines.join("\n")}\n`, stderr: "" };
}

function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

// Re-exported for callers embedding the CLI surface.
export { supportedClaimTypes };

// ── Executable entry ──────────────────────────────────────────────────────────
const invokedPath = process.argv[1];
const isMain =
  invokedPath !== undefined &&
  import.meta.url === pathToFileURL(invokedPath).href;

if (isMain) {
  runCli(process.argv.slice(2), { readFile: (p) => fsReadFile(p, "utf8") })
    .then((r) => {
      if (r.stdout) process.stdout.write(r.stdout);
      if (r.stderr) process.stderr.write(r.stderr);
      process.exit(r.exitCode);
    })
    .catch((err) => {
      process.stderr.write(`fatal: ${errMsg(err)}\n`);
      process.exit(2);
    });
}
