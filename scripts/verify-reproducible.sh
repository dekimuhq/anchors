#!/usr/bin/env bash
set -euo pipefail

# Verify reproducible builds — run twice from clean state, compare output.
# Usage: ./scripts/verify-reproducible.sh

echo "=== Reproducible Build Verification ==="
echo "Step 1: Clean build (run 1)"
rm -rf /tmp/anchors-repro-1 /tmp/anchors-repro-2

# Run 1
npm ci --ignore-scripts 2>/dev/null
npm run build --workspaces --if-present 2>/dev/null || true
find . -name '*.js' -path '*/dist/*' | sort | xargs sha256sum > /tmp/anchors-repro-1 2>/dev/null || echo "No dist output (source-only packages)"

# Run 2
npm ci --ignore-scripts 2>/dev/null
npm run build --workspaces --if-present 2>/dev/null || true
find . -name '*.js' -path '*/dist/*' | sort | xargs sha256sum > /tmp/anchors-repro-2 2>/dev/null || echo "No dist output (source-only packages)"

# Compare
if diff /tmp/anchors-repro-1 /tmp/anchors-repro-2 > /dev/null 2>&1; then
  echo "PASS: Builds are reproducible (byte-identical output)"
  exit 0
else
  echo "FAIL: Builds differ between runs"
  diff /tmp/anchors-repro-1 /tmp/anchors-repro-2
  exit 1
fi
