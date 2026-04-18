#!/usr/bin/env bash
# make-sha256sums.sh — aggregate SHA256 hashes for a directory of release artifacts.
#
# Usage: scripts/make-sha256sums.sh <dist-dir>
#
# Produces:   <dist-dir>/SHA256SUMS     — sorted, BSD-style checksum file
# Verifies:   sha256sum -c SHA256SUMS   at the end
#
# This is a helper for LOCAL smoke-testing. Published releases are always signed
# and hashed by CI (.github/workflows/release.yml); do not publish the output of
# this script.

set -euo pipefail

DIST="${1:-}"
if [[ -z "$DIST" ]]; then
  echo "usage: $0 <dist-dir>" >&2
  exit 2
fi
if [[ ! -d "$DIST" ]]; then
  echo "error: '$DIST' is not a directory" >&2
  exit 2
fi

cd "$DIST"

# Remove any prior SHA256SUMS so it is never hashed into itself.
rm -f SHA256SUMS SHA256SUMS.minisig

# Hash every regular file in the directory, sorted by filename for determinism.
shopt -s nullglob
files=()
for f in *; do
  [[ -f "$f" ]] || continue
  files+=("$f")
done
if [[ ${#files[@]} -eq 0 ]]; then
  echo "error: no files in $DIST to hash" >&2
  exit 1
fi

# Pick the hashing tool available on the host.
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "${files[@]}" | sort -k 2 > SHA256SUMS
elif command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "${files[@]}" | sort -k 2 > SHA256SUMS
else
  echo "error: need sha256sum or shasum on PATH" >&2
  exit 1
fi

echo "wrote $DIST/SHA256SUMS:"
cat SHA256SUMS

echo
echo "verifying..."
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum -c SHA256SUMS
else
  shasum -a 256 -c SHA256SUMS
fi
