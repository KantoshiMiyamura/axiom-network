#!/usr/bin/env bash
# Axiom Network — release signing (GPG tag + minisign SHA256SUMS).
#
# REAL signing script. Produces:
#   - SHA256SUMS                      (plain text, one hash per artifact)
#   - SHA256SUMS.minisig              (minisign signature of SHA256SUMS)
#   - v<tag>.tag.asc                  (GPG-signed annotated tag message)
#
# This script DOES NOT:
#   - push to GitHub
#   - create a GitHub release
#   - upload artifacts
# Those steps are in publish-release.sh, which is separate by design:
# you can always re-sign without re-publishing.
#
# REQUIREMENTS:
#   - GPG with a private key capable of signing
#   - minisign (https://jedisct1.github.io/minisign/)
#     Install:
#       Linux:   sudo apt-get install minisign  (or brew install minisign)
#       macOS:   brew install minisign
#       Windows: https://github.com/jedisct1/minisign/releases
#   - git, sha256sum (or shasum)
#
# INPUTS (environment):
#   AXIOM_TAG                 e.g. v1.0.1-testnet.2 (must already exist locally
#                             as an annotated tag)
#   AXIOM_GPG_KEY_ID          long key id of your signing GPG key (the script
#                             re-signs the tag with this key)
#   AXIOM_MINISIGN_SECKEY     path to minisign secret key file (usually
#                             ~/.minisign/minisign.key)
#   AXIOM_MINISIGN_PASSWORD   optional; if set, piped to minisign stdin instead
#                             of interactive prompt. Prefer interactive.
#   AXIOM_ARTIFACTS_DIR       directory with the release artifacts to hash
#
# INVOCATION (copy-paste):
#
#   export AXIOM_TAG=v1.0.1-testnet.2
#   export AXIOM_GPG_KEY_ID=0xDEADBEEFCAFEBABE
#   export AXIOM_MINISIGN_SECKEY=$HOME/.minisign/minisign.key
#   export AXIOM_ARTIFACTS_DIR=$PWD/dist
#   scripts/release/sign-release.sh
#
# The script is idempotent: re-running re-computes SHA256SUMS and re-signs.

set -euo pipefail

: "${AXIOM_TAG:?set AXIOM_TAG=v...}"
: "${AXIOM_GPG_KEY_ID:?set AXIOM_GPG_KEY_ID=<long-key-id>}"
: "${AXIOM_MINISIGN_SECKEY:?set AXIOM_MINISIGN_SECKEY=/path/to/minisign.key}"
: "${AXIOM_ARTIFACTS_DIR:?set AXIOM_ARTIFACTS_DIR=/path/to/dist}"

for cmd in gpg minisign git sha256sum; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "missing: $cmd" >&2; exit 1; }
done

[ -f "$AXIOM_MINISIGN_SECKEY" ] || { echo "minisign seckey not found: $AXIOM_MINISIGN_SECKEY" >&2; exit 1; }
[ -d "$AXIOM_ARTIFACTS_DIR" ]    || { echo "artifacts dir not found: $AXIOM_ARTIFACTS_DIR" >&2; exit 1; }

# 1) Confirm the tag exists as an annotated tag.
if ! git rev-parse -q --verify "refs/tags/$AXIOM_TAG" >/dev/null; then
    echo "ERROR: tag $AXIOM_TAG does not exist locally. Create it first:" >&2
    echo "  git tag -a $AXIOM_TAG -m 'Axiom Network $AXIOM_TAG'" >&2
    exit 1
fi

# 2) Re-sign the tag with GPG (replaces any unsigned tag).
echo "── Signing git tag $AXIOM_TAG with GPG key $AXIOM_GPG_KEY_ID ──"
MSG="$(git tag -l --format='%(contents)' "$AXIOM_TAG")"
[ -n "$MSG" ] || MSG="Axiom Network $AXIOM_TAG"
git tag -d "$AXIOM_TAG" >/dev/null
git -c user.signingkey="$AXIOM_GPG_KEY_ID" tag -s "$AXIOM_TAG" -m "$MSG"
git verify-tag "$AXIOM_TAG"
echo "  tag signed + verified."

# 3) Compute SHA256SUMS.
cd "$AXIOM_ARTIFACTS_DIR"
echo "── Computing SHA256SUMS in $AXIOM_ARTIFACTS_DIR ──"
# Sort for determinism; exclude pre-existing signatures/sums.
find . -maxdepth 1 -type f \
    ! -name 'SHA256SUMS' ! -name 'SHA256SUMS.minisig' ! -name '*.asc' \
    -print0 | sort -z | xargs -0 sha256sum >SHA256SUMS
cat SHA256SUMS

# 4) Sign SHA256SUMS with minisign.
echo "── Signing SHA256SUMS with minisign ──"
if [ -n "${AXIOM_MINISIGN_PASSWORD:-}" ]; then
    echo "  (using piped password — use interactive mode for release signing)"
    printf "%s\n" "$AXIOM_MINISIGN_PASSWORD" \
        | minisign -S -s "$AXIOM_MINISIGN_SECKEY" -m SHA256SUMS -x SHA256SUMS.minisig \
            -c "axiom-network $AXIOM_TAG" \
            -t "axiom-network $AXIOM_TAG"
else
    minisign -S -s "$AXIOM_MINISIGN_SECKEY" -m SHA256SUMS -x SHA256SUMS.minisig \
        -c "axiom-network $AXIOM_TAG" \
        -t "axiom-network $AXIOM_TAG"
fi

# 5) Self-verify (with the corresponding public key, if present next to the seckey).
PUBKEY="${AXIOM_MINISIGN_SECKEY%.key}.pub"
if [ -f "$PUBKEY" ]; then
    echo "── Verifying SHA256SUMS.minisig with $PUBKEY ──"
    minisign -V -p "$PUBKEY" -m SHA256SUMS -x SHA256SUMS.minisig
fi

echo
echo "── Done ──"
echo "Signed tag:   $AXIOM_TAG"
echo "SHA256SUMS:   $AXIOM_ARTIFACTS_DIR/SHA256SUMS"
echo "minisig:      $AXIOM_ARTIFACTS_DIR/SHA256SUMS.minisig"
echo
echo "Next step: publish via gh release create + upload these two files"
echo "  alongside every binary. See scripts/release/publish-release.sh."
