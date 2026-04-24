#!/usr/bin/env bash
# Axiom Network — publish a signed release to GitHub.
#
# Runs AFTER sign-release.sh. Assumes:
#   - $AXIOM_ARTIFACTS_DIR contains: binaries + SHA256SUMS + SHA256SUMS.minisig
#   - The git tag has been signed and pushed (git push origin $AXIOM_TAG)
#   - gh CLI is authenticated (`gh auth status` must succeed)
#
# This is the ONLY script that touches the remote (GitHub). Kept separate
# so signing and publishing can be reviewed independently.
#
# INPUTS (environment):
#   AXIOM_TAG                 e.g. v1.0.1-testnet.2
#   AXIOM_ARTIFACTS_DIR       directory with the signed artifacts
#   AXIOM_RELEASE_NOTES       path to release notes markdown (required)
#   AXIOM_RELEASE_TITLE       optional; defaults to "Axiom Network $AXIOM_TAG"
#   AXIOM_RELEASE_DRAFT=1     optional; create as draft (default: published)
#   AXIOM_RELEASE_PRERELEASE=1 optional; mark as prerelease (default for
#                              testnet tags: prerelease=1)
#
# Invocation:
#   export AXIOM_TAG=v1.0.1-testnet.2
#   export AXIOM_ARTIFACTS_DIR=$PWD/dist
#   export AXIOM_RELEASE_NOTES=$PWD/dist/RELEASE_NOTES.md
#   scripts/release/publish-release.sh

set -euo pipefail

: "${AXIOM_TAG:?set AXIOM_TAG}"
: "${AXIOM_ARTIFACTS_DIR:?set AXIOM_ARTIFACTS_DIR}"
: "${AXIOM_RELEASE_NOTES:?set AXIOM_RELEASE_NOTES=/path/to/notes.md}"

command -v gh >/dev/null || { echo "gh not installed" >&2; exit 1; }
gh auth status >/dev/null || { echo "gh not authenticated — run: gh auth login" >&2; exit 1; }

[ -f "$AXIOM_ARTIFACTS_DIR/SHA256SUMS" ]         || { echo "missing SHA256SUMS (run sign-release.sh first)" >&2; exit 1; }
[ -f "$AXIOM_ARTIFACTS_DIR/SHA256SUMS.minisig" ] || { echo "missing SHA256SUMS.minisig (run sign-release.sh first)" >&2; exit 1; }
[ -f "$AXIOM_RELEASE_NOTES" ]                    || { echo "missing release notes: $AXIOM_RELEASE_NOTES" >&2; exit 1; }

# Verify the tag is signed (refuse to publish unsigned tags).
git verify-tag "$AXIOM_TAG" || { echo "tag $AXIOM_TAG is not GPG-signed — run sign-release.sh first" >&2; exit 1; }

# Infer testnet → prerelease unless overridden.
PRE_FLAG=""
if [ "${AXIOM_RELEASE_PRERELEASE:-}" = "1" ] || [[ "$AXIOM_TAG" == *"testnet"* ]]; then
    PRE_FLAG="--prerelease"
fi
DRAFT_FLAG=""
[ "${AXIOM_RELEASE_DRAFT:-}" = "1" ] && DRAFT_FLAG="--draft"

TITLE="${AXIOM_RELEASE_TITLE:-Axiom Network $AXIOM_TAG}"

echo "── Creating release $AXIOM_TAG ──"
cd "$AXIOM_ARTIFACTS_DIR"

# Enumerate every file that's not a hash/signature container — they all get uploaded.
UPLOADS=()
while IFS= read -r -d '' f; do UPLOADS+=("$f"); done \
    < <(find . -maxdepth 1 -type f -print0)

gh release create "$AXIOM_TAG" \
    --title "$TITLE" \
    --notes-file "$AXIOM_RELEASE_NOTES" \
    $PRE_FLAG $DRAFT_FLAG \
    "${UPLOADS[@]}"

echo
echo "Release published: https://github.com/$(gh repo view --json nameWithOwner -q .nameWithOwner)/releases/tag/$AXIOM_TAG"
