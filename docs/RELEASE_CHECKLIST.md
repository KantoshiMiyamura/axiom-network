# Release Checklist

Step-by-step commands to cut a release. **Every step is explicit.** Secrets are
never typed into this file, the shell, or any commit — they live only in your
OS keyring, your GPG agent, and GitHub Actions secrets.

---

## 0. One-time prerequisites (skip after the first release)

### 0a. Set a real git identity (local only, never committed)

```bash
git config --global user.name  "YOUR NAME"
git config --global user.email "you@example.com"
```

### 0b. Create a GPG key for signing tags and commits

> **Run these ON YOUR LOCAL MACHINE.** I (the assistant) will never do this for
> you, and you should never paste the private key into a chat window.

```bash
# 1. Generate a key. Choose: (1) RSA and RSA, 4096 bits, no expiry or 2-5 yr.
gpg --full-generate-key

# 2. Find the long key id of the key you just made.
gpg --list-secret-keys --keyid-format LONG
#    Look for a line like:
#    sec   rsa4096/3AA5C34371567BD2 2026-04-18 [SC]

# 3. Tell git to use it for commits AND tags.
export KEYID=3AA5C34371567BD2          # replace with YOUR key id
git config --global user.signingkey "$KEYID"
git config --global commit.gpgSign  true
git config --global tag.gpgSign     true

# 4. Export the PUBLIC key so users can verify your tags.
gpg --armor --export "$KEYID" > docs/release-key.asc
git add docs/release-key.asc
git commit -S -m "chore: publish GPG release key"
```

### 0c. Create a minisign key for signing SHA256SUMS

> Run on the **same local machine**. This key should stay offline except when
> you upload it to GitHub secrets.

```bash
# 1. Generate. You WILL be prompted for a passphrase — use a strong one.
minisign -G -p docs/minisign.pub -s ~/.minisign/axiom-release.key

# 2. Commit the PUBLIC key only.
git add docs/minisign.pub
git commit -S -m "chore: publish minisign release key"

# 3. Upload the SECRET key as a GitHub Actions repo secret.
#    Use the GitHub UI: Settings → Secrets and variables → Actions → New secret.
#    Create TWO secrets:
#      - MINISIGN_SECRET_KEY → paste the full contents of ~/.minisign/axiom-release.key
#      - MINISIGN_PASSWORD   → the passphrase you chose above
#
#    After pasting, delete the local secret key ONLY if you have a secure backup:
#      rm ~/.minisign/axiom-release.key
```

Neither secret leaves your machine through any channel other than the GitHub
secret UI. The workflow reads them via `${{ secrets.* }}`, never logs them, and
never writes them to disk outside a `mktemp` file that is wiped at step end.

---

## 1. Pre-flight checks

Run these in a clean checkout of `main`.

```bash
# a. Confirm clean tree.
git checkout main
git fetch --all --tags
git pull --ff-only
git status           # must say: nothing to commit, working tree clean

# b. Confirm versions match the intended tag.
export VERSION=1.0.0                  # change for each release
grep -rn '^version = ' Cargo.toml crates/*/Cargo.toml \
  | grep -v "= \"$VERSION\""          # should print nothing

# c. Local smoke build (optional but recommended).
bash scripts/build-release.sh
bash scripts/make-sha256sums.sh release/

# d. Full CI check already passed on main — confirm in the Actions UI.
```

If any of a/b fail, fix on a branch, PR, merge to main, and restart.

---

## 2. Cut the signed tag

```bash
# The -s flag signs with your GPG key configured in step 0b.
git tag -s "v$VERSION" -m "Axiom Network v$VERSION"

# Verify locally BEFORE pushing.
git tag -v "v$VERSION"
# Expected: "Good signature from \"YOUR NAME <you@example.com>\""

# Push the tag to trigger CI.
git push origin "v$VERSION"
```

Pushing `v$VERSION` triggers `.github/workflows/release.yml`, which:

1. Resolves and checks out the tag.
2. Fails if the tag is not annotated (`git cat-file -t v$VERSION` must be `tag`).
3. Fails if the tag does not match HEAD at checkout.
4. Builds node binaries on 4 platform runners.
5. Builds 4 wallet installers (MSI, AppImage, .deb, DMG).
6. Aggregates all artifacts, produces `SHA256SUMS`, signs it with minisign.
7. Creates a **draft** GitHub Release with every file attached.

---

## 3. Verify the draft release

Run **on a different machine** if possible (proves reproducibility/integrity).

```bash
mkdir ~/axiom-release-verify && cd ~/axiom-release-verify
gh release download "v$VERSION" --dir .

# Verify.
bash /path/to/repo/scripts/verify-release.sh .
```

The script must print `OK — release artifacts are authentic and unmodified.`

Spot-check at least one binary runs:

```bash
unzip -p axiom-v${VERSION}-x86_64-pc-windows-msvc.zip axiom.exe > /tmp/axiom.exe
# or on Linux:
tar -xOzf axiom-v${VERSION}-x86_64-unknown-linux-gnu.tar.gz \
  "axiom-v${VERSION}-x86_64-unknown-linux-gnu/axiom" > /tmp/axiom
chmod +x /tmp/axiom && /tmp/axiom --version    # prints: axiom v${VERSION}
```

---

## 4. Publish

Open the draft release in the GitHub UI. Confirm:

- [ ] Auto-generated release notes read correctly
- [ ] A verification section at the top links to `docs/release-key.asc` and `docs/minisign.pub`
- [ ] All expected assets are attached (see checklist below)
- [ ] `SHA256SUMS.minisig` is present

Then click **Publish release**. Uncheck "set as latest release" if this is a
pre-release (tag like `v1.0.0-rc1`).

---

## 5. Update the website

```bash
bash scripts/update-downloads-page.sh "v$VERSION"
git add web/downloads.html "web/downloads/${VERSION}/"
git commit -S -m "web: publish v$VERSION downloads"
git push
```

The script only replaces content between `<!-- RELEASE-ASSETS:BEGIN -->` and
`<!-- RELEASE-ASSETS:END -->`. Review `git diff` before pushing.

---

## 6. Announce (manual)

- [ ] Blog post / changelog
- [ ] Social channels
- [ ] Update pinned issues / README "Latest release" badge

---

## Expected artifact list (for `v$VERSION`)

```
SHA256SUMS
SHA256SUMS.minisig
axiom-v${VERSION}-x86_64-pc-windows-msvc.zip
axiom-v${VERSION}-x86_64-unknown-linux-gnu.tar.gz
axiom-v${VERSION}-aarch64-apple-darwin.tar.gz
axiom-v${VERSION}-x86_64-apple-darwin.tar.gz
Axiom_Wallet_${VERSION}_x64_en-US.msi              (from wallet-windows-msi)
axiom-wallet_${VERSION}_amd64.AppImage             (from wallet-linux-appimage)
axiom-wallet_${VERSION}_amd64.deb                  (from wallet-linux-deb)
Axiom Wallet_${VERSION}_aarch64.dmg                (from wallet-macos-dmg)
```

(Wallet filenames come from Tauri; confirm exact names on the first release.)

---

## Re-running CI for an existing tag

If a CI job flaked and the draft release is incomplete, re-run without
re-tagging:

1. GitHub UI → Actions → Release workflow → **Run workflow**
2. Enter the tag (e.g. `v1.0.0`)
3. The workflow uses the existing signed tag; no new commits, no new tag.

---

## Retagging (only if NOT yet published)

```bash
gh release delete "v$VERSION" --yes
git push --delete origin "v$VERSION"
git tag -d "v$VERSION"
# fix the issue, commit, then recut
git tag -s "v$VERSION" -m "Axiom Network v$VERSION"
git push origin "v$VERSION"
```

If already **published**, never delete. Cut `v${VERSION%.*}.$((${VERSION##*.}+1))`
with the fix.
