# Releasing Axiom Network

This document is the single source of truth for cutting a release. Every release
— mainnet, testnet, or patch — follows this procedure. No manual uploads, no
hand-built zips, no one-off hashes.

---

## Prerequisites (one-time per maintainer)

### 1. Real git identity

Placeholder identities (`Your Name <you@example.com>`) are rejected. Set a
durable identity **once** on the release machine:

```bash
git config --global user.name  "Jane Doe"
git config --global user.email "jane@axiomnetwork.org"
```

### 2. Signing key for tags

Tags must be cryptographically signed so downstream users can verify a release
is genuine. Generate a GPG key (or reuse one) and tell git about it:

```bash
gpg --full-generate-key               # RSA 4096, no expiry for release key
gpg --list-secret-keys --keyid-format LONG
# copy the long key id, e.g. 3AA5C34371567BD2
git config --global user.signingkey 3AA5C34371567BD2
git config --global tag.gpgSign  true
git config --global commit.gpgSign true
```

Publish the public key alongside the release so users can verify tags:

```bash
gpg --armor --export 3AA5C34371567BD2 > docs/release-key.asc
```

### 3. Minisign key for SHA256SUMS

CI signs the aggregated `SHA256SUMS` file with minisign. Generate the key **on a
secure machine** (ideally offline) and store it as a GitHub Actions secret:

```bash
minisign -G -p docs/minisign.pub -s minisign.key
# Enter a strong passphrase when prompted
```

In the repository settings on GitHub, add two secrets:

- `MINISIGN_SECRET_KEY` — contents of `minisign.key`
- `MINISIGN_PASSWORD`   — the passphrase

Commit `docs/minisign.pub` to the repo. Never commit `minisign.key`.

---

## Release procedure

### Step 1 — Freeze versions

Every `Cargo.toml` that declares `version = "..."` must match the tag you are
about to cut. For v1.0.0:

```bash
grep -rn '^version = ' crates/*/Cargo.toml Cargo.toml
```

All entries should show `version = "1.0.0"`. Update any that disagree, commit,
push to `main`.

### Step 2 — Clean working tree

```bash
git status          # must show: nothing to commit, working tree clean
git fetch --all
git pull --ff-only
```

If anything is dirty, stop. Do not tag a dirty tree.

### Step 3 — Create signed, annotated tag

```bash
git tag -s v1.0.0 -m "Axiom Network v1.0.0"
git push origin v1.0.0
```

The `-s` flag signs the tag with your GPG key. Verify locally before pushing:

```bash
git tag -v v1.0.0
```

You should see `Good signature from "Jane Doe <jane@…>"`.

### Step 4 — CI builds everything

Pushing a tag matching `v[0-9]+.[0-9]+.[0-9]+` triggers
`.github/workflows/release.yml`. The workflow:

1. Verifies the tag points to `HEAD` on each runner.
2. Pins Rust 1.93.1.
3. Builds on **four** matrix targets:
   - `x86_64-pc-windows-msvc`   → `axiom-v{VER}-x86_64-pc-windows-msvc.zip`
   - `x86_64-unknown-linux-gnu` → `axiom-v{VER}-x86_64-unknown-linux-gnu.tar.gz`
   - `aarch64-apple-darwin`     → `axiom-v{VER}-aarch64-apple-darwin.tar.gz`
   - `x86_64-apple-darwin`      → `axiom-v{VER}-x86_64-apple-darwin.tar.gz`
4. Runs `cargo test --release --workspace --lib` on each target.
5. Builds four wallet installers: MSI, AppImage, .deb, DMG.
6. Aggregates all artifacts, produces `SHA256SUMS`, signs it with minisign.
7. Creates a **draft** GitHub Release with every file attached.

Watch the workflow at `https://github.com/<owner>/<repo>/actions`. If any job
fails, do **not** publish the draft — investigate, fix, re-tag (`v1.0.1` or
delete-and-recreate — see "Retagging" below).

### Step 5 — Verify artifacts

Once CI is green, pull the draft release artifacts locally:

```bash
gh release download v1.0.0 --dir dist
cd dist
sha256sum -c SHA256SUMS
minisign -Vm SHA256SUMS -p ../docs/minisign.pub
```

Both checks must pass. Spot-check one binary:

```bash
unzip -p axiom-v1.0.0-x86_64-pc-windows-msvc.zip axiom.exe | sha256sum
```

### Step 6 — Publish

In the GitHub UI, edit the draft release:

1. Confirm the auto-generated release notes read correctly.
2. Add a section at the top linking to `docs/minisign.pub` and
   `docs/release-key.asc` for verification.
3. Click **Publish release**.

### Step 7 — Update website

The website at `web/downloads.html` must point at **real** GitHub Release URLs,
not locally-built files. After publishing:

```bash
# URLs follow the pattern:
#   https://github.com/<owner>/<repo>/releases/download/v1.0.0/<filename>
```

Replace any `<button disabled>` placeholders with `<a href>` links to the
published assets. Commit and push to `main`.

---

## Reproducibility

Anyone should be able to reproduce our binaries from source:

```bash
git clone https://github.com/<owner>/<repo>.git
cd <repo>
git checkout v1.0.0
git tag -v v1.0.0                           # verify tag signature
rustup install 1.93.1
cargo build --release --target x86_64-unknown-linux-gnu \
  -p axiom-cli -p axiom-node -p axiom-keygen -p axiom-sign -p axiom-bump-fee
sha256sum target/x86_64-unknown-linux-gnu/release/axiom
```

The hash should match the corresponding entry in `SHA256SUMS`. Small drift may
occur from embedded timestamps or build paths — open an issue if hashes differ
materially.

---

## Retagging

If a release must be redone **before** publication (draft only):

```bash
gh release delete v1.0.0 --yes
git push --delete origin v1.0.0
git tag -d v1.0.0
# fix the issue, commit, then re-cut the tag
git tag -s v1.0.0 -m "Axiom Network v1.0.0"
git push origin v1.0.0
```

If a release has already been **published**, do not delete it. Cut a patch
(`v1.0.1`) with the fix.

---

## Emergency: local release build

CI is the source of truth. Local builds exist only for smoke-testing before a
tag. Do **not** publish locally-built artifacts.

```bash
scripts/build-release.sh              # single-target, current host
scripts/make-sha256sums.sh dist/      # aggregate hashes across local dist dir
```

---

## Checklist

Copy this into the PR description for the version bump commit:

- [ ] All `Cargo.toml` versions match the tag
- [ ] Working tree clean on `main`
- [ ] Signed tag created and verified locally (`git tag -v`)
- [ ] CI release workflow green on all 8 matrix jobs
- [ ] `sha256sum -c SHA256SUMS` passes
- [ ] `minisign -Vm SHA256SUMS -p docs/minisign.pub` passes
- [ ] Draft release notes reviewed
- [ ] Website updated with real GitHub Release URLs
- [ ] Announcement posted
