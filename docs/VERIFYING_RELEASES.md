# Verifying Axiom Network Releases

You should never run a blockchain binary you cannot verify. Every Axiom release
ships with:

- **`SHA256SUMS`** — a list of SHA-256 hashes for every artifact.
- **`SHA256SUMS.minisig`** — a minisign signature over `SHA256SUMS`, made with
  the project's release key.

The release public keys are:

- **Minisign public key** — [`docs/minisign.pub`](./minisign.pub) in this repo.
- **GPG release key** (for tag verification) — [`docs/release-key.asc`](./release-key.asc).

Both are committed to the repository. Fetch them from a trusted checkout, not
from a third-party mirror.

---

## Quick verification (one command)

If you cloned the repo, the bundled script does everything:

```bash
mkdir ~/axiom-verify && cd ~/axiom-verify
# Download the release assets you plan to run (adjust the tag).
gh release download v1.0.0

# Run the verifier.
bash /path/to/repo/scripts/verify-release.sh .
```

Expected output ends with:

```
OK — release artifacts are authentic and unmodified.
```

If it prints anything else, **do not run the binaries**. Open an issue.

---

## Manual verification (no repo checkout)

### 1. Install tools

`minisign` is not packaged in the Debian/Ubuntu repos, so install the
official binary directly from the upstream release. Pin the version that
matches the one used in CI to ensure reproducible verification.

```bash
# Linux x86_64 — install the pinned upstream binary (same version used in CI).
MINISIGN_VERSION="0.12"
curl -fsSL "https://github.com/jedisct1/minisign/releases/download/${MINISIGN_VERSION}/minisign-${MINISIGN_VERSION}-linux.tar.gz" \
    -o minisign.tar.gz
tar -xzf minisign.tar.gz
sudo install -m 755 "minisign-linux/x86_64/minisign" /usr/local/bin/minisign
rm -rf minisign.tar.gz minisign-linux
minisign -v
```

```bash
# macOS
brew install minisign
```

```powershell
# Windows (PowerShell, as Administrator)
winget install jedisct1.minisign
```

You also need standard checksum tools (`sha256sum` on Linux, `shasum -a 256`
on macOS, `Get-FileHash` on Windows).

### 2. Download the public key and the release

```bash
# Fetch the public key from the official repo over HTTPS.
curl -fsSLO https://raw.githubusercontent.com/<owner>/<repo>/main/docs/minisign.pub

# Download the release files.
TAG=v1.0.0
for f in SHA256SUMS SHA256SUMS.minisig \
         axiom-v1.0.0-x86_64-unknown-linux-gnu.tar.gz ; do
    curl -fsSLO "https://github.com/<owner>/<repo>/releases/download/${TAG}/${f}"
done
```

### 3. Verify the signature on SHA256SUMS

```bash
minisign -Vm SHA256SUMS -p minisign.pub
```

Expected:

```
Signature and comment signature verified
Trusted comment: ...
```

### 4. Verify each artifact hash

```bash
sha256sum -c SHA256SUMS
# or on macOS: shasum -a 256 -c SHA256SUMS
```

Every file you downloaded should print `OK`.

### 5. (Optional) Verify the git tag signature

If you want to prove the source code you compile yourself matches the tagged
release:

```bash
# Import the project's GPG public key.
curl -fsSL https://raw.githubusercontent.com/<owner>/<repo>/main/docs/release-key.asc \
  | gpg --import

git clone https://github.com/<owner>/<repo>.git
cd <repo>
git tag -v v1.0.0
```

Expected:

```
gpg: Good signature from "Project Maintainer <...>"
```

---

## What "verified" proves

- **SHA256SUMS verified with minisign** → the file listing hashes was produced
  by whoever holds the project's release key.
- **Hashes verified** → the binaries you downloaded are byte-for-byte identical
  to what that key signed.
- **Tag signature verified** → the source code at that commit was signed by the
  project's GPG release key.

Together, these chain identity (GPG tag) → source (commit) → build (CI) →
artifacts (minisign). Any break in the chain is cause for alarm.

---

## Reporting a mismatch

If any step fails, do not run the binaries. Open an issue with:

1. Which file failed.
2. The exact command output (redact any private info first).
3. The URL you downloaded from.

Do not post suspected-tampered binaries publicly.
