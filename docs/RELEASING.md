# Releasing witnessd

This document describes how to create and publish releases of witnessd.

## Prerequisites

1. **goreleaser** - Install via Homebrew:
   ```bash
   brew install goreleaser
   ```

2. **Apple Developer Account** - For macOS code signing and notarization

3. **GitHub Token** - With `repo` scope for publishing releases

4. **Homebrew Tap Repository** - Create `writerslogic/homebrew-tap` on GitHub

## Environment Variables

Set these environment variables before running a release:

```bash
# GitHub
export GITHUB_TOKEN="ghp_..."           # GitHub personal access token
export HOMEBREW_TAP_TOKEN="ghp_..."     # Token for homebrew-tap repo

# Apple Developer (for macOS notarization)
export APPLE_DEVELOPER_ID="Developer ID Application: Your Name (TEAMID)"
export APPLE_ISSUER_ID="..."            # App Store Connect API Issuer ID
export APPLE_KEY_ID="..."               # App Store Connect API Key ID
export APPLE_PRIVATE_KEY="path/to/AuthKey_XXXX.p8"

# Optional: For other package managers
export SCOOP_BUCKET_TOKEN="ghp_..."     # For Windows Scoop bucket
export AUR_SSH_PRIVATE_KEY="..."        # For Arch Linux AUR
```

## Apple Developer Setup

### 1. Create Developer ID Certificate

1. Go to [Apple Developer](https://developer.apple.com/account/)
2. Navigate to Certificates, Identifiers & Profiles
3. Create a new "Developer ID Application" certificate
4. Download and install in Keychain

### 2. Create App Store Connect API Key

1. Go to [App Store Connect](https://appstoreconnect.apple.com/)
2. Navigate to Users and Access > Keys
3. Click "+" to create a new key
4. Download the .p8 file (only available once!)
5. Note the Key ID and Issuer ID

### 3. Verify Setup

```bash
# Check certificate is installed
security find-identity -v -p codesigning

# Test signing locally
make build
make sign
```

## Creating a Release

### 1. Update Version

Witnessd uses git tags for versioning. Create a new tag:

```bash
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0
```

### 2. Run goreleaser

For a full release:
```bash
make release
```

For a snapshot (testing):
```bash
make release-snapshot
```

For a dry run (no publishing):
```bash
make release-dry-run
```

### 3. Verify Release

1. Check [GitHub Releases](https://github.com/writerslogic/witnessd/releases)
2. Verify checksums
3. Test installation:
   ```bash
   brew install writerslogic/tap/witnessd
   witnessd version
   ```

## Manual Signing (without goreleaser)

If you need to sign binaries manually:

```bash
# Build
make build

# Sign
export APPLE_DEVELOPER_ID="Developer ID Application: Your Name (TEAMID)"
make sign

# Notarize
export APPLE_ISSUER_ID="..."
export APPLE_KEY_ID="..."
export APPLE_PRIVATE_KEY="path/to/AuthKey.p8"
make notarize
```

## Package Managers

### Homebrew (macOS/Linux)

Goreleaser automatically updates the Homebrew tap. Users install with:
```bash
brew install writerslogic/tap/witnessd
```

### APT/DEB (Debian/Ubuntu)

.deb packages are generated automatically. To host:
1. Create a GitHub release with the .deb file
2. Or set up an APT repository

### RPM (Fedora/RHEL)

.rpm packages are generated automatically.

### Scoop (Windows)

Goreleaser updates the Scoop bucket. Users install with:
```powershell
scoop bucket add witnessd https://github.com/writerslogic/scoop-bucket
scoop install witnessd
```

### AUR (Arch Linux)

The `witnessd-bin` package is automatically updated in the AUR.

## Troubleshooting

### "Developer ID Application" not found

Make sure the certificate is installed in your Keychain and not expired:
```bash
security find-identity -v -p codesigning
```

### Notarization fails

1. Check the notarization log:
   ```bash
   xcrun notarytool log <submission-id> \
     --issuer "$APPLE_ISSUER_ID" \
     --key-id "$APPLE_KEY_ID" \
     --key "$APPLE_PRIVATE_KEY"
   ```

2. Common issues:
   - Missing `--options runtime` in codesign
   - Unsigned dependencies
   - Hardened runtime issues

### GitHub token issues

Ensure your token has the `repo` scope and hasn't expired.

## Release Checklist

- [ ] All tests pass: `make test`
- [ ] Linting passes: `make lint`
- [ ] Documentation updated
- [ ] CHANGELOG updated (if not using auto-changelog)
- [ ] Version tag created and pushed
- [ ] Environment variables set
- [ ] `make release` succeeds
- [ ] GitHub release looks correct
- [ ] Homebrew installation works
- [ ] Windows/Linux packages work
