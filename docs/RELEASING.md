# Releasing witnessd

This document describes how to create and publish releases of witnessd.

## Prerequisites

1. **Rust Toolchain** - Stable release.

2. **cargo-dist** - For building distributable artifacts (optional, handled by CI).

3. **Apple Developer Account** - For macOS code signing and notarization.

4. **GitHub Token** - With `repo` scope for publishing releases.

## Environment Variables

Set these environment variables in your CI/CD (GitHub Secrets) or locally:

```bash
# GitHub
export GITHUB_TOKEN="ghp_..."           # GitHub personal access token

# Apple Developer (for macOS notarization)
export APPLE_DEVELOPER_ID="Developer ID Application: Your Name (TEAMID)"
export APPLE_ISSUER_ID="..."            # App Store Connect API Issuer ID
export APPLE_KEY_ID="..."               # App Store Connect API Key ID
# The private key content or path
export APPLE_API_KEY="..."
```

## Creating a Release

### 1. Update Version

Update the version in `rust/witnessd-cli/Cargo.toml` and `rust/witnessd-core/Cargo.toml`.

```bash
# Example: bump version to 0.1.0
# Commit changes
git commit -am "chore: bump version to 0.1.0"
```

### 2. Create Tag

Witnessd uses git tags for versioning. Create a new tag:

```bash
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0
```

### 3. CI/CD Release

The GitHub Actions workflow (`.github/workflows/release.yml`) will automatically:
1. Build binaries for macOS, Linux, and Windows.
2. Sign and notarize macOS binaries.
3. Create a GitHub Release with artifacts.
4. Generate SLSA provenance.

### 4. Verify Release

1. Check [GitHub Releases](https://github.com/writerslogic/witnessd/releases)
2. Verify checksums and signatures.

## Manual Signing (macOS)

If you need to sign binaries manually:

```bash
# Build release binary
cd rust/witnessd-cli
cargo build --release

# Sign
codesign --force --options runtime --sign "$APPLE_DEVELOPER_ID" target/release/witnessd

# Verify signature
codesign -dv --verbose=4 target/release/witnessd
```

## Package Managers

### Homebrew (macOS/Linux)

The release workflow can configured to update a Homebrew tap.

### Linux Packages

CI generates `.tar.gz` archives. Users can install by extracting to `$PATH`.

### Windows

CI generates `.zip` archives.

## Release Checklist

- [ ] All tests pass: `cargo test --all-features`
- [ ] Linting passes: `cargo clippy`
- [ ] Documentation updated
- [ ] Version bumped in Cargo.toml files
- [ ] Version tag created and pushed
- [ ] GitHub release looks correct
