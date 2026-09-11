# Releasing

Releases are cut from `main` by pushing a `vMAJOR.MINOR.PATCH` tag. The
[`Release` workflow](../.github/workflows/release.yml) then builds the
distribution archive, signs it with Sigstore build provenance, and publishes the
GitHub release.

## Repository rules

Two rulesets guard release integrity:

- **`main-protection`** — CI (`test` on PHP 8.1–8.5 and `lowest-dependencies`)
  must pass before `main` moves, history stays linear, and the branch cannot be
  force-pushed or deleted. Repository admins may bypass, so the maintainer can
  still push directly; everyone else goes through a pull request.
- **`release-tag-protection`** — `v*` tags cannot be deleted, moved, or
  overwritten by anyone, including admins. A published version number therefore
  always points at the same commit.

Because tags are immutable, a bad release is corrected with a new patch version
rather than by retagging.

## Cutting a release

1. Move the `Unreleased` entries in `CHANGELOG.md` under a new
   `## MAJOR.MINOR.PATCH - YYYY-MM-DD` heading and push that to `main`.
2. Wait for CI to pass on `main`.
3. Create a signed, annotated tag and push it:

   ```bash
   git tag -s v0.1.2 -m "v0.1.2"
   git push origin v0.1.2
   ```

4. The workflow validates the tag name, reports whether the tag signature
   verifies, builds `apple-sign-in-php-<version>.tar.gz` (respecting
   `.gitattributes` export rules), attaches its SHA-256 checksum, attests build
   provenance, and creates the release with the matching changelog section as
   release notes.

Pre-release tags (`v0.2.0-rc.1`) are published as GitHub pre-releases
automatically.

## Signing

Two independent signatures cover a release.

### Build provenance (automatic)

`actions/attest-build-provenance` signs the release archive through Sigstore
using a short-lived, workflow-bound identity — there is no key to manage or
leak. Consumers verify that the archive really came from this repository's
release workflow:

```bash
gh attestation verify apple-sign-in-php-0.1.2.tar.gz --repo binuka200/apple-sign-in-php
```

Checksums are published alongside the archive:

```bash
sha256sum -c apple-sign-in-php-0.1.2.tar.gz.sha256
```

### Tag signatures (maintainer key)

Signed tags prove the maintainer, not just the runner, authorized the version.
Set this up once with either an SSH or a GPG key.

SSH signing (simplest if a GitHub SSH key already exists):

```bash
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global tag.gpgSign true
```

GPG signing:

```bash
gpg --full-generate-key            # Ed25519 or RSA 4096, with a passphrase
gpg --list-secret-keys --keyid-format=long
git config --global user.signingkey <KEY_ID>
git config --global tag.gpgSign true
gpg --armor --export <KEY_ID>      # add this at github.com/settings/keys
```

The public key must be registered on GitHub (SSH keys as a *signing* key, GPG
keys under GPG keys) for the tag to show as **Verified** and for the workflow's
signature check to pass.

Until a signing key is registered, the `Check tag signature` step only emits a
warning so releases are not blocked. Once signing is in place, make it binding
by replacing the `::warning::` line in that step with:

```bash
echo "::error::Tag $TAG has no verified signature (reason: $reason)."
exit 1
```

## Packagist

Packagist reads tags directly from this repository, so a pushed tag publishes
the new version. Nothing in the release pipeline uploads package archives
elsewhere.
