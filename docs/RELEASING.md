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
   git tag -s v0.1.4 -m "v0.1.4"
   git push origin v0.1.4
   ```

4. The workflow validates the tag name, fails unless the tag carries a verified
   signature, builds `apple-sign-in-php-<version>.tar.gz` (respecting
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
The release workflow **fails** when a tag is unsigned or its signature does not
verify, so this must be in place before cutting a release.

This repository is configured for SSH signing with a dedicated key:

```bash
git config --local gpg.format ssh
git config --local user.signingkey ~/.ssh/id_ed25519_signing.pub
git config --local tag.gpgSign true
git config --local gpg.ssh.allowedSignersFile ~/.ssh/allowed_signers
```

Setting up the key on a new machine:

```bash
ssh-keygen -t ed25519 -C "you@example.com" -f ~/.ssh/id_ed25519_signing
gh auth refresh -h github.com -s admin:ssh_signing_key
gh ssh-key add ~/.ssh/id_ed25519_signing.pub --type signing --title "release signing"
```

The key must be registered with `--type signing`. An authentication key of the
same value does not make tags verify.

Load the key once per machine so signing does not prompt for the passphrase on
every tag (on macOS this stores it in the Keychain and survives reboots):

```bash
ssh-add --apple-use-keychain ~/.ssh/id_ed25519_signing
```

`~/.ssh/allowed_signers` maps the signing key to the git identities that use it,
which is what lets `git tag -v v0.1.4` verify locally:

```
binuka200@users.noreply.github.com ssh-ed25519 AAAA...
you@example.com ssh-ed25519 AAAA...
```

To confirm GitHub accepts a signature, check the tag object after pushing:

```bash
sha="$(gh api repos/binuka200/apple-sign-in-php/git/ref/tags/v0.1.4 --jq '.object.sha')"
gh api "repos/binuka200/apple-sign-in-php/git/tags/$sha" --jq '.verification'
```

GPG signing works equally well if preferred; set `user.signingkey` to the key id,
leave `gpg.format` unset, and upload the armored public key under GPG keys.

Tags pushed before signing was configured (`v0.1.0` through `v0.1.3`) remain
unsigned. Tag protection makes them immutable, and signing them after the fact
would misrepresent when they were authorized.

## Packagist

Packagist reads tags directly from this repository, so a pushed tag publishes
the new version. Nothing in the release pipeline uploads package archives
elsewhere.
