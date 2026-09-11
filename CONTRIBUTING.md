# Contributing

Thank you for helping improve Safe Apple Sign In for PHP.

## Development

Fork the repository, create a focused branch, and install the development
dependencies:

```bash
composer install
```

Before opening a pull request, run the same checks used by CI:

```bash
composer check
composer audit --locked
```

Pull requests should explain the problem and the chosen behavior. Add or update
tests for observable changes, including failure cases. Keep commits focused and
update `CHANGELOG.md` under `Unreleased` when a change affects package users.

Security-sensitive changes require explicit tests for their failure behavior.
Avoid adding framework-specific behavior to the core package; adapters can live
in separate namespaces.

## Compatibility

The package supports the PHP and dependency versions declared in
`composer.json`. New public APIs should preserve backward compatibility within
a release line. Before 1.0, any necessary breaking change must be documented in
the changelog.

## Coverage

`composer coverage` reports line coverage of `src` and fails below the floor
committed in `composer.json`. New code should not lower it; raise the floor
when coverage improves.

## Releases

Maintainers cut releases by pushing a signed `v*` tag; see
[docs/RELEASING.md](docs/RELEASING.md). Changes to `main` must pass CI, and
release tags cannot be moved or deleted once pushed.

## Security reports

Report suspected vulnerabilities through
[GitHub private vulnerability reporting](https://github.com/binuka200/apple-sign-in-php/security/advisories/new)
instead of opening a public issue.
