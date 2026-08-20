# Contributing

Security-sensitive changes need tests for their failure behavior. Please run
`composer test` and `composer lint` before opening a pull request. Avoid adding
framework-specific behavior to the core package; adapters can live in separate
namespaces.

Report suspected vulnerabilities through
[GitHub private vulnerability reporting](https://github.com/binuka200/apple-sign-in-php/security/advisories/new)
instead of opening a public issue.
