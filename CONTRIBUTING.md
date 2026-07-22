# Contributing to Aegis

Thank you for your interest in contributing to Aegis.

## Contributor License Agreement (CLA)

All contributions require signing the [Contributor License Agreement](CLA.md) (CLA)
before a pull request can be merged. This is enforced automatically by the
`cla-assistant` bot, which will comment on your pull request with a link to sign
if you haven't already. Signing is a one-time action per contributor (or per
organization, for corporate contributions).

Pull requests that have not signed the CLA will be blocked from merging until the
CLA check passes.

## Development workflow

1. Fork the repository and create a feature branch.
2. Make your changes, following the existing code style.
3. Add or update tests for any behavior change (this project follows a test-first
   workflow: write a failing test, then implement).
4. Run `npm run typecheck` and `npm test` locally before opening a pull request.
5. Open a pull request against `main` and sign the CLA when prompted.

## Reporting issues

Please open a GitHub issue with a clear description, reproduction steps, and
expected vs. actual behavior.
