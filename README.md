# Aegis Agent Gateway

Aegis is an agent governance gateway: a policy-enforcing proxy that sits in front of
AI agent tool calls, evaluates them against OPA/Rego policy, and produces a tamper-evident
audit trail.

## Status

v0.1 foundation — under active development. Not yet production-ready.

## Requirements

- Node.js `>=22.0.0`
- npm `>=10.0.0`

## Getting started

```bash
npm install
cp .env.example .env   # then fill in real values — never commit .env
npm run dev
```

## Scripts

| Script | Purpose |
| --- | --- |
| `npm run dev` | Run the server locally with hot reload |
| `npm run build` | Type-check and compile to `dist/` |
| `npm run typecheck` | Type-check without emitting |
| `npm test` | Run the unit test suite (vitest) |

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributions require signing the
Contributor License Agreement (CLA), enforced automatically on pull requests.
