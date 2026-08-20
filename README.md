# Bitcoin Math Lab / BitClone

**See Bitcoin execute.**

Bitcoin Math Lab makes Bitcoin's inner workings visible, interactive, and practical for learners and developers.
BitClone is the Python execution, consensus, tracing, and analysis engine that powers those experiences.

The project is working toward a public MVP on **October 12, 2026**. The launch experience will let a visitor step
through a curated P2PKH spend, inspect each opcode and stack transition, and understand why the script succeeds or
fails.

> [!WARNING]
> BitClone is experimental educational software. Do not use it to secure funds or as a replacement for Bitcoin Core.

## Why this project exists

Bitcoin implementations are precise, but their behavior can be difficult to see. Bitcoin Math Lab turns execution
into an explorable sequence: opcodes, bytes, stack values, validation decisions, and plain-language explanations.

The product is organized around four long-term areas:

- **Learn:** interactive visualizers, lessons, and transaction exploration.
- **Build:** script, transaction, PSBT, descriptor, and Miniscript tools.
- **Analyze:** historical and protocol analysis with exportable results.
- **Enterprise:** hosted APIs, team learning, and institutional training.

The MVP intentionally focuses on the first of these: learning one important Bitcoin spend type exceptionally well.

## Project links

- [Bitcoin Math Lab organization](https://github.com/BitcoinMathLab)
- [Frontend application](https://github.com/BitcoinMathLab/frontend)
- [Product backend](https://github.com/BitcoinMathLab/backend)
- [Public project board](https://github.com/orgs/BitcoinMathLab/projects/1)
- `bitcoinmathlab.com` — public website planned for the MVP window

## Planned MVP architecture

```text
Bitcoin Math Lab web app
        |
        v
FastAPI application
        |
        v
BitClone engine ----> Bitcoin Core
  serialization        blockchain source of truth
  script execution
  tracing and analysis
```

BitClone does not aim to replace Bitcoin Core in the MVP. It supplies reusable execution and analysis capabilities;
Bitcoin Core remains the production blockchain backend.

## Repository status

This repository contains the BitClone engine and its existing local operator API. It includes Bitcoin data types,
script and cryptographic primitives, block and transaction validation, peer-to-peer networking, chain storage,
mempool policy, a read-only API, and browser-based operator tooling. The public Bitcoin Math Lab experience is being
developed separately on top of this foundation.

See the [roadmap](ROADMAP.md) for current scope and dates, and [active tickets](tickets.md) for the work in progress.
Deferred independent-node work is retained in the [backlog](backlog.md).

## Local development

BitClone currently targets Python 3.12.

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pytest
```

Browser test dependencies are optional unless you are changing the existing operator console:

```bash
npm ci
npx playwright install chromium
npm run test:browser
```

The previous detailed notes for remote Bitcoin Core access, the API, and the operator console are preserved in the
[development reference](docs/bitclone-development.md).

The MVP script visualizer foundation is documented in the immutable
[execution trace model](docs/execution-trace-model.md) and the opt-in
[script tracing guide](docs/script-tracing.md).

The transport-neutral Story 9.3 boundary for validating and tracing a complete legacy P2PKH spend is documented in
the [P2PKH spend tracing guide](docs/p2pkh-spend-tracing.md). HTTP validation and response models remain in the
separate Bitcoin Math Lab backend.

## Contributing and security

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md) before opening a pull request.

Please report vulnerabilities privately according to [SECURITY.md](SECURITY.md). Never include credentials, API
tokens, wallet seeds, private keys, or personal data in a public issue.

## License

BitClone is available under the [MIT License](LICENSE).
