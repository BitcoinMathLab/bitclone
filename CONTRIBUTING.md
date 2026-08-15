# Contributing to Bitcoin Math Lab

Thank you for helping make Bitcoin easier to inspect and understand. Contributions to this repository should advance
the BitClone engine or the Bitcoin Math Lab experiences built on it.

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Before starting

1. Check the [roadmap](ROADMAP.md), [active tickets](tickets.md), and existing GitHub issues.
2. Open an issue before beginning a large feature, architectural change, or new dependency.
3. Keep pull requests focused on one outcome. Avoid mixing unrelated cleanup with functional changes.
4. For security vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of opening an issue.

## Development setup

BitClone targets Python 3.12.

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pytest
```

For changes to the browser operator console:

```bash
npm ci
npx playwright install chromium
npm run test:browser
```

Some integration workflows use a separately operated Bitcoin Core node. They are not required for mocked unit tests.
See the [development reference](docs/bitclone-development.md) for that optional setup.

## Making a change

- Branch from `main` and use a descriptive branch name.
- Match the style and boundaries of the surrounding code.
- Add or update tests for observable behavior and regressions.
- Prefer focused commits with messages that explain the outcome.
- Update documentation and tickets when behavior or planned scope changes.
- Never commit credentials, RPC cookies, API tokens, wallet material, runtime databases, or generated test artifacts.

Run the relevant checks before submitting:

```bash
.venv/bin/python -m pytest
git diff --check
```

Run `npm run test:browser` as well when browser behavior changes.

## Pull requests

Explain what changed, why it matters, and how it was verified. Link the issue with `Closes #...` when applicable.
Keep the pull request in draft while required checks or known work remain. Review feedback should be resolved with new
commits rather than hidden by unrelated rewrites.

All contributions must be your own work or material you are legally permitted to submit. Note the origin and license
of any adapted test vector, fixture, or source material in the pull request and alongside the material where practical.
