# Security Policy

## Supported versions

Bitcoin Math Lab and BitClone are pre-release projects. Security fixes are applied only to the latest revision of the
`main` branch until the first versioned release.

BitClone is experimental educational software. Do not use it to secure funds, expose it directly to the public
internet, or treat it as a replacement for Bitcoin Core.

## Reporting a vulnerability

Do not open a public issue or discussion for a suspected vulnerability.

Use [GitHub private vulnerability reporting](https://github.com/BitcoinMathLab/bitclone/security/advisories/new) and
include:

- the affected component and revision;
- the expected and observed behavior;
- the smallest safe reproduction you can provide;
- the likely impact and any known mitigations; and
- whether the issue has been disclosed anywhere else.

Never include real wallet seeds, private keys, RPC cookies, access tokens, or other people's personal data. Use regtest,
signet, generated keys, and redacted logs wherever possible.

We will acknowledge a report within five business days, provide a preliminary assessment when enough information is
available, and coordinate remediation and disclosure with the reporter. Timelines will depend on severity and the
complexity of a safe fix. Please allow a reasonable remediation period before public disclosure.

## Scope

Reports are especially valuable when they involve:

- incorrect script, transaction, block, or consensus behavior;
- authentication or authorization bypasses;
- exposure of credentials, wallet material, or private data;
- unsafe network binding or cross-origin behavior;
- denial of service from untrusted network or API input; or
- dependency or build-pipeline compromise.

General bugs, feature requests, and hardening suggestions without a security impact belong in the public issue tracker.
