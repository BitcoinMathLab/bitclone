# Bitcoin Math Lab Brand Foundation

## Brand decision

**Customer-facing name:** Bitcoin Math Lab  
**Engine name:** BitClone  
**Tagline:** See Bitcoin execute.

Bitcoin Math Lab is the product and public identity. BitClone is the reusable execution, consensus, tracing, and
analysis engine inside the product. Public copy should lead with Bitcoin Math Lab; use BitClone when discussing the
technical engine, source package, or implementation architecture.

This confirms Bitcoin Math Lab as the project name. It is a product decision, not formal legal or trademark clearance.
Complete an appropriate Canadian and international trademark review before commercial launch.

## Core message

### One-sentence mission

Bitcoin Math Lab makes Bitcoin's inner workings visible, interactive, and practical for learners and developers.

### One-paragraph description

Bitcoin Math Lab is an interactive education and developer platform for exploring how Bitcoin actually works. It lets
people trace scripts step by step, inspect real transactions, experiment with Bitcoin primitives, and understand
consensus behavior through clear visual tools. The platform combines a modern browser experience with the reusable
BitClone execution engine and Bitcoin Core as its production blockchain source of truth.

### Short description

Interactive tools for learning, building, and experimenting with Bitcoin.

### Voice

- Precise without sounding academic.
- Curious, calm, and technically credible.
- Explain the mechanism before introducing jargon.
- Treat Bitcoin as inspectable engineering, not as hype or financial advice.
- Prefer concrete verbs: trace, inspect, execute, build, compare, and understand.

## Logo

The mark is a traced **M** drawn as a connected execution path. Its nodes evoke a stack trace, a coordinate plot, and
the stepwise evaluation used throughout Bitcoin Math Lab. It deliberately avoids using the Bitcoin currency symbol as
the entire identity, allowing the brand to remain distinctive while the amber color retains an immediate Bitcoin cue.

Assets:

- [Mark](../assets/brand/bitcoin-math-lab-mark.svg)
- [Horizontal logo for light backgrounds](../assets/brand/bitcoin-math-lab-horizontal.svg)
- [Horizontal logo for dark backgrounds](../assets/brand/bitcoin-math-lab-horizontal-dark.svg)

Keep clear space around the mark equal to one node diameter. Do not rotate it, recolor individual path segments, add
effects, or place it on a visually noisy background. At sizes below 24 pixels, use the mark without the wordmark.

## Color

| Token | Hex | Purpose |
|---|---:|---|
| Canvas | `#080B12` | Primary dark background |
| Surface | `#10151F` | Cards and elevated dark surfaces |
| Graphite | `#273142` | Borders and structural lines |
| Paper | `#F6F3EA` | Warm light background and dark-mode text |
| Signal Amber | `#F5A524` | Primary action, trace position, and brand mark |
| Trace Blue | `#65A7FF` | Links, byte selection, and informational state |
| Valid Green | `#43D18B` | Successful execution and valid state |
| Error Coral | `#FF6B6B` | Failed execution and destructive state |

Signal Amber and state colors should carry meaning, not decorate every surface. Use Paper on Canvas for primary
dark-mode text and Canvas on Signal Amber for text placed on the primary color. Paper, Amber, Blue, Green, and Coral
all exceed a 7:1 contrast ratio on Canvas; Canvas on Amber has a 9.64:1 ratio.

## Typography

**Interface and editorial:** Inter  
**Code, hashes, bytes, and stack values:** IBM Plex Mono

Use Inter's variable font where practical, with system sans-serif fallbacks. Use a restrained weight range:
400 for prose, 600 for interface labels, and 700 for headings. Technical values should use IBM Plex Mono at 400 or
500. The existing BitClone console already uses Inter-compatible system fallbacks, making this direction evolutionary
rather than a visual reset.

## Domain and account plan

Availability checks were performed on 2026-07-30. Registration status was updated on 2026-08-10:

| Target | Result | Recommendation |
|---|---|---|
| `bitcoinmathlab.com` | Registered through Cloudflare; expires 2027-08-11 with auto-renewal enabled | Use as the canonical domain |
| `bitcoinmathlab.org` | No registration record returned by PIR RDAP | Defensive purchase and redirect |
| `bitcoinmathlab.net` | No registration record returned by Verisign RDAP | Optional defensive purchase |
| `bitcoinmathlab.ca` | No registration record returned through RDAP | Purchase if Canadian identity will be emphasized |
| `bitcoinmathlab.dev` | No registration record returned by Google Registry RDAP | Optional developer-documentation redirect |
| `github.com/bitcoinmathlab` | GitHub API returned not found | Reserve as the organization name |

An absent RDAP or API record is not a guarantee of checkout availability and does not reserve a name. The `.com` is
the canonical domain. A sensible defensive bundle is `.org` and `.ca`; add `.net` or `.dev` only if their renewal
cost is justified.

Target the consistent handle `@bitcoinmathlab` on GitHub, X, YouTube, and any newsletter provider. Bitcoin Math Lab
will not maintain a LinkedIn presence. Platform availability still requires a manual, logged-in check immediately
before reservation.

## Operator checklist

- [x] Reserve `bitcoinmathlab@gmail.com` as the bootstrap and recovery account.
- [x] Purchase `bitcoinmathlab.com` through Cloudflare.
- [x] Confirm auto-renewal and WHOIS privacy for `bitcoinmathlab.com`.
- [x] Confirm domain registration; no separate registrant-verification request was received.
- [ ] Confirm DNSSEC is active for `bitcoinmathlab.com` (enabled 2026-08-10; DS record pending).
- [ ] Purchase selected defensive domains before public launch (deferred until launch readiness).
- [ ] Reserve the GitHub organization `bitcoinmathlab`.
- [ ] Reserve `@bitcoinmathlab` on X.
- [ ] Reserve the Bitcoin Math Lab YouTube handle.
- [ ] Record registrar, renewal, recovery, and account ownership in a private credential manager.
- [ ] Complete a trademark review before taking paid subscriptions.
