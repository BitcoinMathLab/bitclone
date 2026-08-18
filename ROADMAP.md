# Bitcoin Math Lab Roadmap

> **Mission**
>
> Build the world's best platform for learning, experimenting with, developing, and analyzing Bitcoin.

---

# Guiding Principles

Every feature should satisfy at least one of the following:

- Teach Bitcoin more effectively.
- Help developers understand Bitcoin.
- Save developers time.
- Produce recurring revenue.
- Build reusable technology.

If a feature satisfies none of these goals, it belongs in the backlog.

---

# 2026 MVP Launch Commitment

**Launch date:** Monday, October 12, 2026 (Canadian Thanksgiving)

**Delivery window:** August 17–October 11, 2026

The MVP is a public, mobile-friendly Bitcoin Math Lab website with one complete interactive learning experience: a
visitor can step through a curated P2PKH spend, see each opcode and stack transition, read a plain-language explanation,
and understand why the script succeeds or fails.

## Launch scope

The MVP includes:

- a clear landing page, lightweight About and Roadmap content, and working contact links;
- one signup path for launch updates and early-access interest;
- a deterministic P2PKH trace model and execution API;
- play, pause, previous, next, and reset controls;
- opcode, byte, main-stack, and alt-stack visualization;
- at least one successful and one failing curated P2PKH example;
- responsive and keyboard-accessible core flows;
- production hosting, the `bitcoinmathlab.com` domain, HTTPS, analytics, error monitoring, and basic SEO;
- public project documentation, a launch article, and a repeatable deployment and rollback check.

The MVP does **not** include accounts, payments, user-authored scripts, real-transaction lookup, P2SH, SegWit, Taproot,
multiple lesson families, a full CMS, or an independent-node runtime. These remain post-launch work unless every launch
criterion is already complete.

## Eight-week delivery plan

| Week | Dates | Outcome | Exit check |
|---|---|---|---|
| 1 | Aug 17–23 | Foundation and frozen scope | Story 1.3 complete; MVP contract, ownership, and acceptance criteria recorded |
| 2 | Aug 24–30 | Website shell and deployment path | Responsive shell and landing page run in a hosted preview environment |
| 3 | Aug 31–Sep 6 | Public-presence vertical slice | Domain, HTTPS, signup, analytics, error monitoring, and essential pages work end to end |
| 4 | Sep 7–13 | Trace data model | Immutable steps, stack snapshots, opcode metadata, JSON serialization, and tests are complete |
| 5 | Sep 14–20 | Script-tracing engine | Successful and failing P2PKH fixtures produce clear, deterministic traces |
| 6 | Sep 21–27 | API and visualizer player | The deployed frontend can execute a fixture and navigate every returned step |
| 7 | Sep 28–Oct 4 | Complete learning experience | Stack, opcode, byte, timeline, explanation, and failure states form one coherent lesson |
| 8 | Oct 5–11 | Release candidate and launch prep | Accessibility, responsive, security, analytics, SEO, rollback, and launch smoke checks pass |
| Launch | Oct 12 | Public MVP | Production is live, monitored, and linked from the public project profiles |

Each week must end with a demonstrable integrated increment. Scope is removed before quality gates are relaxed. Any
unfinished launch-critical item at the end of Week 6 triggers a feature freeze; Weeks 7 and 8 then prioritize the
complete P2PKH path, reliability, and launch readiness.

## MVP definition of done

The Thanksgiving launch is complete when:

- a first-time visitor can explain the role of the P2PKH opcodes after completing the guided trace;
- the successful and failing examples behave consistently across supported desktop and mobile browsers;
- no secrets or wallet material are required, accepted, logged, or returned by the public experience;
- automated engine, API, and critical browser-flow tests pass in CI;
- production health, error reporting, analytics, backup or rollback, and contact channels have been verified;
- the site clearly identifies the product as educational, experimental, and not financial advice; and
- the team has completed a launch-day smoke test and assigned post-launch monitoring ownership.

---

# Vision

Bitcoin Math Lab is **not** intended to compete with Bitcoin Core.

Bitcoin Core is the industry's reference implementation and remains the production blockchain backend.

Bitcoin Math Lab builds educational, analytical, and developer tools on top of Bitcoin.

BitClone exists to provide reusable Bitcoin execution and analysis libraries rather than replacing Bitcoin Core during the MVP phase.

---

# Product Architecture

Bitcoin Math Lab

├── Angular Frontend

├── FastAPI Backend

├── BitClone Engine

│ ├── Serialization

│ ├── Consensus

│ ├── Script Engine

│ ├── Trace Engine

│ ├── Analysis

│ └── Bitcoin Core Adapter

└── Bitcoin Core

    └── Blockchain Source of Truth

---

# Long-Term Product

Bitcoin Math Lab eventually becomes four integrated products.

## Learn

Interactive educational tools.

- Script Visualizer
- Transaction Explorer
- Taproot Explorer
- Interactive lessons
- Guided tutorials
- Quizzes

---

## Build

Professional developer tools.

- Script Studio
- Transaction Constructor
- PSBT Explorer
- Descriptor Explorer
- Miniscript Explorer
- API

---

## Analyze

Market intelligence.

- Historical price explorer
- Regression models
- Forecasting
- Cycle analysis
- Volatility
- CSV export

---

## Enterprise

Commercial offerings.

- Team subscriptions
- Hosted APIs
- Corporate training
- University licensing

---

# Success Milestones

## Phase 1

First website visitor.

---

## Phase 2

First registered user.

---

## Phase 3

First paying customer.

---

## Phase 4

$100 Monthly Recurring Revenue.

---

## Phase 5

$1,000 Monthly Recurring Revenue.

---

## Phase 6

$10,000 Monthly Recurring Revenue.

---

# Release 0.1 — Public Presence

**Target:** September 6, 2026 (end of Week 3)

## Objective

Establish a professional public identity.

### Deliverables

- Landing page
- About page
- Documentation
- Blog
- Logo
- Branding
- GitHub organization
- Contact page
- Newsletter signup
- Waitlist

### Definition of Done

People can discover Bitcoin Math Lab and subscribe for updates.

---

# Continuous Workstream — Build in Public

## Objective

Build an audience while building the product without creating a separate release gate.

### Deliverables

- One short weekly development update
- Regular X posts drawn from completed work
- Screenshots and short demos of integrated increments
- GitHub activity
- A launch announcement and newsletter update

### Operating constraint

Communication reuses delivery artifacts and is time-boxed. Product work is not delayed to meet an independent content
calendar.

---

# Release 0.2 — Interactive Script Visualizer

**Target:** October 12, 2026 (MVP launch)

## Goal

Launch the flagship educational tool as the October 12, 2026 MVP.

---

## Sprint 9 — Trace Engine

### Story 9.1

Execution Trace Model

- [x] Immutable execution steps
- [x] Stack snapshots
- [x] Alt-stack snapshots
- [x] Opcode metadata
- [x] JSON serialization
- [x] Tests

The versioned contract and ordering rules are documented in
[docs/execution-trace-model.md](docs/execution-trace-model.md).

---

### Story 9.2

Script Tracing

- Optional tracing mode
- Capture every opcode
- Plain-English explanations
- Failure diagnostics

---

### Story 9.3

Backend API

- Execute P2PKH
- Return structured trace
- Integration tests

---

## Sprint 10 — Visualizer

### Story 10.1

Frontend Player

- Play
- Pause
- Previous
- Next
- Reset

---

### Story 10.2

Visualization

- Animated stack
- Opcode highlighting
- Byte highlighting
- Timeline

---

### Story 10.3

Lessons

- P2PK
- P2PKH
- Valid examples
- Invalid examples

### Definition of Done

A beginner understands a P2PKH spend by stepping through it.

---

# Release 0.3 — Real Bitcoin Transactions

## Sprint 11

### Bitcoin Core Adapter

- Lookup transactions
- Retrieve previous outputs
- Build execution context

---

### Spend Classification

Support

- P2PK
- P2PKH
- P2SH
- P2WPKH
- P2WSH
- Taproot Key Path
- Taproot Script Path

---

### Educational Fixtures

- Curated successful spends
- Curated failures
- Regression tests

### Definition of Done

Users can analyze real Bitcoin transactions.

---

# Release 0.4 — Standard Script Library

## Sprint 12

### Templates

- P2SH
- P2WPKH
- P2WSH
- Taproot Key Path
- Taproot Script Path

---

### User Experience

- Better animations
- Better explanations
- Byte inspector
- Hex decoding
- Documentation

### Definition of Done

Support all standard Bitcoin output types.

---

# Release 0.5 — Script Studio Pro

## Sprint 13

### Workspace

- Arbitrary locking scripts
- Arbitrary unlocking scripts
- Witness editor
- Editable transaction context

---

### Professional Debugging

- Stack history
- Failure diagnostics
- Export traces
- Shareable links

---

### Validation

- Compare against Bitcoin Core
- Extensive regression tests

### Definition of Done

Professional developers can analyze arbitrary scripts.

---

# Release 0.6 — Commercial Launch

## Sprint 14

### Accounts

- Email login
- GitHub login
- Profiles

---

### Billing

- Stripe
- Subscription management
- Billing portal

---

### Website

- Pricing
- Documentation
- Privacy Policy
- Terms of Service

### Definition of Done

The first customer can purchase Script Studio Pro.

---

# Release 0.7 — Revenue Validation

## Sprint 15

### External Beta

Invite

- Wallet developers
- Open-source contributors
- Bitcoin educators
- Technical Bitcoin users

---

### Analytics

Track

- Visitors
- Registrations
- Lesson completion
- Trace executions
- Upgrade clicks
- Paid conversions
- Retention

---

### Goal

Acquire the first paying customer.

---

# Release 0.8 — Bitcoin Market Intelligence

## Historical Data

- Multiple exchanges
- Multiple currencies
- CSV export

---

## Analytics

- Linear regression
- Logarithmic regression
- Moving averages
- Halving overlays
- Regression channels
- Volatility

---

## Forecasting

- Confidence intervals
- Multiple models
- Monte Carlo
- Backtesting
- Residual analysis

### Definition of Done

Investors can perform meaningful Bitcoin market analysis.

---

# Release 0.9 — Developer Toolkit

Professional Bitcoin development tools.

- PSBT Explorer
- Descriptor Explorer
- Transaction Constructor
- Miniscript Explorer
- Transaction Visualizer
- Script Generator

---

# Release 1.0 — Bitcoin Platform

Bitcoin Math Lab becomes an integrated ecosystem combining

- Education
- Script Studio
- Transaction Explorer
- Developer Toolkit
- Market Analytics
- APIs

Customer feedback determines whether BitClone should continue toward becoming an independent Python Bitcoin node.

---

# BitClone Roadmap

BitClone is a reusable backend engine.

## Module A

Serialization

- Blocks
- Transactions
- Scripts
- Addresses

---

## Module B

Consensus

- Script
- Sighash
- Validation

---

## Module C

Trace Engine

- Execution tracing
- Stack history
- Diagnostics
- JSON serialization

---

## Module D

Analysis

- Spend detection
- Script classification
- Failure diagnostics

---

## Module E

Node

Deferred until product-market fit.

- Networking
- Mempool
- Wallet
- Mining
- Synchronization

---

## Module F

Research

Experimental work.

- Independent runtime
- Performance
- Alternative architectures

---

# Deferred Features

These are intentionally postponed until after revenue validation.

## Full Node

- RBF
- Package relay
- Mempool policy
- Mining
- Wallet
- Independent networking
- Independent Initial Block Download

---

## Operations

- Desktop packaging
- Fleet management
- Hosted infrastructure
- Enterprise deployment

---

# Product Philosophy

Every release should produce something visible.

Every sprint should improve the product.

Every feature should help someone learn Bitcoin or become more productive.

Revenue validation takes priority over engineering completeness.

Perfect software that nobody uses is failure.

Useful software that customers pay for is success.

---

# 2030 Vision

Bitcoin Math Lab becomes the definitive platform for Bitcoin education and experimentation.

Whether someone wants to:

- understand Script,
- inspect a transaction,
- learn Taproot,
- build a wallet,
- analyze Bitcoin's market cycles,
- or teach a university course,

Bitcoin Math Lab should be the first place they go.
