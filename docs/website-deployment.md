# Bitcoin Math Lab Website Deployment

This runbook defines the Story 2.3 deployment path for the public Angular website. It deliberately excludes the
FastAPI backend: the backend receives its own hosting decision when the execution API is ready in Week 6.

## Decision

Use the following MVP stack:

| Concern | Service | MVP cost | Reason |
|---|---|---:|---|
| Static Angular hosting and previews | Cloudflare Pages | $0 | The domain and DNS are already in Cloudflare; Pages supports GitHub builds, preview deployments, custom domains, and rollbacks. |
| DNS and HTTPS | Cloudflare | $0 | Keep registration, DNS, certificates, and redirects under the existing account. |
| Traffic and performance analytics | Cloudflare Web Analytics | $0 | Provides privacy-first page and performance analytics without collecting visitor personal data. |
| Frontend error monitoring | Sentry Developer | $0 | Provides one-user error monitoring, tracing, email alerts, and up to 5,000 errors per month. |

Costs and plan limits were checked on 2026-08-15. Reconfirm them before accepting a paid upgrade.

Primary references:

- [Deploy an Angular site to Cloudflare Pages](https://developers.cloudflare.com/pages/framework-guides/deploy-an-angular-site/)
- [Cloudflare Pages limits](https://developers.cloudflare.com/pages/platform/limits/)
- [Cloudflare preview deployments](https://developers.cloudflare.com/pages/configuration/preview-deployments/)
- [Cloudflare custom domains](https://developers.cloudflare.com/pages/configuration/custom-domains/)
- [Cloudflare Pages rollbacks](https://developers.cloudflare.com/pages/configuration/rollbacks/)
- [Cloudflare Web Analytics](https://developers.cloudflare.com/web-analytics/about/)
- [Sentry pricing](https://sentry.io/pricing/)

## Ownership and access

The Cloudflare and Sentry accounts must use `bitcoinmathlab@gmail.com` for bootstrap or recovery and must be recorded
in the private credential manager. Give integrations only the permissions they need:

- scope the Cloudflare GitHub application to `BitcoinMathLab/frontend`;
- never commit Cloudflare API tokens, the Sentry auth token, or account recovery material;
- treat a Sentry browser DSN as configuration rather than a secret, but keep source-map upload tokens in the hosting
  provider's encrypted environment settings; and
- record who can deploy, change DNS, view errors, and perform a rollback.

## Phase 1 — Repository readiness

Complete these changes in `BitcoinMathLab/frontend` before connecting production:

1. Pin a supported Node version for local, CI, and Cloudflare builds.
2. Add production security headers without breaking Angular assets or Sentry ingestion.
3. Add canonical, Open Graph, and social-card metadata.
4. Add `robots.txt` and `sitemap.xml` for `https://bitcoinmathlab.com`.
5. Install and configure Sentry for uncaught Angular errors. Do not enable session replay for the MVP, do not send
   default personally identifiable information, and start with conservative tracing or no performance sampling.
6. Preserve the existing formatting, unit-test, production-build, and bundle-budget gates.

## Phase 2 — Hosted preview

Create the Pages project by importing `BitcoinMathLab/frontend` through Cloudflare's Git integration. Do not create a
Direct Upload project first because Pages cannot later add Git integration to an existing Direct Upload project.

Use this initial configuration:

| Setting | Value |
|---|---|
| Production branch | `main` |
| Build command | `npm run build` |
| Build output directory | `dist/bitcoin-math-lab/browser` |
| Preview branches | All non-production branches |
| GitHub application scope | `BitcoinMathLab/frontend` only |

Cloudflare Pages recognizes an Angular build without a top-level `404.html` as a single-page application and routes
deep links to the root application. Verify this behavior rather than adding a rewrite pre-emptively.

Before connecting the domain, the `pages.dev` preview must pass:

- Home, About, Roadmap, Blog, Contact, and an unknown route load directly and after refresh;
- desktop and mobile navigation work without horizontal page overflow;
- the GitHub, X, contact, and early-access email links have the intended destinations;
- the browser console has no unexpected errors;
- Cloudflare marks branch previews `noindex`;
- a controlled frontend error appears in Sentry with the environment and release identifier; and
- a previous successful production deployment can be selected as a rollback target.

## Phase 3 — Production domain and HTTPS

1. Add `bitcoinmathlab.com` as the Pages custom apex domain from the Pages dashboard so Cloudflare creates the correct
   DNS association.
2. Add `www.bitcoinmathlab.com` and redirect it permanently to `https://bitcoinmathlab.com`.
3. Keep `https://bitcoinmathlab.com` as the single canonical origin.
4. Confirm the Cloudflare Universal certificate is active, force HTTP to HTTPS, and test certificate renewal status.
5. Recheck DNSSEC after the pending DS record has propagated.
6. Redirect the production `pages.dev` hostname to the canonical domain while leaving preview hostnames available.

Do not manually point a CNAME at Pages without first associating the custom domain in the Pages dashboard; Cloudflare
documents that this can produce a `522` response.

## Phase 4 — Analytics, monitoring, and SEO

Enable Cloudflare Web Analytics for the proxied production zone and verify that a real visit appears. Keep the MVP
measurement plan intentionally small:

- visits and page views by route;
- aggregate referrer, country, device, and browser dimensions; and
- Core Web Vitals or equivalent real-user performance signals.

Cloudflare Web Analytics does not currently support custom events, so early-access and outbound-link activation
tracking are explicitly deferred rather than introducing another analytics service for the MVP.

Verify Sentry receives a controlled error, sends an email notification, identifies the production environment and
release, and does not include submitted email content or default PII. Remove the controlled error immediately after
verification.

For SEO, verify the canonical URL, description, social preview metadata, `robots.txt`, and `sitemap.xml` from the
deployed origin. Preview deployments must remain non-indexable. Submit the production sitemap only after the domain is
stable.

## Rollback and smoke procedure

For every production release:

1. Record the frontend commit SHA and Cloudflare deployment identifier.
2. Run the critical production smoke checks below.
3. If a launch-critical check fails, use Pages **Deployments → Rollback to this deployment** to select the last known
   good production build.
4. Repeat the smoke checks against the restored deployment and record the incident.

Critical smoke checks:

- `https://bitcoinmathlab.com` returns HTTPS without a certificate warning;
- all public routes load directly and after refresh;
- primary navigation and the early-access email action work on desktop and mobile;
- no unexpected browser-console or Sentry errors appear;
- analytics receives a production visit; and
- the canonical URL and educational/not-financial-advice language are present.

## Story 2.3 acceptance criteria

Story 2.3 is complete when:

- a merge to `frontend/main` automatically produces a traceable production deployment;
- pull requests receive non-indexable preview deployments;
- `bitcoinmathlab.com` is canonical, HTTPS-only, and globally reachable, with `www` redirected;
- all public Angular routes survive direct navigation and refresh;
- Cloudflare Web Analytics records production traffic without collecting visitor personal data;
- Sentry records a controlled Angular error and sends an alert without default PII or session replay;
- essential SEO files and metadata are available from the production origin;
- the production smoke checklist passes on desktop and mobile; and
- an operator has successfully rehearsed and documented a rollback to a known-good deployment.
