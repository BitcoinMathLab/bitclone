# Bitcoin Math Lab Project Organization

This runbook defines the initial public GitHub structure for Bitcoin Math Lab. It intentionally keeps account creation,
repository transfers, and access-control changes as operator actions because they require the project owner's authenticated
accounts.

## GitHub organization

- **Organization:** [`BitcoinMathLab`](https://github.com/BitcoinMathLab)
- **Display name:** Bitcoin Math Lab
- **Website:** `https://bitcoinmathlab.com`
- **Contact:** `bitcoinmathlab@gmail.com`
- **Description:** Interactive tools for learning, building, and experimenting with Bitcoin.

Enable two-factor authentication for every owner and keep at least two recovery methods in the private credential manager.
Use owner access only for organization administration; use repository roles for routine work.

## Repository map

| Repository | Purpose | Initial state |
|---|---|---|
| `bitclone` | Reusable Bitcoin execution, consensus, tracing, networking, and analysis engine | Transferred from `DrGregDoyle/BitClone` with history and collaboration metadata preserved |
| `frontend` | Bitcoin Math Lab browser application | Created empty; do not copy the current dependency-free BitClone operator console into it |
| `backend` | Product-specific API, accounts, labs, and orchestration around BitClone and Bitcoin Core | Created empty; keep the reusable engine in `bitclone` |
| `.github` | Organization profile and organization-wide community defaults | Create with a public `profile/README.md` during the documentation work |

Use lowercase repository names in URLs and package references. Set each repository's homepage, description, topics, and
social preview before announcing it. Recommended topics for `bitclone` are `bitcoin`, `education`, `python`, `consensus`,
and `developer-tools`.

## GitHub Project

The public [Bitcoin Math Lab Roadmap](https://github.com/orgs/BitcoinMathLab/projects/1) uses these fields:

- Status: Backlog, Ready, In progress, In review, Done
- Release: the release number from `tickets.md`
- Sprint: the sprint number from `tickets.md`
- Story: the story identifier, such as `1.2`
- Area: Frontend, Backend, BitClone, Documentation, Infrastructure
- Priority: P0, P1, P2, P3

Use a board view grouped by Status and a roadmap view grouped by Release. Add new issues to Backlog automatically, move
pull requests to In review when opened, and mark linked items Done when their pull request merges.

## Repository settings

The transferred repository uses `main` as its default branch. Protect `main` with a ruleset that:

- requires a pull request before merging;
- requires pull requests but no approval while the organization has only one member; require one approval and dismiss
  stale approvals after a second maintainer joins;
- requires conversation resolution;
- requires the `Python 3.12 tests` and `Chromium browser tests` status checks;
- requires branches to be up to date before merging;
- blocks force pushes and deletion;
- applies to administrators, with emergency bypass limited to organization owners.

Enable vulnerability reporting, secret scanning, push protection, and Dependabot security updates wherever the selected
GitHub plan makes them available. Disable wiki and discussions until there is an explicit plan to maintain them.

## Migration order

1. [x] Reserve the GitHub organization.
2. [x] Create the `frontend` and `backend` repositories.
3. [x] Transfer `DrGregDoyle/BitClone` to `BitcoinMathLab/bitclone` with its history and collaboration metadata.
4. [x] Rename `master` to `main`, select it as the default branch, and update the local `origin` URL.
5. [x] Confirm issues, pull requests, releases, stars, and redirects survived the transfer.
6. [x] Create the organization project and its fields.
7. [ ] Apply the `main` branch ruleset after the first CI run exposes both required status checks.
8. [ ] Add the organization profile and repository metadata, then verify the public view while signed out.

## Social accounts

The `@bitcoinmathlab` X handle and the [Bitcoin Math Lab YouTube
channel](https://www.youtube.com/channel/UCrudVt9ijO9K1gmjqmg8LcQ) have been reserved. Associate both with
`bitcoinmathlab@gmail.com`, enable two-factor authentication, save recovery codes in the private credential manager, use
the brand mark as the avatar, and link `https://bitcoinmathlab.com`. Do not publish introductory posts or videos until the
website and organization profile provide a useful destination.
