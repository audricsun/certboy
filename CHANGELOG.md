## [2026.4.3] - 2026-04-20

### ⚙️ Miscellaneous Tasks

- Improve ci workflow
## [2026.4.2-dev0] - 2026-04-20

### 💼 Other

- Bump version to 2026.4.2-dev0
## [2026.4.1-dev0] - 2026-04-20

### 💼 Other

- Merge pull request #33 from audricsun/chore/use-dev-tag-for-release-flow

Chore/use dev tag for release flow

### 📚 Documentation

- Update tools with which this project build

### ⚙️ Miscellaneous Tasks

- Update release tag flow with bumpver
## [2026.16.49] - 2026-04-19

### 🐛 Bug Fixes

- *(ci)* Checkout triggering workflow sha and allow dirty for cargo publish
- *(ci)* Restore cargo check to sync Cargo.lock after bumpver

### 💼 Other

- Merge pull request #32 from audricsun/fix-ci-publish-workflow

Fix ci publish workflow
- Bump version to 2026.16.49
## [2026.16.48] - 2026-04-19

### 💼 Other

- Merge branch 'main' into fix-ci-publish-tag-trigger
- Merge pull request #31 from audricsun/fix-ci-publish-tag-trigger

fix(ci): trigger CI Publish on tag push instead of workflow_run
- Bump version to 2026.16.48
## [2026.16.47] - 2026-04-19

### 🐛 Bug Fixes

- *(ci)* Trigger CI Publish when CI Build completes (not just on main)
- *(ci)* Remove branches filter from workflow_run trigger so CI Publish runs after CI Build on tags

### 💼 Other

- Merge pull request #30 from audricsun/ci-bumpversion-skip-cargo-check

perf(ci): skip cargo check in bumpversion workflow to reduce runtime …
- Bump version to 2026.16.47

### ⚡ Performance

- *(ci)* Skip cargo check in bumpversion workflow to reduce runtime by ~2min
## [2026.16.46] - 2026-04-19

### 🐛 Bug Fixes

- *(ci)* Also ignore Cargo.toml/lock and bumpver.toml in bumpversion workflow

### 💼 Other

- Bump version to 2026.16.46
## [2026.16.45] - 2026-04-19

### 💼 Other

- Bump version to 2026.16.45
## [2026.16.44] - 2026-04-19

### 💼 Other

- Bump version to 2026.16.44
## [2026.16.43] - 2026-04-19

### 🐛 Bug Fixes

- *(ci)* Correct paths-ignore syntax in bumpversion workflow

### 💼 Other

- Merge pull request #28 from audricsun/ci/fix-bump-version-trigger-conditions

ci: reorg pipelines
- Bump version to 2026.16.43

### ⚙️ Miscellaneous Tasks

- Reorg pipelines
## [2026.16.42] - 2026-04-17

### 💼 Other

- Merge pull request #27 from audricsun/ci/reorg-ci-pipelines

ci: reorg pipelines
- Bump version to 2026.16.42

### ⚙️ Miscellaneous Tasks

- Reorg pipelines
## [2026.16.41] - 2026-04-17

### 🐛 Bug Fixes

- Version check failed

### 💼 Other

- Bump version to 2026.16.18
- Merge pull request #22 from audricsun/fix/ci-failure-update

Fix/ci failure update
- Bump version to 2026.16.19
- Bump version to 2026.16.20
- Bump version to 2026.16.21
- Bump version to 2026.16.22
- Bump version to 2026.16.23
- Bump version to 2026.16.24
- Bump version to 2026.16.25
- Bump version to 2026.16.26
- Bump version to 2026.16.27
- Bump version to 2026.16.28
- Bump version to 2026.16.29
- Bump version to 2026.16.30
- Bump version to 2026.16.31
- Bump version to 2026.16.32
- Bump version to 2026.16.33
- Bump version to 2026.16.34
- Bump version to 2026.16.35
- Bump version to 2026.16.36
- Bump version to 2026.16.37
- Bump version to 2026.16.38
- Bump version to 2026.16.39
- Merge pull request #23 from audricsun/refact/reorder-modules

Refact/reorder modules
- Merge pull request #24 from audricsun/ci/fix-bumpversion

ci: fix bump version logic check
- Merge pull request #25 from audricsun/ci/fix-bumpversion-v2

ci: fix bump version logic check
- Bump version to 2026.16.40
- Merge pull request #26 from audricsun/docs/update-favicon-url

docs: update zensical favicon settings to use custom favicon
- Bump version to 2026.16.41

### 🚜 Refactor

- Improve code structure based on agent revbiew

### 📚 Documentation

- Update installation guide part
- Update installation guide part
- Add repo url to the doc site page
- Update zensical favicon settings to use custom favicon

### ⚙️ Miscellaneous Tasks

- Ignore STABLE.txt from repo
- Add multi arch release
- Run build jobs on PR
- Run build jobs on PR
- Fix github page favicon missing
- Fix github page favicon missing
- Fix ci loop
- Fix bump version logic check
- Fix bump version logic check
## [2026.16.17] - 2026-04-17

### 💼 Other

- Merge pull request #21 from audricsun/docs/add-github-page

chore: fix github pages
- Bump version to 2026.16.17

### ⚙️ Miscellaneous Tasks

- Fix github pages
- Fix github pages
## [2026.16.16] - 2026-04-16

### 💼 Other

- Merge pull request #20 from audricsun/docs/add-github-page

docs: add doc site
- Bump version to 2026.16.16

### 📚 Documentation

- Add doc site
## [2026.16.15] - 2026-04-16

### 🐛 Bug Fixes

- *(ci)* Use --current flag for git-cliff changelog generation

### 💼 Other

- Merge pull request #19 from audricsun/fix/git-cliff-release-note

fix(ci): use --current flag for git-cliff changelog generation
- Bump version to 2026.16.15
## [2026.16.14] - 2026-04-16

### 💼 Other

- Rename --check-remote to --remote|-R and restructure output into three stages

- Renamed CLI flag from --check-remote to --remote (short: -R)
- Renamed CheckOptions.check_remote to remote

Remote check output now shows three dependent stages:
1. DNS: DNS resolution status and resolved IPs
2. Connectivity: TCP connect to port 443 (only if DNS succeeded)
3. CertSignature: SSL handshake + cert fetch + serial comparison (only if connectivity succeeded)

Each stage shows:
- Success: ✓ with green checkmark and details
- Failure: ✗ with red X and error message

The stages are cascading - if DNS fails, Connectivity and CertSignature are skipped.
If Connectivity fails, CertSignature is skipped.
- Reduce connectivity check timeout to 500ms

Use tokio::time::timeout for fast failure on unreachable hosts.
Previously used 10 second timeouts which caused slow checks.
- Merge pull request #18 from audricsun/remote-check-stages

Remote check stages
- Bump version to 2026.16.14
## [2026.16.13] - 2026-04-16

### 🐛 Bug Fixes

- Remove unnecessary mut in fetch_remote_cert

### 💼 Other

- Add --check-remote flag to certboy check subcommand

Implements DNS resolution check, shows resolved IPs, and compares
remote TLS certificate fingerprint with local certificate.

Features:
- DNS resolution check with resolved IP addresses display
- Connect to domain:443 to fetch remote TLS certificate
- Compare remote cert serial with local cert serial
- Only applies to TLS certificates (not CA/ICA)

The check_remote logic:
1. Filters to only TLS/Server certificates in the context
2. For each TLS cert, performs DNS resolution on domain:443
3. Connects to remote and fetches peer certificate
4. Compares certificate serials to determine if local and remote
   use the same certificate
- Fix lint/clippy issue
- Merge pull request #17 from audricsun/feature/check-remote

Feature/check remote
- Bump version to 2026.16.13
## [2026.16.12] - 2026-04-14

### 💼 Other

- Merge pull request #15 from audricsun/patch/repo-update

ci: add coverage report action
- Bump version to 2026.16.12

### ⚙️ Miscellaneous Tasks

- Add coverage report action
- Update coverage action
## [2026.16.11] - 2026-04-14

### 💼 Other

- Merge pull request #14 from audricsun/ci/improve-pipeline-with-cache

ci: add cache to CI
- Bump version to 2026.16.11

### ⚙️ Miscellaneous Tasks

- Add cache to CI
## [2026.16.10] - 2026-04-14

### 💼 Other

- Merge pull request #13 from audricsun/ci/fix-push-v3

Ci/fix push v3
- Bump version to 2026.16.10

### ⚙️ Miscellaneous Tasks

- Commit Cargo.lock before cargo publish (build may update lockfile)
- Commit Cargo.lock in auto-bump step before push (keeps lockfile clean for publish)
- Amend Cargo.lock into bump commit (no separate commit)
- Guard Cargo.lock amend (skip if unchanged)
## [2026.16.9] - 2026-04-14

### 🐛 Bug Fixes

- Rand::thread_rng() -> rand::rng() for rand 0.9

### 💼 Other

- Merge pull request #2 from audricsun/chore/fix-ci-issues

chore: fix audit and clippy issues
- Merge pull request #3 from audricsun/chore/auto-release-pipeline-with-github-actions

chore: enable release at pipeline
- Bump version to 2026.16.3
- Merge pull request #4 from audricsun/chore/fix-ci-permissions

Chore/fix ci permissions
- Merge pull request #5 from audricsun/test/test-ci

docs: update readme
- Bump version to 2026.16.4
- Merge pull request #6 from audricsun/dependabot/cargo/rand-0.9.3

chore(deps): bump rand from 0.8.5 to 0.9.3
- Bump version to 2026.16.5
- Bump deps
- Merge pull request #7 from audricsun/chore/bump-deps

Chore: bump deps
- Bump version to 2026.16.6
- Merge pull request #8 from audricsun/chore/bump-deps

Chore/bump deps
- Bump version to 2026.16.7
- Merge pull request #9 from audricsun/ci/fix-push-token-v2

ci: set git identity with --local right before git push
- Merge pull request #10 from audricsun/ci/test-pipeline

docs: update readme
- Merge pull request #11 from audricsun/ci/test-pipeline-v2

ci: set git identity before make bump; use explicit 'git push origin …
- Bump version to 2026.16.8
- Merge pull request #12 from audricsun/ci/fix-push-v3

Ci/fix push v3
- Bump version to 2026.16.9

### 📚 Documentation

- Update readme
- Update readme
- Update readme

### ⚙️ Miscellaneous Tasks

- Enable release at pipeline
- Update CI for issues
- Fix ci permissions
- Fix ci permissions
- *(gh)* VERSION-gated release pipeline improvements
- *(gitlab)* Remove — migrated to GitHub Actions
- *(gh)* Add explicit git credential config and robust cancel via curl
- *(gh)* Remove self-cancel step — concurrency group handles old run cancellation
- *(gh)* Add VERSION and artifact guards in release step
- Split into 3 workflows (tests, pr, release) for clarity and reliability
- Fix ci-pr.yml checkout to use default GITHUB_TOKEN (GH_PAT unavailable for fork PRs)
- Remove ci-pr.yml (version check belongs only in ci-release.yml)
- Remove --locked from build-musl (target add requires lock file update)
- Update actions/checkout from v4 to v5 (Node.js 24)
- Remove --locked from build and publish (deps updated, lockfile may change)
- Set git identity with --local right before git push
- Use GH_PAT for collaborator permission check
- Set git identity before make bump; use explicit 'git push origin main'
- Set git identity before make bump; use explicit 'git push origin main'
- Set git identity before git tag in Tag and GitHub release step
## [2026.16.2] - 2026-04-13

### 💼 Other

- Bump version to 2026.16.2

### ⚙️ Miscellaneous Tasks

- Fix audit and clippy issues
- Fix fmt
## [2026.16.1] - 2026-04-13

### 💼 Other

- Project init
- Bump version to 2026.16.1
