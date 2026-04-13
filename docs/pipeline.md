# Pipeline Workflow

This repository uses GitLab CI to validate changes and produce build artifacts. GitHub Actions mirrors the build artifacts step.

## GitLab CI Overview

Stages:

- `test`: check/fmt/test/e2e/build
- `release`: publish (master branch only)

## Publish on master

The pipeline includes a `cargo-publish` job:

- Runs only on `master` branch pipelines (not on merge request pipelines)
- Runs only after the `test` stage succeeds
- Executes `cargo publish --locked`

Required CI variables:

- `CARGO_REGISTRY_TOKEN`: Cargo registry token with publish permission

## Local verification (same intent as CI)

```bash
cargo fmt --check
cargo test
```
