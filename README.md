# certboy

[![CI](https://img.shields.io/github/actions/workflow/status/audricsun/certboy/ci-tests.yml?label=CI)](https://github.com/audricsun/certboy/actions)
[![Build](https://img.shields.io/github/actions/workflow/status/audricsun/certboy/ci-build.yml?label=Build)](https://github.com/audricsun/certboy/actions)
[![Pages](https://img.shields.io/github/actions/workflow/status/audricsun/certboy/ci-pages.yml?label=Pages)](https://github.com/audricsun/certboy/actions)
[![Rust](https://img.shields.io/badge/rust-1.75+-?logo=rust)](https://rustup.rs/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

<div align="left"><img src="docs/images/logo.png" width="400"></div>

Certboy is a Rust CLI for managing a local PKI:

- Root CA (self-signed)
- Intermediate CA (issued by a Root CA)
- TLS/server certificates (issued by Root CA or ICA)

![screenshot](docs/screenshot.png)

## Disclaimer

This project is just a POC for my personal study and homelab. DO NOT SUGGEST USING FOR PRODUCTION.
certboy stores everything in a single “context” directory and provides utilities for creating, inspecting, exporting, importing, renewing, and revoking certificates.

## Default Context

- Default: `~/.local/state/certboy` (or `$XDG_STATE_HOME/certboy`)
- Override: `--context <path>`
- Env override: `CERTBOY_CONTEXT`

## Key Algorithm

- Root CA key algorithm defaults to ECDSA P-256.
- The algorithm is written to `meta.json` and all ICAs/TLS certificates under that Root CA inherit it.

## Install

Build from source:

```bash
cargo build --release
sudo cp target/release/certboy /usr/local/bin/
```

## Quickstart

```bash
./scripts/quickstart.sh
```

## Common Examples

Initialize a Root CA:

```bash
certboy --domain example.com --cn ExampleOrg --root-ca
```

Initialize a Root CA with RSA:

```bash
certboy --domain example.com --cn ExampleOrg --root-ca --key-algorithm rsa
```

Create an Intermediate CA:

```bash
certboy --domain ops.example.com --ca example.com --cn Ops.ExampleOrg
```

Issue a TLS certificate (single domain):

```bash
certboy --ca example.com -d auth.example.com
```

Issue a TLS certificate with multiple SANs (positional args are merged with `-d/--domain`):

```bash
certboy --ca ops.example.com docs.ops.example.com docs1.ops.example.com '*.ops.example.com' 127.0.0.1
```

Check certificates:

```bash
certboy check
certboy check --detail
certboy check --renew
```

## Environment Variables

- `LOGLEVEL`: default log level (`trace|debug|info|warn|error`)
- `CERTBOY_CONTEXT`: default context path (equivalent to `--context`)

## Documentation

Full documentation available at: **[https://audricsun.github.io/certboy/](https://audricsun.github.io/certboy/)**

## Development

```bash
cargo fmt
cargo test
```

## Release Workflow

Releases are automated. To trigger a release:

```bash
# Update VERSION to release version (e.g., 2026.4.1)
# The ci-bumpversion workflow auto-bumps dev versions
# The ci-git-tag workflow creates the git tag
# The ci-build workflow builds multi-platform binaries
# The ci-publish workflow creates GitHub Release and publishes to crates.io
```

## Built With

- [Rust](https://www.rust-lang.org/) - Language
- [OpenSSL](https://www.openssl.org/) - Cryptography (vendored)
- [clap](https://github.com/clap-rs/clap) - CLI argument parsing
- [tokio](https://tokio.rs/) - Async runtime
- [tracing](https://tokio.rs/blog/tracing) - Structured logging
- [serde](https://serde.rs/) - Serialization
- [chrono](https://crates.io/crates/chrono) - Date/time

### Dev Tools

- [cargo-nextest](https://nextest.rs/) - Test runner
- [cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov) - Code coverage
- [cargo-audit](https://rustsec.org/) - Security auditing
- [git-cliff](https://github.com/orf/git-cliff) - Changelog generation
- [bumpver](https://github.com/mbarkhau/bumpver) - Version bumping
- [zensical](https://github.com/nicowillis/zensical) - Documentation generator
- [cross](https://github.com/cross-rs/cross) - Cross-compilation
