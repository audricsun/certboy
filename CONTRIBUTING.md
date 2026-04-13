# Contributing to certboy

Thanks for contributing.

## Development Setup

- Rust toolchain (stable)
- OpenSSL development headers as needed by your environment

## Local Checks

Run formatting and tests before submitting changes:

```bash
cargo fmt
cargo test
```

## Submitting Changes

- Keep changes focused and easy to review.
- Update documentation if you change behavior, flags, defaults, or file layouts.
- If you add a new feature or fix a bug, add or update tests where appropriate.

## Reporting Issues

When filing an issue, include:

- What you ran (command + flags)
- Expected vs actual behavior
- Relevant output (redact secrets)
- Your OS and Rust version

## Security

Do not include private keys, passwords, or tokens in issues or pull requests.
