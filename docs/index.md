# Certboy

<div align="center"><img src="images/logo.png" width="250"></div>

Certboy is a Rust CLI for managing a local PKI (Public Key Infrastructure):

- **Root CA** - Self-signed trust anchor
- **Intermediate CA (ICA)** - Issued by a Root CA for delegated signing
- **TLS/server certificates** - Issued by Root CA or ICA

## Features

- Simple CLI interface for certificate management
- Automatic certificate chain handling
- Certificate expiration monitoring
- Shell completion scripts for bash, zsh, fish, and PowerShell
- Import/export functionality
- Remote TLS certificate verification

## Quick Links

- [Get Started](get-started.md) - Installation and quickstart guide
- [User Guides](user-guides/index.md) - Detailed guides for each feature
- [CLI Reference](reference/index.md) - Complete command reference

## Disclaimer

This project is a POC for personal study and homelab use. **Do not suggest using for production.**

---

*For questions or issues, please refer to the [GitHub repository](https://github.com/audricsun/certboy).*