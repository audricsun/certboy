---
layout: default
title: Root CA
---

# Root CA

A Root Certificate Authority (CA) is the trust anchor in a PKI hierarchy. It is self-signed and used to sign Intermediate CAs and TLS certificates.

## Create a Root CA

```bash
certboy --domain example.com --cn "Example Organization" --root-ca
```

**Parameters:**

| Flag | Description | Required |
|------|-------------|----------|
| `--domain` | The domain for the Root CA | Yes |
| `--cn` | Common Name for the CA | Yes |
| `--country` | Country code (default: CN) | No |
| `--key-algorithm` | `ecdsa` (default) or `rsa` | No |
| `--expiration` | Expiration in days (default: 7300/20 years) | No |
| `--encrypt-key` | Encrypt private key with passphrase | No |

## Examples

### Basic Root CA (ECDSA)

```bash
certboy --domain example.com --cn "Example Organization" --root-ca
```

### Root CA with RSA

```bash
certboy --domain example.com --cn "Example Organization" --root-ca --key-algorithm rsa
```

### Root CA with Custom Expiration

```bash
# 10 years (3650 days)
certboy --domain example.com --cn "Example Organization" --root-ca --expiration 3650
```

### Encrypted Private Key

```bash
certboy --domain example.com --cn "Example Organization" --root-ca --encrypt-key
```

This creates a `pass.key` file containing the passphrase for the encrypted private key.

## Context Structure

After creating a Root CA, the context directory contains:

```
~/.local/state/certboy/
└── example.com/
    ├── meta.json          # CA metadata (algorithm, created date)
    ├── crt.pem            # Public certificate
    ├── key.pem            # Private key (encrypted if --encrypt-key)
    ├── pass.key           # Encryption passphrase (if applicable)
    ├── intermediates.d/   # Intermediate CAs directory
    └── certs.d/           # TLS certificates directory
```

## Key Algorithm Inheritance

When you create a Root CA, all certificates issued under it inherit the key algorithm:

- **ECDSA P-256** (default) - Faster, shorter signatures
- **RSA** - Broader compatibility

The algorithm is stored in `meta.json` and applies to all ICAs and TLS certificates under this Root CA.