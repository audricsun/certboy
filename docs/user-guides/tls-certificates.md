---
layout: default
title: TLS Certificates
---

# TLS Certificates

TLS certificates (also called server certificates) are end-entity certificates used by websites and services to enable HTTPS.

## Issue a TLS Certificate

```bash
certboy --ca example.com -d www.example.com
```

**Parameters:**

| Flag | Description | Required |
|------|-------------|----------|
| `--ca` | Parent CA (Root CA or ICA) name | Yes |
| `--domain`, `-d` | Domain name(s) for the certificate | Yes |
| `--force` | Force re-sign existing certificate | No |
| `--expiration` | Expiration in days (default: 1095/3 years) | No |
| `--encrypt-key` | Encrypt private key with passphrase | No |

## Examples

### Single Domain

```bash
certboy --ca example.com -d www.example.com
```

### Multiple SANs (Subject Alternative Names)

```bash
certboy --ca example.com \
  --domain api.example.com \
  --domain '*.example.com' \
  --domain 192.168.1.100
```

### Wildcard Certificate

```bash
certboy --ca example.com -d '*.example.com'
```

### Force Re-sign

If a certificate already exists and you need to re-issue it:

```bash
certboy --ca example.com -d www.example.com --force
```

### Encrypted Private Key

```bash
certboy --ca example.com -d www.example.com --encrypt-key
```

## Certificate Chain

TLS certificates issued by an ICA include the full certificate chain in `fullchain.crt`:

```
fullchain.crt
├── TLS certificate (www.example.com)
├── Intermediate CA certificate (ops.example.com)
└── Root CA certificate (example.com)
```

## Context Structure

```
example.com/
├── intermediates.d/
│   └── ops.example.com/
│       └── certs.d/
│           └── api.example.com/
│               ├── meta.json
│               ├── crt.pem           # Public certificate
│               ├── fullchain.crt     # Certificate + chain
│               ├── key.pem           # Private key
│               └── pass.key          # Encryption passphrase (if applicable)
└── certs.d/
    └── www.example.com/
        ├── meta.json
        ├── crt.pem
        ├── fullchain.crt
        ├── key.pem
        └── pass.key
```

## Expiration

Default expiration periods:

| Certificate Type | Default | Example |
|-----------------|---------|---------|
| Root CA | 7300 days (20 years) | 730 |
| Intermediate CA | 3650 days (10 years) | 1825 |
| TLS Certificate | 1095 days (3 years) | 365 |

Use `--expiration` to override:

```bash
certboy --ca example.com -d www.example.com --expiration 365
```